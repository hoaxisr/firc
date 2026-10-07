#include "greatest.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "firc/iptables.h"
#include "firc/log.h"
#include "firc/loop.h"
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

typedef struct {
    firc_tunsup_t *s;
    firc_loop_t *loop;
    int backoffs[64];
    int n_backoffs;
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
    unsetenv("FAKE_NOACK");
    unsetenv("FAKE_EVENTS");
    unsetenv("FAKE_AFTER");
    unsetenv("FAKE_ACK_COUNT");
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
    if (ev != NULL) {
        r->n_ev++;
        if (ev->kind == FIRC_TEV_NODE_DOWN && r->n_down < 16) {
            r->down_pos[r->n_down++] = ev->pos;
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
    firc_loop_add_timer(r->loop, ms, 0, stop_cb, NULL, NULL);
    firc_loop_run(r->loop);
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
    firc_tunnels_t set = {&t, 1};
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
    /* catches: a wrong flag, address or mark format, or a link on the command line */
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
    firc_tunnels_t set = {&t, 1};
    uint32_t marks[] = {0x1a};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, marks));
    run_ms(&r, 700);
    char buf[512];
    read_file(g_argv, buf, sizeof buf);
    ASSERT_STR_EQ("--control\n-d\ntunvless3\n-a\n198.51.100.4/32\n-A\n2\n--by\nlatency\n--interval\n45\n"
                  "--silence\n12\n-t\n7\n-m\n0x1a\n--insecure\n--ca\n/opt/etc/ca.pem\n",
                  buf);
    ASSERT(strstr(buf, "vless://") == NULL);
    rec_close(&r);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST argv_minimal_without_options(void)
{
    /* catches: -m, --insecure or --ca passed when not set */
    env_setup("ok");
    char *links[] = {"vless://secret@h1:443#one"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {&t, 1};
    uint32_t marks[] = {0};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, marks));
    run_ms(&r, 700);
    char buf[512];
    read_file(g_argv, buf, sizeof buf);
    ASSERT_STR_EQ("--control\n-d\ntunvless0\n-a\n198.51.100.1/32\n-A\n1\n--by\nlatency\n--interval\n30\n"
                  "--silence\n10\n-t\n5\n",
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
    firc_tunnels_t set = {&t, 1};
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
    ASSERT(strstr(buf, "INF tunnel tunvless0: tunvless[info]: up\n") != NULL);
    ASSERT(strstr(buf, "WRN tunnel tunvless0: tunvless[warn]: bad option\n") != NULL);
    ASSERT(strstr(buf, "vless://") == NULL);
    ASSERT(no_children());
    env_teardown();
    PASS();
}

TEST crash_restarts_with_growing_backoff(void)
{
    /* catches: no restart after a crash, or a backoff that does not double */
    env_setup("crash");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {&t, 1};
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
    rec_close(&r);
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
    firc_tunnels_t set = {&t, 1};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 10);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 2200);
    ASSERT(r.n_backoffs >= 7);
    const int want[] = {3, 6, 12, 24, 48, 60, 60};
    for (int i = 0; i < 7; i++) {
        ASSERT_EQ(want[i], r.backoffs[i]);
    }
    for (int i = 7; i < r.n_backoffs; i++) {
        ASSERT_EQ(60, r.backoffs[i]);
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
    firc_tunnels_t set = {&t, 1};
    static rec_t r;
    rec_open(&r);
    firc_tunsup_set_second_ms_for_test(r.s, 10);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 1600);
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
    /* catches: a tight restart loop on a config error */
    env_setup("badconf");
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {&t, 1};
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
    firc_tunnels_t set = {&t, 1};
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
    firc_tunnels_t set = {&t, 1};
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
    firc_tunnels_t set = {&t, 1};
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
    firc_tunnels_t set = {&t, 1};
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
    firc_tunnels_t set = {&t, 1};
    firc_tunnels_t set2 = {&t2, 1};
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
    firc_tunnels_t set = {t, 2};
    firc_tunnels_t set2 = {t2, 2};
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
    firc_tunnels_t set = {t, 2};
    firc_tunnels_t set2 = {&t2, 1};
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
    firc_tunnels_t set = {&t, 1};
    firc_tunnels_t set_off = {&off, 1};
    firc_tunnels_t set_on = {&on, 1};
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
    firc_tunnels_t set = {t, 3};
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

static void *save_thread(void *ud)
{
    firc_ipt_executable_t *exe = ud;
    uint8_t *out = NULL;
    size_t len = 0;
    exe->ops->save(exe, &out, &len);
    free(out);
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
    firc_ipt_executable_t *exe = firc_ipt_executable_real_new(FIRC_IPT_PROTO_IPV4);
    ASSERT(exe != NULL);
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, save_thread, exe));
    struct timespec ts = {0, 300 * 1000000L};
    nanosleep(&ts, NULL);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {&t, 1};
    static rec_t r;
    rec_open(&r);
    open_fds(during);
    ASSERT(fresh_pipes(before, during) > 0);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 300);
    pthread_join(th, NULL);
    firc_ipt_executable_free(exe);
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

TEST warn_tag_followed_by_space_is_warn(void)
{
    /* catches: "tunvless[warn] tunnel: ..." logged at INFO, or any "tunvless[warn" prefix taken as WARN */
    env_setup("warnsp");
    log_to_file();
    ASSERT(g_log_fd >= 0);
    char *links[] = {"vless://u@h:443#x"};
    firc_tunnel_t t;
    tun_init(&t, "a", 0, links, 1);
    firc_tunnels_t set = {&t, 1};
    static rec_t r;
    rec_open(&r);
    ASSERT_EQ(FIRC_OK, firc_tunsup_apply(r.s, &set, NULL));
    run_ms(&r, 500);
    rec_close(&r);
    log_done();
    char buf[8192];
    read_file(g_log, buf, sizeof buf);
    ASSERT(strstr(buf, "WRN tunnel tunvless0: tunvless[warn] tunnel: device tunvless0 was not created\n") != NULL);
    ASSERT(strstr(buf, "INF tunnel tunvless0: tunvless[warn]ing: not a warn tag\n") != NULL);
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
    firc_tunnels_t set = {&t, 1};
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
    firc_tunnels_t set = {&t, 1};
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
    firc_tunnels_t set = {t, 2};
    firc_tunnels_t set2 = {t2, 2};
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
    firc_tunnels_t set = {&t, 1};
    firc_tunnels_t set2 = {&t2, 1};
    firc_tunnels_t set3 = {&t3, 1};
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
    firc_tunnels_t both = {t, 2};
    firc_tunnels_t only_b = {&t[1], 1};
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
static firc_tunnels_t g_set1 = {&g_t1, 1};
static firc_tunnels_t g_set2 = {&g_t2, 1};

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
    /* catches: a child that never takes the new list left running on the old one */
    env_setup("nodes");
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
    ASSERT_EQ(1, count_of(log, "tunnel tunvless0: tunvless did not take the node list in 10 s, restarting"));
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
    ASSERT_EQ(1, count_of(log, "tunnel tunvless0: pin table full, restarting"));
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
    run_ms(&r, 900);
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
    static firc_tunnels_t set3 = {&t3, 1};
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
    ASSERT_EQ(1, count_of(log, "tunnel tunvless0: tunvless took 1 of 2 nodes, node states go by name until it restarts"));
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
    static firc_tunnels_t set3 = {&t3, 1};
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

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(ok_child_up_links_on_stdin);
    RUN_TEST(reap_hook_names_each_child_once_reaped);
    RUN_TEST(argv_full_and_no_link);
    RUN_TEST(argv_minimal_without_options);
    RUN_TEST(stderr_logged_by_level_without_links);
    RUN_TEST(crash_restarts_with_growing_backoff);
    RUN_TEST(backoff_doubles_up_to_sixty);
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
    RUN_TEST(warn_tag_followed_by_space_is_warn);
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
    GREATEST_MAIN_END();
}
