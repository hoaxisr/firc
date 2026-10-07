#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */
#include "greatest.h"

#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "firc/loop.h"
#include "firc/tunprobe.h"

#define FAKE "tests/unit/fixtures/fake_tunvless.sh"
#define U "00000000-0000-4000-8000-000000000001"

typedef struct {
    firc_loop_t *loop;
    char dir[64];
    char argv[128];
    char in[128];
    char starts[128];
    char fds[128];
    int calls;
    size_t n;
    firc_tunprobe_row_t rows[512];
    int64_t done_at;
} fx_t;

static fx_t g_fx;

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void setup(void *ud)
{
    (void)ud;
    memset(&g_fx, 0, sizeof g_fx);
    snprintf(g_fx.dir, sizeof g_fx.dir, "/tmp/firc_tunprobe_XXXXXX");
    if (mkdtemp(g_fx.dir) == NULL) {
        abort();
    }
    snprintf(g_fx.argv, sizeof g_fx.argv, "%s/argv", g_fx.dir);
    snprintf(g_fx.in, sizeof g_fx.in, "%s/stdin", g_fx.dir);
    snprintf(g_fx.starts, sizeof g_fx.starts, "%s/starts", g_fx.dir);
    snprintf(g_fx.fds, sizeof g_fx.fds, "%s/fds", g_fx.dir);
    setenv("FAKE_ARGV_OUT", g_fx.argv, 1);
    setenv("FAKE_STDIN_OUT", g_fx.in, 1);
    setenv("FAKE_STARTS_OUT", g_fx.starts, 1);
    setenv("FAKE_FDS_OUT", g_fx.fds, 1);
    setenv("FAKE_MODE", "probe", 1);
    if (firc_loop_create(&g_fx.loop) != FIRC_OK) {
        abort();
    }
}

static void teardown(void *ud)
{
    (void)ud;
    firc_loop_destroy(g_fx.loop);
    unlink(g_fx.argv);
    unlink(g_fx.in);
    unlink(g_fx.starts);
    unlink(g_fx.fds);
    rmdir(g_fx.dir);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

static void on_done(const firc_tunprobe_row_t *rows, size_t n, void *ud)
{
    (void)ud;
    g_fx.calls++;
    g_fx.n = n;
    memcpy(g_fx.rows, rows, (n < 512 ? n : 512) * sizeof *rows);
    g_fx.done_at = now_ms();
}

typedef bool (*pred_fn)(void);

typedef struct {
    int64_t deadline;
    pred_fn until;
} wait_t;

static void tick(firc_loop_t *loop, void *ud)
{
    wait_t *w = ud;
    if ((w->until != NULL && w->until()) || now_ms() >= w->deadline) {
        firc_loop_stop(loop);
    }
}

static void run_until(int ms, pred_fn until)
{
    wait_t w = {now_ms() + ms, until};
    int timer = 0;
    firc_loop_add_timer(g_fx.loop, 10, 10, tick, &w, &timer);
    firc_loop_run(g_fx.loop);
    firc_loop_del_timer(g_fx.loop, timer);
}

static bool answered(void)
{
    return g_fx.calls > 0;
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

static pid_t child_pid(void)
{
    char buf[256];
    slurp(g_fx.starts, buf, sizeof buf);
    const char *sp = strchr(buf, ' ');
    return sp != NULL ? (pid_t)atoi(sp + 1) : 0;
}

static bool started(void)
{
    return child_pid() > 0;
}

static firc_tunprobe_opts_t opts(uint32_t mark, bool insecure, const char *ca, int64_t kill_ms)
{
    firc_tunprobe_opts_t o = {.binary = FAKE, .mark = mark, .insecure = insecure, .ca = ca, .timeout_s = 3,
                              .kill_after_ms = kill_ms};
    return o;
}

/* catches: results mapped to the wrong link, a failed node read as ok, or the links not all written */
TEST each_link_gets_the_row_the_child_printed_for_its_index(void)
{
    char *links[] = {"vless://" U "@a.example.invalid:443?security=none#A",
                     "vless://" U "@fail.example.invalid:443?security=none#F",
                     "vless://" U "@c.example.invalid:443?security=none#C"};
    firc_tunprobe_opts_t o = opts(0, false, NULL, 5000);
    firc_tunprobe_t *p = NULL;
    ASSERT_EQ(FIRC_OK, firc_tunprobe_start(g_fx.loop, &o, links, 3, on_done, NULL, &p));
    run_until(5000, answered);
    ASSERT_EQ(1, g_fx.calls);
    ASSERT_EQ_FMT((size_t)3, g_fx.n, "%zu");
    ASSERT(g_fx.rows[0].have && g_fx.rows[0].ok);
    ASSERT_EQ(10, g_fx.rows[0].handshake_ms);
    ASSERT_EQ(20, g_fx.rows[0].first_byte_ms);
    ASSERT_STR_EQ("", g_fx.rows[0].why);
    ASSERT(g_fx.rows[1].have);
    ASSERT_FALSE(g_fx.rows[1].ok);
    ASSERT_STR_EQ("connection refused", g_fx.rows[1].why);
    ASSERT(g_fx.rows[2].have && g_fx.rows[2].ok);
    ASSERT_EQ(12, g_fx.rows[2].handshake_ms);
    ASSERT_EQ(22, g_fx.rows[2].first_byte_ms);
    char buf[1024];
    slurp(g_fx.in, buf, sizeof buf);
    char want[1024];
    snprintf(want, sizeof want, "%s\n%s\n%s\n", links[0], links[1], links[2]);
    ASSERT_STR_EQ(want, buf);
    PASS();
}

/* catches: a mark, --insecure or --ca missing from the probe, or given when not asked for */
TEST the_command_line_carries_mark_insecure_and_ca_only_when_set(void)
{
    char *links[] = {"vless://" U "@a.example.invalid:443?security=none#A"};
    firc_tunprobe_opts_t o = opts(0x2a0000, true, "/etc/ca.pem", 5000);
    firc_tunprobe_t *p = NULL;
    ASSERT_EQ(FIRC_OK, firc_tunprobe_start(g_fx.loop, &o, links, 1, on_done, NULL, &p));
    run_until(5000, answered);
    char buf[512];
    slurp(g_fx.argv, buf, sizeof buf);
    ASSERT_STR_EQ("--probe\n-t\n3\n-m\n0x2a0000\n--insecure\n--ca\n/etc/ca.pem\n-\n", buf);
    g_fx.calls = 0;
    o = opts(0, false, "", 5000);
    ASSERT_EQ(FIRC_OK, firc_tunprobe_start(g_fx.loop, &o, links, 1, on_done, NULL, &p));
    run_until(5000, answered);
    slurp(g_fx.argv, buf, sizeof buf);
    ASSERT_STR_EQ("--probe\n-t\n3\n-\n", buf);
    PASS();
}

/* catches: a stdin write that stops at the pipe buffer, losing the rows of later links */
TEST links_beyond_a_pipe_buffer_all_reach_the_child(void)
{
    static char store[400][320];
    static char *links[400];
    for (int i = 0; i < 400; i++) {
        snprintf(store[i], sizeof store[i], "vless://" U "@n%d.example.invalid:443?security=none&path=%0200d#N%d", i,
                 0, i);
        links[i] = store[i];
    }
    firc_tunprobe_opts_t o = opts(0, false, NULL, 20000);
    firc_tunprobe_t *p = NULL;
    ASSERT_EQ(FIRC_OK, firc_tunprobe_start(g_fx.loop, &o, links, 400, on_done, NULL, &p));
    run_until(20000, answered);
    ASSERT_EQ(1, g_fx.calls);
    ASSERT_EQ_FMT((size_t)400, g_fx.n, "%zu");
    ASSERT(g_fx.rows[399].have && g_fx.rows[399].ok);
    ASSERT_EQ(409, g_fx.rows[399].handshake_ms);
    PASS();
}

/* catches: a hung child kept past its deadline, left unreaped, or the answer never given */
TEST a_hung_child_is_killed_at_the_deadline(void)
{
    setenv("FAKE_MODE", "noread", 1);
    char *links[] = {"vless://" U "@a.example.invalid:443?security=none#A"};
    firc_tunprobe_opts_t o = opts(0, false, NULL, 300);
    firc_tunprobe_t *p = NULL;
    int64_t t0 = now_ms();
    ASSERT_EQ(FIRC_OK, firc_tunprobe_start(g_fx.loop, &o, links, 1, on_done, NULL, &p));
    run_until(3000, answered);
    ASSERT_EQ(1, g_fx.calls);
    ASSERT(g_fx.done_at - t0 >= 300);
    ASSERT(g_fx.done_at - t0 < 2000);
    ASSERT_FALSE(g_fx.rows[0].have);
    pid_t pid = child_pid();
    ASSERT(pid > 0);
    ASSERT(kill(pid, 0) == -1 && errno == ESRCH);
    PASS();
}

/* catches: a cancel that leaves the child running or still answers */
TEST a_cancel_kills_the_child_and_never_answers(void)
{
    setenv("FAKE_MODE", "noread", 1);
    char *links[] = {"vless://" U "@a.example.invalid:443?security=none#A"};
    firc_tunprobe_opts_t o = opts(0, false, NULL, 300);
    firc_tunprobe_t *p = NULL;
    ASSERT_EQ(FIRC_OK, firc_tunprobe_start(g_fx.loop, &o, links, 1, on_done, NULL, &p));
    run_until(3000, started);
    pid_t pid = child_pid();
    ASSERT(pid > 0);
    firc_tunprobe_cancel(p);
    ASSERT(kill(pid, 0) == -1 && errno == ESRCH);
    run_until(600, NULL);
    ASSERT_EQ(0, g_fx.calls);
    PASS();
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

/* catches: a probe pipe or /dev/null left open across exec, reaching the child beyond fds 0-2 */
TEST the_child_gets_only_fds_0_to_2(void)
{
    static bool before[FD_CAP];
    open_fds(before);
    setenv("FAKE_MODE", "fds", 1);
    char *links[] = {"vless://" U "@a.example.invalid:443?security=none#A"};
    firc_tunprobe_opts_t o = opts(0, false, NULL, 400);
    firc_tunprobe_t *p = NULL;
    ASSERT_EQ(FIRC_OK, firc_tunprobe_start(g_fx.loop, &o, links, 1, on_done, NULL, &p));
    run_until(3000, answered);
    char buf[8192];
    slurp(g_fx.fds, buf, sizeof buf);
    int seen = 0;
    ASSERT_EQ(0, child_fds_not_inherited(buf, before, &seen));
    ASSERT(seen >= 3);
    PASS();
}

/* catches: a deadline that does not grow with the number of links */
TEST the_deadline_is_three_seconds_a_link_plus_five(void)
{
    ASSERT_EQ(8000, firc_tunprobe_deadline_ms(1));
    ASSERT_EQ(17000, firc_tunprobe_deadline_ms(4));
    ASSERT_EQ(773000, firc_tunprobe_deadline_ms(256));
    PASS();
}

SUITE(tunprobe)
{
    GREATEST_SET_SETUP_CB(setup, NULL);
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(each_link_gets_the_row_the_child_printed_for_its_index);
    RUN_TEST(the_command_line_carries_mark_insecure_and_ca_only_when_set);
    RUN_TEST(links_beyond_a_pipe_buffer_all_reach_the_child);
    RUN_TEST(a_hung_child_is_killed_at_the_deadline);
    RUN_TEST(a_cancel_kills_the_child_and_never_answers);
    RUN_TEST(the_child_gets_only_fds_0_to_2);
    RUN_TEST(the_deadline_is_three_seconds_a_link_plus_five);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(tunprobe);
    GREATEST_MAIN_END();
}
