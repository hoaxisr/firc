#include "greatest.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/rtnetlink.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "fake_rtnl.h"
#include "firc/events.h"
#include "firc/httpd.h"
#include "firc/sub_fetch.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/mark.h"
#include "firc/rtnl.h"
#include "firc/tunnet.h"
#include "firc/tunrun.h"
#include "firc/tunsubs.h"
#include "firc/tunwatch.h"

#define FAKE "tests/unit/fixtures/fake_tunvless.sh"
#define START 4200u

typedef struct {
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    firc_loop_t *loop;
    firc_tunrun_t *run;
    char dir[64];
    char starts[128];
    char argv[128];
} fx_t;

static fx_t *g_fx;
static bool g_link_wan[2];
static const char *const g_link[] = {"lo", "firc-noip0"};
static firc_tunsubs_t *g_subs;
static pid_t g_watch_pid;
static pid_t g_watch_pid2;
static uint32_t g_watch_mark;
static int g_dels_while_alive;

typedef struct {
    const char *id;
    int n;
    firc_uplink_kind_t uplink;
    const char *ref;
    bool off;
} spec_t;

static void tunnels_of(firc_tunnels_t *out, const spec_t *s, size_t n)
{
    out->n = n;
    out->t = calloc(n + 1, sizeof *out->t);
    for (size_t i = 0; i < n; i++) {
        firc_tunnel_t *t = &out->t[i];
        snprintf(t->id, sizeof t->id, "%s", s[i].id);
        snprintf(t->device, sizeof t->device, "tunvless%d", s[i].n);
        t->enable = !s[i].off;
        t->uplink = s[i].uplink;
        snprintf(t->uplink_ref, sizeof t->uplink_ref, "%s", s[i].ref != NULL ? s[i].ref : "");
        t->src = calloc(1, sizeof *t->src);
        t->src[0].kind = FIRC_TUN_SRC_LINK;
        snprintf(t->src[0].id, sizeof t->src[0].id, "%08zx", i);
        t->src[0].link = strdup("vless://11111111-2222-3333-4444-555555555555@h.example:1?security=none#a");
        t->n_src = 1;
        t->active = 1;
        snprintf(t->by, sizeof t->by, "connection");
        t->interval_s = 60;
        t->silence_s = 20;
        t->timeout_s = 8;
    }
}

static bool fx_up(fx_t *f, unsigned link_flags)
{
    memset(f, 0, sizeof *f);
    snprintf(f->dir, sizeof f->dir, "/tmp/firc_tunrun_XXXXXX");
    if (mkdtemp(f->dir) == NULL) {
        return false;
    }
    snprintf(f->starts, sizeof f->starts, "%s/starts", f->dir);
    snprintf(f->argv, sizeof f->argv, "%s/argv", f->dir);
    setenv("FAKE_STARTS_OUT", f->starts, 1);
    setenv("FAKE_ARGV_OUT", f->argv, 1);
    setenv("FAKE_MODE", "ok", 1);
    unsetenv("FAKE_STUBBORN_DEV");
    unsetenv("FAKE_EVENTS");
    unsetenv("FAKE_AFTER");
    unsetenv("FAKE_STDIN_OUT");
    unsetenv("FAKE_STDIN_DIR");
    unsetenv("FAKE_SLEEP");
    unsetenv("FAKE_TCPPORT");
    unsetenv("FAKE_MAPCOUNT");
    unsetenv("FAKE_MISS");
    unsetenv("FAKE_NOACK");
    unsetenv("FAKE_CLOSED");
    f->kernel = fake_rtnl_start(&f->rtnl);
    if (f->kernel == NULL || firc_loop_create(&f->loop) != FIRC_OK) {
        return false;
    }
    fake_rtnl_set_link_flags(f->kernel, link_flags);
    const firc_tunrun_lan_t lan = {g_link, g_link_wan, 2};
    f->run = firc_tunrun_new(f->loop, f->rtnl, START, FAKE, &lan);
    memset(g_link_wan, 0, sizeof g_link_wan);
    g_fx = f;
    return f->run != NULL;
}

static void fx_down(fx_t *f)
{
    if (g_subs != NULL) {
        firc_tunrun_set_subs(f->run, NULL);
        firc_tunsubs_free(g_subs);
        g_subs = NULL;
        char cmd[128];
        snprintf(cmd, sizeof cmd, "rm -rf '%s/cache'", f->dir);
        if (system(cmd) != 0) {
        }
    }
    if (f->run != NULL) {
        firc_tunrun_free(f->run);
        f->run = NULL;
    }
    if (f->loop != NULL) {
        firc_loop_destroy(f->loop);
        f->loop = NULL;
    }
    if (f->rtnl != NULL) {
        firc_rtnl_close(f->rtnl);
        f->rtnl = NULL;
    }
    if (f->kernel != NULL) {
        fake_rtnl_stop(f->kernel);
        f->kernel = NULL;
    }
    if (f->dir[0] != 0) {
        for (int i = 0; i < 4; i++) {
            char dev[96];
            snprintf(dev, sizeof dev, "%s/tunvless%d", f->dir, i);
            unlink(dev);
        }
        unlink(f->starts);
        unlink(f->argv);
        rmdir(f->dir);
        f->dir[0] = 0;
    }
    g_fx = NULL;
}

static void kx_reset(void);

static void teardown(void *ud)
{
    (void)ud;
    kx_reset();
    g_watch_pid = 0;
    g_watch_pid2 = 0;
    unsetenv("FAKE_STUBBORN_DEV");
    if (g_fx != NULL) {
        fx_down(g_fx);
    }
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}

static void apply(fx_t *f, const spec_t *s, size_t n)
{
    firc_tunnels_t t;
    tunnels_of(&t, s, n);
    (void)firc_tunrun_apply(f->run, &t);
    firc_tunnels_free(&t);
}

static size_t slurp(const char *path, char *buf, size_t cap)
{
    buf[0] = 0;
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        return 0;
    }
    size_t n = fread(buf, 1, cap - 1, fp);
    buf[n] = 0;
    fclose(fp);
    return n;
}

static int starts_of(fx_t *f, const char *dev)
{
    char buf[2048];
    slurp(f->starts, buf, sizeof buf);
    int n = 0;
    size_t dl = strlen(dev);
    for (const char *p = buf; *p != 0;) {
        if (strncmp(p, dev, dl) == 0 && p[dl] == ' ') {
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

static pid_t last_pid(fx_t *f, const char *dev)
{
    char buf[2048];
    slurp(f->starts, buf, sizeof buf);
    pid_t pid = 0;
    size_t dl = strlen(dev);
    for (const char *p = buf; *p != 0;) {
        if (strncmp(p, dev, dl) == 0 && p[dl] == ' ') {
            pid = (pid_t)atoi(p + dl + 1);
        }
        const char *nl = strchr(p, '\n');
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    return pid;
}

typedef struct {
    fx_t *f;
    const char *dev;
    int want;
    int64_t deadline;
} wait_t;

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void poll_cb(firc_loop_t *loop, void *ud)
{
    wait_t *w = ud;
    if (starts_of(w->f, w->dev) >= w->want || now_ms() >= w->deadline) {
        firc_loop_stop(loop);
    }
}

static int run_until_starts(fx_t *f, const char *dev, int want, int ms)
{
    wait_t w = {f, dev, want, now_ms() + ms};
    int timer = 0;
    firc_loop_add_timer(f->loop, 20, 20, poll_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
    return starts_of(f, dev);
}

static void on_record(const fake_rtnl_msg_t *m, void *ud)
{
    (void)ud;
    bool alive = (g_watch_pid > 0 && kill(g_watch_pid, 0) == 0) || (g_watch_pid2 > 0 && kill(g_watch_pid2, 0) == 0);
    if (m->type == RTM_DELRULE && (g_watch_mark == 0 || m->mark == g_watch_mark) && alive) {
        g_dels_while_alive++;
    }
}

static void watch(fx_t *f, pid_t pid, uint32_t mark)
{
    g_watch_pid = pid;
    g_watch_mark = mark;
    g_dels_while_alive = 0;
    fake_rtnl_on_record(f->kernel, on_record, NULL);
}

typedef struct {
    fx_t *f;
    size_t want;
    int64_t deadline;
} dels_t;

static size_t count(fx_t *f, uint16_t type, uint8_t rtm_type, uint32_t priority);

static void dels_cb(firc_loop_t *loop, void *ud)
{
    dels_t *w = ud;
    if (count(w->f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL) >= w->want || now_ms() >= w->deadline) {
        firc_loop_stop(loop);
    }
}

static size_t run_until_dels(fx_t *f, size_t want, int ms)
{
    dels_t w = {f, want, now_ms() + ms};
    int timer = 0;
    firc_loop_add_timer(f->loop, 20, 20, dels_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
    return count(f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL);
}

static int wait_starts(fx_t *f, const char *dev, int want, int ms)
{
    int64_t deadline = now_ms() + ms;
    while (starts_of(f, dev) < want && now_ms() < deadline) {
        struct timespec ts = {0, 20 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return starts_of(f, dev);
}

static size_t count(fx_t *f, uint16_t type, uint8_t rtm_type, uint32_t priority)
{
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f->kernel, m, 64), c = 0;
    for (size_t i = 0; i < n && i < 64; i++) {
        if (m[i].type == type && (rtm_type == 0 || m[i].rtm_type == rtm_type) &&
            (priority == 0 || m[i].priority == priority)) {
            c++;
        }
    }
    return c;
}

static uint32_t last_rule_mark(fx_t *f)
{
    fake_rtnl_msg_t m[64];
    size_t n = fake_rtnl_messages(f->kernel, m, 64);
    uint32_t mark = 0;
    for (size_t i = 0; i < n && i < 64; i++) {
        if (m[i].type == RTM_NEWRULE) {
            mark = m[i].mark;
        }
    }
    return mark;
}

static bool argv_has(fx_t *f, const char *arg)
{
    char buf[1024];
    slurp(f->argv, buf, sizeof buf);
    size_t al = strlen(arg);
    for (const char *p = buf; *p != 0;) {
        const char *nl = strchr(p, '\n');
        size_t l = nl != NULL ? (size_t)(nl - p) : strlen(p);
        if (l == al && strncmp(p, arg, al) == 0) {
            return true;
        }
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
    return false;
}

/* catches: a tunnel uplink resolved to the tunnel id rather than that tunnel's device */
TEST uplink_device_names_the_device_packets_leave_by(void)
{
    firc_tunnel_t t[2];
    memset(t, 0, sizeof t);
    strcpy(t[0].id, "a");
    strcpy(t[0].device, "tunvless3");
    strcpy(t[1].id, "b");
    strcpy(t[1].device, "tunvless5");
    firc_tunnels_t all = {.t = t, .n = 2};
    t[1].uplink = FIRC_UPLINK_TUNNEL;
    strcpy(t[1].uplink_ref, "a");
    ASSERT_STR_EQ("tunvless3", firc_tunnet_uplink_device(&t[1], &all));
    strcpy(t[1].uplink_ref, "zz");
    ASSERT_EQ(NULL, firc_tunnet_uplink_device(&t[1], &all));
    t[1].uplink = FIRC_UPLINK_IFACE;
    strcpy(t[1].uplink_ref, "ppp0");
    ASSERT_STR_EQ("ppp0", firc_tunnet_uplink_device(&t[1], &all));
    t[1].uplink = FIRC_UPLINK_AUTO;
    ASSERT_EQ(NULL, firc_tunnet_uplink_device(&t[1], &all));
    PASS();
}

/* catches: journal lines that drift from the agreed wording or lose a node name */
TEST journal_lines_read_as_agreed(void)
{
    firc_tev_t ev;
    char buf[240];
    firc_log_level_t lv = FIRC_LOG_DEBUG;

    memset(&ev, 0, sizeof ev);
    ev.kind = FIRC_TEV_ACTIVE;
    strcpy(ev.active[0], "NL-1");
    strcpy(ev.active[1], "my-vps");
    ev.n_active = 2;
    ASSERT(firc_tun_journal_line(&ev, buf, sizeof buf, &lv));
    ASSERT_STR_EQ("active NL-1, my-vps", buf);
    ASSERT_EQ(FIRC_LOG_INFO, lv);

    memset(&ev, 0, sizeof ev);
    ev.kind = FIRC_TEV_NODE_DOWN;
    strcpy(ev.node, "NL-3");
    strcpy(ev.why, "timeout");
    ASSERT(firc_tun_journal_line(&ev, buf, sizeof buf, &lv));
    ASSERT_STR_EQ("NL-3 does not answer (timeout)", buf);
    ASSERT_EQ(FIRC_LOG_WARN, lv);
    ev.why[0] = 0;
    ASSERT(firc_tun_journal_line(&ev, buf, sizeof buf, &lv));
    ASSERT_STR_EQ("NL-3 does not answer", buf);

    memset(&ev, 0, sizeof ev);
    ev.kind = FIRC_TEV_NODE_UP;
    strcpy(ev.node, "NL-3");
    ASSERT(firc_tun_journal_line(&ev, buf, sizeof buf, &lv));
    ASSERT_STR_EQ("NL-3 answers again", buf);
    ASSERT_EQ(FIRC_LOG_INFO, lv);

    memset(&ev, 0, sizeof ev);
    ev.kind = FIRC_TEV_NO_NODE;
    ev.retry_s = 60;
    ASSERT(firc_tun_journal_line(&ev, buf, sizeof buf, &lv));
    ASSERT_STR_EQ("no node answers, retry in 60 s", buf);
    ASSERT_EQ(FIRC_LOG_WARN, lv);
    ev.retry_s = 0;
    ASSERT(firc_tun_journal_line(&ev, buf, sizeof buf, &lv));
    ASSERT_STR_EQ("no node answers", buf);
    PASS();
}

/* catches: an empty "active" line, or a line for every start and ready */
TEST quiet_events_write_no_line(void)
{
    char buf[240];
    firc_log_level_t lv = FIRC_LOG_DEBUG;
    firc_tev_t ev;
    memset(&ev, 0, sizeof ev);
    ev.kind = FIRC_TEV_READY;
    ASSERT_FALSE(firc_tun_journal_line(&ev, buf, sizeof buf, &lv));
    ev.kind = FIRC_TEV_ACTIVE;
    ASSERT_FALSE(firc_tun_journal_line(&ev, buf, sizeof buf, &lv));
    PASS();
}

static int journal_count(const char *source, const char *text);

/* catches: a tunnel whose uplink was never written started anyway, leaving by the main route, or the refusal journalled as fircd's */
TEST a_failed_uplink_is_not_started_until_a_reload_writes_it(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP));
    firc_event_reset_for_test();
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}, {"b", 1, FIRC_UPLINK_AUTO, NULL, false}};
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWRULE, EPERM);
    apply(&f, s, 2);
    ASSERT_EQ(1, wait_starts(&f, "tunvless1", 1, 2000));
    ASSERT_EQ(0, starts_of(&f, "tunvless0"));
    ASSERT_EQ(1, journal_count("tunvless0", "not started, its uplink could not be set up (system error)"));
    apply(&f, s, 2);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    ASSERT(argv_has(&f, "-m"));
    ASSERT_EQ(1, starts_of(&f, "tunvless1"));
    fx_down(&f);
    PASS();
}

/* catches: a field allocated for an uplink whose rule failed staying reserved, so a group gets the next one */
TEST a_failed_uplink_gives_its_mark_field_back(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWRULE, EPERM);
    apply(&f, s, 1);
    uint32_t field = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "grp", &field));
    ASSERT_EQ_FMT(1u, field, "%u");
    fx_down(&f);
    PASS();
}

static int uplink_ok_of(fx_t *f, const char *id)
{
    firc_tun_state_t st[8];
    size_t n = firc_tunrun_states(f->run, st, 8);
    for (size_t i = 0; i < n && i < 8; i++) {
        if (strcmp(st[i].id, id) == 0) {
            return st[i].uplink_ok ? 1 : 0;
        }
    }
    return -1;
}

/* catches: uplink_ok stuck at true while the uplink device is down, or not raised when the route is written */
TEST uplink_ok_follows_the_uplink_route(void)
{
    fx_t f;
    ASSERT(fx_up(&f, 0));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}, {"b", 1, FIRC_UPLINK_AUTO, NULL, false}};
    apply(&f, s, 2);
    ASSERT_EQ(0, uplink_ok_of(&f, "a"));
    ASSERT_EQ(1, uplink_ok_of(&f, "b"));
    fake_rtnl_set_link_flags(f.kernel, IFF_UP | IFF_POINTOPOINT);
    firc_tunrun_refresh_uplinks(f.run, "lo");
    ASSERT_EQ(1, uplink_ok_of(&f, "a"));
    fake_rtnl_set_link_flags(f.kernel, 0);
    apply(&f, s, 2);
    ASSERT_EQ(0, uplink_ok_of(&f, "a"));
    ASSERT_EQ(1, uplink_ok_of(&f, "b"));
    fx_down(&f);
    PASS();
}

/* catches: an uplink whose default route failed keeping its rule (and its mark field) */
TEST a_failed_default_route_takes_the_rule_back(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    fake_rtnl_fail_after_of(f.kernel, RTM_NEWROUTE, EPERM, 1);
    apply(&f, s, 1);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ(0, wait_starts(&f, "tunvless0", 1, 300));
    fx_down(&f);
    PASS();
}

/* catches: a removed tunnel's rule deleted while its tunvless still runs, or its field still held after */
TEST a_removed_tunnel_gives_back_its_rule_and_field_once_reaped(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t two[] = {{"x", 0, FIRC_UPLINK_IFACE, "lo", false}, {"a", 1, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, two, 2);
    ASSERT_EQ(1, wait_starts(&f, "tunvless1", 1, 2000));
    ASSERT_EQ_FMT(0x20000u, last_rule_mark(&f), "%#x");
    watch(&f, last_pid(&f, "tunvless1"), 0x20000u);
    apply(&f, NULL, 0);
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ_FMT((size_t)2, run_until_dels(&f, 2, 3000), "%zu");
    ASSERT_EQ(0, g_dels_while_alive);
    const spec_t one[] = {{"a", 1, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, one, 1);
    ASSERT_EQ_FMT(0x10000u, last_rule_mark(&f), "%#x");
    fx_down(&f);
    PASS();
}

typedef struct {
    const char *owner;
    uint32_t field;
} owner_q_t;

static void owner_cb(void *ud, const firc_rtnl_field_t *v, size_t n)
{
    owner_q_t *q = ud;
    q->field = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(v[i].owner, q->owner) == 0) {
            q->field = v[i].field;
        }
    }
}

static uint32_t field_of(fx_t *f, const char *owner)
{
    owner_q_t q = {owner, 0};
    firc_rtnl_fields_now(f->rtnl, owner_cb, &q);
    return q.field;
}

/* catches: a restarted daemon handing a tunnel a fresh field instead of the one the field map kept for it */
TEST a_restart_gives_a_tunnel_the_field_it_had(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "tun:a", 3));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, s, 1);
    ASSERT_EQ_FMT(0x30000u, last_rule_mark(&f), "%#x");
    ASSERT_EQ_FMT(3u, field_of(&f, "tun:a"), "%u");
    fx_down(&f);
    PASS();
}

/* catches: a field the map kept for a tunnel since deleted, disabled or set to auto staying reserved for ever */
TEST an_apply_frees_seeded_fields_no_tunnel_holds(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "tun:gone", 1));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "tun:b", 2));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "tun:c", 5));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "0000000a", 4));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false},
                        {"b", 1, FIRC_UPLINK_AUTO, NULL, false},
                        {"c", 2, FIRC_UPLINK_IFACE, "lo", true}};
    apply(&f, s, 3);
    ASSERT_EQ_FMT(0x30000u, last_rule_mark(&f), "%#x");
    ASSERT_EQ_FMT(0u, field_of(&f, "tun:gone"), "%u");
    ASSERT_EQ_FMT(0u, field_of(&f, "tun:b"), "%u");
    ASSERT_EQ_FMT(0u, field_of(&f, "tun:c"), "%u");
    ASSERT_EQ_FMT(4u, field_of(&f, "0000000a"), "%u");
    ASSERT_EQ_FMT(3u, field_of(&f, "tun:a"), "%u");
    uint32_t field = 0;
    ASSERT_EQ(FIRC_OK, firc_rtnl_alloc_mark_field_for(f.rtnl, "grp", &field));
    ASSERT_EQ_FMT(1u, field, "%u");
    fx_down(&f);
    PASS();
}

/* catches: a removed tunnel's field leaving the map while its tunvless still sends with that mark */
TEST a_removed_tunnel_keeps_its_field_in_the_map_until_reaped(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t one[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, one, 1);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    ASSERT_EQ_FMT(1u, field_of(&f, "tun:a"), "%u");
    watch(&f, last_pid(&f, "tunvless0"), 0x10000u);
    apply(&f, NULL, 0);
    apply(&f, NULL, 0);
    ASSERT_EQ_FMT(1u, field_of(&f, "tun:a"), "%u");
    ASSERT_EQ_FMT((size_t)1, run_until_dels(&f, 1, 3000), "%zu");
    ASSERT_EQ(0, g_dels_while_alive);
    ASSERT_EQ_FMT(0u, field_of(&f, "tun:a"), "%u");
    fx_down(&f);
    PASS();
}

/* catches: a tunnel back before its old child was reaped losing its rule to that reap */
TEST a_tunnel_back_before_the_reap_keeps_its_uplink(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t one[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, one, 1);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    apply(&f, NULL, 0);
    apply(&f, one, 1);
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 3000));
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELRULE, 0, 0), "%zu");
    ASSERT(argv_has(&f, "-m"));
    fx_down(&f);
    PASS();
}

typedef struct {
    fx_t *f;
    pid_t first;
    pid_t second;
    size_t dels_at_second_reap;
    bool second_reaped;
    int64_t deadline;
} holders_t;

static void holders_cb(firc_loop_t *loop, void *ud)
{
    holders_t *h = ud;
    if (!h->second_reaped && (h->second <= 0 || kill(h->second, 0) != 0)) {
        h->second_reaped = true;
        h->dels_at_second_reap = count(h->f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL);
        kill(h->first, SIGKILL);
    }
    if ((h->second_reaped && count(h->f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL) > 0) || now_ms() >= h->deadline) {
        firc_loop_stop(loop);
    }
}

static void run_holders(fx_t *f, holders_t *h)
{
    h->f = f;
    h->deadline = now_ms() + 4000;
    int timer = 0;
    firc_loop_add_timer(f->loop, 20, 20, holders_cb, h, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
}

/* catches: a second removal taking the holder from a deferred slot (pid 0) and freeing the rule under a live child */
TEST removed_twice_keeps_the_rule_while_the_first_child_lives(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    setenv("FAKE_STUBBORN_DEV", "tunvless0", 1);
    const spec_t x[] = {{"x", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, x, 1);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    pid_t p1 = last_pid(&f, "tunvless0");
    uint32_t mark = last_rule_mark(&f);
    watch(&f, p1, mark);
    apply(&f, NULL, 0);
    apply(&f, x, 1);
    apply(&f, NULL, 0);
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ(0, kill(p1, 0));
    holders_t h = {.first = p1, .second = 0};
    run_holders(&f, &h);
    ASSERT_EQ_FMT((size_t)0, h.dels_at_second_reap, "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ(0, g_dels_while_alive);
    fx_down(&f);
    PASS();
}

/* catches: the reap of a later child releasing the rule while an earlier, stubborn child still holds its mark */
TEST a_later_child_reaped_first_leaves_the_rule_to_the_earlier(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    setenv("FAKE_STUBBORN_DEV", "tunvless0", 1);
    const spec_t x0[] = {{"x", 0, FIRC_UPLINK_IFACE, "lo", false}};
    const spec_t x1[] = {{"x", 1, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, x0, 1);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    pid_t p1 = last_pid(&f, "tunvless0");
    uint32_t mark = last_rule_mark(&f);
    apply(&f, NULL, 0);
    apply(&f, x1, 1);
    ASSERT_EQ(1, wait_starts(&f, "tunvless1", 1, 2000));
    pid_t p2 = last_pid(&f, "tunvless1");
    ASSERT(argv_has(&f, "-m"));
    watch(&f, p1, mark);
    g_watch_pid2 = p2;
    apply(&f, NULL, 0);
    holders_t h = {.first = p1, .second = p2};
    run_holders(&f, &h);
    ASSERT(h.second_reaped);
    ASSERT_EQ_FMT((size_t)0, h.dels_at_second_reap, "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ(0, g_dels_while_alive);
    fx_down(&f);
    PASS();
}

/* catches: an uplink moved between interfaces through remove and apply (a window on main) or left on the old one */
TEST moving_an_uplink_keeps_the_rule_and_moves_the_default(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t lo[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, lo, 1);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_UNICAST, 0), "%zu");
    const spec_t gone[] = {{"a", 0, FIRC_UPLINK_IFACE, "firc-nope0", false}};
    apply(&f, gone, 1);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELRULE, 0, 0), "%zu");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELROUTE, RTN_UNICAST, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELROUTE, RTN_BLACKHOLE, 0), "%zu");
    fx_down(&f);
    PASS();
}

/* catches: a disabled tunnel holding a rule, a table and a mark field */
TEST a_disabled_tunnel_gets_no_uplink_until_enabled(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t off[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", true}};
    apply(&f, off, 1);
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_NEWRULE, 0, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_NEWROUTE, 0, 0), "%zu");
    const spec_t on[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, on, 1);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    ASSERT(argv_has(&f, "-m"));
    fx_down(&f);
    PASS();
}

/* catches: an uplink switched to auto keeping its rule, or tunvless kept on the old mark */
TEST switching_to_auto_drops_the_rule_and_the_mark(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t iface[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, iface, 1);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    ASSERT(argv_has(&f, "-m"));
    const spec_t aut[] = {{"a", 0, FIRC_UPLINK_AUTO, NULL, false}};
    apply(&f, aut, 1);
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 3000));
    ASSERT_FALSE(argv_has(&f, "-m"));
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    fx_down(&f);
    PASS();
}

/* catches: a reload rewriting the rule or restarting tunvless when nothing changed */
TEST an_unchanged_reload_keeps_rule_and_process(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, s, 1);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    pid_t pid = last_pid(&f, "tunvless0");
    apply(&f, s, 1);
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 2, 700));
    ASSERT(pid > 0 && kill(pid, 0) == 0);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_DELRULE, 0, 0), "%zu");
    fx_down(&f);
    PASS();
}

#define U "11111111-2222-3333-4444-555555555555"
#define TWO_LINKS                                                                        \
    "tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"                         \
    "      - id: 0000000a\n        link: \"vless://" U "@a.example:443?security=none#a\"\n" \
    "      - id: 0000000b\n        link: \"vless://" U "@b.example:443?security=none#b\"\n"

static void apply_yaml(fx_t *f, const char *doc)
{
    firc_tunnels_t t = {0};
    firc_tun_err_t e = {0};
    if (firc_tunnels_load_buffer(&t, doc, strlen(doc), &e) != FIRC_OK) {
        fprintf(stderr, "config: %s: %s\n", e.where, e.why);
        return;
    }
    (void)firc_tunrun_apply(f->run, &t);
    firc_tunnels_free(&t);
}

typedef struct {
    const char *path;
    char *buf;
    size_t cap;
    bool done;
    int64_t deadline;
} file_wait_t;

static void file_cb(firc_loop_t *loop, void *ud)
{
    file_wait_t *w = ud;
    size_t n = slurp(w->path, w->buf, w->cap);
    w->done = n >= 2 && w->buf[n - 1] == '\n' && w->buf[n - 2] == '\n';
    if (w->done || now_ms() >= w->deadline) {
        firc_loop_stop(loop);
    }
}

static bool run_until_file(fx_t *f, const char *path, char *buf, size_t cap, int ms)
{
    file_wait_t w = {path, buf, cap, false, now_ms() + ms};
    int timer = 0;
    firc_loop_add_timer(f->loop, 20, 20, file_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
    return w.done;
}

/* catches: an excluded node sent, or the links not rewritten from the parsed nodes */
TEST only_the_effective_links_reach_tunvless(void)
{
    fx_t f;
    ASSERT(fx_up(&f, 0));
    char in[256];
    snprintf(in, sizeof in, "%s/stdin", f.dir);
    setenv("FAKE_STDIN_OUT", in, 1);
    apply_yaml(&f, TWO_LINKS "    exclude: [\"0000000b:b\"]\n");
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    char buf[1024];
    bool done = run_until_file(&f, in, buf, sizeof buf, 2000);
    unsetenv("FAKE_STDIN_OUT");
    unlink(in);
    ASSERT(done);
    ASSERT_STR_EQ("vless://" U "@a.example:443?type=tcp&security=none#a\n\n", buf);
    fx_down(&f);
    PASS();
}

/* catches: a filter or order edit restarting tunvless although the links it is sent stay the same */
TEST a_filter_edit_keeps_tunvless_running(void)
{
    fx_t f;
    ASSERT(fx_up(&f, 0));
    apply_yaml(&f, TWO_LINKS);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    apply_yaml(&f, TWO_LINKS "    filter: \"zzz\"\n    order: [\"0000000a:a\"]\n");
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 2, 700));
    fx_down(&f);
    PASS();
}

/* catches: a changed list of sent links restarting tunvless, or never reaching it */
TEST a_changed_sent_list_reaches_tunvless_without_a_restart(void)
{
    fx_t f;
    ASSERT(fx_up(&f, 0));
    char in[256];
    snprintf(in, sizeof in, "%s/stdin", f.dir);
    setenv("FAKE_STDIN_OUT", in, 1);
    apply_yaml(&f, TWO_LINKS);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    uint64_t before = firc_tunrun_start_seq(f.run);
    apply_yaml(&f, TWO_LINKS "    exclude: [\"0000000a:a\"]\n");
    int starts = run_until_starts(&f, "tunvless0", 2, 1000);
    char buf[1024];
    slurp(in, buf, sizeof buf);
    unsetenv("FAKE_STDIN_OUT");
    unlink(in);
    ASSERT_EQ(1, starts);
    ASSERT(strstr(buf, "\n\nnodes\nvless://" U "@b.example:443?type=tcp&security=none#b\n\n") != NULL);
    ASSERT(firc_tunrun_updated(f.run, "a") > before);
    ASSERT(firc_tunrun_started(f.run, "a") <= before);
    fx_down(&f);
    PASS();
}

static void run_ms(fx_t *f, int ms);

#define FOUR_LINKS                                                                               \
    "tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"                                   \
    "      - id: 0000000a\n        link: \"vless://" U "@a.example:443?security=none#a\"\n"         \
    "      - id: 0000000b\n        link: \"vless://" U "@b.example:443?security=none#b\"\n"         \
    "      - id: 0000000c\n        link: \"vless://" U "@c.example:443?security=none#c\"\n"         \
    "      - id: 0000000d\n        link: \"vless://" U "@d.example:443?security=none#d\"\n"
#define LINK_OF(h) "vless://" U "@" h ".example:443?type=tcp&security=none#" h "\n"

/* catches: a list past tunvless's stdin limit sent whole (refused, or cut by tunvless out of step with fircd), or the cut journalled as fircd's */
TEST a_list_past_the_stdin_limit_is_cut_from_the_end(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    firc_event_reset_for_test();
    char in[256], logp[256];
    snprintf(in, sizeof in, "%s/stdin", f.dir);
    snprintf(logp, sizeof logp, "%s/log", f.dir);
    setenv("FAKE_STDIN_OUT", in, 1);
    int lfd = open(logp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    ASSERT(lfd >= 0);
    firc_log_set_fd(lfd);
    firc_tunrun_set_list_max_for_test(f.run, 200);
    apply_yaml(&f, FOUR_LINKS "    exclude: [\"0000000a:a\"]\n");
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    const firc_tun_nodes_t *rows = firc_tunrun_nodes(f.run, "a");
    ASSERT(rows != NULL && rows->n == 4);
    ASSERT_STR_EQ("", rows->v[2].skip_reason);
    ASSERT_STR_EQ("over tunvless's 1 MiB node list", rows->v[3].skip_reason);
    apply_yaml(&f, FOUR_LINKS);
    run_ms(&f, 400);
    firc_log_set_fd(STDOUT_FILENO);
    close(lfd);
    char buf[2048];
    slurp(in, buf, sizeof buf);
    char log[4096];
    slurp(logp, log, sizeof log);
    unsetenv("FAKE_STDIN_OUT");
    unlink(in);
    unlink(logp);
    ASSERT_STR_EQ(LINK_OF("b") LINK_OF("c") "\nnodes\n" LINK_OF("a") LINK_OF("b") "\n", buf);
    ASSERT_EQ(1, starts_of(&f, "tunvless0"));
    ASSERT(strstr(log, "WRN tunvless0: node list over 200 bytes, 2 nodes kept, 1 left out\n") != NULL);
    ASSERT(strstr(log, "WRN tunvless0: node list over 200 bytes, 2 nodes kept, 2 left out\n") != NULL);
    ASSERT_EQ(1, journal_count("tunvless0", "node list over 200 bytes, 2 nodes kept, 1 left out"));
    fx_down(&f);
    PASS();
}

/* catches: a link-up ignored (uplink closed until a reload) or applied to an unrelated interface */
TEST link_up_rewrites_the_default_of_its_own_uplink(void)
{
    fx_t f;
    ASSERT(fx_up(&f, 0));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, s, 1);
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_NEWROUTE, RTN_UNICAST, 0), "%zu");
    fake_rtnl_set_link_flags(f.kernel, IFF_UP | IFF_POINTOPOINT);
    firc_tunrun_refresh_uplinks(f.run, "firc-nope0");
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_NEWROUTE, RTN_UNICAST, 0), "%zu");
    firc_tunrun_refresh_uplinks(f.run, "lo");
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_NEWROUTE, RTN_UNICAST, 0), "%zu");
    fx_down(&f);
    PASS();
}

/* catches: a re-read of every interface leaving tunnel uplinks out, or only the first of them rewritten */
TEST a_reread_of_everything_rewrites_every_uplink(void)
{
    fx_t f;
    ASSERT(fx_up(&f, 0));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}, {"b", 1, FIRC_UPLINK_IFACE, "lo", false},
                        {"c", 2, FIRC_UPLINK_AUTO, NULL, false}};
    apply(&f, s, 3);
    ASSERT_EQ_FMT((size_t)0, count(&f, RTM_NEWROUTE, RTN_UNICAST, 0), "%zu");
    fake_rtnl_set_link_flags(f.kernel, IFF_UP | IFF_POINTOPOINT);
    firc_tunrun_refresh_uplinks(f.run, NULL);
    ASSERT_EQ_FMT((size_t)2, count(&f, RTM_NEWROUTE, RTN_UNICAST, 0), "%zu");
    ASSERT_EQ(1, uplink_ok_of(&f, "a"));
    ASSERT_EQ(1, uplink_ok_of(&f, "b"));
    fx_down(&f);
    PASS();
}

/* catches: a stop leaving a child running or an uplink rule in the kernel */
TEST stop_ends_children_then_removes_uplinks(void)
{
    fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}};
    apply(&f, s, 1);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    pid_t pid = last_pid(&f, "tunvless0");
    ASSERT(pid > 0);
    watch(&f, pid, 0);
    firc_tunrun_stop(f.run, 1000);
    ASSERT(kill(pid, 0) == -1 && errno == ESRCH);
    ASSERT_EQ_FMT((size_t)1, count(&f, RTM_DELRULE, 0, FIRC_RULE_PRIORITY_TUNNEL), "%zu");
    ASSERT_EQ(0, g_dels_while_alive);
    fx_down(&f);
    PASS();
}

#define SUB_PORT 18141
#define SUB_BODY "vless://" U "@a.example:443?security=none#A\nvless://" U "@b.example:443?security=none#B\n"
#define SUB_TUN                                                                               \
    "tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n      - id: 0000000a\n"           \
    "        subscription: { name: P, url: \"http://127.0.0.1:18141/sub?k=1\", interval: 0s }\n"

typedef struct {
    firc_loop_t *loop;
    firc_httpd_t *srv;
    pthread_t thread;
    int delay_ms;
} sub_srv_t;

static void h_slow_sub(firc_http_req_t *req, firc_http_res_t *res, void *ud)
{
    (void)req;
    int ms = ((sub_srv_t *)ud)->delay_ms;
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)SUB_BODY, strlen(SUB_BODY));
}

static pthread_mutex_t g_body_mu = PTHREAD_MUTEX_INITIALIZER;
static char g_x_body[512];
static char g_y_body[512];

static void h_body(firc_http_req_t *req, firc_http_res_t *res, void *ud)
{
    (void)req;
    char body[512];
    pthread_mutex_lock(&g_body_mu);
    snprintf(body, sizeof body, "%s", (const char *)ud);
    pthread_mutex_unlock(&g_body_mu);
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)body, strlen(body));
}

static void set_x_body(const char *body)
{
    pthread_mutex_lock(&g_body_mu);
    snprintf(g_x_body, sizeof g_x_body, "%s", body);
    pthread_mutex_unlock(&g_body_mu);
}

static void *sub_srv_thread(void *ud)
{
    firc_loop_run(((sub_srv_t *)ud)->loop);
    return NULL;
}

static bool sub_srv_start(sub_srv_t *s, int delay_ms)
{
    memset(s, 0, sizeof *s);
    s->delay_ms = delay_ms;
    if (firc_loop_create(&s->loop) != FIRC_OK || firc_httpd_create(s->loop, &s->srv) != FIRC_OK) {
        return false;
    }
    firc_httpd_route(s->srv, "GET", "/sub", h_slow_sub, s);
    firc_httpd_route(s->srv, "GET", "/x", h_body, g_x_body);
    firc_httpd_route(s->srv, "GET", "/y", h_body, g_y_body);
    if (firc_httpd_listen_tcp(s->srv, "127.0.0.1", SUB_PORT) != FIRC_OK) {
        return false;
    }
    return pthread_create(&s->thread, NULL, sub_srv_thread, s) == 0;
}

static void sub_srv_stop(sub_srv_t *s)
{
    firc_loop_stop(s->loop);
    pthread_join(s->thread, NULL);
    firc_httpd_destroy(s->srv);
    firc_loop_destroy(s->loop);
}

static int journal_count(const char *source, const char *text)
{
    firc_event_t ev[64];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, 64, &next, &dropped);
    int c = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].kind == FIRC_EVENT_LOG && strcmp(ev[i].u.log.source, source) == 0 &&
            strcmp(ev[i].u.log.text, text) == 0) {
            c++;
        }
    }
    return c;
}

static int journal_from(const char *source, const char *text)
{
    static firc_event_t ev[64];
    uint64_t since = 0, dropped = 0;
    int c = 0;
    for (;;) {
        uint64_t next = since;
        size_t n = firc_event_read(since, ev, 64, &next, &dropped);
        for (size_t i = 0; i < n; i++) {
            if (ev[i].kind == FIRC_EVENT_LOG && (source == NULL || strcmp(ev[i].u.log.source, source) == 0) &&
                strstr(ev[i].u.log.text, text) != NULL) {
                c++;
            }
        }
        if (n == 0 || next == since) {
            return c;
        }
        since = next;
    }
}

static int journal_all(const char *text)
{
    return journal_from(NULL, text);
}

/* catches: a body landing after a save built from the config it was fetched for, or a tunnel started with no nodes */
TEST a_save_during_a_refresh_takes_the_new_config(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    sub_srv_t srv;
    ASSERT(sub_srv_start(&srv, 500));
    firc_event_reset_for_test();
    char cache[96];
    snprintf(cache, sizeof cache, "%s/cache", f.dir);
    g_subs = firc_tunsubs_new(f.loop, cache, firc_tunrun_bodies_changed, f.run);
    ASSERT(g_subs != NULL);
    firc_tunrun_set_subs(f.run, g_subs);
    char in[256];
    snprintf(in, sizeof in, "%s/stdin", f.dir);
    setenv("FAKE_STDIN_OUT", in, 1);
    apply_yaml(&f, SUB_TUN "    exclude: [\"0000000a:B\"]\n");
    ASSERT_EQ(0, run_until_starts(&f, "tunvless0", 1, 150));
    apply_yaml(&f, SUB_TUN "    exclude: [\"0000000a:A\"]\n");
    ASSERT_EQ(1, journal_count("tunvless0", "no nodes to use yet"));
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 3000));
    char buf[1024];
    bool done = run_until_file(&f, in, buf, sizeof buf, 2000);
    int starts = run_until_starts(&f, "tunvless0", 2, 700);
    unsetenv("FAKE_STDIN_OUT");
    unlink(in);
    sub_srv_stop(&srv);
    ASSERT(done);
    ASSERT_STR_EQ("vless://" U "@b.example:443?type=tcp&security=none#B\n\n", buf);
    ASSERT_EQ(1, starts);
    fx_down(&f);
    PASS();
}

#define XY_TUN(id, n, path, extra)                                                                   \
    "  - id: " id "\n    device: tunvless" n "\n    sources:\n      - id: 0000000" n "\n"                \
    "        subscription: { name: P, url: \"http://127.0.0.1:18141/" path "?k=1\", interval: 0s }\n" extra

static void subs_up(fx_t *f)
{
    char cache[96];
    snprintf(cache, sizeof cache, "%s/cache", f->dir);
    g_subs = firc_tunsubs_new(f->loop, cache, firc_tunrun_bodies_changed, f->run);
    firc_tunrun_set_subs(f->run, g_subs);
}

/* catches: a body change restarting a tunnel, or updating one whose sent list stays the same */
TEST a_body_change_updates_only_the_tunnel_using_it(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    static sub_srv_t srv;
    set_x_body("vless://" U "@a.example:443?security=none#A\nvless://" U "@b.example:443?security=none#B\n");
    pthread_mutex_lock(&g_body_mu);
    snprintf(g_y_body, sizeof g_y_body, "%s", "vless://" U "@y.example:443?security=none#Y\n");
    pthread_mutex_unlock(&g_body_mu);
    ASSERT(sub_srv_start(&srv, 0));
    subs_up(&f);
    ASSERT(g_subs != NULL);
    apply_yaml(&f, "tunnels:\n" XY_TUN("a", "0", "x", "") XY_TUN("b", "1", "y", "")
                       XY_TUN("c", "2", "x", "    filter: \"^(A|B)$\"\n"));
    int s0 = run_until_starts(&f, "tunvless0", 1, 3000);
    int s1 = run_until_starts(&f, "tunvless1", 1, 3000);
    int s2 = run_until_starts(&f, "tunvless2", 2, 600);
    set_x_body("vless://" U "@a.example:443?security=none#A\nvless://" U "@b.example:443?security=none#B\n"
               "vless://" U "@c.example:443?security=none#C\n");
    uint64_t before = firc_tunrun_start_seq(f.run);
    firc_err_t rc = firc_tunsubs_refresh(g_subs, "a");
    int r0 = run_until_starts(&f, "tunvless0", 2, 1500);
    int r2 = run_until_starts(&f, "tunvless2", 2, 300);
    int r1 = starts_of(&f, "tunvless1");
    sub_srv_stop(&srv);
    ASSERT_EQ(1, s0);
    ASSERT_EQ(1, s1);
    ASSERT_EQ(1, s2);
    ASSERT_EQ(FIRC_OK, rc);
    ASSERT_EQ(1, r0);
    ASSERT_EQ(1, r2);
    ASSERT_EQ(1, r1);
    ASSERT(firc_tunrun_updated(f.run, "a") > before);
    ASSERT(firc_tunrun_updated(f.run, "b") <= before);
    ASSERT(firc_tunrun_updated(f.run, "c") <= before);
    fx_down(&f);
    PASS();
}

/* catches: an apply that leaves the cache file of a subscription no tunnel names any more */
TEST an_apply_sweeps_unused_cache_files(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    subs_up(&f);
    ASSERT(g_subs != NULL);
    char stale[128];
    snprintf(stale, sizeof stale, "%s/cache/0123456789abcdef", f.dir);
    FILE *fp = fopen(stale, "we");
    ASSERT(fp != NULL);
    fputs("x\n", fp);
    fclose(fp);
    apply_yaml(&f, TWO_LINKS);
    ASSERT_EQ(-1, access(stale, F_OK));
    fx_down(&f);
    PASS();
}

#define WAIT_TUN                                                                                 \
    "  - id: w\n    device: tunvless3\n    sources:\n      - id: 0000000c\n"                      \
    "        subscription: { name: P, url: \"http://127.0.0.1:1/none\", interval: 0s }\n"

/* catches: a waiting, disabled or uplink-less tunnel missing from the states, or the states out of config order */
TEST every_configured_tunnel_has_a_state(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    fake_rtnl_fail_next_of(f.kernel, RTM_NEWRULE, EPERM);
    apply_yaml(&f, "tunnels:\n  - id: u\n    device: tunvless2\n    uplink: \"iface:lo\"\n    sources:\n"
                   "      - link: \"vless://" U "@a.example:443?security=none#A\"\n"
                   "  - id: off\n    device: tunvless1\n    enable: false\n"
                   "  - id: a\n    device: tunvless0\n    sources:\n"
                   "      - link: \"vless://" U "@a.example:443?security=none#A\"\n" WAIT_TUN);
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    firc_tun_state_t st[8];
    size_t n = firc_tunrun_states(f.run, st, 8);
    ASSERT_EQ_FMT((size_t)4, n, "%zu");
    ASSERT_STR_EQ("u", st[0].id);
    ASSERT_STR_EQ("tunvless2", st[0].device);
    ASSERT_EQ(FIRC_TUN_ST_UPLINK_DOWN, st[0].status);
    ASSERT_FALSE(st[0].uplink_ok);
    ASSERT_STR_EQ("off", st[1].id);
    ASSERT_EQ(FIRC_TUN_ST_OFF, st[1].status);
    ASSERT_STR_EQ("a", st[2].id);
    ASSERT(st[2].status == FIRC_TUN_ST_STARTING || st[2].status == FIRC_TUN_ST_UP);
    ASSERT_STR_EQ("w", st[3].id);
    ASSERT_STR_EQ("tunvless3", st[3].device);
    ASSERT_EQ(FIRC_TUN_ST_WAITING, st[3].status);
    ASSERT(st[3].since_ms > 0 && st[3].since_ms <= now_ms());
    fx_down(&f);
    PASS();
}

/* catches: a restart ignored for an unchanged tunnel, or accepted for an unknown or disabled one */
TEST a_restart_starts_an_unchanged_child_again(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    apply_yaml(&f, TWO_LINKS "  - id: off\n    device: tunvless1\n    enable: false\n");
    ASSERT_EQ(1, wait_starts(&f, "tunvless0", 1, 2000));
    pid_t pid = last_pid(&f, "tunvless0");
    ASSERT_EQ(FIRC_ERR_NOENT, firc_tunrun_restart(f.run, "zz"));
    ASSERT_EQ(FIRC_ERR_STATE, firc_tunrun_restart(f.run, "off"));
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 3000));
    ASSERT(last_pid(&f, "tunvless0") != pid);
    ASSERT_EQ(0, starts_of(&f, "tunvless1"));
    fx_down(&f);
    PASS();
}

/* catches: a tunnel left running counted as restarted, or a started one missed */
TEST the_start_counter_names_what_an_apply_started(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_AUTO, NULL, false}, {"b", 1, FIRC_UPLINK_AUTO, NULL, false}};
    apply(&f, s, 2);
    ASSERT_EQ(1, wait_starts(&f, "tunvless1", 1, 2000));
    uint64_t before = firc_tunrun_start_seq(f.run);
    ASSERT(firc_tunrun_started(f.run, "a") > 0 && firc_tunrun_started(f.run, "a") <= before);
    const spec_t s2[] = {{"a", 0, FIRC_UPLINK_AUTO, NULL, false}, {"b", 2, FIRC_UPLINK_AUTO, NULL, false},
                         {"c", 3, FIRC_UPLINK_AUTO, NULL, true}};
    apply(&f, s2, 3);
    ASSERT(firc_tunrun_started(f.run, "a") <= before);
    ASSERT(firc_tunrun_started(f.run, "b") > before);
    ASSERT_EQ(0, firc_tunrun_started(f.run, "c"));
    ASSERT_EQ(0, firc_tunrun_started(f.run, "zz"));
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT(firc_tunrun_started(f.run, "a") > firc_tunrun_started(f.run, "b"));
    fx_down(&f);
    PASS();
}

static void run_ms(fx_t *f, int ms)
{
    int64_t end = now_ms() + ms;
    wait_t w = {f, "never", 1, end};
    int timer = 0;
    firc_loop_add_timer(f->loop, 20, 20, poll_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
}

#define AB_LINKS                                                                         \
    "tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"                         \
    "      - id: 0000000a\n        link: \"vless://" U "@a.example:443?security=none#A\"\n" \
    "      - id: 0000000b\n        link: \"vless://" U "@b.example:443?security=none#B\"\n"

/* catches: a node_down not remembered per tunnel, remembered across a restart of the child, or journalled as fircd's */
TEST node_down_lasts_until_the_child_restarts(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    firc_event_reset_for_test();
    setenv("FAKE_MODE", "down", 1);
    apply_yaml(&f, AB_LINKS);
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    run_ms(&f, 300);
    ASSERT_EQ(1, journal_count("tunvless0", "active A"));
    ASSERT_EQ(1, journal_count("tunvless0", "B does not answer (x)"));
    int64_t since = 0;
    ASSERT(firc_tunrun_node_down(f.run, "a", "0000000b:B", &since));
    ASSERT(since > 0 && since <= now_ms());
    ASSERT_FALSE(firc_tunrun_node_down(f.run, "a", "0000000a:A", &since));
    ASSERT_FALSE(firc_tunrun_node_down(f.run, "zz", "0000000b:B", &since));
    ASSERT(firc_tunrun_node_active(f.run, "a", "0000000a:A"));
    setenv("FAKE_MODE", "ok", 1);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 3000));
    run_ms(&f, 300);
    ASSERT_FALSE(firc_tunrun_node_down(f.run, "a", "0000000b:B", &since));
    fx_down(&f);
    PASS();
}

#define SAME_NAME                                                                        \
    "tunnels:\n  - id: a\n    device: tunvless0\n    sources:\n"                         \
    "      - id: 0000000a\n        link: \"vless://" U "@a.example:443?security=none#n\"\n" \
    "      - id: 0000000b\n        link: \"vless://" U "@b.example:443?security=none#n\"\n"

/* catches: two nodes with one name sharing a state although tunvless numbered them apart */
TEST node_states_follow_the_index_not_the_name(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    setenv("FAKE_MODE", "nodes", 1);
    setenv("FAKE_EVENTS",
           "{\"type\":\"active\",\"nodes\":[\"n\"],\"index\":[0]}\n"
           "{\"type\":\"node_down\",\"node\":\"n\",\"index\":1,\"why\":\"t\"}",
           1);
    apply_yaml(&f, SAME_NAME);
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    run_ms(&f, 300);
    int64_t since = 0;
    ASSERT(firc_tunrun_node_active(f.run, "a", "0000000a:n"));
    ASSERT_FALSE(firc_tunrun_node_active(f.run, "a", "0000000b:n"));
    ASSERT(firc_tunrun_node_down(f.run, "a", "0000000b:n", &since));
    ASSERT_FALSE(firc_tunrun_node_down(f.run, "a", "0000000a:n", &since));
    fx_down(&f);
    PASS();
}

/* catches: a node number that points at a node of another name (numbering out of step) trusted over the name */
TEST an_index_naming_another_node_falls_back_to_the_name(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    setenv("FAKE_MODE", "nodes", 1);
    setenv("FAKE_EVENTS", "{\"type\":\"node_down\",\"node\":\"B\",\"index\":0,\"why\":\"t\"}", 1);
    apply_yaml(&f, AB_LINKS);
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    run_ms(&f, 300);
    int64_t since = 0;
    ASSERT(firc_tunrun_node_down(f.run, "a", "0000000b:B", &since));
    ASSERT_FALSE(firc_tunrun_node_down(f.run, "a", "0000000a:A", &since));
    fx_down(&f);
    PASS();
}

/* catches: a node that left the list coming back still marked down from before */
TEST a_node_that_leaves_the_list_forgets_its_down(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    setenv("FAKE_MODE", "down", 1);
    apply_yaml(&f, AB_LINKS);
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    run_ms(&f, 300);
    int64_t since = 0;
    ASSERT(firc_tunrun_node_down(f.run, "a", "0000000b:B", &since));
    apply_yaml(&f, AB_LINKS "    exclude: [\"0000000b:B\"]\n");
    run_ms(&f, 200);
    apply_yaml(&f, AB_LINKS);
    run_ms(&f, 200);
    ASSERT_EQ(1, starts_of(&f, "tunvless0"));
    ASSERT_FALSE(firc_tunrun_node_down(f.run, "a", "0000000b:B", &since));
    fx_down(&f);
    PASS();
}

/* catches: node rows kept with their links, or not kept for the API at all */
TEST the_built_rows_are_kept_without_links(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    apply_yaml(&f, TWO_LINKS "    exclude: [\"0000000b:b\"]\n");
    const firc_tun_nodes_t *rows = firc_tunrun_nodes(f.run, "a");
    ASSERT(rows != NULL);
    ASSERT_EQ_FMT((size_t)2, rows->n, "%zu");
    ASSERT_STR_EQ("0000000a:a", rows->v[0].key);
    ASSERT_FALSE(rows->v[0].excluded);
    ASSERT_STR_EQ("0000000b:b", rows->v[1].key);
    ASSERT(rows->v[1].excluded);
    ASSERT_EQ(NULL, rows->v[0].link);
    ASSERT_EQ(NULL, rows->v[1].link);
    ASSERT_EQ(NULL, firc_tunrun_nodes(f.run, "zz"));
    fx_down(&f);
    PASS();
}

/* catches: a mark reported held with no child running on it, or an auto tunnel given a mark */
TEST mark_of_reports_the_uplink_mark_and_whether_a_child_holds_it(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, IFF_UP | IFF_POINTOPOINT));
    const spec_t s[] = {{"a", 0, FIRC_UPLINK_IFACE, "lo", false}, {"b", 1, FIRC_UPLINK_AUTO, NULL, false}};
    uint32_t mark = 1;
    bool held = true;
    ASSERT_FALSE(firc_tunrun_mark_of(f.run, "a", &mark, &held));
    apply(&f, s, 2);
    ASSERT(firc_tunrun_mark_of(f.run, "a", &mark, &held));
    ASSERT_EQ_FMT(last_rule_mark(&f), mark, "%u");
    ASSERT(mark != 0);
    ASSERT(held);
    ASSERT(firc_tunrun_mark_of(f.run, "b", &mark, &held));
    ASSERT_EQ_FMT(0u, mark, "%u");
    ASSERT_FALSE(held);
    fx_down(&f);
    PASS();
}

typedef struct {
    fx_t *f;
    const char *id;
    firc_tun_status_t want;
    int64_t deadline;
} status_wait_t;

static firc_tun_status_t status_of(fx_t *f, const char *id)
{
    firc_tun_state_t st[8];
    size_t n = firc_tunrun_states(f->run, st, 8);
    for (size_t i = 0; i < n && i < 8; i++) {
        if (strcmp(st[i].id, id) == 0) {
            return st[i].status;
        }
    }
    return FIRC_TUN_ST_OFF;
}

static void status_cb(firc_loop_t *loop, void *ud)
{
    status_wait_t *w = ud;
    if (status_of(w->f, w->id) == w->want || now_ms() >= w->deadline) {
        firc_loop_stop(loop);
    }
}

static firc_tun_status_t run_until_status(fx_t *f, const char *id, firc_tun_status_t want, int ms)
{
    status_wait_t w = {f, id, want, now_ms() + ms};
    int timer = 0;
    firc_loop_add_timer(f->loop, 20, 20, status_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
    return status_of(f, id);
}

/* catches: a tunnel with no node, a child in backoff or still starting, an off or waiting tunnel read as carrying,
   an up one read as down, or a device no tunnel names read as down */
TEST device_down_is_every_status_but_up(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    setenv("FAKE_MODE", "noread", 1);
    apply_yaml(&f, AB_LINKS "  - id: off\n    device: tunvless1\n    enable: false\n" WAIT_TUN);
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    ASSERT_EQ(FIRC_TUN_ST_STARTING, status_of(&f, "a"));
    ASSERTm("starting carries nothing yet", firc_tunrun_device_down(f.run, "tunvless0"));
    ASSERTm("off", firc_tunrun_device_down(f.run, "tunvless1"));
    ASSERTm("waiting", firc_tunrun_device_down(f.run, "tunvless3"));
    ASSERT_FALSEm("no tunnel names it", firc_tunrun_device_down(f.run, "tunvless7"));
    ASSERT_FALSEm("not a tunnel", firc_tunrun_device_down(f.run, "lo"));
    ASSERT_FALSEm("no device", firc_tunrun_device_down(f.run, NULL));

    setenv("FAKE_MODE", "ok", 1);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    ASSERT_FALSEm("up carries", firc_tunrun_device_down(f.run, "tunvless0"));

    setenv("FAKE_MODE", "nodes", 1);
    setenv("FAKE_EVENTS", "{\"type\":\"no_node\",\"retry\":5}", 1);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, run_until_status(&f, "a", FIRC_TUN_ST_NO_NODE, 3000));
    ASSERTm("no node", firc_tunrun_device_down(f.run, "tunvless0"));

    setenv("FAKE_MODE", "crash", 1);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_BACKOFF, run_until_status(&f, "a", FIRC_TUN_ST_BACKOFF, 3000));
    ASSERTm("backoff", firc_tunrun_device_down(f.run, "tunvless0"));
    fx_down(&f);
    PASS();
}

TEST device_starting_is_a_start_or_a_wait_with_its_since(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    setenv("FAKE_MODE", "noread", 1);
    apply_yaml(&f, AB_LINKS "  - id: off\n    device: tunvless1\n    enable: false\n" WAIT_TUN);
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    ASSERT_EQ(FIRC_TUN_ST_STARTING, status_of(&f, "a"));
    firc_tun_state_t st[FIRC_TUN_MAX];
    size_t n = firc_tunrun_states(f.run, st, FIRC_TUN_MAX);
    int64_t want_a = 0, want_wait = 0;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(st[i].device, "tunvless0") == 0) { want_a = st[i].since_ms; }
        if (strcmp(st[i].device, "tunvless3") == 0) { want_wait = st[i].since_ms; }
    }
    int64_t since = -1;
    ASSERT(firc_tunrun_device_starting(f.run, "tunvless0", &since));
    ASSERT(want_a != 0 && want_a == since);
    since = -1;
    ASSERTm("waiting for its first nodes", firc_tunrun_device_starting(f.run, "tunvless3", &since));
    ASSERT(want_wait != 0 && want_wait == since);
    ASSERT_FALSEm("off", firc_tunrun_device_starting(f.run, "tunvless1", &since));
    ASSERT_FALSEm("no tunnel names it", firc_tunrun_device_starting(f.run, "tunvless7", &since));
    ASSERT_FALSEm("no device", firc_tunrun_device_starting(f.run, NULL, &since));

    setenv("FAKE_MODE", "ok", 1);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    ASSERT_FALSEm("up", firc_tunrun_device_starting(f.run, "tunvless0", &since));

    setenv("FAKE_MODE", "crash", 1);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_BACKOFF, run_until_status(&f, "a", FIRC_TUN_ST_BACKOFF, 3000));
    ASSERT_FALSEm("backoff", firc_tunrun_device_starting(f.run, "tunvless0", &since));
    fx_down(&f);
    PASS();
}

static int64_t g_watch_now;
static int64_t watch_now(void) { return g_watch_now; }

static int journal_level_count(firc_log_level_t level, const char *source, const char *text)
{
    firc_event_t ev[64];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, 64, &next, &dropped);
    int c = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].kind == FIRC_EVENT_LOG && ev[i].u.log.level == level && strcmp(ev[i].u.log.source, source) == 0 &&
            strcmp(ev[i].u.log.text, text) == 0) {
            c++;
        }
    }
    return c;
}

/* Catches: a tunnel with no working node never said at ERROR, said for an off tunnel, said under another source, or its recovery not said. */
TEST five_minutes_without_a_node_is_an_error_for_the_device(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    firc_event_reset_for_test();
    g_watch_now = 1000;
    (void)firc_tunrun_set_watch_for_test(f.run, watch_now, 20);
    setenv("FAKE_MODE", "nodes", 1);
    setenv("FAKE_EVENTS", "{\"type\":\"no_node\",\"retry\":5}", 1);
    apply_yaml(&f, AB_LINKS "  - id: off\n    device: tunvless1\n    enable: false\n");
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, run_until_status(&f, "a", FIRC_TUN_ST_NO_NODE, 3000));
    run_ms(&f, 100);
    g_watch_now += FIRC_TUNWATCH_AFTER_MS;
    run_ms(&f, 100);
    ASSERT_EQ(1, journal_level_count(FIRC_LOG_ERROR, "tunvless0", "no node has worked for 5 min; groups on it fail closed"));
    ASSERT_EQ(0, journal_level_count(FIRC_LOG_ERROR, "tunvless1", "no node has worked for 5 min; groups on it fail closed"));
    setenv("FAKE_MODE", "ok", 1);
    unsetenv("FAKE_EVENTS");
    g_watch_now += 60 * 1000;
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    run_ms(&f, 100);
    ASSERT_EQ(1, journal_level_count(FIRC_LOG_INFO, "tunvless0", "recovered: a node works again after 6 min without one"));
    fx_down(&f);
    PASS();
}

static int journal_prefix_count(firc_log_level_t level, const char *source, const char *prefix)
{
    firc_event_t ev[256];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, ev, 256, &next, &dropped);
    int c = 0;
    for (size_t i = 0; i < n; i++) {
        if (ev[i].kind == FIRC_EVENT_LOG && ev[i].u.log.level == level && strcmp(ev[i].u.log.source, source) == 0 &&
            strncmp(ev[i].u.log.text, prefix, strlen(prefix)) == 0) {
            c++;
        }
    }
    return c;
}

/* Catches: a tunnel with no node answering warned at every retry, so one outage fills the warning ring, or the first answer after it not said. */
TEST twenty_no_node_retries_leave_one_warning(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    firc_event_reset_for_test();
    static char evs[2048];
    evs[0] = 0;
    for (int i = 0; i < 20; i++) { strcat(evs, i ? "\n{\"type\":\"no_node\",\"retry\":5}" : "{\"type\":\"no_node\",\"retry\":5}"); }
    setenv("FAKE_MODE", "nodes", 1);
    setenv("FAKE_EVENTS", evs, 1);
    apply_yaml(&f, AB_LINKS);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, run_until_status(&f, "a", FIRC_TUN_ST_NO_NODE, 3000));
    run_ms(&f, 300);
    int warned = journal_level_count(FIRC_LOG_WARN, "tunvless0", "no node answers, retry in 5 s");
    int quiet = journal_level_count(FIRC_LOG_DEBUG, "tunvless0", "no node answers, retry in 5 s");
    setenv("FAKE_MODE", "ok", 1);
    unsetenv("FAKE_EVENTS");
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    run_ms(&f, 100);
    fx_down(&f);
    ASSERT_EQ(1, warned);
    ASSERT_EQ(19, quiet);
    ASSERT_EQ(1, journal_prefix_count(FIRC_LOG_INFO, "tunvless0", "nodes: recovered after 20 failures over "));
    PASS();
}

/* Catches: the watch run only from its timer, so a tunnel's alarm and recovery wait up to a period instead of following the child's events. */
TEST the_watch_follows_the_childs_events(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    firc_event_reset_for_test();
    g_watch_now = 1000;
    (void)firc_tunrun_set_watch_for_test(f.run, watch_now, 3600000);
    setenv("FAKE_MODE", "nodes", 1);
    setenv("FAKE_EVENTS", "{\"type\":\"no_node\",\"retry\":5}", 1);
    apply_yaml(&f, AB_LINKS);
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, run_until_status(&f, "a", FIRC_TUN_ST_NO_NODE, 3000));
    g_watch_now += FIRC_TUNWATCH_AFTER_MS;
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_NO_NODE, run_until_status(&f, "a", FIRC_TUN_ST_NO_NODE, 3000));
    run_ms(&f, 100);
    ASSERT_EQ(1, journal_level_count(FIRC_LOG_ERROR, "tunvless0", "no node has worked for 5 min; groups on it fail closed"));
    setenv("FAKE_MODE", "ok", 1);
    unsetenv("FAKE_EVENTS");
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    run_ms(&f, 100);
    ASSERT_EQ(1, journal_level_count(FIRC_LOG_INFO, "tunvless0", "recovered: a node works again after 5 min without one"));
    fx_down(&f);
    PASS();
}

/* Catches: the watch timer left on the loop after a stop, to run on a freed tunrun. */
TEST a_stop_takes_the_watch_timer_off_the_loop(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    int id = firc_tunrun_set_watch_for_test(f.run, watch_now, 20);
    ASSERT(id > 0);
    firc_tunrun_stop(f.run, 0);
    ASSERT_EQ(FIRC_ERR_NOENT, firc_loop_del_timer(f.loop, id));
    fx_down(&f);
    PASS();
}

/* catches: a tunnel removed from the config still read down while its child lives out the grace */
TEST a_removed_tunnel_is_not_down_while_its_child_ends(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    setenv("FAKE_MODE", "noread", 1);
    setenv("FAKE_STUBBORN_DEV", "tunvless0", 1);
    apply_yaml(&f, AB_LINKS);
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    pid_t pid = last_pid(&f, "tunvless0");
    ASSERTm("fixture: starting reads down", firc_tunrun_device_down(f.run, "tunvless0"));
    apply(&f, NULL, 0);
    run_ms(&f, 200);
    ASSERT_EQm("fixture: the child is still in its grace", 0, kill(pid, 0));
    ASSERT_FALSE(firc_tunrun_device_down(f.run, "tunvless0"));
    fx_down(&f);
    PASS();
}

typedef struct {
    uint16_t ports[FIRC_KTCP_DEVICES];
    int n_ports;
    const firc_ktcp_image_t *cur;
    firc_ktcp_image_t im[3];
    firc_ktcp_image_t real;
    int closed[FIRC_KTCP_DEVICES];
    int ready[FIRC_KTCP_DEVICES];
} kx_t;

static kx_t g_kx;

static void kx_reset(void)
{
    for (int i = 0; i < 3; i++) {
        firc_ktcp_image_free(&g_kx.im[i]);
    }
    firc_ktcp_image_free(&g_kx.real);
    memset(&g_kx, 0, sizeof g_kx);
}

static void kx_ports(const uint16_t ports[FIRC_KTCP_DEVICES], void *ud)
{
    (void)ud;
    memcpy(g_kx.ports, ports, sizeof g_kx.ports);
    g_kx.n_ports++;
}

static const firc_ktcp_image_t *kx_image(void *ud)
{
    (void)ud;
    return g_kx.cur != NULL ? g_kx.cur : &g_kx.im[0];
}

static bool kx_real_of(uint8_t dev, const uint8_t fake[4], uint8_t real[4], void *ud)
{
    (void)ud;
    for (size_t i = 0; i < g_kx.real.n; i++) {
        if (g_kx.real.v[i].dev == dev && memcmp(g_kx.real.v[i].fake, fake, 4) == 0) {
            memcpy(real, g_kx.real.v[i].real, 4);
            return true;
        }
    }
    return false;
}

static void kx_closed(uint8_t dev, void *ud)
{
    (void)ud;
    if (dev < FIRC_KTCP_DEVICES) {
        g_kx.closed[dev]++;
    }
}

static void kx_ready(uint8_t dev, void *ud)
{
    (void)ud;
    if (dev < FIRC_KTCP_DEVICES) {
        g_kx.ready[dev]++;
    }
}

static void kx_attach(fx_t *f)
{
    firc_tunrun_ktcp_t k = {kx_ports, kx_image, kx_real_of, NULL, kx_closed, kx_ready};
    firc_tunrun_set_ktcp(f->run, &k);
}

static void pair(firc_ktcp_image_t *im, uint8_t dev, const char *fake, const char *real)
{
    uint8_t a[4];
    uint8_t b[4];
    inet_pton(AF_INET, fake, a);
    inet_pton(AF_INET, real, b);
    (void)firc_ktcp_image_add(im, dev, a, b);
    firc_ktcp_image_sort(im);
}

static void ktcp_env(fx_t *f)
{
    setenv("FAKE_MODE", "ktcp", 1);
    setenv("FAKE_STDIN_DIR", f->dir, 1);
}

#define KT_TUN(id, n, extra)                                                                 \
    "  - id: " id "\n    device: tunvless" n "\n" extra "    sources:\n"                       \
    "      - id: 0000000a\n        link: \"vless://" U "@a.example:443?security=none#A\"\n"
#define KT_ON "    advanced: { kernelTcp: true }\n"
#define KT_FIRST "vless://" U "@a.example:443?type=tcp&security=none#A\n\n"

typedef bool (*cond_fn)(fx_t *f, const void *arg);

typedef struct {
    fx_t *f;
    cond_fn fn;
    const void *arg;
    int64_t deadline;
    bool met;
} cond_wait_t;

static void cond_cb(firc_loop_t *loop, void *ud)
{
    cond_wait_t *w = ud;
    w->met = w->fn(w->f, w->arg);
    if (w->met || now_ms() >= w->deadline) {
        firc_loop_stop(loop);
    }
}

static bool run_until(fx_t *f, cond_fn fn, const void *arg, int ms)
{
    cond_wait_t w = {f, fn, arg, now_ms() + ms, false};
    int timer = 0;
    firc_loop_add_timer(f->loop, 20, 20, cond_cb, &w, &timer);
    firc_loop_run(f->loop);
    firc_loop_del_timer(f->loop, timer);
    return w.met;
}

static char g_in[16384];

static const char *stdin_of(fx_t *f, const char *dev)
{
    char path[128];
    snprintf(path, sizeof path, "%s/%s", f->dir, dev);
    slurp(path, g_in, sizeof g_in);
    return g_in;
}

typedef struct {
    const char *dev;
    const char *text;
} dev_text_t;

static bool ends_with(fx_t *f, const void *arg)
{
    const dev_text_t *d = arg;
    const char *in = stdin_of(f, d->dev);
    size_t a = strlen(in);
    size_t b = strlen(d->text);
    return a >= b && strcmp(in + a - b, d->text) == 0;
}

static bool run_until_tail(fx_t *f, const char *dev, const char *text, int ms)
{
    dev_text_t d = {dev, text};
    return run_until(f, ends_with, &d, ms);
}

static bool contains(fx_t *f, const void *arg)
{
    const dev_text_t *d = arg;
    return strstr(stdin_of(f, d->dev), d->text) != NULL;
}

static int occurrences(const char *hay, const char *needle)
{
    int n = 0;
    for (const char *p = strstr(hay, needle); p != NULL; p = strstr(p + 1, needle)) {
        n++;
    }
    return n;
}

static uint16_t tcp_port_of(fx_t *f, const char *id)
{
    firc_tun_state_t st[8];
    size_t n = firc_tunrun_states(f->run, st, 8);
    for (size_t i = 0; i < n && i < 8; i++) {
        if (strcmp(st[i].id, id) == 0) {
            return st[i].tcp_port;
        }
    }
    return 0xffff;
}

static bool port_is(fx_t *f, const void *arg)
{
    (void)f;
    const uint16_t *want = arg;
    return g_kx.ports[want[0]] == want[1];
}

static bool run_until_port(fx_t *f, uint16_t dev, uint16_t port, int ms)
{
    uint16_t want[2] = {dev, port};
    return run_until(f, port_is, want, ms);
}

/* catches: no map pushed on ready, a plain map that leaves stale entries of a previous child, or another device's pairs */
TEST ready_with_a_port_publishes_it_and_sends_mapall(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    kx_attach(&f);
    pair(&g_kx.im[0], 0, "198.18.0.2", "192.0.2.2");
    pair(&g_kx.im[0], 0, "198.18.0.1", "192.0.2.1");
    pair(&g_kx.im[0], 1, "198.18.1.1", "192.0.2.9");
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    ASSERT(run_until_tail(&f, "tunvless0", "\n\nmapall\n198.18.0.1 192.0.2.1\n198.18.0.2 192.0.2.2\n\n", 3000));
    ASSERT_STR_EQ(KT_FIRST "mapall\n198.18.0.1 192.0.2.1\n198.18.0.2 192.0.2.2\n\n", stdin_of(&f, "tunvless0"));
    ASSERT_EQ(3600, g_kx.ports[0]);
    ASSERT_EQ(3600, tcp_port_of(&f, "a"));
    fx_down(&f);
    PASS();
}

/* catches: /state showing a listening port while the kernel lacks REDIRECT or addrtype, so nothing is ever redirected to it */
TEST a_kernel_without_redirect_reports_no_port(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    kx_attach(&f);
    firc_tunrun_set_ktcp_usable(f.run, false);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    ASSERT(run_until_tail(&f, "tunvless0", "mapall\n\n", 3000));
    ASSERT_EQ(3600, g_kx.ports[0]);
    ASSERT_EQ(0, tcp_port_of(&f, "a"));
    firc_tunrun_set_ktcp_usable(f.run, true);
    ASSERT_EQ(3600, tcp_port_of(&f, "a"));
    fx_down(&f);
    PASS();
}

/* catches: a READY naming a port other than the tunnel's trusted, which would send its TCP to someone else's socket, or said to be a taken port */
TEST a_ready_naming_another_port_publishes_nothing(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    setenv("FAKE_TCPPORT", "3655", 1);
    kx_attach(&f);
    static const char foreign[] = "tunvless reported port 3655, not 3600; TCP stays on the TUN";
    int taken0 = journal_all("port 3600 is taken"), foreign0 = journal_from("tunvless0", foreign);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    run_ms(&f, 300);
    ASSERT_EQ(0, g_kx.ports[0]);
    ASSERT_EQ(0, g_kx.ports[55]);
    ASSERT_EQ(0, tcp_port_of(&f, "a"));
    ASSERT_STR_EQ(KT_FIRST, stdin_of(&f, "tunvless0"));
    ASSERT_EQ(taken0, journal_all("port 3600 is taken"));
    ASSERT_EQ(foreign0 + 1, journal_from("tunvless0", foreign));
    fx_down(&f);
    PASS();
}

/* catches: the port dropped while the child is down, so the rule vanishes and flows fall to the TUN unseen */
TEST the_port_survives_an_exit_and_backoff(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    kx_attach(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    ASSERT(run_until_port(&f, 0, 3600, 3000));
    int calls = g_kx.n_ports;
    setenv("FAKE_MODE", "late", 1);
    setenv("FAKE_SLEEP", "5", 1);
    kill(last_pid(&f, "tunvless0"), SIGKILL);
    ASSERT_EQ(FIRC_TUN_ST_BACKOFF, run_until_status(&f, "a", FIRC_TUN_ST_BACKOFF, 2000));
    ASSERT_EQ(3600, tcp_port_of(&f, "a"));
    ASSERT_EQ(3600, g_kx.ports[0]);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 2000));
    run_ms(&f, 200);
    ASSERT_EQ(FIRC_TUN_ST_STARTING, status_of(&f, "a"));
    ASSERT_EQ(3600, tcp_port_of(&f, "a"));
    ASSERT_EQ(3600, g_kx.ports[0]);
    ASSERT_EQ(calls, g_kx.n_ports);
    fx_down(&f);
    PASS();
}

/* catches: a port kept after tunvless could not bind it, so the rule hands the group's TCP to whoever holds it */
TEST a_zero_port_is_journalled_and_clears_the_port(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    kx_attach(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    ASSERT(run_until_port(&f, 0, 3600, 3000));
    ASSERT(run_until_tail(&f, "tunvless0", "mapall\n\n", 2000));
    static const char line[] = "port 3600 is taken, TCP stays on the TUN";
    int before = journal_from("tunvless0", line);
    setenv("FAKE_TCPPORT", "0", 1);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT(run_until_port(&f, 0, 0, 3000));
    ASSERT_EQ(0, tcp_port_of(&f, "a"));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    pair(&g_kx.im[1], 0, "198.18.0.1", "192.0.2.1");
    firc_tunrun_map_pushed(f.run, &g_kx.im[0], &g_kx.im[1]);
    run_ms(&f, 300);
    ASSERT_EQ(before + 1, journal_from("tunvless0", line));
    ASSERT_EQ(0, journal_all("vless://"));
    ASSERT_EQ(0, journal_all(U));
    ASSERT_STR_EQ(KT_FIRST, stdin_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

/* catches: a port kept for a tunnel removed, disabled or switched to the TUN, or one dropped by an unchanged apply */
TEST disable_remove_or_kernel_tcp_off_clears_the_port(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    kx_attach(&f);
    static const char on[] = "tunnels:\n" KT_TUN("a", "0", KT_ON);
    static const char line[] = "port 3600 is taken, TCP stays on the TUN";
    int before = journal_all(line);
    apply_yaml(&f, on);
    ASSERT(run_until_port(&f, 0, 3600, 3000));
    int calls = g_kx.n_ports;
    apply_yaml(&f, on);
    run_ms(&f, 300);
    ASSERT_EQ(3600, g_kx.ports[0]);
    ASSERT_EQ(calls, g_kx.n_ports);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", ""));
    ASSERTm("kernelTcp off", g_kx.ports[0] == 0 && tcp_port_of(&f, "a") == 0);
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    run_ms(&f, 200);
    ASSERT_EQ(0, g_kx.ports[0]);
    apply_yaml(&f, on);
    ASSERT(run_until_port(&f, 0, 3600, 3000));
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON "    enable: false\n"));
    ASSERTm("disabled", g_kx.ports[0] == 0 && tcp_port_of(&f, "a") == 0);
    apply_yaml(&f, on);
    ASSERT(run_until_port(&f, 0, 3600, 3000));
    apply(&f, NULL, 0);
    ASSERTm("removed", g_kx.ports[0] == 0);
    ASSERT_EQ(before, journal_all(line));
    fx_down(&f);
    PASS();
}

/* catches: a delta sent to a child still starting, to a tunnel without a port, or with another device's lines */
TEST deltas_go_only_to_ready_children_with_a_port(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    setenv("FAKE_SLEEP", "0.8", 1);
    kx_attach(&f);
    firc_ktcp_image_t *im1 = &g_kx.im[0];
    firc_ktcp_image_t *im2 = &g_kx.im[1];
    firc_ktcp_image_t *im3 = &g_kx.im[2];
    pair(im2, 0, "198.18.0.1", "192.0.2.1");
    pair(im2, 0, "198.18.0.2", "192.0.2.2");
    pair(im2, 1, "198.18.1.1", "192.0.2.11");
    pair(im2, 2, "198.18.2.1", "192.0.2.21");
    pair(im3, 0, "198.18.0.2", "192.0.2.22");
    pair(im3, 0, "198.18.0.3", "192.0.2.3");
    pair(im3, 1, "198.18.1.2", "192.0.2.12");
    pair(im3, 2, "198.18.2.1", "192.0.2.31");
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON) KT_TUN("b", "1", "") KT_TUN("c", "2", KT_ON));
    ASSERT_EQ(1, run_until_starts(&f, "tunvless1", 1, 2000));
    run_ms(&f, 100);
    firc_tunrun_map_pushed(f.run, im1, im2);
    g_kx.cur = im2;
    ASSERT(run_until_tail(&f, "tunvless0", "\nmapall\n198.18.0.1 192.0.2.1\n198.18.0.2 192.0.2.2\n\n", 3000));
    ASSERT(run_until_tail(&f, "tunvless2", "\nmapall\n198.18.2.1 192.0.2.21\n\n", 3000));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "b", FIRC_TUN_ST_UP, 3000));
    firc_tunrun_map_pushed(f.run, im2, im3);
    g_kx.cur = im3;
    ASSERT(run_until_tail(&f, "tunvless0", "\nmap\n198.18.0.1 -\n198.18.0.2 192.0.2.22\n198.18.0.3 192.0.2.3\n\n", 2000));
    run_ms(&f, 200);
    ASSERT_STR_EQ(KT_FIRST "mapall\n198.18.0.1 192.0.2.1\n198.18.0.2 192.0.2.2\n\n"
                           "map\n198.18.0.1 -\n198.18.0.2 192.0.2.22\n198.18.0.3 192.0.2.3\n\n",
                  stdin_of(&f, "tunvless0"));
    ASSERT_STR_EQ(KT_FIRST, stdin_of(&f, "tunvless1"));
    ASSERT_STR_EQ(KT_FIRST "mapall\n198.18.2.1 192.0.2.21\n\nmap\n198.18.2.1 192.0.2.31\n\n", stdin_of(&f, "tunvless2"));
    fx_down(&f);
    PASS();
}

/* catches: an endless mapall loop at a short count, no resend, the warning repeated, or no resend for the next child */
TEST a_map_count_drift_resends_mapall_once(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    setenv("FAKE_MAPCOUNT", "1", 1);
    kx_attach(&f);
    pair(&g_kx.im[0], 0, "198.18.0.1", "192.0.2.1");
    pair(&g_kx.im[0], 0, "198.18.0.2", "192.0.2.2");
    pair(&g_kx.im[0], 0, "198.18.0.3", "192.0.2.3");
    pair(&g_kx.im[1], 0, "198.18.0.1", "192.0.2.1");
    static const char line[] = "map lines, its map is no longer resent";
    static const char first[] = "tunvless took 1 of 3 map lines, its map is no longer resent";
    int before = journal_from("tunvless0", line);
    int before_first = journal_from("tunvless0", first);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    dev_text_t two = {"tunvless0", "mapall\n198.18.0.1 192.0.2.1\n198.18.0.2 192.0.2.2\n198.18.0.3 192.0.2.3\n\nmapall\n"};
    ASSERT(run_until(&f, contains, &two, 3000));
    run_ms(&f, 400);
    firc_tunrun_map_pushed(f.run, &g_kx.im[0], &g_kx.im[1]);
    g_kx.cur = &g_kx.im[1];
    ASSERT(run_until_tail(&f, "tunvless0", "\nmap\n198.18.0.2 -\n198.18.0.3 -\n\n", 2000));
    run_ms(&f, 400);
    ASSERT_EQ(2, occurrences(stdin_of(&f, "tunvless0"), "mapall\n"));
    ASSERT_EQ(before + 1, journal_from("tunvless0", line));
    ASSERT_EQ(before_first + 1, journal_from("tunvless0", first));
    g_kx.cur = &g_kx.im[0];
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 3000));
    ASSERT(run_until(&f, contains, &two, 3000));
    run_ms(&f, 400);
    ASSERT_EQ(2, occurrences(stdin_of(&f, "tunvless0"), "mapall\n"));
    ASSERT_EQ(before + 2, journal_from("tunvless0", line));
    ASSERT_EQ(0, journal_all("vless://"));
    ASSERT_EQ(0, journal_all(U));
    fx_down(&f);
    PASS();
}

static void miss_setup(fx_t *f)
{
    ktcp_env(f);
    setenv("FAKE_MISS", "{\"type\":\"miss\",\"fake\":\"198.18.1.7\"}", 1);
    kx_attach(f);
}

/* catches: a miss left unanswered, answered with more than its line, or looked up on another device */
TEST a_miss_is_answered_with_one_line(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    miss_setup(&f);
    pair(&g_kx.real, 0, "198.18.1.7", "192.0.2.66");
    pair(&g_kx.real, 1, "198.18.1.7", "192.0.2.77");
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "1", KT_ON));
    ASSERT(run_until_tail(&f, "tunvless1", "\nmap\n198.18.1.7 192.0.2.77\n\n", 3000));
    run_ms(&f, 200);
    ASSERT_STR_EQ(KT_FIRST "mapall\n\nmap\n198.18.1.7 192.0.2.77\n\n", stdin_of(&f, "tunvless1"));
    fx_down(&f);
    PASS();
}

/* catches: a miss answered with any pool pair rather than one routed into the asking device */
TEST a_miss_for_another_device_s_group_gets_a_dash(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    miss_setup(&f);
    pair(&g_kx.real, 0, "198.18.1.7", "192.0.2.66");
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "1", KT_ON));
    ASSERT(run_until_tail(&f, "tunvless1", "\nmap\n198.18.1.7 -\n\n", 3000));
    run_ms(&f, 200);
    ASSERT_STR_EQ(KT_FIRST "mapall\n\nmap\n198.18.1.7 -\n\n", stdin_of(&f, "tunvless1"));
    fx_down(&f);
    PASS();
}

/* catches: a miss answered for a tunnel without a port, which redirects nothing */
TEST a_miss_from_a_child_without_a_port_is_ignored(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    miss_setup(&f);
    setenv("FAKE_TCPPORT", "0", 1);
    pair(&g_kx.real, 2, "198.18.1.7", "192.0.2.88");
    pair(&g_kx.real, 3, "198.18.1.7", "192.0.2.89");
    apply_yaml(&f, "tunnels:\n" KT_TUN("b", "2", "") KT_TUN("c", "3", KT_ON));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "b", FIRC_TUN_ST_UP, 3000));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "c", FIRC_TUN_ST_UP, 3000));
    apply_yaml(&f, "tunnels:\n" KT_TUN("b", "2", "")
                   "      - id: 0000000b\n        link: \"vless://" U "@b.example:443?security=none#B\"\n"
                   KT_TUN("c", "3", KT_ON)
                   "      - id: 0000000b\n        link: \"vless://" U "@b.example:443?security=none#B\"\n");
    dev_text_t b_nodes = {"tunvless2", "\nnodes\n"};
    dev_text_t c_nodes = {"tunvless3", "\nnodes\n"};
    ASSERT(run_until(&f, contains, &b_nodes, 2000));
    ASSERT(run_until(&f, contains, &c_nodes, 2000));
    run_ms(&f, 400);
    ASSERT_EQ(1, starts_of(&f, "tunvless2"));
    ASSERT_EQ(1, starts_of(&f, "tunvless3"));
    ASSERT(strstr(stdin_of(&f, "tunvless2"), "\nmap\n") == NULL);
    ASSERT(strstr(stdin_of(&f, "tunvless3"), "\nmap\n") == NULL);
    fx_down(&f);
    PASS();
}

/* catches: close queued to a child still starting, sent to one whose port was not bound, a wrong sent count, its ack not logged or not handed on, or a new child not reported */
TEST close_goes_to_the_live_child_only(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    static const char acked[] = "tunvless closed 1 connections";
    int before = journal_from("tunvless0", acked);
    ktcp_env(&f);
    setenv("FAKE_SLEEP", "0.6", 1);
    kx_attach(&f);
    firc_nf_prefix_t p = {.family = 4, .cidr = 24, .addr = {198, 18, 0, 0}};
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    run_ms(&f, 100);
    ASSERT_EQ(0, firc_tunrun_close(f.run, 0, &p, 1));
    ASSERT(run_until_tail(&f, "tunvless0", "mapall\n\n", 3000));
    ASSERT_EQ(1, firc_tunrun_close(f.run, 0, &p, 1));
    ASSERT_EQ(0, firc_tunrun_close(f.run, 5, &p, 1));
    ASSERT(run_until_tail(&f, "tunvless0", "close\n198.18.0.0/24\n\n", 2000));
    run_ms(&f, 200);
    ASSERT_STR_EQ(KT_FIRST "mapall\n\nclose\n198.18.0.0/24\n\n", stdin_of(&f, "tunvless0"));
    ASSERT_EQ(before + 1, journal_from("tunvless0", acked));
    ASSERT_EQ(1, g_kx.closed[0]);
    ASSERT_EQ(0, g_kx.closed[5]);
    ASSERT_EQ(1, g_kx.ready[0]);
    unsetenv("FAKE_SLEEP");
    setenv("FAKE_TCPPORT", "0", 1);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 3000));
    ASSERT_EQ(FIRC_TUN_ST_UP, run_until_status(&f, "a", FIRC_TUN_ST_UP, 3000));
    ASSERT_EQ(0, firc_tunrun_close(f.run, 0, &p, 1));
    run_ms(&f, 300);
    ASSERT_STR_EQ(KT_FIRST, stdin_of(&f, "tunvless0"));
    ASSERT_EQ(2, g_kx.ready[0]);
    fx_down(&f);
    PASS();
}

/* catches: bytes replacing instead of adding, lost across a child restart, or kept per tunnel id so a restart's new slot starts at zero */
TEST bytes_accumulate_across_events_and_a_child_restart(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    setenv("FAKE_AFTER", "{\"type\":\"bytes\",\"rx\":1000,\"tx\":20}", 1);
    kx_attach(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    uint64_t rx = 0, tx = 0;
    for (int i = 0; i < 300 && rx < 1000; i++) {
        run_ms(&f, 10);
        (void)firc_tunrun_ktcp_bytes(f.run, "tunvless0", &rx, &tx);
    }
    ASSERT_EQ(1000u, (unsigned)rx);
    ASSERT_EQ(20u, (unsigned)tx);
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 3000));
    for (int i = 0; i < 300 && rx < 2000; i++) {
        run_ms(&f, 10);
        (void)firc_tunrun_ktcp_bytes(f.run, "tunvless0", &rx, &tx);
    }
    ASSERT_EQ(2000u, (unsigned)rx);
    ASSERT_EQ(40u, (unsigned)tx);
    ASSERT_EQ(0, journal_from("tunvless0", "bytes"));
    unsetenv("FAKE_AFTER");
    fx_down(&f);
    PASS();
}

static bool state_port_is(fx_t *f, const void *arg)
{
    return tcp_port_of(f, "a") == *(const uint16_t *)arg;
}

/* catches: hooks attached after a child reported its port left without that port until the next change */
TEST attaching_the_hooks_publishes_the_ports_held(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    static const uint16_t want = 3600;
    ASSERT(run_until(&f, state_port_is, &want, 3000));
    ASSERT_EQ(0, g_kx.n_ports);
    kx_attach(&f);
    ASSERT_EQ(1, g_kx.n_ports);
    ASSERT_EQ(3600, g_kx.ports[0]);
    fx_down(&f);
    PASS();
}

/* catches: the pool set through the tunnel runner never reaching a kernel-TCP child's --tcp-pool */
TEST the_pool_set_on_the_runner_reaches_the_child(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ktcp_env(&f);
    static const uint8_t base[4] = {198, 18, 0, 0};
    firc_tunrun_set_tcp_pool(f.run, base, 15);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", KT_ON));
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 2000));
    ASSERT(argv_has(&f, "--tcp-pool"));
    ASSERT(argv_has(&f, "198.18.0.0/15"));
    fx_down(&f);
    PASS();
}

#define IB_HEAD "    inbounds:\n"
#define IB_ITEM(port, listen, node, more) "      - { port: " port ", listen: " listen ", node: \"" node "\"" more " }\n"
#define LINK_A "vless://" U "@a.example:443?type=tcp&security=none#A"
#define IB_A IB_HEAD IB_ITEM("1081", "lo", "0000000a:A", "")
#define IB_SENT_A "inbounds\n127.0.0.1:1081 - - " LINK_A "\n\n"

static void ib_env(fx_t *f)
{
    setenv("FAKE_STDIN_DIR", f->dir, 1);
    firc_event_reset_for_test();
}

static firc_tun_ib_state_t g_ib;

static const firc_tun_ib_state_t *ib_of(fx_t *f, uint16_t port)
{
    static firc_tun_state_t st[8];
    size_t n = firc_tunrun_states(f->run, st, 8);
    for (size_t i = 0; i < n && i < 8; i++) {
        for (size_t k = 0; strcmp(st[i].id, "a") == 0 && k < st[i].n_ib; k++) {
            if (st[i].ib[k].port == port) {
                g_ib = st[i].ib[k];
                return &g_ib;
            }
        }
    }
    return NULL;
}

static const char *ib_state(fx_t *f, uint16_t port)
{
    const firc_tun_ib_state_t *s = ib_of(f, port);
    return s != NULL ? s->state : "(none)";
}

static int journal_at(firc_log_level_t level, const char *source, const char *text)
{
    static firc_event_t ev[64];
    uint64_t since = 0, dropped = 0;
    int c = 0;
    for (;;) {
        uint64_t next = since;
        size_t n = firc_event_read(since, ev, 64, &next, &dropped);
        for (size_t i = 0; i < n; i++) {
            if (ev[i].kind == FIRC_EVENT_LOG && ev[i].u.log.level == level && strcmp(ev[i].u.log.source, source) == 0 &&
                strcmp(ev[i].u.log.text, text) == 0) {
                c++;
            }
        }
        if (n == 0 || next == since) {
            return c;
        }
        since = next;
    }
}

static void unlink_stdin(fx_t *f, const char *dev)
{
    char path[128];
    snprintf(path, sizeof path, "%s/%s", f->dir, dev);
    unlink(path);
}

/* catches: inbounds never sent after ready, sent before the node list, or written with another address or field order */
TEST inbounds_go_out_after_ready(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A, stdin_of(&f, "tunvless0"));
    ASSERT_STR_EQ("starting", ib_state(&f, 1081));
    ASSERT_EQ(0, journal_all("inbounds not sent"));
    fx_down(&f);
    PASS();
}

/* catches: a whole-group inbound looked up as a node key and sent as a dash, or journalled as a gone node */
TEST a_whole_group_inbound_sends_a_star(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_HEAD IB_ITEM("1081", "lo", "*", "")));
    ASSERT(run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1081 - - *\n\n", 3000));
    firc_tunrun_refresh_inbounds(f.run);
    ASSERT_STR_EQ("starting", ib_state(&f, 1081));
    ASSERT_EQ(0, journal_at(FIRC_LOG_WARN, "tunvless0", "inbound :1081: node * is gone"));
    fx_down(&f);
    PASS();
}

/* catches: the inbounds a child got kept as sent across its restart, so the new child never gets them */
TEST a_restarted_child_gets_them_again(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    unlink_stdin(&f, "tunvless0");
    ASSERT_EQ(FIRC_OK, firc_tunrun_restart(f.run, "a"));
    ASSERT_EQ(2, run_until_starts(&f, "tunvless0", 2, 3000));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A, stdin_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

/* catches: every save, refresh or re-read resending inbounds that did not change, which makes tunvless rebind */
TEST an_unchanged_save_sends_nothing(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    firc_tunrun_refresh_inbounds(f.run);
    firc_tunrun_bodies_changed(f.run);
    run_ms(&f, 300);
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A, stdin_of(&f, "tunvless0"));
    ASSERT_EQ(1, starts_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

/* catches: a changed port never sent, or sent again on the next refresh with nothing changed */
TEST a_changed_port_sends_once(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_HEAD IB_ITEM("1082", "lo", "0000000a:A", "")));
    ASSERT(run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1082 - - " LINK_A "\n\n", 2000));
    firc_tunrun_refresh_inbounds(f.run);
    run_ms(&f, 200);
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A "inbounds\n127.0.0.1:1082 - - " LINK_A "\n\n", stdin_of(&f, "tunvless0"));
    ASSERT_EQ(1, starts_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

#define KT_TUN_Z(extra)                                                                       \
    "  - id: a\n    device: tunvless0\n" extra "    sources:\n"                                \
    "      - id: 0000000a\n        link: \"vless://" U "@a.example:443?security=none#Z\"\n"

/* catches: a gone node sent with a stale link or left out, its warning repeated per refresh or missing, or no line when it is back */
TEST a_renamed_node_sends_a_dash(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    apply_yaml(&f, "tunnels:\n" KT_TUN_Z(IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1081 - - -\n\n", 2000));
    firc_tunrun_refresh_inbounds(f.run);
    firc_tunrun_refresh_inbounds(f.run);
    ASSERT_STR_EQ("no-node", ib_state(&f, 1081));
    ASSERT_EQ(1, journal_at(FIRC_LOG_WARN, "tunvless0", "inbound :1081: node 0000000a:A is gone"));
    ASSERT_EQ(0, journal_at(FIRC_LOG_INFO, "tunvless0", "inbound :1081: node 0000000a:A is back"));
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 2000));
    ASSERT_EQ(1, journal_at(FIRC_LOG_INFO, "tunvless0", "inbound :1081: node 0000000a:A is back"));
    ASSERT_EQ(1, journal_at(FIRC_LOG_WARN, "tunvless0", "inbound :1081: node 0000000a:A is gone"));
    ASSERT_EQ(1, starts_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

/* catches: the node looked up among the sent rows only, so an excluded node's port refuses */
TEST an_excluded_node_still_binds(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, TWO_LINKS "    exclude: [\"0000000a:a\"]\n" IB_HEAD IB_ITEM("1081", "lo", "0000000a:a", ""));
    ASSERT(run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1081 - - vless://" U "@a.example:443?type=tcp&security=none#a\n\n", 3000));
    ASSERT_STR_EQ(LINK_OF("b") "\ninbounds\n127.0.0.1:1081 - - " LINK_OF("a") "\n", stdin_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

/* catches: the node looked up after the filter, so a port bound to a filtered-out subscription node refuses */
TEST a_filtered_out_node_still_binds(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    static sub_srv_t srv;
    set_x_body("vless://" U "@a.example:443?security=none#A\nvless://" U "@b.example:443?security=none#B\n");
    ASSERT(sub_srv_start(&srv, 0));
    subs_up(&f);
    ASSERT(g_subs != NULL);
    apply_yaml(&f, "tunnels:\n" XY_TUN("a", "0", "x", "    filter: \"^B$\"\n" IB_HEAD IB_ITEM("1081", "lo", "00000000:A", "")));
    bool sent = run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1081 - - " LINK_A "\n\n", 3000);
    sub_srv_stop(&srv);
    ASSERT(sent);
    ASSERT_STR_EQ("vless://" U "@b.example:443?type=tcp&security=none#B\n\n" "inbounds\n127.0.0.1:1081 - - " LINK_A "\n\n",
                  stdin_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

/* catches: a listen outside the running app.link sent to tunvless, or its state and warning missing */
TEST a_listen_outside_app_link_sends_no_line(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A IB_ITEM("1082", "br9", "0000000a:A", "")));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    firc_tunrun_refresh_inbounds(f.run);
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A, stdin_of(&f, "tunvless0"));
    ASSERT_STR_EQ("not-lan", ib_state(&f, 1082));
    ASSERT_EQ(1, journal_at(FIRC_LOG_WARN, "tunvless0", "inbound :1082: br9 is not a LAN interface of app.link"));
    fx_down(&f);
    PASS();
}

/* catches: an app.link entry the firmware called a WAN at start listened on, its role read anew instead of from the snapshot */
TEST a_wan_listen_sends_no_line(void)
{
    static fx_t f;
    g_link_wan[0] = true;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", KT_FIRST, 3000));
    firc_tunrun_refresh_inbounds(f.run);
    run_ms(&f, 300);
    ASSERT_STR_EQ(KT_FIRST, stdin_of(&f, "tunvless0"));
    ASSERT_STR_EQ("not-lan", ib_state(&f, 1081));
    ASSERT_EQ(1, journal_at(FIRC_LOG_WARN, "tunvless0", "inbound :1081: lo is not a LAN interface of app.link"));
    fx_down(&f);
    PASS();
}

/* catches: an empty command sent where no line ever was, or a listen moved into app.link journalled as a node back */
TEST a_listen_moved_into_app_link_sends_its_line_quietly(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_HEAD IB_ITEM("1081", "br9", "0000000a:A", "")));
    ASSERT(run_until_tail(&f, "tunvless0", KT_FIRST, 3000));
    run_ms(&f, 300);
    ASSERT_STR_EQ(KT_FIRST, stdin_of(&f, "tunvless0"));
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", KT_FIRST IB_SENT_A, 2000));
    ASSERT_EQ(0, journal_all("is back"));
    fx_down(&f);
    PASS();
}

static bool ib_state_is(fx_t *f, const void *arg);

/* catches: an event for a port with no line in the last command changing an inbound fircd itself decided on */
TEST an_event_for_a_port_without_a_line_is_ignored(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER",
           "{\"type\":\"inbound\",\"port\":1082,\"state\":\"up\",\"why\":\"\"}\n"
           "{\"type\":\"ibytes\",\"port\":1082,\"rx\":9,\"tx\":9}\n"
           "{\"type\":\"inbound\",\"port\":1081,\"state\":\"up\",\"why\":\"\"}",
           1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A IB_ITEM("1082", "br9", "0000000a:A", "")));
    static const char *const up[] = {"1081", "up"};
    bool was_up = run_until(&f, ib_state_is, up, 3000);
    unsetenv("FAKE_AFTER");
    ASSERT(was_up);
    ASSERT_STR_EQ("not-lan", ib_state(&f, 1082));
    ASSERT_EQ(0u, (unsigned)ib_of(&f, 1082)->rx);
    fx_down(&f);
    PASS();
}

#define IB_THREE IB_A IB_ITEM("1082", "lo", "0000000a:A", "") IB_ITEM("1083", "lo", "0000000a:A", "")

/* catches: the sources parsed once per inbound on the loop thread instead of once per refresh */
TEST one_refresh_parses_once_for_three_inbounds(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_THREE));
    ASSERT(run_until_tail(&f, "tunvless0", "127.0.0.1:1083 - - " LINK_A "\n\n", 3000));
    size_t before = firc_tun_nodes_parses_for_test();
    firc_tunrun_refresh_inbounds(f.run);
    ASSERT_EQ_FMT((size_t)1, firc_tun_nodes_parses_for_test() - before, "%zu");
    fx_down(&f);
    PASS();
}

/* catches: an apply parsing again for the inbounds from the start of the child it spawns, besides its own refresh */
TEST an_apply_parses_once_for_the_list_and_once_for_inbounds(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    size_t before = firc_tun_nodes_parses_for_test();
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_THREE));
    ASSERT_EQ_FMT((size_t)2, firc_tun_nodes_parses_for_test() - before, "%zu");
    ASSERT_EQ(1, run_until_starts(&f, "tunvless0", 1, 3000));
    fx_down(&f);
    PASS();
}

/* catches: a failed lookup read as a gone node, sending a dash line and a gone warning */
TEST a_failed_lookup_keeps_what_was_sent(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER", "{\"type\":\"inbound\",\"port\":1081,\"state\":\"up\",\"why\":\"\"}", 1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    static const char *const up[] = {"1081", "up"};
    bool was_up = run_until(&f, ib_state_is, up, 3000);
    unsetenv("FAKE_AFTER");
    ASSERT(was_up);
    firc_tun_nodes_set_fail_for_test(true);
    firc_tunrun_refresh_inbounds(f.run);
    firc_tun_nodes_set_fail_for_test(false);
    run_ms(&f, 200);
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A, stdin_of(&f, "tunvless0"));
    ASSERT_STR_EQ("up", ib_state(&f, 1081));
    ASSERT_EQ(0, journal_all("is gone"));
    fx_down(&f);
    PASS();
}

/* catches: an inbound edit counted as a node change, sending nodes or restarting tunvless, or a password journalled */
TEST an_inbound_change_sends_no_nodes(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    uint64_t before = firc_tunrun_start_seq(f.run);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_HEAD IB_ITEM("1081", "lo", "0000000a:A", ", user: alice, password: s3cret")));
    ASSERT(run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1081 alice s3cret " LINK_A "\n\n", 2000));
    ASSERT(strstr(stdin_of(&f, "tunvless0"), "nodes\n") == NULL);
    ASSERT_EQ(1, starts_of(&f, "tunvless0"));
    ASSERT(firc_tunrun_updated(f.run, "a") <= before);
    ASSERT_EQ(0, journal_all("s3cret"));
    fx_down(&f);
    PASS();
}

/* catches: an interface without an IPv4 sent with an empty or zero address instead of left out */
TEST an_interface_without_ipv4_is_no_address(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A IB_ITEM("1082", "firc-noip0", "0000000a:A", "")));
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A, 3000));
    firc_tunrun_refresh_inbounds(f.run);
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A, stdin_of(&f, "tunvless0"));
    ASSERT_STR_EQ("no-address", ib_state(&f, 1082));
    ASSERT_EQ(1, journal_at(FIRC_LOG_WARN, "tunvless0", "inbound :1082: firc-noip0 has no IPv4 address"));
    fx_down(&f);
    PASS();
}

static bool ib_state_is(fx_t *f, const void *arg)
{
    const char *const *w = arg;
    return strcmp(ib_state(f, (uint16_t)atoi(w[0])), w[1]) == 0;
}

/* catches: a busy port left out of the journal, journalled at another level or as fircd's, or its state not kept */
TEST busy_event_is_an_error_line(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER",
           "{\"type\":\"inbound\",\"port\":1081,\"state\":\"busy\",\"why\":\"address in use\"}\n"
           "{\"type\":\"inbound\",\"port\":1081,\"state\":\"busy\",\"why\":\"address in use\"}",
           1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    static const char *const want[] = {"1081", "busy"};
    bool busy = run_until(&f, ib_state_is, want, 3000);
    run_ms(&f, 100);
    unsetenv("FAKE_AFTER");
    ASSERT(busy);
    ASSERT_STR_EQ("address in use", ib_of(&f, 1081)->why);
    ASSERT_EQ(1, journal_at(FIRC_LOG_ERROR, "tunvless0", "inbound :1081 on lo: port is busy"));
    fx_down(&f);
    PASS();
}

/* catches: a port that lost the bind race left busy until restart because an unchanged refresh sends nothing */
TEST a_busy_inbound_is_sent_again_on_an_unchanged_refresh(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER", "{\"type\":\"inbound\",\"port\":1081,\"state\":\"busy\",\"why\":\"address in use\"}", 1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    static const char *const want[] = {"1081", "busy"};
    bool busy = run_until(&f, ib_state_is, want, 3000);
    unsetenv("FAKE_AFTER");
    ASSERT(busy);
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A, stdin_of(&f, "tunvless0"));
    firc_tunrun_refresh_inbounds(f.run);
    ASSERT(run_until_tail(&f, "tunvless0", IB_SENT_A IB_SENT_A, 2000));
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A IB_SENT_A, stdin_of(&f, "tunvless0"));
    ASSERT_EQ(1, starts_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

/* catches: every unattended retry of a still-busy port journalling the error again */
TEST a_still_busy_inbound_is_journalled_once(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER", "{\"type\":\"inbound\",\"port\":1081,\"state\":\"busy\",\"why\":\"address in use\"}", 1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    static const char *const want[] = {"1081", "busy"};
    bool busy = run_until(&f, ib_state_is, want, 3000);
    unsetenv("FAKE_AFTER");
    ASSERT(busy);
    for (int r = 0; r < 3; r++) {
        firc_tunrun_refresh_inbounds(f.run);
        ASSERT_STR_EQ("busy", ib_of(&f, 1081)->state);
        run_ms(&f, 100);
    }
    ASSERT_STR_EQ(KT_FIRST IB_SENT_A IB_SENT_A IB_SENT_A IB_SENT_A, stdin_of(&f, "tunvless0"));
    ASSERT_STR_EQ("busy", ib_of(&f, 1081)->state);
    ASSERT_EQ(1, journal_at(FIRC_LOG_ERROR, "tunvless0", "inbound :1081 on lo: port is busy"));
    fx_down(&f);
    PASS();
}

/* catches: a changed inbound that is busy again kept silent as if it were only a retry */
TEST a_changed_busy_inbound_is_journalled_again(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER", "{\"type\":\"inbound\",\"port\":1081,\"state\":\"busy\",\"why\":\"address in use\"}", 1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    static const char *const want[] = {"1081", "busy"};
    bool busy = run_until(&f, ib_state_is, want, 3000);
    unsetenv("FAKE_AFTER");
    ASSERT(busy);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_HEAD IB_ITEM("1081", "lo", "0000000a:A", ", user: bob, password: pw")));
    ASSERT(run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1081 bob pw " LINK_A "\n\n", 2000));
    ASSERT(run_until(&f, ib_state_is, want, 2000));
    run_ms(&f, 100);
    ASSERT_EQ(2, journal_at(FIRC_LOG_ERROR, "tunvless0", "inbound :1081 on lo: port is busy"));
    fx_down(&f);
    PASS();
}

/* catches: a busy port that a retry freed kept busy */
TEST a_busy_inbound_comes_up_on_a_retry(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER", "{\"type\":\"inbound\",\"port\":1081,\"state\":\"busy\",\"why\":\"address in use\"}", 1);
    setenv("FAKE_IB_AGAIN", "{\"type\":\"inbound\",\"port\":1081,\"state\":\"up\",\"why\":\"\"}", 1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    static const char *const busy_w[] = {"1081", "busy"};
    bool busy = run_until(&f, ib_state_is, busy_w, 3000);
    unsetenv("FAKE_AFTER");
    unsetenv("FAKE_IB_AGAIN");
    ASSERT(busy);
    firc_tunrun_refresh_inbounds(f.run);
    static const char *const up_w[] = {"1081", "up"};
    ASSERT(run_until(&f, ib_state_is, up_w, 2000));
    ASSERT_STR_EQ("", ib_of(&f, 1081)->why);
    fx_down(&f);
    PASS();
}

static bool ib_rx_is(fx_t *f, const void *arg)
{
    const firc_tun_ib_state_t *s = ib_of(f, 1081);
    return s != NULL && s->rx == *(const uint64_t *)arg;
}

/* catches: bytes replacing instead of adding, added to the wrong port, or an up event ignored */
TEST ibytes_sum_per_port(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER",
           "{\"type\":\"ibytes\",\"port\":1081,\"rx\":100,\"tx\":5}\n"
           "{\"type\":\"ibytes\",\"port\":1082,\"rx\":7,\"tx\":1}\n"
           "{\"type\":\"ibytes\",\"port\":1081,\"rx\":50,\"tx\":3}\n"
           "{\"type\":\"inbound\",\"port\":1081,\"state\":\"up\",\"why\":\"\"}",
           1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A IB_ITEM("1082", "lo", "0000000a:A", "")));
    static const uint64_t want = 150;
    bool summed = run_until(&f, ib_rx_is, &want, 3000);
    run_ms(&f, 100);
    unsetenv("FAKE_AFTER");
    ASSERT(summed);
    ASSERT_EQ(150u, (unsigned)ib_of(&f, 1081)->rx);
    ASSERT_EQ(8u, (unsigned)ib_of(&f, 1081)->tx);
    ASSERT_EQ(7u, (unsigned)ib_of(&f, 1082)->rx);
    ASSERT_EQ(1u, (unsigned)ib_of(&f, 1082)->tx);
    ASSERT_STR_EQ("up", ib_state(&f, 1081));
    ASSERT_STR_EQ("starting", ib_state(&f, 1082));
    fx_down(&f);
    PASS();
}

/* catches: a space, a percent sign or a lone dash in user or password sent raw, which splits or empties the field */
TEST user_with_space_is_percent_encoded(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_HEAD IB_ITEM("1081", "lo", "0000000a:A", ", user: \"s t\", password: \"p%w\"")
                                               IB_ITEM("1082", "lo", "0000000a:A", ", user: \"-\", password: \"-\"")));
    ASSERT(run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1081 s%20t p%25w " LINK_A "\n127.0.0.1:1082 %2D %2D " LINK_A "\n\n", 3000));
    fx_down(&f);
    PASS();
}

/* catches: a dead child's inbounds still reported up through its backoff */
TEST a_child_that_died_shows_its_inbounds_starting(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER", "{\"type\":\"inbound\",\"port\":1081,\"state\":\"up\",\"why\":\"\"}", 1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    static const char *const up[] = {"1081", "up"};
    bool was_up = run_until(&f, ib_state_is, up, 3000);
    unsetenv("FAKE_AFTER");
    ASSERT(was_up);
    pid_t pid = last_pid(&f, "tunvless0");
    ASSERT(pid > 0 && kill(pid, SIGKILL) == 0);
    static const char *const starting[] = {"1081", "starting"};
    ASSERT(run_until(&f, ib_state_is, starting, 2000));
    ASSERT_EQ(1, starts_of(&f, "tunvless0"));
    fx_down(&f);
    PASS();
}

/* catches: an inbound's bytes and state left at its old index when a save puts another inbound before it */
TEST inbound_state_follows_its_port_across_a_save(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    setenv("FAKE_AFTER", "{\"type\":\"ibytes\",\"port\":1081,\"rx\":100,\"tx\":5}", 1);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_A));
    static const uint64_t want = 100;
    bool counted = run_until(&f, ib_rx_is, &want, 3000);
    unsetenv("FAKE_AFTER");
    ASSERT(counted);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", IB_HEAD IB_ITEM("1080", "lo", "0000000a:A", "") IB_ITEM("1081", "lo", "0000000a:A", "")));
    ASSERT_EQ(100u, (unsigned)ib_of(&f, 1081)->rx);
    ASSERT_EQ(0u, (unsigned)ib_of(&f, 1080)->rx);
    fx_down(&f);
    PASS();
}

/* catches: a port rebound to another gone node kept silent because the old node was already reported gone */
TEST a_gone_port_rebound_to_another_gone_node_warns_again(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN_Z(IB_A));
    ASSERT(run_until_tail(&f, "tunvless0", "inbounds\n127.0.0.1:1081 - - -\n\n", 3000));
    apply_yaml(&f, "tunnels:\n" KT_TUN_Z(IB_HEAD IB_ITEM("1081", "lo", "0000000a:Y", "")));
    ASSERT_EQ(1, journal_at(FIRC_LOG_WARN, "tunvless0", "inbound :1081: node 0000000a:A is gone"));
    ASSERT_EQ(1, journal_at(FIRC_LOG_WARN, "tunvless0", "inbound :1081: node 0000000a:Y is gone"));
    fx_down(&f);
    PASS();
}

/* catches: a disabled tunnel's inbounds reported as starting or with a stale state */
TEST a_disabled_tunnel_s_inbounds_are_off(void)
{
    static fx_t f;
    ASSERT(fx_up(&f, 0));
    ib_env(&f);
    apply_yaml(&f, "tunnels:\n" KT_TUN("a", "0", "    enable: false\n" IB_A));
    firc_tunrun_refresh_inbounds(f.run);
    ASSERT_STR_EQ("off", ib_state(&f, 1081));
    fx_down(&f);
    PASS();
}

SUITE(tunrun)
{
    GREATEST_SET_TEARDOWN_CB(teardown, NULL);
    RUN_TEST(uplink_device_names_the_device_packets_leave_by);
    RUN_TEST(journal_lines_read_as_agreed);
    RUN_TEST(quiet_events_write_no_line);
    RUN_TEST(a_failed_uplink_is_not_started_until_a_reload_writes_it);
    RUN_TEST(a_failed_default_route_takes_the_rule_back);
    RUN_TEST(a_failed_uplink_gives_its_mark_field_back);
    RUN_TEST(uplink_ok_follows_the_uplink_route);
    RUN_TEST(a_removed_tunnel_gives_back_its_rule_and_field_once_reaped);
    RUN_TEST(a_restart_gives_a_tunnel_the_field_it_had);
    RUN_TEST(an_apply_frees_seeded_fields_no_tunnel_holds);
    RUN_TEST(a_removed_tunnel_keeps_its_field_in_the_map_until_reaped);
    RUN_TEST(a_tunnel_back_before_the_reap_keeps_its_uplink);
    RUN_TEST(removed_twice_keeps_the_rule_while_the_first_child_lives);
    RUN_TEST(a_later_child_reaped_first_leaves_the_rule_to_the_earlier);
    RUN_TEST(moving_an_uplink_keeps_the_rule_and_moves_the_default);
    RUN_TEST(a_disabled_tunnel_gets_no_uplink_until_enabled);
    RUN_TEST(switching_to_auto_drops_the_rule_and_the_mark);
    RUN_TEST(an_unchanged_reload_keeps_rule_and_process);
    RUN_TEST(link_up_rewrites_the_default_of_its_own_uplink);
    RUN_TEST(a_reread_of_everything_rewrites_every_uplink);
    RUN_TEST(stop_ends_children_then_removes_uplinks);
    RUN_TEST(only_the_effective_links_reach_tunvless);
    RUN_TEST(a_filter_edit_keeps_tunvless_running);
    RUN_TEST(a_changed_sent_list_reaches_tunvless_without_a_restart);
    RUN_TEST(a_list_past_the_stdin_limit_is_cut_from_the_end);
    RUN_TEST(a_save_during_a_refresh_takes_the_new_config);
    RUN_TEST(a_body_change_updates_only_the_tunnel_using_it);
    RUN_TEST(an_apply_sweeps_unused_cache_files);
    RUN_TEST(every_configured_tunnel_has_a_state);
    RUN_TEST(a_restart_starts_an_unchanged_child_again);
    RUN_TEST(the_start_counter_names_what_an_apply_started);
    RUN_TEST(node_down_lasts_until_the_child_restarts);
    RUN_TEST(node_states_follow_the_index_not_the_name);
    RUN_TEST(an_index_naming_another_node_falls_back_to_the_name);
    RUN_TEST(a_node_that_leaves_the_list_forgets_its_down);
    RUN_TEST(the_built_rows_are_kept_without_links);
    RUN_TEST(mark_of_reports_the_uplink_mark_and_whether_a_child_holds_it);
    RUN_TEST(device_down_is_every_status_but_up);
    RUN_TEST(device_starting_is_a_start_or_a_wait_with_its_since);
    RUN_TEST(five_minutes_without_a_node_is_an_error_for_the_device);
    RUN_TEST(twenty_no_node_retries_leave_one_warning);
    RUN_TEST(the_watch_follows_the_childs_events);
    RUN_TEST(a_stop_takes_the_watch_timer_off_the_loop);
    RUN_TEST(a_removed_tunnel_is_not_down_while_its_child_ends);
    RUN_TEST(ready_with_a_port_publishes_it_and_sends_mapall);
    RUN_TEST(a_kernel_without_redirect_reports_no_port);
    RUN_TEST(a_ready_naming_another_port_publishes_nothing);
    RUN_TEST(the_port_survives_an_exit_and_backoff);
    RUN_TEST(a_zero_port_is_journalled_and_clears_the_port);
    RUN_TEST(disable_remove_or_kernel_tcp_off_clears_the_port);
    RUN_TEST(deltas_go_only_to_ready_children_with_a_port);
    RUN_TEST(a_map_count_drift_resends_mapall_once);
    RUN_TEST(a_miss_is_answered_with_one_line);
    RUN_TEST(a_miss_for_another_device_s_group_gets_a_dash);
    RUN_TEST(a_miss_from_a_child_without_a_port_is_ignored);
    RUN_TEST(close_goes_to_the_live_child_only);
    RUN_TEST(bytes_accumulate_across_events_and_a_child_restart);
    RUN_TEST(attaching_the_hooks_publishes_the_ports_held);
    RUN_TEST(the_pool_set_on_the_runner_reaches_the_child);
    RUN_TEST(inbounds_go_out_after_ready);
    RUN_TEST(a_whole_group_inbound_sends_a_star);
    RUN_TEST(a_restarted_child_gets_them_again);
    RUN_TEST(an_unchanged_save_sends_nothing);
    RUN_TEST(a_changed_port_sends_once);
    RUN_TEST(a_renamed_node_sends_a_dash);
    RUN_TEST(an_excluded_node_still_binds);
    RUN_TEST(a_filtered_out_node_still_binds);
    RUN_TEST(a_listen_outside_app_link_sends_no_line);
    RUN_TEST(a_wan_listen_sends_no_line);
    RUN_TEST(a_listen_moved_into_app_link_sends_its_line_quietly);
    RUN_TEST(an_event_for_a_port_without_a_line_is_ignored);
    RUN_TEST(one_refresh_parses_once_for_three_inbounds);
    RUN_TEST(an_apply_parses_once_for_the_list_and_once_for_inbounds);
    RUN_TEST(a_failed_lookup_keeps_what_was_sent);
    RUN_TEST(an_inbound_change_sends_no_nodes);
    RUN_TEST(an_interface_without_ipv4_is_no_address);
    RUN_TEST(busy_event_is_an_error_line);
    RUN_TEST(a_busy_inbound_is_sent_again_on_an_unchanged_refresh);
    RUN_TEST(a_still_busy_inbound_is_journalled_once);
    RUN_TEST(a_busy_inbound_comes_up_on_a_retry);
    RUN_TEST(a_changed_busy_inbound_is_journalled_again);
    RUN_TEST(ibytes_sum_per_port);
    RUN_TEST(user_with_space_is_percent_encoded);
    RUN_TEST(a_disabled_tunnel_s_inbounds_are_off);
    RUN_TEST(a_child_that_died_shows_its_inbounds_starting);
    RUN_TEST(inbound_state_follows_its_port_across_a_save);
    RUN_TEST(a_gone_port_rebound_to_another_gone_node_warns_again);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    GREATEST_MAIN_BEGIN();
    firc_sub_fetch_global_init();
    RUN_SUITE(tunrun);
    firc_sub_fetch_global_cleanup();
    GREATEST_MAIN_END();
}
