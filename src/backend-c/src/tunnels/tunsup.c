#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */

#include "firc/tunsup.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "firc/log.h"

extern char **environ;

#define BACKOFF_BASE_S 3
#define BACKOFF_CAP_S 60
#define STABLE_S 60
#define REAP_RETRY_MS 100
#define STOP_POLL_MS 50
#define TERM_GRACE_S 5
#define ACK_S 10
#define INDEX_MAX 4096
#define WARN_TAG "tunvless[warn]"

typedef struct slot {
    firc_tunsup_t *s;
    firc_tunnel_t cfg;
    uint32_t mark;
    firc_tun_state_t st;
    pid_t pid;
    int in_fd;
    int out_fd;
    int err_fd;
    char *in_buf;
    size_t in_len;
    size_t in_off;
    firc_tun_lines_t out_lines;
    firc_tun_lines_t err_lines;
    int reap_timer;
    int restart_timer;
    int kill_timer;
    int64_t started_ms;
    int next_backoff_s;
    bool terminating;
    bool gone;
    bool warned_bad;
    bool warned_drop_out;
    bool warned_drop_err;
    bool deferred;
    pid_t stop_pid;
    uint32_t run_mark;
    char run_dev[16];
    uint64_t start_seq;
    uint64_t update_seq;
    uint64_t *ix;
    size_t n_ix;
    int acks;
    int ack_timer;
    bool ready;
    bool drift;
    size_t *want;
    size_t n_want;
} slot_t;

struct firc_tunsup {
    firc_loop_t *loop;
    char *binary;
    firc_tun_event_fn on_event;
    void *ud;
    firc_tun_reap_fn on_reap;
    void *reap_ud;
    pthread_t loop_thread;
    slot_t **v;
    size_t n;
    int second_ms;
    bool stopped;
    uint64_t seq;
};

static void spawn(slot_t *sl);
static bool device_busy(const slot_t *sl);

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void free_src(firc_tun_src_t *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free(v[i].link);
        free(v[i].sub.url);
    }
    free(v);
}

static char *dup_or_null(const char *s, bool *ok)
{
    if (s == NULL) {
        return NULL;
    }
    char *d = strdup(s);
    if (d == NULL) {
        *ok = false;
    }
    return d;
}

static firc_err_t copy_cfg(firc_tunnel_t *dst, const firc_tunnel_t *src)
{
    firc_tun_src_t *v = NULL;
    if (src->n_src > 0) {
        v = calloc(src->n_src, sizeof *v);
        if (v == NULL) {
            return FIRC_ERR_NOMEM;
        }
        bool ok = true;
        for (size_t i = 0; i < src->n_src; i++) {
            v[i] = src->src[i];
            v[i].link = dup_or_null(src->src[i].link, &ok);
            v[i].sub.url = dup_or_null(src->src[i].sub.url, &ok);
        }
        if (!ok) {
            free_src(v, src->n_src);
            return FIRC_ERR_NOMEM;
        }
    }
    free_src(dst->src, dst->n_src);
    *dst = *src;
    dst->src = v;
    dst->filter = NULL;
    dst->order = NULL;
    dst->n_order = 0;
    dst->exclude = NULL;
    dst->n_exclude = 0;
    return FIRC_OK;
}

static void notify(slot_t *sl, const firc_tev_t *ev)
{
    if (!sl->gone && sl->s->on_event != NULL) {
        sl->s->on_event(&sl->st, ev, sl->s->ud);
    }
}

static void put_status(slot_t *sl, firc_tun_status_t status)
{
    if (sl->st.status != status) {
        sl->st.status = status;
        sl->st.since_ms = now_ms();
    }
}

static void set_status(slot_t *sl, firc_tun_status_t status)
{
    put_status(sl, status);
    notify(sl, NULL);
}

static void drop_timer(firc_tunsup_t *s, int *id)
{
    if (*id != 0) {
        firc_loop_del_timer(s->loop, *id);
        *id = 0;
    }
}

static void drop_fd(firc_tunsup_t *s, int *fd)
{
    if (*fd >= 0) {
        firc_loop_del_fd(s->loop, *fd);
        close(*fd);
        *fd = -1;
    }
}

static void close_in(slot_t *sl)
{
    drop_fd(sl->s, &sl->in_fd);
    free(sl->in_buf);
    sl->in_buf = NULL;
    sl->in_len = 0;
    sl->in_off = 0;
}

static void release_io(slot_t *sl)
{
    close_in(sl);
    drop_fd(sl->s, &sl->out_fd);
    drop_fd(sl->s, &sl->err_fd);
    drop_timer(sl->s, &sl->reap_timer);
    drop_timer(sl->s, &sl->kill_timer);
    drop_timer(sl->s, &sl->ack_timer);
    sl->acks = 0;
    sl->n_want = 0;
    sl->ready = false;
    memset(&sl->out_lines, 0, sizeof sl->out_lines);
    memset(&sl->err_lines, 0, sizeof sl->err_lines);
}

static void slot_free(slot_t *sl)
{
    release_io(sl);
    drop_timer(sl->s, &sl->restart_timer);
    free_src(sl->cfg.src, sl->cfg.n_src);
    free(sl->ix);
    free(sl->want);
    free(sl);
}

static void slot_remove(firc_tunsup_t *s, slot_t *sl)
{
    for (size_t i = 0; i < s->n; i++) {
        if (s->v[i] == sl) {
            memmove(&s->v[i], &s->v[i + 1], (s->n - i - 1) * sizeof *s->v);
            s->n--;
            break;
        }
    }
    slot_free(sl);
}

static int exit_code(int status)
{
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return -1;
}

static void restart_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    slot_t *sl = ud;
    sl->restart_timer = 0;
    spawn(sl);
}

static void schedule_backoff(slot_t *sl)
{
    firc_tunsup_t *s = sl->s;
    if (sl->started_ms != 0 && now_ms() - sl->started_ms >= (int64_t)STABLE_S * s->second_ms) {
        sl->next_backoff_s = BACKOFF_BASE_S;
    }
    sl->st.backoff_s = sl->next_backoff_s;
    sl->next_backoff_s = sl->next_backoff_s * 2 > BACKOFF_CAP_S ? BACKOFF_CAP_S : sl->next_backoff_s * 2;
    drop_timer(s, &sl->restart_timer);
    if (firc_loop_add_timer(s->loop, (uint64_t)sl->st.backoff_s * (uint64_t)s->second_ms, 0, restart_cb, sl,
                            &sl->restart_timer) != FIRC_OK) {
        sl->restart_timer = 0;
        FIRC_WARN("tunnel %s: cannot schedule a restart", sl->cfg.device);
    }
    FIRC_WARN("tunnel %s: exited (%d), restart in %d s", sl->cfg.device, sl->st.last_exit, sl->st.backoff_s);
    set_status(sl, FIRC_TUN_ST_BACKOFF);
}

static void reaped(slot_t *sl, pid_t pid)
{
    if (sl->s->on_reap != NULL) {
        sl->s->on_reap(sl->cfg.id, pid, sl->s->reap_ud);
    }
}

static void exit_one(slot_t *sl, int code)
{
    firc_tunsup_t *s = sl->s;
    pid_t pid = sl->pid;
    release_io(sl);
    sl->pid = 0;
    sl->run_dev[0] = 0;
    sl->st.last_exit = code;
    sl->st.n_active = 0;
    reaped(sl, pid);
    if (sl->gone) {
        slot_remove(s, sl);
        return;
    }
    if (sl->terminating) {
        sl->terminating = false;
        if (sl->cfg.enable) {
            spawn(sl);
        } else {
            set_status(sl, FIRC_TUN_ST_OFF);
        }
        return;
    }
    if (code == 2) {
        FIRC_WARN("tunnel %s: configuration refused, not restarted", sl->cfg.device);
        set_status(sl, FIRC_TUN_ST_BAD_CONFIG);
        return;
    }
    schedule_backoff(sl);
}

static void handle_exit(slot_t *sl, int code)
{
    firc_tunsup_t *s = sl->s;
    exit_one(sl, code);
    for (size_t i = 0; i < s->n; i++) {
        slot_t *o = s->v[i];
        if (o->deferred && o->pid <= 0 && !o->gone && o->cfg.enable && !device_busy(o)) {
            spawn(o);
        }
    }
}

static void check_reap(slot_t *sl);

static void reap_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    slot_t *sl = ud;
    sl->reap_timer = 0;
    check_reap(sl);
}

static void check_reap(slot_t *sl)
{
    if (sl->out_fd >= 0 || sl->err_fd >= 0 || sl->pid <= 0 || sl->reap_timer != 0) {
        return;
    }
    int status = 0;
    pid_t r;
    do {
        r = waitpid(sl->pid, &status, WNOHANG);
    } while (r < 0 && errno == EINTR);
    if (r == sl->pid) {
        handle_exit(sl, exit_code(status));
    } else if (r < 0) {
        handle_exit(sl, -1);
    } else if (firc_loop_add_timer(sl->s->loop, REAP_RETRY_MS, 0, reap_cb, sl, &sl->reap_timer) != FIRC_OK) {
        sl->reap_timer = 0;
    }
}

static void warn_bad_once(slot_t *sl)
{
    if (!sl->warned_bad) {
        sl->warned_bad = true;
        FIRC_WARN("tunnel %s: unreadable event from tunvless ignored", sl->cfg.device);
    }
}

static uint64_t link_hash(const char *link)
{
    uint64_t h = 1469598103934665603ULL;
    for (const unsigned char *p = (const unsigned char *)link; *p != 0; p++) {
        h ^= *p;
        h *= 1099511628211ULL;
    }
    return h;
}

static bool index_add(slot_t *sl)
{
    for (size_t i = 0; i < sl->cfg.n_src; i++) {
        if (sl->cfg.src[i].kind != FIRC_TUN_SRC_LINK) {
            continue;
        }
        uint64_t h = link_hash(sl->cfg.src[i].link);
        bool known = false;
        for (size_t k = 0; k < sl->n_ix && !known; k++) {
            known = sl->ix[k] == h;
        }
        if (known) {
            continue;
        }
        if (sl->n_ix >= INDEX_MAX) {
            return false;
        }
        uint64_t *grown = realloc(sl->ix, (sl->n_ix + 1) * sizeof *grown);
        if (grown == NULL) {
            return false;
        }
        sl->ix = grown;
        sl->ix[sl->n_ix++] = h;
    }
    return true;
}

static size_t distinct_links(const slot_t *sl)
{
    size_t n = 0;
    for (size_t i = 0; i < sl->cfg.n_src; i++) {
        if (sl->cfg.src[i].kind != FIRC_TUN_SRC_LINK) {
            continue;
        }
        bool seen = false;
        for (size_t k = 0; k < i && !seen; k++) {
            seen = sl->cfg.src[k].kind == FIRC_TUN_SRC_LINK && strcmp(sl->cfg.src[k].link, sl->cfg.src[i].link) == 0;
        }
        n += seen ? 0 : 1;
    }
    return n;
}

static void took(slot_t *sl, int count)
{
    if (sl->n_want == 0) {
        return;
    }
    size_t want = sl->want[0];
    memmove(&sl->want[0], &sl->want[1], (sl->n_want - 1) * sizeof *sl->want);
    sl->n_want--;
    if ((size_t)count != want && !sl->drift) {
        sl->drift = true;
        FIRC_WARN("tunnel %s: tunvless took %d of %zu nodes, node states go by name until it restarts", sl->cfg.device,
                  count, want);
    }
}

static int pos_of(const slot_t *sl, int index)
{
    if (sl->drift || index < 0 || (size_t)index >= sl->n_ix) {
        return -1;
    }
    for (size_t i = 0; i < sl->cfg.n_src; i++) {
        if (sl->cfg.src[i].kind == FIRC_TUN_SRC_LINK && link_hash(sl->cfg.src[i].link) == sl->ix[index]) {
            return (int)i;
        }
    }
    return -1;
}

static void restart_child(slot_t *sl);

static void ack_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    slot_t *sl = ud;
    sl->ack_timer = 0;
    FIRC_WARN("tunnel %s: tunvless did not take the node list in %d s, restarting", sl->cfg.device, ACK_S);
    restart_child(sl);
}

static void arm_ack(slot_t *sl)
{
    if (sl->ack_timer != 0 || sl->acks == 0 || !sl->ready || sl->terminating) {
        return;
    }
    if (firc_loop_add_timer(sl->s->loop, (uint64_t)ACK_S * (uint64_t)sl->s->second_ms, 0, ack_cb, sl,
                            &sl->ack_timer) != FIRC_OK) {
        sl->ack_timer = 0;
    }
}

static void on_out_line(const char *line, size_t len, void *ud)
{
    slot_t *sl = ud;
    firc_tev_t ev;
    firc_tun_event_parse(line, len, &ev);
    switch (ev.kind) {
    case FIRC_TEV_READY:
        if (ev.dev[0] == 0) {
            warn_bad_once(sl);
            return;
        }
        sl->ready = true;
        arm_ack(sl);
        break;
    case FIRC_TEV_NODES:
        if (sl->acks > 0) {
            sl->acks--;
        }
        took(sl, ev.count);
        drop_timer(sl->s, &sl->ack_timer);
        arm_ack(sl);
        break;
    case FIRC_TEV_PINS_FULL:
        if (!sl->terminating) {
            FIRC_WARN("tunnel %s: pin table full, restarting", sl->cfg.device);
            restart_child(sl);
        }
        return;
    case FIRC_TEV_ACTIVE:
        for (size_t i = 0; i < ev.n_active && i < 8; i++) {
            ev.active_pos[i] = pos_of(sl, ev.active_index[i]);
        }
        memcpy(sl->st.active, ev.active, sizeof sl->st.active);
        sl->st.n_active = ev.n_active;
        put_status(sl, ev.n_active > 0 ? FIRC_TUN_ST_UP : FIRC_TUN_ST_NO_NODE);
        break;
    case FIRC_TEV_NO_NODE:
        sl->st.n_active = 0;
        put_status(sl, FIRC_TUN_ST_NO_NODE);
        break;
    case FIRC_TEV_NODE_DOWN:
    case FIRC_TEV_NODE_UP:
        if (ev.node[0] == 0) {
            warn_bad_once(sl);
            return;
        }
        ev.pos = pos_of(sl, ev.index);
        break;
    case FIRC_TEV_BAD:
    default:
        warn_bad_once(sl);
        return;
    }
    notify(sl, &ev);
}

static void on_err_line(const char *line, size_t len, void *ud)
{
    slot_t *sl = ud;
    size_t wl = sizeof WARN_TAG - 1;
    bool warn = len > wl && memcmp(line, WARN_TAG, wl) == 0 && (line[wl] == ':' || line[wl] == ' ');
    firc_log_level_t level = warn ? FIRC_LOG_WARN : FIRC_LOG_INFO;
    firc_log(level, "tunnel %s: %.*s", sl->cfg.device, (int)len, line);
}

static void drain(slot_t *sl, int *fd, firc_tun_lines_t *lines, firc_tun_line_fn fn, bool *warned,
                  const char *what)
{
    char buf[4096];
    for (;;) {
        ssize_t n = read(*fd, buf, sizeof buf);
        if (n > 0) {
            if (firc_tun_lines_feed(lines, buf, (size_t)n, fn, sl) > 0 && !*warned) {
                *warned = true;
                FIRC_WARN("tunnel %s: oversize %s line from tunvless dropped", sl->cfg.device, what);
            }
            if (*fd < 0) {
                return;
            }
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && errno == EAGAIN) {
            return;
        }
        drop_fd(sl->s, fd);
        check_reap(sl);
        return;
    }
}

static void out_cb(firc_loop_t *loop, int fd, uint32_t events, void *ud)
{
    (void)loop;
    (void)fd;
    (void)events;
    slot_t *sl = ud;
    drain(sl, &sl->out_fd, &sl->out_lines, on_out_line, &sl->warned_drop_out, "stdout");
}

static void err_cb(firc_loop_t *loop, int fd, uint32_t events, void *ud)
{
    (void)loop;
    (void)fd;
    (void)events;
    slot_t *sl = ud;
    drain(sl, &sl->err_fd, &sl->err_lines, on_err_line, &sl->warned_drop_err, "stderr");
}

static void in_cb(firc_loop_t *loop, int fd, uint32_t events, void *ud)
{
    slot_t *sl = ud;
    if (sl->in_off >= sl->in_len && (events & (EPOLLERR | EPOLLHUP)) != 0) {
        close_in(sl);
        return;
    }
    while (sl->in_off < sl->in_len) {
        ssize_t n = write(fd, sl->in_buf + sl->in_off, sl->in_len - sl->in_off);
        if (n > 0) {
            sl->in_off += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && errno == EAGAIN) {
            return;
        }
        FIRC_WARN("tunnel %s: node list not delivered: %s", sl->cfg.device, strerror(errno));
        close_in(sl);
        if (sl->pid > 0) {
            kill(sl->pid, SIGTERM);
        }
        return;
    }
    free(sl->in_buf);
    sl->in_buf = NULL;
    sl->in_len = 0;
    sl->in_off = 0;
    if (firc_loop_mod_fd(loop, fd, 0) != FIRC_OK) {
        close_in(sl);
    }
}

static char *node_list(const firc_tunnel_t *t, size_t *len);

static bool queue_nodes(slot_t *sl)
{
    if (sl->in_fd < 0 || !index_add(sl)) {
        return false;
    }
    static const char cmd[] = "nodes\n";
    size_t ln = 0;
    char *list = node_list(&sl->cfg, &ln);
    size_t pend = sl->in_len - sl->in_off;
    char *buf = list == NULL ? NULL : malloc(pend + sizeof cmd - 1 + ln);
    if (buf == NULL) {
        free(list);
        return false;
    }
    if (pend > 0) {
        memcpy(buf, sl->in_buf + sl->in_off, pend);
    }
    memcpy(buf + pend, cmd, sizeof cmd - 1);
    memcpy(buf + pend + sizeof cmd - 1, list, ln);
    free(list);
    free(sl->in_buf);
    sl->in_buf = buf;
    sl->in_len = pend + sizeof cmd - 1 + ln;
    sl->in_off = 0;
    size_t *grown = realloc(sl->want, (sl->n_want + 1) * sizeof *grown);
    if (grown == NULL || firc_loop_mod_fd(sl->s->loop, sl->in_fd, EPOLLOUT) != FIRC_OK) {
        if (grown != NULL) {
            sl->want = grown;
        }
        return false;
    }
    sl->want = grown;
    sl->want[sl->n_want++] = distinct_links(sl);
    sl->acks++;
    arm_ack(sl);
    return true;
}

static char *node_list(const firc_tunnel_t *t, size_t *len)
{
    size_t n = 1;
    for (size_t i = 0; i < t->n_src; i++) {
        if (t->src[i].kind == FIRC_TUN_SRC_LINK) {
            n += strlen(t->src[i].link) + 1;
        }
    }
    char *buf = malloc(n);
    if (buf == NULL) {
        return NULL;
    }
    size_t off = 0;
    for (size_t i = 0; i < t->n_src; i++) {
        if (t->src[i].kind != FIRC_TUN_SRC_LINK) {
            continue;
        }
        size_t l = strlen(t->src[i].link);
        memcpy(buf + off, t->src[i].link, l);
        off += l;
        buf[off++] = '\n';
    }
    buf[off++] = '\n';
    *len = off;
    return buf;
}

static int device_index(const char *device)
{
    if (strncmp(device, "tunvless", 8) != 0) {
        return -1;
    }
    const char *p = device + 8;
    if (*p < '0' || *p > '9' || (p[0] == '0' && p[1] != 0)) {
        return -1;
    }
    int n = 0;
    for (; *p != 0; p++) {
        if (*p < '0' || *p > '9' || n > 25) {
            return -1;
        }
        n = n * 10 + (*p - '0');
    }
    return n <= 253 ? n : -1;
}

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void close_pair(int p[2])
{
    if (p[0] >= 0) {
        close(p[0]);
    }
    if (p[1] >= 0) {
        close(p[1]);
    }
}

static int start_child(firc_tunsup_t *s, const char *const argv[], pid_t *pid, int *in_fd, int *out_fd,
                       int *err_fd)
{
    int in[2] = {-1, -1};
    int out[2] = {-1, -1};
    int err[2] = {-1, -1};
    if (pipe2(in, O_CLOEXEC) != 0 || pipe2(out, O_CLOEXEC) != 0 || pipe2(err, O_CLOEXEC) != 0) {
        int e = errno;
        close_pair(in);
        close_pair(out);
        close_pair(err);
        return e;
    }
    int rc = 0;
    if (set_nonblock(in[1]) != 0 || set_nonblock(out[0]) != 0 || set_nonblock(err[0]) != 0) {
        rc = errno;
    }
    posix_spawn_file_actions_t fa;
    posix_spawnattr_t attr;
    bool fa_ok = false;
    bool attr_ok = false;
    if (rc == 0) {
        rc = posix_spawn_file_actions_init(&fa);
        fa_ok = rc == 0;
    }
    if (rc == 0) {
        rc = posix_spawn_file_actions_adddup2(&fa, in[0], STDIN_FILENO);
    }
    if (rc == 0) {
        rc = posix_spawn_file_actions_adddup2(&fa, out[1], STDOUT_FILENO);
    }
    if (rc == 0) {
        rc = posix_spawn_file_actions_adddup2(&fa, err[1], STDERR_FILENO);
    }
    if (rc == 0) {
        rc = posix_spawnattr_init(&attr);
        attr_ok = rc == 0;
    }
    sigset_t all;
    sigset_t none;
    sigfillset(&all);
    sigemptyset(&none);
    if (rc == 0) {
        rc = posix_spawnattr_setsigdefault(&attr, &all);
    }
    if (rc == 0) {
        rc = posix_spawnattr_setsigmask(&attr, &none);
    }
    if (rc == 0) {
        rc = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    }
    if (rc == 0) {
        rc = posix_spawnp(pid, s->binary, &fa, &attr, (char *const *)argv, environ);
    }
    if (attr_ok) {
        posix_spawnattr_destroy(&attr);
    }
    if (fa_ok) {
        posix_spawn_file_actions_destroy(&fa);
    }
    close(in[0]);
    close(out[1]);
    close(err[1]);
    if (rc != 0) {
        close(in[1]);
        close(out[0]);
        close(err[0]);
        return rc;
    }
    *in_fd = in[1];
    *out_fd = out[0];
    *err_fd = err[0];
    return 0;
}

static bool device_busy(const slot_t *sl)
{
    const firc_tunsup_t *s = sl->s;
    for (size_t i = 0; i < s->n; i++) {
        const slot_t *o = s->v[i];
        if (o != sl && o->pid > 0 && strcmp(o->run_dev, sl->cfg.device) == 0) {
            return true;
        }
    }
    return false;
}

static void spawn(slot_t *sl)
{
    firc_tunsup_t *s = sl->s;
    const firc_tunnel_t *t = &sl->cfg;
    sl->deferred = device_busy(sl);
    if (sl->deferred) {
        FIRC_INFO("tunnel %s: waiting for the previous holder of the device to exit", t->device);
        sl->st.n_active = 0;
        set_status(sl, FIRC_TUN_ST_STARTING);
        return;
    }
    char addr[32];
    char active[16];
    char interval[16];
    char silence[16];
    char timeout[16];
    char mark[16];
    snprintf(addr, sizeof addr, "198.51.100.%d/32", 1 + device_index(t->device));
    snprintf(active, sizeof active, "%d", t->active);
    snprintf(interval, sizeof interval, "%d", t->interval_s);
    snprintf(silence, sizeof silence, "%d", t->silence_s);
    snprintf(timeout, sizeof timeout, "%d", t->timeout_s);
    snprintf(mark, sizeof mark, "0x%x", (unsigned)sl->mark);
    const char *argv[24];
    size_t a = 0;
    argv[a++] = s->binary;
    argv[a++] = "--control";
    argv[a++] = "-d";
    argv[a++] = t->device;
    argv[a++] = "-a";
    argv[a++] = addr;
    argv[a++] = "-A";
    argv[a++] = active;
    argv[a++] = "--by";
    argv[a++] = t->by;
    argv[a++] = "--interval";
    argv[a++] = interval;
    argv[a++] = "--silence";
    argv[a++] = silence;
    argv[a++] = "-t";
    argv[a++] = timeout;
    if (sl->mark != 0) {
        argv[a++] = "-m";
        argv[a++] = mark;
    }
    if (t->insecure) {
        argv[a++] = "--insecure";
    }
    if (t->ca[0] != 0) {
        argv[a++] = "--ca";
        argv[a++] = t->ca;
    }
    argv[a] = NULL;

    sl->st.n_active = 0;
    sl->warned_bad = false;
    sl->warned_drop_out = false;
    sl->warned_drop_err = false;
    sl->started_ms = 0;
    sl->n_ix = 0;
    sl->drift = false;
    (void)index_add(sl);
    sl->in_buf = node_list(t, &sl->in_len);
    sl->in_off = 0;
    int rc = sl->in_buf == NULL ? ENOMEM : start_child(s, argv, &sl->pid, &sl->in_fd, &sl->out_fd, &sl->err_fd);
    if (rc != 0) {
        free(sl->in_buf);
        sl->in_buf = NULL;
        sl->pid = 0;
        FIRC_WARN("tunnel %s: cannot start %s: %s", t->device, s->binary, strerror(rc));
        sl->st.last_exit = -1;
        schedule_backoff(sl);
        return;
    }
    sl->started_ms = now_ms();
    snprintf(sl->run_dev, sizeof sl->run_dev, "%s", t->device);
    sl->run_mark = sl->mark;
    if (firc_loop_add_fd(s->loop, sl->out_fd, EPOLLIN, out_cb, sl) != FIRC_OK ||
        firc_loop_add_fd(s->loop, sl->err_fd, EPOLLIN, err_cb, sl) != FIRC_OK ||
        firc_loop_add_fd(s->loop, sl->in_fd, EPOLLOUT, in_cb, sl) != FIRC_OK) {
        FIRC_WARN("tunnel %s: cannot watch the child", t->device);
        kill(sl->pid, SIGKILL);
        int status = 0;
        while (waitpid(sl->pid, &status, 0) < 0 && errno == EINTR) {
        }
        release_io(sl);
        sl->pid = 0;
        sl->st.last_exit = -1;
        schedule_backoff(sl);
        return;
    }
    set_status(sl, FIRC_TUN_ST_STARTING);
}

static void terminate(slot_t *sl);

static void kill_cb(firc_loop_t *loop, void *ud)
{
    (void)loop;
    slot_t *sl = ud;
    sl->kill_timer = 0;
    if (sl->pid > 0) {
        kill(sl->pid, SIGKILL);
    }
}

static void terminate(slot_t *sl)
{
    kill(sl->pid, SIGTERM);
    drop_timer(sl->s, &sl->ack_timer);
    if (sl->terminating && sl->kill_timer != 0) {
        return;
    }
    sl->terminating = true;
    drop_timer(sl->s, &sl->kill_timer);
    if (firc_loop_add_timer(sl->s->loop, (uint64_t)TERM_GRACE_S * (uint64_t)sl->s->second_ms, 0, kill_cb, sl, &sl->kill_timer) != FIRC_OK) {
        sl->kill_timer = 0;
    }
}

static slot_t *find_slot(const firc_tunsup_t *s, const char *id)
{
    for (size_t i = 0; i < s->n; i++) {
        if (!s->v[i]->gone && strcmp(s->v[i]->cfg.id, id) == 0) {
            return s->v[i];
        }
    }
    return NULL;
}

static slot_t *slot_new(firc_tunsup_t *s, const firc_tunnel_t *t, uint32_t mark)
{
    slot_t *sl = calloc(1, sizeof *sl);
    if (sl == NULL) {
        return NULL;
    }
    if (copy_cfg(&sl->cfg, t) != FIRC_OK) {
        free(sl);
        return NULL;
    }
    sl->s = s;
    sl->mark = mark;
    sl->in_fd = -1;
    sl->out_fd = -1;
    sl->err_fd = -1;
    sl->next_backoff_s = BACKOFF_BASE_S;
    snprintf(sl->st.id, sizeof sl->st.id, "%s", t->id);
    snprintf(sl->st.device, sizeof sl->st.device, "%s", t->device);
    sl->st.status = FIRC_TUN_ST_OFF;
    sl->st.since_ms = now_ms();
    sl->st.uplink_ok = true;
    return sl;
}

static size_t *start_order(const firc_tunnels_t *want)
{
    size_t n = want->n;
    size_t *order = calloc(n + 1, sizeof *order);
    bool *placed = calloc(n + 1, sizeof *placed);
    if (order == NULL || placed == NULL) {
        free(order);
        free(placed);
        return NULL;
    }
    size_t k = 0;
    while (k < n) {
        bool progress = false;
        for (size_t i = 0; i < n; i++) {
            if (placed[i]) {
                continue;
            }
            const firc_tunnel_t *t = &want->t[i];
            bool ready = true;
            if (t->uplink == FIRC_UPLINK_TUNNEL) {
                for (size_t j = 0; j < n; j++) {
                    if (j != i && !placed[j] && strcmp(want->t[j].id, t->uplink_ref) == 0) {
                        ready = false;
                    }
                }
            }
            if (ready) {
                placed[i] = true;
                order[k++] = i;
                progress = true;
            }
        }
        if (!progress) {
            for (size_t i = 0; i < n; i++) {
                if (!placed[i]) {
                    placed[i] = true;
                    order[k++] = i;
                }
            }
        }
    }
    free(placed);
    return order;
}

static void retire(firc_tunsup_t *s, slot_t *sl)
{
    if (sl->pid > 0) {
        sl->gone = true;
        drop_timer(s, &sl->restart_timer);
        terminate(sl);
        return;
    }
    slot_remove(s, sl);
}

static void reconfigure(slot_t *sl, const firc_tunnel_t *t, uint32_t mark)
{
    if (copy_cfg(&sl->cfg, t) != FIRC_OK) {
        FIRC_WARN("tunnel %s: out of memory, left as it was", t->device);
        return;
    }
    sl->mark = mark;
    snprintf(sl->st.device, sizeof sl->st.device, "%s", t->device);
    sl->next_backoff_s = BACKOFF_BASE_S;
    sl->deferred = false;
    drop_timer(sl->s, &sl->restart_timer);
    if (sl->pid > 0) {
        terminate(sl);
    } else if (t->enable) {
        spawn(sl);
    } else {
        set_status(sl, FIRC_TUN_ST_OFF);
    }
}

static void restart_child(slot_t *sl)
{
    firc_tunsup_t *s = sl->s;
    sl->start_seq = ++s->seq;
    sl->next_backoff_s = BACKOFF_BASE_S;
    drop_timer(s, &sl->restart_timer);
    if (sl->pid > 0) {
        terminate(sl);
    } else if (!sl->deferred) {
        spawn(sl);
    }
}

static void update_nodes(slot_t *sl, const firc_tunnel_t *t, uint32_t mark)
{
    if (sl->pid <= 0 || sl->terminating) {
        if (sl->pid <= 0 && t->enable) {
            sl->start_seq = ++sl->s->seq;
        }
        reconfigure(sl, t, mark);
        return;
    }
    if (copy_cfg(&sl->cfg, t) != FIRC_OK) {
        FIRC_WARN("tunnel %s: out of memory, left as it was", t->device);
        return;
    }
    if (queue_nodes(sl)) {
        sl->update_seq = ++sl->s->seq;
        return;
    }
    FIRC_WARN("tunnel %s: the new node list cannot be sent, restarting", t->device);
    restart_child(sl);
}

static bool listed(slot_t *const *v, size_t n, const slot_t *sl)
{
    for (size_t i = 0; i < n; i++) {
        if (v[i] == sl) {
            return true;
        }
    }
    return false;
}

static void sort_like(firc_tunsup_t *s, const firc_tunnels_t *want)
{
    slot_t **v = calloc(s->n + 1, sizeof *v);
    if (v == NULL) {
        return;
    }
    size_t n = 0;
    for (size_t i = 0; i < want->n && n < s->n; i++) {
        slot_t *sl = find_slot(s, want->t[i].id);
        if (sl != NULL && !listed(v, n, sl)) {
            v[n++] = sl;
        }
    }
    for (size_t i = 0; i < s->n && n < s->n; i++) {
        if (!listed(v, n, s->v[i])) {
            v[n++] = s->v[i];
        }
    }
    memcpy(s->v, v, n * sizeof *v);
    free(v);
}

firc_err_t firc_tunsup_apply(firc_tunsup_t *s, const firc_tunnels_t *want, const uint32_t *marks)
{
    assert(pthread_equal(s->loop_thread, pthread_self()));
    if (!pthread_equal(s->loop_thread, pthread_self()) || s->stopped) {
        return FIRC_ERR_STATE;
    }
    for (size_t i = 0; i < want->n; i++) {
        if (device_index(want->t[i].device) < 0) {
            return FIRC_ERR_INVAL;
        }
    }
    size_t *order = start_order(want);
    if (order == NULL) {
        return FIRC_ERR_NOMEM;
    }
    for (size_t i = 0; i < s->n;) {
        slot_t *sl = s->v[i];
        bool wanted = false;
        for (size_t j = 0; j < want->n && !sl->gone; j++) {
            wanted = wanted || strcmp(want->t[j].id, sl->cfg.id) == 0;
        }
        if (sl->gone || wanted) {
            i++;
            continue;
        }
        size_t before = s->n;
        retire(s, sl);
        if (s->n == before) {
            i++;
        }
    }
    slot_t **grown = realloc(s->v, (s->n + want->n + 1) * sizeof *grown);
    if (grown == NULL) {
        free(order);
        return FIRC_ERR_NOMEM;
    }
    s->v = grown;
    firc_err_t rc = FIRC_OK;
    for (size_t k = 0; k < want->n; k++) {
        size_t i = order[k];
        const firc_tunnel_t *t = &want->t[i];
        uint32_t mark = marks != NULL ? marks[i] : 0;
        slot_t *sl = find_slot(s, t->id);
        if (sl == NULL) {
            sl = slot_new(s, t, mark);
            if (sl == NULL) {
                rc = FIRC_ERR_NOMEM;
                continue;
            }
            s->v[s->n++] = sl;
            if (t->enable) {
                sl->start_seq = ++s->seq;
                spawn(sl);
            } else {
                notify(sl, NULL);
            }
        } else if (!firc_tunnel_same_argv(&sl->cfg, t) || sl->mark != mark) {
            if (t->enable) {
                sl->start_seq = ++s->seq;
            }
            reconfigure(sl, t, mark);
        } else if (!firc_tunnel_same_nodes(&sl->cfg, t)) {
            update_nodes(sl, t, mark);
        }
    }
    free(order);
    sort_like(s, want);
    return rc;
}

firc_tunsup_t *firc_tunsup_new(firc_loop_t *loop, const char *binary, firc_tun_event_fn on_event, void *ud)
{
    firc_tunsup_t *s = calloc(1, sizeof *s);
    if (s == NULL) {
        return NULL;
    }
    s->binary = strdup(binary);
    if (s->binary == NULL) {
        free(s);
        return NULL;
    }
    s->loop = loop;
    s->on_event = on_event;
    s->ud = ud;
    s->loop_thread = pthread_self();
    s->second_ms = 1000;
    return s;
}

size_t firc_tunsup_states(const firc_tunsup_t *s, firc_tun_state_t *out, size_t cap)
{
    size_t n = 0;
    for (size_t i = 0; i < s->n; i++) {
        if (s->v[i]->gone) {
            continue;
        }
        if (n < cap) {
            out[n] = s->v[i]->st;
        }
        n++;
    }
    return n;
}

static bool reap_now(slot_t *sl)
{
    int status = 0;
    pid_t r;
    do {
        r = waitpid(sl->pid, &status, WNOHANG);
    } while (r < 0 && errno == EINTR);
    if (r == 0) {
        return false;
    }
    sl->st.last_exit = r == sl->pid ? exit_code(status) : -1;
    sl->pid = 0;
    return true;
}

void firc_tunsup_stop(firc_tunsup_t *s, int grace_ms)
{
    assert(pthread_equal(s->loop_thread, pthread_self()));
    for (size_t i = 0; i < s->n; i++) {
        slot_t *sl = s->v[i];
        release_io(sl);
        drop_timer(s, &sl->restart_timer);
        sl->stop_pid = sl->pid;
        if (sl->pid > 0) {
            kill(sl->pid, SIGTERM);
        }
    }
    int64_t t0 = now_ms();
    for (;;) {
        size_t left = 0;
        for (size_t i = 0; i < s->n; i++) {
            if (s->v[i]->pid > 0 && !reap_now(s->v[i])) {
                left++;
            }
        }
        if (left == 0 || now_ms() - t0 >= grace_ms) {
            break;
        }
        struct timespec ts = {0, STOP_POLL_MS * 1000000L};
        nanosleep(&ts, NULL);
    }
    for (size_t i = 0; i < s->n; i++) {
        slot_t *sl = s->v[i];
        if (sl->pid > 0) {
            kill(sl->pid, SIGKILL);
            int status = 0;
            pid_t r;
            do {
                r = waitpid(sl->pid, &status, 0);
            } while (r < 0 && errno == EINTR);
            sl->st.last_exit = r == sl->pid ? exit_code(status) : -1;
            sl->pid = 0;
        }
        sl->terminating = false;
        sl->deferred = false;
        sl->run_dev[0] = 0;
        sl->st.n_active = 0;
        put_status(sl, FIRC_TUN_ST_OFF);
        notify(sl, NULL);
        if (sl->stop_pid > 0) {
            pid_t pid = sl->stop_pid;
            sl->stop_pid = 0;
            reaped(sl, pid);
        }
    }
    for (size_t i = 0; i < s->n;) {
        if (s->v[i]->gone) {
            slot_remove(s, s->v[i]);
        } else {
            i++;
        }
    }
    s->stopped = true;
}

void firc_tunsup_free(firc_tunsup_t *s)
{
    if (s == NULL) {
        return;
    }
    firc_tunsup_stop(s, 0);
    for (size_t i = 0; i < s->n; i++) {
        slot_free(s->v[i]);
    }
    free(s->v);
    free(s->binary);
    free(s);
}

void firc_tunsup_set_on_reap(firc_tunsup_t *s, firc_tun_reap_fn fn, void *ud)
{
    s->on_reap = fn;
    s->reap_ud = ud;
}

void firc_tunsup_set_uplink_ok(firc_tunsup_t *s, const char *id, bool ok)
{
    slot_t *sl = find_slot(s, id);
    if (sl != NULL) {
        sl->st.uplink_ok = ok;
    }
}

bool firc_tunsup_holds(const firc_tunsup_t *s, const char *id, uint32_t mark)
{
    for (size_t i = 0; i < s->n; i++) {
        const slot_t *sl = s->v[i];
        if (sl->pid > 0 && sl->run_mark == mark && strcmp(sl->cfg.id, id) == 0) {
            return true;
        }
    }
    return false;
}

void firc_tunsup_set_second_ms_for_test(firc_tunsup_t *s, int ms)
{
    s->second_ms = ms;
}

firc_err_t firc_tunsup_restart(firc_tunsup_t *s, const char *id)
{
    slot_t *sl = find_slot(s, id);
    if (sl == NULL) {
        return FIRC_ERR_NOENT;
    }
    if (!sl->cfg.enable || s->stopped) {
        return FIRC_ERR_STATE;
    }
    restart_child(sl);
    return FIRC_OK;
}

uint64_t firc_tunsup_start_seq(const firc_tunsup_t *s)
{
    return s->seq;
}

uint64_t firc_tunsup_started(const firc_tunsup_t *s, const char *id)
{
    const slot_t *sl = find_slot(s, id);
    return sl != NULL ? sl->start_seq : 0;
}

uint64_t firc_tunsup_updated(const firc_tunsup_t *s, const char *id)
{
    const slot_t *sl = find_slot(s, id);
    return sl != NULL ? sl->update_seq : 0;
}
