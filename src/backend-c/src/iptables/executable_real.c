#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */

#include "firc/iptables.h"
#include "firc/bytebuf.h"
#include "firc/log.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <time.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#define FIRC_IPT_STDERR_CAP ((size_t)256 * 1024)

typedef struct exe_real {
    firc_ipt_executable_t base;
    firc_ipt_proto_t proto;
    const char *save_cmd;
    const char *restore_cmd;
    firc_cancel_t *cancel;
} exe_real_t;

/* The table moved under us: FIRC_ERR_AGAIN, rebuild from scratch. */
static const char *const k_retryable_messages[] = {
    "No chain/target/match by that name",
    "No such file or directory",
    "Chain already exists",
    "does a rule with that number exist",
    "Resource temporarily unavailable",
    "Device or resource busy",
    "holding the xtables lock",
    "doesn't exist",
    "does not exist",
};

/* Checked first: their text ends in the retryable "No such file or directory". */
static const char *const k_permanent_messages[] = {
    "Couldn't load match",
    "Couldn't load target",
};

bool firc_ipt_stderr_is_retryable(const char *stderr_text, size_t len) {
    if (len == 0 || stderr_text == NULL) { return false; }

    /* Not NUL-terminated: search a bounded copy. */
    char scratch[4096];
    size_t n = len < sizeof(scratch) - 1 ? len : sizeof(scratch) - 1;
    memcpy(scratch, stderr_text, n);
    scratch[n] = '\0';

    for (size_t i = 0; i < sizeof(k_permanent_messages) / sizeof(k_permanent_messages[0]); i++) {
        if (strstr(scratch, k_permanent_messages[i]) != NULL) { return false; }
    }
    for (size_t i = 0; i < sizeof(k_retryable_messages) / sizeof(k_retryable_messages[0]); i++) {
        if (strstr(scratch, k_retryable_messages[i]) != NULL) { return true; }
    }
    return false;
}

static bool stderr_is_retryable(const firc_bytebuf_t *err_buf) {
    return firc_ipt_stderr_is_retryable((const char *)err_buf->data, err_buf->len);
}

static void kill_child(pid_t pid) {
    kill(pid, SIGKILL);
    int status;
    pid_t w;
    do {
        w = waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);
}

static firc_err_t set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) { return firc_err_from_errno(errno); }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { return firc_err_from_errno(errno); }
    return FIRC_OK;
}

static void close_if_valid(int fd) {
    if (fd >= 0) { close(fd); }
}

static firc_err_t spawn_with_pipes(const char *const argv[], bool need_stdin_pipe, pid_t *pid_out,
                                 int *stdin_wr, int *stdout_rd, int *stderr_rd) {
    int in_pipe[2] = {-1, -1};
    int out_pipe[2] = {-1, -1};
    int err_pipe[2] = {-1, -1};

    /* Set before any early return. */
    *pid_out = -1;
    *stdin_wr = -1;
    *stdout_rd = -1;
    *stderr_rd = -1;

    if (need_stdin_pipe && pipe2(in_pipe, O_CLOEXEC) != 0) { return firc_err_from_errno(errno); }
    if (pipe2(out_pipe, O_CLOEXEC) != 0) {
        close_if_valid(in_pipe[0]);
        close_if_valid(in_pipe[1]);
        return firc_err_from_errno(errno);
    }
    if (pipe2(err_pipe, O_CLOEXEC) != 0) {
        close_if_valid(in_pipe[0]);
        close_if_valid(in_pipe[1]);
        close(out_pipe[0]);
        close(out_pipe[1]);
        return firc_err_from_errno(errno);
    }

    posix_spawn_file_actions_t fa;
    int aerr = posix_spawn_file_actions_init(&fa);
    bool fa_ok = aerr == 0;

    /* one errno at a time: two OR-ed together name a third */
#define FA(call) do { if (aerr == 0) { aerr = (call); } } while (0)
    if (need_stdin_pipe) {
        FA(posix_spawn_file_actions_adddup2(&fa, in_pipe[0], STDIN_FILENO));
        FA(posix_spawn_file_actions_addclose(&fa, in_pipe[0]));
        FA(posix_spawn_file_actions_addclose(&fa, in_pipe[1]));
    } else {
        FA(posix_spawn_file_actions_addopen(&fa, STDIN_FILENO, "/dev/null", O_RDONLY, 0));
    }
    FA(posix_spawn_file_actions_adddup2(&fa, out_pipe[1], STDOUT_FILENO));
    FA(posix_spawn_file_actions_addclose(&fa, out_pipe[0]));
    FA(posix_spawn_file_actions_addclose(&fa, out_pipe[1]));
    FA(posix_spawn_file_actions_adddup2(&fa, err_pipe[1], STDERR_FILENO));
    FA(posix_spawn_file_actions_addclose(&fa, err_pipe[0]));
    FA(posix_spawn_file_actions_addclose(&fa, err_pipe[1]));
#undef FA

    /* Default signal dispositions and mask: the daemon ignores SIGPIPE and the loop blocks signals. */
    posix_spawnattr_t attr;
    sigset_t all, none;
    sigfillset(&all);
    sigemptyset(&none);
    bool attr_ok = posix_spawnattr_init(&attr) == 0;
    int perr = attr_ok ? 0 : ENOMEM;
    if (attr_ok) { perr = posix_spawnattr_setsigdefault(&attr, &all); }
    if (attr_ok && perr == 0) { perr = posix_spawnattr_setsigmask(&attr, &none); }
    if (attr_ok && perr == 0) { perr = posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK); }
    pid_t pid = -1;
    int rc = aerr != 0 ? aerr : perr;
    if (rc == 0) {
        rc = posix_spawnp(&pid, argv[0], &fa, &attr, (char *const *)argv, environ);
    }
    if (attr_ok) { posix_spawnattr_destroy(&attr); }
    if (fa_ok) { posix_spawn_file_actions_destroy(&fa); }

    if (need_stdin_pipe) { close(in_pipe[0]); }
    close(out_pipe[1]);
    close(err_pipe[1]);

    if (rc != 0) {
        close_if_valid(in_pipe[1]);
        close(out_pipe[0]);
        close(err_pipe[0]);
        return firc_err_from_errno(rc);
    }

    *pid_out = pid;
    *stdin_wr = need_stdin_pipe ? in_pipe[1] : -1;
    *stdout_rd = out_pipe[0];
    *stderr_rd = err_pipe[0];
    return FIRC_OK;
}

const char *firc_ipt_offending_line(const uint8_t *data, size_t len, const char *stderr_text,
                                    size_t stderr_len, size_t *out_len)
{
    if (data == NULL || len == 0 || stderr_text == NULL || stderr_len == 0) { return NULL; }

    /* 1.4.21 prints "line N failed" bare; newer versions prefix a banner. */
    unsigned long want = 0;
    bool found = false;
    for (size_t i = 0; i + 5 <= stderr_len && !found; i++) {
        if (memcmp(stderr_text + i, "line ", 5) != 0) { continue; }
        size_t j = i + 5;
        unsigned long n = 0;
        size_t digits = 0;
        while (j < stderr_len && stderr_text[j] >= '0' && stderr_text[j] <= '9') {
            n = n * 10 + (unsigned long)(stderr_text[j] - '0');
            j++;
            digits++;
            if (digits > 9) { return NULL; }
        }
        if (digits == 0) { continue; }
        if (j + 7 <= stderr_len && memcmp(stderr_text + j, " failed", 7) == 0) {
            want = n;
            found = true;
        }
    }
    if (!found || want == 0) { return NULL; }

    const char *p = (const char *)data;
    const char *end = p + len;
    for (unsigned long at = 1; p < end; at++) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t line_len = nl != NULL ? (size_t)(nl - p) : (size_t)(end - p);
        if (at == want) {
            if (out_len != NULL) { *out_len = line_len; }
            return p;
        }
        if (nl == NULL) { break; }
        p = nl + 1;
    }
    return NULL;
}

/* A refusal at COMMIT is DEBUG: a lost race with the firmware looks the same; the committer says ERR if it persists. */
static firc_err_t wait_child(pid_t pid, const char *cmd, firc_bytebuf_t *err_buf,
                             const uint8_t *sent, size_t sent_len) {
    int status = 0;
    pid_t w;
    do {
        w = waitpid(pid, &status, 0);
    } while (w < 0 && errno == EINTR);

    if (w < 0) { return firc_err_from_errno(errno); }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        if (stderr_is_retryable(err_buf)) {
            FIRC_DEBUG("%s lost a race with another writer (status=%d): %.*s", cmd, status,
                     (int)err_buf->len, (const char *)err_buf->data);
            return FIRC_ERR_AGAIN;
        }
        size_t line_len = 0;
        const char *line = firc_ipt_offending_line(sent, sent_len, (const char *)err_buf->data,
                                                   err_buf->len, &line_len);
        if (line != NULL && line_len == 6 && memcmp(line, "COMMIT", 6) == 0) {
            FIRC_DEBUG("%s failed at COMMIT (status=%d): %.*s", cmd, status, (int)err_buf->len,
                       (const char *)err_buf->data);
        } else if (line != NULL) {
            FIRC_WARN("%s failed (status=%d): %.*s -- the line it refused was: %.*s", cmd,
                     status, (int)err_buf->len, (const char *)err_buf->data, (int)line_len, line);
        } else {
            FIRC_WARN("%s failed (status=%d): %.*s", cmd, status, (int)err_buf->len,
                     (const char *)err_buf->data);
        }
        return FIRC_ERR_IO;
    }
    return FIRC_OK;
}

static uint64_t elapsed_ms(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (uint64_t)(t1.tv_sec - t0->tv_sec) * 1000u + (uint64_t)((t1.tv_nsec - t0->tv_nsec) / 1000000);
}

static firc_err_t real_save_run(firc_ipt_executable_t *self, const char *table, uint8_t **out,
                                 size_t *out_len) {
    exe_real_t *e = (exe_real_t *)self;
    const char *argv[] = {e->save_cmd, "-t", table, NULL};

    pid_t pid;
    int stdin_wr, stdout_rd, stderr_rd;
    if (firc_cancel_raised(e->cancel)) { return FIRC_ERR_CANCELED; }

    firc_err_t err = spawn_with_pipes(argv, false, &pid, &stdin_wr, &stdout_rd, &stderr_rd);
    if (err != FIRC_OK) { return err; }
    (void)stdin_wr;

    const int cancel_fd = firc_cancel_fd(e->cancel);
    bool canceled = false;

    if (err == FIRC_OK) { err = set_nonblock(stdout_rd); }
    if (err == FIRC_OK) { err = set_nonblock(stderr_rd); }

    firc_bytebuf_t out_buf, err_buf;
    firc_bytebuf_init(&out_buf);
    firc_bytebuf_init_bounded(&err_buf, FIRC_IPT_STDERR_CAP);

    bool stdout_eof = (err != FIRC_OK);
    bool stderr_eof = (err != FIRC_OK);
    bool stdout_limited = false;

    while (err == FIRC_OK && (!stdout_eof || !stderr_eof)) {
        struct pollfd pfds[3];
        int n = 0, idx_out = -1, idx_err = -1, idx_cancel = -1;
        if (!stdout_eof) {
            pfds[n].fd = stdout_rd;
            pfds[n].events = POLLIN;
            idx_out = n++;
        }
        if (!stderr_eof) {
            pfds[n].fd = stderr_rd;
            pfds[n].events = POLLIN;
            idx_err = n++;
        }
        if (cancel_fd >= 0) {
            pfds[n].fd = cancel_fd;
            pfds[n].events = POLLIN;
            idx_cancel = n++;
        }

        int pr = poll(pfds, (nfds_t)n, -1);
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            err = firc_err_from_errno(errno);
            break;
        }

        if (idx_cancel >= 0 && pfds[idx_cancel].revents != 0) {
            canceled = true;
            break;
        }

        if (idx_out >= 0 && pfds[idx_out].revents != 0) {
            uint8_t tmp[4096];
            ssize_t rn = read(stdout_rd, tmp, sizeof(tmp));
            if (rn < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    err = firc_err_from_errno(errno);
                    break;
                }
            } else if (rn == 0) {
                stdout_eof = true;
            } else if (!stdout_limited) {
                firc_err_t aerr = firc_bytebuf_append(&out_buf, tmp, (size_t)rn);
                if (aerr == FIRC_ERR_LIMIT) {
                    stdout_limited = true;
                } else if (aerr != FIRC_OK) {
                    err = aerr;
                    break;
                }
            }
        }
        if (idx_err >= 0 && pfds[idx_err].revents != 0) {
            uint8_t tmp[1024];
            ssize_t rn = read(stderr_rd, tmp, sizeof(tmp));
            if (rn < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    err = firc_err_from_errno(errno);
                    break;
                }
            } else if (rn == 0) {
                stderr_eof = true;
            } else {
                (void)firc_bytebuf_append(&err_buf, tmp, (size_t)rn);
            }
        }
    }

    close(stdout_rd);
    close(stderr_rd);

    if (canceled) {
        kill_child(pid);
        err = FIRC_ERR_CANCELED;
    } else {
        firc_err_t wait_err = wait_child(pid, e->save_cmd, &err_buf, NULL, 0);
        if (err == FIRC_OK) { err = wait_err; }
        if (err == FIRC_OK && stdout_limited) { err = FIRC_ERR_LIMIT; }
    }

    firc_bytebuf_free(&err_buf);

    if (err != FIRC_OK) {
        firc_bytebuf_free(&out_buf);
        return err;
    }

    *out = out_buf.data;
    *out_len = out_buf.len;
    return FIRC_OK;
}

static firc_err_t real_save(firc_ipt_executable_t *self, const char *table, uint8_t **out, size_t *out_len) {
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_err_t err = real_save_run(self, table, out, out_len);
    FIRC_DEBUG("%s -t %s: %llu ms, %zu bytes (%s)", ((exe_real_t *)self)->save_cmd, table,
               (unsigned long long)elapsed_ms(&t0), err == FIRC_OK ? *out_len : 0, firc_err_str(err));
    return err;
}

static firc_err_t real_restore_argv(firc_ipt_executable_t *self, const uint8_t *data, size_t len,
                                    const char *const *argv, const char *label);

static firc_err_t real_restore(firc_ipt_executable_t *self, const uint8_t *data, size_t len) {
    exe_real_t *e = (exe_real_t *)self;
    const char *argv[] = {e->restore_cmd, "--noflush", NULL};
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_err_t err = real_restore_argv(self, data, len, argv, e->restore_cmd);
    FIRC_DEBUG("%s: %llu ms, %zu bytes (%s)", e->restore_cmd, (unsigned long long)elapsed_ms(&t0), len,
               firc_err_str(err));
    return err;
}

static firc_err_t real_restore_argv(firc_ipt_executable_t *self, const uint8_t *data, size_t len,
                                    const char *const *argv, const char *label) {
    exe_real_t *e = (exe_real_t *)self;

    pid_t pid;
    int stdin_wr, stdout_rd, stderr_rd;
    if (firc_cancel_raised(e->cancel)) { return FIRC_ERR_CANCELED; }

    firc_err_t err = spawn_with_pipes(argv, true, &pid, &stdin_wr, &stdout_rd, &stderr_rd);
    if (err != FIRC_OK) { return err; }

    const int cancel_fd = firc_cancel_fd(e->cancel);
    bool canceled = false;

    if (err == FIRC_OK) { err = set_nonblock(stdin_wr); }
    if (err == FIRC_OK) { err = set_nonblock(stdout_rd); }
    if (err == FIRC_OK) { err = set_nonblock(stderr_rd); }

    firc_bytebuf_t err_buf;
    firc_bytebuf_init_bounded(&err_buf, FIRC_IPT_STDERR_CAP);

    size_t written = 0;
    bool stdin_done = (len == 0) || (err != FIRC_OK);
    if ((len == 0 || err != FIRC_OK) && stdin_wr >= 0) {
        close(stdin_wr);
        stdin_wr = -1;
    }
    bool stdout_eof = (err != FIRC_OK);
    bool stderr_eof = (err != FIRC_OK);

    /* Write stdin while draining stdout/stderr, or a full stderr pipe deadlocks the child. */

    while (err == FIRC_OK && (!stdin_done || !stdout_eof || !stderr_eof)) {
        struct pollfd pfds[4];
        int n = 0, idx_in = -1, idx_out = -1, idx_err = -1, idx_cancel = -1;
        if (!stdin_done) {
            pfds[n].fd = stdin_wr;
            pfds[n].events = POLLOUT;
            idx_in = n++;
        }
        if (!stdout_eof) {
            pfds[n].fd = stdout_rd;
            pfds[n].events = POLLIN;
            idx_out = n++;
        }
        if (!stderr_eof) {
            pfds[n].fd = stderr_rd;
            pfds[n].events = POLLIN;
            idx_err = n++;
        }
        if (cancel_fd >= 0) {
            pfds[n].fd = cancel_fd;
            pfds[n].events = POLLIN;
            idx_cancel = n++;
        }

        int pr = poll(pfds, (nfds_t)n, -1);
        if (pr < 0) {
            if (errno == EINTR) { continue; }
            err = firc_err_from_errno(errno);
            break;
        }

        if (idx_cancel >= 0 && pfds[idx_cancel].revents != 0) {
            canceled = true;
            break;
        }

        if (idx_in >= 0 && pfds[idx_in].revents != 0) {
            if (pfds[idx_in].revents & POLLOUT) {
                ssize_t wn = write(stdin_wr, data + written, len - written);
                if (wn < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                        /* retry next iteration */
                    } else if (errno == EPIPE) {
                        close(stdin_wr);
                        stdin_wr = -1;
                        stdin_done = true;
                    } else {
                        err = firc_err_from_errno(errno);
                        break;
                    }
                } else {
                    written += (size_t)wn;
                    if (written == len) {
                        close(stdin_wr);
                        stdin_wr = -1;
                        stdin_done = true;
                    }
                }
            } else {
                close(stdin_wr);
                stdin_wr = -1;
                stdin_done = true;
            }
        }
        if (idx_out >= 0 && pfds[idx_out].revents != 0) {
            uint8_t tmp[1024];
            ssize_t rn = read(stdout_rd, tmp, sizeof(tmp));
            if (rn < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    err = firc_err_from_errno(errno);
                    break;
                }
            } else if (rn == 0) {
                stdout_eof = true;
            }
        }
        if (idx_err >= 0 && pfds[idx_err].revents != 0) {
            uint8_t tmp[1024];
            ssize_t rn = read(stderr_rd, tmp, sizeof(tmp));
            if (rn < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                    err = firc_err_from_errno(errno);
                    break;
                }
            } else if (rn == 0) {
                stderr_eof = true;
            } else {
                (void)firc_bytebuf_append(&err_buf, tmp, (size_t)rn);
            }
        }
    }

    close_if_valid(stdin_wr);
    close(stdout_rd);
    close(stderr_rd);

    if (canceled) {
        kill_child(pid);
        err = FIRC_ERR_CANCELED;
    } else {
        firc_err_t wait_err = wait_child(pid, label, &err_buf, data, len);
        if (err == FIRC_OK) { err = wait_err; }
    }

    firc_bytebuf_free(&err_buf);
    return err;
}

static void real_set_cancel(firc_ipt_executable_t *self, firc_cancel_t *cancel) {
    ((exe_real_t *)self)->cancel = cancel;
}

static firc_ipt_proto_t real_proto(firc_ipt_executable_t *self) {
    return ((exe_real_t *)self)->proto;
}

static void real_destroy(firc_ipt_executable_t *self) {
    free(self);
}

static const firc_ipt_executable_ops_t k_real_ops = {
    .save = real_save,
    .restore = real_restore,
    .proto = real_proto,
    .destroy = real_destroy,
    .set_cancel = real_set_cancel,
};

firc_ipt_executable_t *firc_ipt_executable_real_new(firc_ipt_proto_t proto) {
    exe_real_t *e = calloc(1, sizeof(*e));
    if (!e) { return NULL; }
    e->base.ops = &k_real_ops;
    e->proto = proto;
    if (proto == FIRC_IPT_PROTO_IPV6) {
        e->save_cmd = "ip6tables-save";
        e->restore_cmd = "ip6tables-restore";
    } else {
        e->save_cmd = "iptables-save";
        e->restore_cmd = "iptables-restore";
    }
    return &e->base;
}
