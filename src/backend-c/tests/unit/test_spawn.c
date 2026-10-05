#include "greatest.h"

#include <dirent.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "firc/spawn.h"

static bool wait_file(const char *path, char *buf, size_t cap) {
    for (int i = 0; i < 300; i++) {
        FILE *f = fopen(path, "r");
        if (f != NULL) {
            size_t n = fread(buf, 1, cap - 1, f);
            fclose(f);
            buf[n] = '\0';
            return true;
        }
        struct timespec ts = {0, 10 * 1000000L};
        nanosleep(&ts, NULL);
    }
    return false;
}

static long field_long(const char *text, const char *key) {
    const char *p = strstr(text, key);
    return p != NULL ? strtol(p + strlen(key), NULL, 10) : -1;
}

/* Copies a /proc/self/status field's value up to its line end. */
static void copy_field(char *out, size_t cap, const char *status, const char *key) {
    const char *p = strstr(status, key);
    if (p == NULL) {
        snprintf(out, cap, "?");
        return;
    }
    p += strlen(key);
    while (*p == '\t' || *p == ' ') { p++; }
    size_t i = 0;
    while (i + 1 < cap && p[i] != '\0' && p[i] != '\n' && p[i] != '\r') {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
}

/* Writes this process's inherited state whole or not at all, then exits. */
static void write_report_and_exit(const char *dir) {
    char tmp[512], final[512];
    snprintf(tmp, sizeof(tmp), "%s/seen.tmp", dir != NULL ? dir : ".");
    snprintf(final, sizeof(final), "%s/seen", dir != NULL ? dir : ".");

    char status[16384];
    status[0] = '\0';
    FILE *sf = fopen("/proc/self/status", "r");
    if (sf != NULL) {
        size_t n = fread(status, 1, sizeof(status) - 1, sf);
        status[n] = '\0';
        fclose(sf);
    }
    char sigblk[32], sigign[32];
    copy_field(sigblk, sizeof(sigblk), status, "SigBlk:");
    copy_field(sigign, sizeof(sigign), status, "SigIgn:");

    char fds[4096];
    fds[0] = '\0';
    DIR *fdd = opendir("/proc/self/fd");
    if (fdd != NULL) {
        struct dirent *e;
        size_t off = 0;
        while ((e = readdir(fdd)) != NULL) {
            if (e->d_name[0] == '.') { continue; }
            int n = snprintf(fds + off, sizeof(fds) - off, "%s ", e->d_name);
            if (n < 0 || (size_t)n >= sizeof(fds) - off) { break; }
            off += (size_t)n;
        }
        closedir(fdd);
    }

    char out[64];
    ssize_t n = readlink("/proc/self/fd/1", out, sizeof(out) - 1);
    if (n < 0) {
        snprintf(out, sizeof(out), "?");
    } else {
        out[n] = '\0';
    }

    FILE *f = fopen(tmp, "w");
    if (f == NULL) { _exit(1); }
    fprintf(f, "ppid=%ld\nsid=%ld\nsigblk=%s\nsigign=%s\nstdout=%s\nfds= %s\n", (long)getppid(),
            (long)getsid(0), sigblk, sigign, out, fds);
    fclose(f);
    rename(tmp, final);
    _exit(0);
}

TEST a_detached_child_is_on_its_own(void) {
    char dir[] = "/tmp/firc_spawn_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char seen[160];
    snprintf(seen, sizeof(seen), "%s/seen", dir);
    ASSERT_EQ(0, setenv("FIRC_SPAWN_TEST_DIR", dir, 1));

    char self[PATH_MAX];
    ssize_t self_len = readlink("/proc/self/exe", self, sizeof(self) - 1);
    ASSERT(self_len > 0);
    self[self_len] = '\0';

    struct sigaction ign;
    memset(&ign, 0, sizeof(ign));
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    struct sigaction old_pipe;
    ASSERT_EQ(0, sigaction(SIGPIPE, &ign, &old_pipe));

    int p[2];
    ASSERT_EQ(0, pipe(p));
    ASSERT_EQ(200, dup2(p[1], 200));
    sigset_t block, old_mask;
    sigemptyset(&block);
    sigaddset(&block, SIGTERM);
    sigaddset(&block, SIGHUP);
    ASSERT_EQ(0, pthread_sigmask(SIG_BLOCK, &block, &old_mask));

    firc_err_t err = firc_spawn_detached(self, "report");

    pthread_sigmask(SIG_SETMASK, &old_mask, NULL);
    sigaction(SIGPIPE, &old_pipe, NULL);
    close(200);
    close(p[0]);
    close(p[1]);
    unsetenv("FIRC_SPAWN_TEST_DIR");
    ASSERT_EQ(FIRC_OK, err);

    char text[4096];
    ASSERT(wait_file(seen, text, sizeof(text)));
    long ppid = field_long(text, "ppid=");
    ASSERT(ppid > 0 && ppid != (long)getpid());
    ASSERT(field_long(text, "sid=") != (long)getsid(0));
    ASSERT(strstr(text, "sigblk=0000000000000000\n") != NULL);
    ASSERT(strstr(text, "sigign=0000000000000000\n") != NULL);
    ASSERT(strstr(text, "stdout=/dev/null\n") != NULL);
    ASSERT(strstr(text, " 200 ") == NULL);

    unlink(seen);
    rmdir(dir);
    PASS();
}

TEST a_script_that_cannot_run_is_an_error(void) {
    ASSERT(firc_spawn_detached("/nonexistent-firc/S99firc", "restart") != FIRC_OK);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "report") == 0) {
        write_report_and_exit(getenv("FIRC_SPAWN_TEST_DIR"));
        return 0;
    }
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_detached_child_is_on_its_own);
    RUN_TEST(a_script_that_cannot_run_is_an_error);
    GREATEST_MAIN_END();
}
