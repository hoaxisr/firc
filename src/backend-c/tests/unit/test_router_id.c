#include "greatest.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "firc/log.h"
#include "firc/router_id.h"

typedef struct {
    const char *version;
    const char *defaults;
    int fail_rounds;
    int calls;
} fake_rci_t;

static firc_err_t fake_get(void *ud, const char *path, char **body)
{
    fake_rci_t *f = ud;
    *body = NULL;
    f->calls++;
    if (f->fail_rounds > 0) {
        if (strcmp(path, "/rci/show/defaults") == 0) {
            f->fail_rounds--;
        }
        return FIRC_ERR_UPSTREAM;
    }
    const char *text = strcmp(path, "/rci/show/version") == 0    ? f->version
                       : strcmp(path, "/rci/show/defaults") == 0 ? f->defaults
                                                                  : NULL;
    if (text == NULL) {
        return FIRC_ERR_UPSTREAM;
    }
    *body = strdup(text);
    return *body != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}

static char g_dir[64];

static bool make_dir(void)
{
    snprintf(g_dir, sizeof g_dir, "/tmp/firc_rid_XXXXXX");
    return mkdtemp(g_dir) != NULL;
}

static void remove_dir(void)
{
    char cmd[160];
    snprintf(cmd, sizeof cmd, "chmod -R u+rwx '%s'; rm -rf '%s'", g_dir, g_dir);
    if (system(cmd) != 0) {
    }
}

static bool is_id(const char *s)
{
    return strlen(s) == 16 && strspn(s, "0123456789abcdef") == 16;
}

static void write_file(const char *path, const char *text)
{
    FILE *fp = fopen(path, "we");
    if (fp != NULL) {
        fputs(text, fp);
        fclose(fp);
    }
}

static void read_file(const char *path, char *out, size_t cap)
{
    out[0] = '\0';
    FILE *fp = fopen(path, "re");
    if (fp != NULL) {
        size_t n = fread(out, 1, cap - 1, fp);
        out[n] = '\0';
        fclose(fp);
    }
}

/* Catches: the id taken without the NUL after the prefix, from more or fewer digits, or in upper case. */
TEST the_id_is_the_hash_of_the_serial(void)
{
    char id[17];
    firc_router_id_from_serial("S123456789", id);
    ASSERT_STR_EQ("6e58d9776d738a31", id);
    firc_router_id_from_serial("S987654321", id);
    ASSERT_STR_EQ("ca4eb400f26f6aeb", id);
    PASS();
}

/* Catches: no id without RCI, an id made anew on every start, or a stored id or its directory readable by others. */
TEST without_rci_the_stored_id_is_made_once(void)
{
    ASSERT(make_dir());
    char path[128], dir[128];
    snprintf(path, sizeof path, "%s/var/lib/firc/hwid", g_dir);
    snprintf(dir, sizeof dir, "%s/var/lib/firc", g_dir);
    firc_router_id_t a = {0};
    firc_router_id_settle(&a, path, true);
    ASSERT(is_id(a.hwid));
    struct stat st;
    ASSERT_EQ(0, stat(path, &st));
    ASSERT_EQ_FMT(0600u, (unsigned)(st.st_mode & 0777), "%o");
    ASSERT_EQ(0, stat(dir, &st));
    ASSERT_EQ_FMT(0700u, (unsigned)(st.st_mode & 0777), "%o");
    firc_router_id_t b = {0};
    firc_router_id_settle(&b, path, true);
    ASSERT_STR_EQ(a.hwid, b.hwid);
    remove_dir();
    PASS();
}

/* Catches: the serial's id sent without being stored, stored with other bytes, or readable by others. */
TEST the_first_serial_answer_is_stored(void)
{
    ASSERT(make_dir());
    char path[128], text[64];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    firc_router_id_t id = {0};
    snprintf(id.hwid, sizeof id.hwid, "6e58d9776d738a31");
    firc_router_id_settle(&id, path, false);
    ASSERT_STR_EQ("6e58d9776d738a31", id.hwid);
    read_file(path, text, sizeof text);
    ASSERT_STR_EQ("6e58d9776d738a31\n", text);
    struct stat st;
    ASSERT_EQ(0, stat(path, &st));
    ASSERT_EQ_FMT(0600u, (unsigned)(st.st_mode & 0777), "%o");
    remove_dir();
    PASS();
}

/* Catches: a later serial replacing the stored id, or the file rewritten with it. */
TEST a_stored_id_wins_over_the_serial(void)
{
    ASSERT(make_dir());
    char path[128], text[64];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    write_file(path, "0123456789abcdef\n");
    firc_router_id_t id = {0};
    snprintf(id.hwid, sizeof id.hwid, "ca4eb400f26f6aeb");
    firc_router_id_settle(&id, path, true);
    ASSERT_STR_EQ("0123456789abcdef", id.hwid);
    read_file(path, text, sizeof text);
    ASSERT_STR_EQ("0123456789abcdef\n", text);
    remove_dir();
    PASS();
}

/* Catches: a file holding something else taken as the id, or left as it was. */
TEST a_file_without_an_id_is_replaced(void)
{
    ASSERT(make_dir());
    char path[128];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    FILE *fp = fopen(path, "we");
    ASSERT(fp != NULL);
    fputs("zzz\n", fp);
    fclose(fp);
    firc_router_id_t id = {0};
    firc_router_id_settle(&id, path, true);
    ASSERT(is_id(id.hwid));
    char line[32] = "";
    fp = fopen(path, "re");
    ASSERT(fp != NULL);
    ASSERT(fgets(line, sizeof line, fp) != NULL);
    fclose(fp);
    char want[32];
    snprintf(want, sizeof want, "%s\n", id.hwid);
    ASSERT_STR_EQ(want, line);
    remove_dir();
    PASS();
}

/* Catches: a crash or an empty id when the id cannot be stored. */
TEST an_id_that_cannot_be_stored_still_names_this_run(void)
{
    if (geteuid() == 0) {
        SKIPm("root writes through a read-only directory");
    }
    ASSERT(make_dir());
    char path[128];
    snprintf(path, sizeof path, "%s/sub/hwid", g_dir);
    ASSERT_EQ(0, chmod(g_dir, 0500));
    firc_router_id_t id = {0};
    firc_router_id_settle(&id, path, true);
    ASSERT(is_id(id.hwid));
    ASSERT_EQ(-1, access(path, F_OK));
    remove_dir();
    PASS();
}

/* Catches: the serial's id dropped when it cannot be stored, a warning per call, or the id written into the log. */
TEST a_serial_id_that_cannot_be_stored_is_used_and_said_once(void)
{
    if (geteuid() == 0) {
        SKIPm("root writes through a read-only directory");
    }
    ASSERT(make_dir());
    char path[128], logpath[128], text[1024];
    snprintf(path, sizeof path, "%s/sub/hwid", g_dir);
    snprintf(logpath, sizeof logpath, "%s/log", g_dir);
    int fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    ASSERT(fd >= 0);
    ASSERT_EQ(0, chmod(g_dir, 0500));
    firc_log_set_fd(fd);
    firc_router_id_t id = {0};
    snprintf(id.hwid, sizeof id.hwid, "6e58d9776d738a31");
    firc_router_id_settle(&id, path, true);
    firc_log_set_fd(2);
    close(fd);
    ASSERT_STR_EQ("6e58d9776d738a31", id.hwid);
    ASSERT_EQ(-1, access(path, F_OK));
    read_file(logpath, text, sizeof text);
    const char *at = strstr(text, "not written");
    ASSERT(at != NULL);
    ASSERT_EQ(NULL, strstr(at + 1, "not written"));
    ASSERT_EQ(NULL, strstr(text, "6e58d9776d738a31"));
    remove_dir();
    PASS();
}

typedef struct {
    int rounds_failing;
    int delay_ms;
} slow_rci_t;

static firc_err_t slow_get(void *ud, const char *path, char **body)
{
    slow_rci_t *f = ud;
    struct timespec ts = {f->delay_ms / 1000, (long)(f->delay_ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
    *body = NULL;
    if (f->rounds_failing > 0) {
        if (strcmp(path, "/rci/show/defaults") == 0) {
            f->rounds_failing--;
        }
        return FIRC_ERR_UPSTREAM;
    }
    *body = strdup(strcmp(path, "/rci/show/version") == 0
                       ? "{\"release\":\"5.01.C.6.0-1\",\"model\":\"Ultra (KN-1810)\"}"
                       : "{\"serial\":\"S123456789\"}");
    return *body != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void nap_ms(long ms)
{
    struct timespec ts = {0, ms * 1000000L};
    nanosleep(&ts, NULL);
}

/* Catches: the caller held while RCI is slow, the late answer lost or handed out twice, or the thread never ending. */
TEST a_late_rci_answer_arrives_without_holding_the_caller(void)
{
    slow_rci_t f = {1, 200};
    firc_router_id_retry_t *r = firc_router_id_retry_start(slow_get, &f, 3, 0);
    ASSERT(r != NULL);
    firc_router_id_t id;
    int64_t end = now_ms() + 3000;
    bool got = false;
    while (!got && now_ms() < end) {
        int64_t t = now_ms();
        got = firc_router_id_retry_poll(&r, &id);
        ASSERT(now_ms() - t < 50);
        nap_ms(10);
    }
    ASSERT(got);
    ASSERT_STR_EQ("6e58d9776d738a31", id.hwid);
    ASSERT_STR_EQ("Ultra (KN-1810)", id.model);
    while (r != NULL && now_ms() < end) {
        ASSERT_FALSE(firc_router_id_retry_poll(&r, &id));
        nap_ms(10);
    }
    ASSERT_EQ(NULL, r);
    PASS();
}

/* Catches: a stop that waits out the remaining rounds and pauses instead of ending at the next pause. */
TEST a_retry_stops_at_its_next_pause(void)
{
    slow_rci_t f = {100, 0};
    firc_router_id_retry_t *r = firc_router_id_retry_start(slow_get, &f, 100, 1000);
    ASSERT(r != NULL);
    nap_ms(20);
    int64_t t = now_ms();
    firc_router_id_retry_stop(r);
    ASSERT(now_ms() - t < 200);
    PASS();
}

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool open;
    firc_router_id_retry_t *r;
} gate_t;

static firc_err_t gated_get(void *ud, const char *path, char **body)
{
    gate_t *g = ud;
    pthread_mutex_lock(&g->mu);
    while (!g->open) {
        pthread_cond_wait(&g->cv, &g->mu);
    }
    pthread_mutex_unlock(&g->mu);
    *body = strdup(strcmp(path, "/rci/show/version") == 0 ? "{\"release\":\"5.01.C.6.0-1\"}"
                                                           : "{\"serial\":\"S987654321\"}");
    return *body != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}

static void answer_and_end(void *ud)
{
    gate_t *g = ud;
    pthread_mutex_lock(&g->mu);
    bool first = !g->open;
    g->open = true;
    pthread_cond_broadcast(&g->cv);
    pthread_mutex_unlock(&g->mu);
    for (int i = 0; first && i < 300 && !firc_router_id_retry_done(g->r); i++) {
        nap_ms(10);
    }
}

/* Catches: a poll that sees the thread ended after a take that came too early, and drops the answer it just published. */
TEST an_answer_published_as_the_thread_ends_is_taken(void)
{
    gate_t g = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false, NULL};
    firc_router_id_retry_t *r = firc_router_id_retry_start(gated_get, &g, 1, 0);
    ASSERT(r != NULL);
    g.r = r;
    firc_router_id_retry_hook_for_test(r, answer_and_end, &g);
    firc_router_id_t id;
    bool got = false;
    for (int i = 0; r != NULL && i < 100; i++) {
        got = firc_router_id_retry_poll(&r, &id) || got;
    }
    ASSERT_EQ(NULL, r);
    ASSERT(got);
    ASSERT_STR_EQ("ca4eb400f26f6aeb", id.hwid);
    ASSERT_STR_EQ("5.01.C.6.0-1", id.release);
    PASS();
}

typedef struct {
    atomic_int calls;
} counted_rci_t;

static firc_err_t counted_get(void *ud, const char *path, char **body)
{
    (void)path;
    counted_rci_t *f = ud;
    atomic_fetch_add(&f->calls, 1);
    nap_ms(300);
    *body = NULL;
    return FIRC_ERR_UPSTREAM;
}

/* Catches: a stop that lets the round ask its second RCI path after the call in flight, holding teardown twice as long. */
TEST a_stop_ends_the_round_after_the_call_in_flight(void)
{
    counted_rci_t f;
    atomic_init(&f.calls, 0);
    firc_router_id_retry_t *r = firc_router_id_retry_start(counted_get, &f, 5, 0);
    ASSERT(r != NULL);
    for (int i = 0; i < 100 && atomic_load(&f.calls) == 0; i++) {
        nap_ms(5);
    }
    firc_router_id_retry_stop(r);
    ASSERT_EQ(1, atomic_load(&f.calls));
    PASS();
}

typedef struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool open;
    bool answers;
    atomic_int calls;
    atomic_int defaults;
} boot_rci_t;

static firc_err_t boot_get(void *ud, const char *path, char **body)
{
    boot_rci_t *b = ud;
    *body = NULL;
    if (strcmp(path, "/rci/show/defaults") == 0) {
        atomic_fetch_add(&b->defaults, 1);
    }
    if (atomic_fetch_add(&b->calls, 1) < 2) {
        return FIRC_ERR_UPSTREAM;
    }
    pthread_mutex_lock(&b->mu);
    while (!b->open) {
        pthread_cond_wait(&b->cv, &b->mu);
    }
    bool answers = b->answers;
    pthread_mutex_unlock(&b->mu);
    if (!answers) {
        return FIRC_ERR_UPSTREAM;
    }
    *body = strdup(strcmp(path, "/rci/show/version") == 0 ? "{\"release\":\"5.01.C.6.0-1\"}"
                                                           : "{\"serial\":\"S987654321\"}");
    return *body != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}

static void boot_open(boot_rci_t *b)
{
    pthread_mutex_lock(&b->mu);
    b->open = true;
    pthread_cond_broadcast(&b->cv);
    pthread_mutex_unlock(&b->mu);
}

static bool boot_next(firc_router_id_retry_t **r, const char *path, firc_router_id_t *id)
{
    for (int i = 0; i < 300; i++) {
        if (firc_router_id_next(r, path, id)) {
            return true;
        }
        nap_ms(10);
    }
    return false;
}

/* Catches: an id sent or a random one stored while the start's retry still asks RCI, or none written once it gives up. */
TEST a_silent_rci_start_sends_no_id_until_the_retry_gives_up(void)
{
    ASSERT(make_dir());
    char path[128], text[64], want[32];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    static boot_rci_t b = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false, false, 0, 0};
    firc_router_id_t id;
    firc_router_id_retry_t *r = firc_router_id_begin(boot_get, &b, 2, 10, path, &id);
    ASSERT(r != NULL);
    ASSERT_STR_EQ("", id.hwid);
    for (int i = 0; i < 5; i++) {
        ASSERT_FALSE(firc_router_id_next(&r, path, &id));
        ASSERT(r != NULL);
        nap_ms(10);
    }
    ASSERT_EQ(-1, access(path, F_OK));
    boot_open(&b);
    ASSERT(boot_next(&r, path, &id));
    ASSERT_EQ(NULL, r);
    ASSERT(is_id(id.hwid));
    read_file(path, text, sizeof text);
    snprintf(want, sizeof want, "%s\n", id.hwid);
    ASSERT_STR_EQ(want, text);
    remove_dir();
    PASS();
}

/* Catches: a late RCI answer lost, its id not stored, or the retry left running. */
TEST a_late_rci_answer_after_a_silent_start_stores_the_serial(void)
{
    ASSERT(make_dir());
    char path[128], text[64];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    static boot_rci_t b = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false, true, 0, 0};
    firc_router_id_t id;
    firc_router_id_retry_t *r = firc_router_id_begin(boot_get, &b, 30, 2000, path, &id);
    ASSERT(r != NULL);
    ASSERT_STR_EQ("", id.hwid);
    ASSERT_FALSE(firc_router_id_next(&r, path, &id));
    boot_open(&b);
    ASSERT(boot_next(&r, path, &id));
    ASSERT_EQ(NULL, r);
    ASSERT_STR_EQ("ca4eb400f26f6aeb", id.hwid);
    ASSERT_STR_EQ("5.01.C.6.0-1", id.release);
    read_file(path, text, sizeof text);
    ASSERT_STR_EQ("ca4eb400f26f6aeb\n", text);
    ASSERT_FALSE(firc_router_id_next(&r, path, &id));
    remove_dir();
    PASS();
}

/* Catches: a stored id waiting for RCI at start, show defaults asked anyway, or a late serial replacing it. */
TEST a_stored_id_is_sent_at_once_and_kept_over_a_late_serial(void)
{
    ASSERT(make_dir());
    char path[128], text[64];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    write_file(path, "0123456789abcdef\n");
    static boot_rci_t b = {PTHREAD_MUTEX_INITIALIZER, PTHREAD_COND_INITIALIZER, false, true, 0, 0};
    firc_router_id_t id;
    firc_router_id_retry_t *r = firc_router_id_begin(boot_get, &b, 30, 2000, path, &id);
    ASSERT(r != NULL);
    ASSERT_STR_EQ("0123456789abcdef", id.hwid);
    boot_open(&b);
    ASSERT(boot_next(&r, path, &id));
    ASSERT_STR_EQ("0123456789abcdef", id.hwid);
    ASSERT_STR_EQ("5.01.C.6.0-1", id.release);
    read_file(path, text, sizeof text);
    ASSERT_STR_EQ("0123456789abcdef\n", text);
    ASSERT_EQ(0, atomic_load(&b.defaults));
    remove_dir();
    PASS();
}

/* Catches: the start round asking show defaults, the serial sent as the id, fields read from the wrong keys, or no retry. */
TEST the_start_asks_the_version_and_the_retry_brings_the_serial(void)
{
    ASSERT(make_dir());
    char path[128], text[64];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    fake_rci_t f = {"{\"release\":\"5.01.C.6.0-1\",\"model\":\"Ultra (KN-1810)\",\"title\":\"5.1\"}",
                    "{\"serial\":\"S123456789\"}", 0, 0};
    firc_router_id_t id;
    firc_router_id_retry_t *r = firc_router_id_begin(fake_get, &f, 30, 2000, path, &id);
    ASSERT_EQ(1, f.calls);
    ASSERT(r != NULL);
    ASSERT_STR_EQ("5.01.C.6.0-1", id.release);
    ASSERT_STR_EQ("Ultra (KN-1810)", id.model);
    ASSERT_STR_EQ("", id.hwid);
    ASSERT_EQ(-1, access(path, F_OK));
    ASSERT(boot_next(&r, path, &id));
    ASSERT_EQ(2, f.calls);
    ASSERT_STR_EQ("6e58d9776d738a31", id.hwid);
    ASSERT_STR_EQ("Ultra (KN-1810)", id.model);
    read_file(path, text, sizeof text);
    ASSERT_STR_EQ("6e58d9776d738a31\n", text);
    remove_dir();
    PASS();
}

/* Catches: show defaults asked although the id is stored, or a retry run when the start already has all it needs. */
TEST with_a_stored_id_show_defaults_is_never_asked(void)
{
    ASSERT(make_dir());
    char path[128];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    write_file(path, "0123456789abcdef\n");
    fake_rci_t f = {"{\"release\":\"r\"}", "{\"serial\":\"S123456789\"}", 0, 0};
    firc_router_id_t id;
    ASSERT_EQ(NULL, firc_router_id_begin(fake_get, &f, 30, 2000, path, &id));
    ASSERT_EQ(1, f.calls);
    ASSERT_STR_EQ("0123456789abcdef", id.hwid);
    ASSERT_STR_EQ("r", id.release);
    remove_dir();
    PASS();
}

/* Catches: a field RCI lacks filled with something, or an unreadable show defaults taken as a serial. */
TEST a_missing_field_stays_empty(void)
{
    ASSERT(make_dir());
    char path[128];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    fake_rci_t f = {"{\"release\":\"5.01.C.6.0-1\"}", "not json", 0, 0};
    firc_router_id_t id;
    firc_router_id_retry_t *r = firc_router_id_begin(fake_get, &f, 2, 0, path, &id);
    ASSERT(r != NULL);
    ASSERT(boot_next(&r, path, &id));
    ASSERT_STR_EQ("5.01.C.6.0-1", id.release);
    ASSERT_STR_EQ("", id.model);
    ASSERT(is_id(id.hwid));
    ASSERT(strcmp(id.hwid, "6e58d9776d738a31") != 0);
    remove_dir();
    PASS();
}

/* Catches: a build without RCI left without an id, or its id not stored. */
TEST without_rci_the_start_has_its_id_at_once(void)
{
    ASSERT(make_dir());
    char path[128];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    firc_router_id_t id;
    ASSERT_EQ(NULL, firc_router_id_begin(NULL, NULL, 30, 2000, path, &id));
    ASSERT(is_id(id.hwid));
    ASSERT_EQ(0, access(path, F_OK));
    remove_dir();
    PASS();
}

typedef struct {
    atomic_int defaults_calls;
    int defaults_ms;
} lazy_rci_t;

static firc_err_t lazy_get(void *ud, const char *path, char **body)
{
    lazy_rci_t *l = ud;
    bool is_version = strcmp(path, "/rci/show/version") == 0;
    if (!is_version) {
        atomic_fetch_add(&l->defaults_calls, 1);
        struct timespec ts = {l->defaults_ms / 1000, (long)(l->defaults_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL);
    }
    *body = strdup(is_version ? "{\"release\":\"5.01.C.6.0-1\",\"model\":\"Ultra (KN-1810)\"}"
                              : "{\"serial\":\"S987654321\"}");
    return *body != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}

/* Catches: a show defaults slower than 2 s holding the start, or its serial never stored by the retry. */
TEST a_slow_show_defaults_still_gives_the_serial_without_holding_the_start(void)
{
    ASSERT(make_dir());
    char path[128], text[64];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    static lazy_rci_t l;
    atomic_init(&l.defaults_calls, 0);
    l.defaults_ms = 2200;
    firc_router_id_t id;
    int64_t t = now_ms();
    firc_router_id_retry_t *r = firc_router_id_begin(lazy_get, &l, 30, 2000, path, &id);
    ASSERT(now_ms() - t < 500);
    ASSERT(r != NULL);
    ASSERT_STR_EQ("", id.hwid);
    ASSERT_STR_EQ("5.01.C.6.0-1", id.release);
    ASSERT(boot_next(&r, path, &id));
    ASSERT_EQ(1, atomic_load(&l.defaults_calls));
    ASSERT_STR_EQ("ca4eb400f26f6aeb", id.hwid);
    read_file(path, text, sizeof text);
    ASSERT_STR_EQ("ca4eb400f26f6aeb\n", text);
    remove_dir();
    PASS();
}

typedef struct {
    atomic_int version;
    atomic_bool defaults;
} part_rci_t;

static firc_err_t part_get(void *ud, const char *path, char **body)
{
    part_rci_t *p = ud;
    *body = NULL;
    bool is_version = strcmp(path, "/rci/show/version") == 0;
    if (is_version ? atomic_fetch_sub(&p->version, 1) <= 0 : !atomic_load(&p->defaults)) {
        return FIRC_ERR_UPSTREAM;
    }
    *body = strdup(is_version ? "{\"release\":\"5.01.C.6.0-1\",\"model\":\"Ultra (KN-1810)\"}"
                              : "{\"serial\":\"S987654321\"}");
    return *body != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}

static bool never_next(firc_router_id_retry_t **r, const char *path, firc_router_id_t *id, int rounds)
{
    for (int i = 0; i < rounds; i++) {
        if (firc_router_id_next(r, path, id) || *r == NULL) {
            return false;
        }
        nap_ms(10);
    }
    return true;
}

/* Catches: a start whose show version answered and show defaults did not taken as answered, storing no serial's id. */
TEST a_start_with_the_version_only_waits_for_the_serial(void)
{
    ASSERT(make_dir());
    char path[128], text[64];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    static part_rci_t p;
    atomic_init(&p.version, 1000000);
    atomic_init(&p.defaults, false);
    firc_router_id_t id;
    firc_router_id_retry_t *r = firc_router_id_begin(part_get, &p, 300, 10, path, &id);
    ASSERT(r != NULL);
    ASSERT_STR_EQ("", id.hwid);
    ASSERT_STR_EQ("5.01.C.6.0-1", id.release);
    ASSERT(never_next(&r, path, &id, 10));
    ASSERT_EQ(-1, access(path, F_OK));
    atomic_store(&p.defaults, true);
    ASSERT(boot_next(&r, path, &id));
    ASSERT_EQ(NULL, r);
    ASSERT_STR_EQ("ca4eb400f26f6aeb", id.hwid);
    read_file(path, text, sizeof text);
    ASSERT_STR_EQ("ca4eb400f26f6aeb\n", text);
    remove_dir();
    PASS();
}

/* Catches: a retry round with the version only ending the retry, so the serial asked later never comes. */
TEST a_retry_round_with_the_version_only_keeps_asking(void)
{
    ASSERT(make_dir());
    char path[128], text[64];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    static part_rci_t p;
    atomic_init(&p.version, 0);
    atomic_init(&p.defaults, false);
    firc_router_id_t id;
    firc_router_id_retry_t *r = firc_router_id_begin(part_get, &p, 300, 10, path, &id);
    ASSERT(r != NULL);
    atomic_store(&p.version, 1000000);
    ASSERT(never_next(&r, path, &id, 10));
    ASSERT_EQ(-1, access(path, F_OK));
    atomic_store(&p.defaults, true);
    ASSERT(boot_next(&r, path, &id));
    ASSERT_STR_EQ("ca4eb400f26f6aeb", id.hwid);
    ASSERT_STR_EQ("Ultra (KN-1810)", id.model);
    read_file(path, text, sizeof text);
    ASSERT_STR_EQ("ca4eb400f26f6aeb\n", text);
    remove_dir();
    PASS();
}

/* Catches: a random id stored before the retry gave up, or the start's firmware and model lost when it gives up. */
TEST without_a_serial_until_the_give_up_a_random_id_is_stored(void)
{
    ASSERT(make_dir());
    char path[128], text[64], want[32];
    snprintf(path, sizeof path, "%s/hwid", g_dir);
    static part_rci_t p;
    atomic_init(&p.version, 1);
    atomic_init(&p.defaults, false);
    firc_router_id_t id;
    firc_router_id_retry_t *r = firc_router_id_begin(part_get, &p, 3, 10, path, &id);
    ASSERT(r != NULL);
    ASSERT_STR_EQ("", id.hwid);
    ASSERT_EQ(-1, access(path, F_OK));
    ASSERT(boot_next(&r, path, &id));
    ASSERT_EQ(NULL, r);
    ASSERT(is_id(id.hwid));
    ASSERT_STR_EQ("5.01.C.6.0-1", id.release);
    ASSERT_STR_EQ("Ultra (KN-1810)", id.model);
    read_file(path, text, sizeof text);
    snprintf(want, sizeof want, "%s\n", id.hwid);
    ASSERT_STR_EQ(want, text);
    remove_dir();
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_id_is_the_hash_of_the_serial);
    RUN_TEST(without_rci_the_stored_id_is_made_once);
    RUN_TEST(the_first_serial_answer_is_stored);
    RUN_TEST(a_stored_id_wins_over_the_serial);
    RUN_TEST(a_file_without_an_id_is_replaced);
    RUN_TEST(an_id_that_cannot_be_stored_still_names_this_run);
    RUN_TEST(a_serial_id_that_cannot_be_stored_is_used_and_said_once);
    RUN_TEST(a_late_rci_answer_arrives_without_holding_the_caller);
    RUN_TEST(a_retry_stops_at_its_next_pause);
    RUN_TEST(an_answer_published_as_the_thread_ends_is_taken);
    RUN_TEST(a_stop_ends_the_round_after_the_call_in_flight);
    RUN_TEST(a_silent_rci_start_sends_no_id_until_the_retry_gives_up);
    RUN_TEST(a_late_rci_answer_after_a_silent_start_stores_the_serial);
    RUN_TEST(a_stored_id_is_sent_at_once_and_kept_over_a_late_serial);
    RUN_TEST(the_start_asks_the_version_and_the_retry_brings_the_serial);
    RUN_TEST(with_a_stored_id_show_defaults_is_never_asked);
    RUN_TEST(a_missing_field_stays_empty);
    RUN_TEST(without_rci_the_start_has_its_id_at_once);
    RUN_TEST(a_slow_show_defaults_still_gives_the_serial_without_holding_the_start);
    RUN_TEST(a_start_with_the_version_only_waits_for_the_serial);
    RUN_TEST(a_retry_round_with_the_version_only_keeps_asking);
    RUN_TEST(without_a_serial_until_the_give_up_a_random_id_is_stored);
    GREATEST_MAIN_END();
}
