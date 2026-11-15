#include "greatest.h"

#include <errno.h>
#include <stdarg.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include "firc/log.h"
#include "firc/opkgtun.h"

#define FX "tests/unit/fixtures/opkgtun/"
#define MAX_LINES 256
#define MAX_ANS 16

#define CREATE3 "POST [{\"interface\":{\"name\":\"OpkgTun3\",\"description\":\"firc:t1\"}}] T=10"
#define DESC3 "{\"interface\":{\"name\":\"OpkgTun3\",\"description\":\"firc:t1 PRAW-1\"}}"
#define LEVEL3 "{\"interface\":{\"name\":\"OpkgTun3\",\"security-level\":{\"public\":true}}}"
#define ADDR3 \
    "{\"interface\":{\"name\":\"OpkgTun3\",\"ip\":{\"address\":{\"address\":\"203.0.113.4\",\"mask\":" \
    "\"255.255.255.255\"}}}}"
#define UP3 "{\"interface\":{\"name\":\"OpkgTun3\",\"up\":true}}"
#define P5_3 "POST [" DESC3 "," ADDR3 "," UP3 "] T=10"
#define DELETE3 "POST [{\"interface\":{\"name\":\"OpkgTun3\",\"no\":true}}] T=10"
#define SAVE "POST [{\"system\":{\"configuration\":{\"save\":{}}}}] T=30"
#define SAVE_OK \
    "[{\"system\":{\"configuration\":{\"save\":{\"status\":[{\"status\":\"message\",\"code\":\"0\"," \
    "\"ident\":\"Core::ConfigurationSaver\",\"message\":\"saving (http/rci).\"}]}}}}]"

typedef struct {
    char *body;
    firc_err_t err;
    int cost_ms;
} answer_t;

typedef struct fake fake_t;

struct fake {
    pthread_mutex_t mu;
    atomic_bool stop;
    int64_t now;
    int64_t limit_ms;
    char lines[MAX_LINES][1024];
    int64_t at[MAX_LINES];
    int n;
    char seen_intent[512];
    char dir[64];
    char path[128];
    answer_t lists[MAX_ANS];
    int n_lists, i_lists;
    answer_t posts[MAX_ANS];
    int n_posts, i_posts;
    answer_t ns[MAX_ANS];
    int n_ns, i_ns;
    bool devs[32];
    int n_devs, i_devs;
    char holder[16];
    firc_err_t unpersist_err;
    atomic_bool parked;
    atomic_bool gate;
    firc_opkgtun_t *m;
    void (*hook)(fake_t *f, const char *line);
    int hook_fired;
    firc_opkgtun_seen_t hook_seen[8];
    int n_hook_seen;
};

static char *slurp(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    char *buf = malloc(65536);
    size_t n = buf != NULL ? fread(buf, 1, 65535, f) : 0;
    fclose(f);
    if (buf != NULL) { buf[n] = '\0'; }
    return buf;
}

static char *fx(const char *name)
{
    char path[160];
    snprintf(path, sizeof path, FX "%s", name);
    return slurp(path);
}

static char *rc_from(const char *fixture, const char *name, const char *desc, const char *addr, const char *mask,
                     int up, bool private_level)
{
    char *text = fx(fixture);
    cJSON *root = cJSON_Parse(text);
    free(text);
    cJSON *item = cJSON_DetachItemFromObjectCaseSensitive(root, "OpkgTun9");
    cJSON_DeleteItemFromObjectCaseSensitive(item, "description");
    if (desc != NULL) { cJSON_AddStringToObject(item, "description", desc); }
    cJSON *ip = cJSON_GetObjectItemCaseSensitive(item, "ip");
    if (addr != NULL) {
        cJSON_DeleteItemFromObjectCaseSensitive(ip, "address");
        cJSON *a = cJSON_AddObjectToObject(ip, "address");
        cJSON_AddStringToObject(a, "address", addr);
        cJSON_AddStringToObject(a, "mask", mask);
    }
    if (up >= 0) {
        cJSON_DeleteItemFromObjectCaseSensitive(item, "up");
        if (up > 0) { cJSON_AddTrueToObject(item, "up"); }
    }
    if (private_level) {
        cJSON_DeleteItemFromObjectCaseSensitive(item, "security-level");
        cJSON *l = cJSON_AddObjectToObject(item, "security-level");
        cJSON_AddTrueToObject(l, "private");
    }
    cJSON_AddItemToObject(root, name, item);
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

static char *ours3(void)
{
    return rc_from("rc-list-ours.json", "OpkgTun3", "firc:t1 PRAW-1", "203.0.113.4", "255.255.255.255", 1, false);
}

static char *created3(void)
{
    return rc_from("rc-list-created.json", "OpkgTun3", "firc:t1", NULL, NULL, -1, false);
}

static char *half3(void)
{
    return rc_from("rc-list-after-refused.json", "OpkgTun3", NULL, NULL, NULL, -1, false);
}

static char *pick(const char *fixture, const int *idx, int n)
{
    char *text = fx(fixture);
    cJSON *src = cJSON_Parse(text);
    free(text);
    cJSON *out = cJSON_CreateArray();
    for (int i = 0; i < n; i++) {
        cJSON_AddItemToArray(out, cJSON_Duplicate(cJSON_GetArrayItem(src, idx[i]), true));
    }
    char *s = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    cJSON_Delete(src);
    return s;
}

static char *p5_answer(void)
{
    static const int idx[] = {0, 2, 3};
    return pick("configure-ok.json", idx, 3);
}

static answer_t ok(char *body)
{
    return (answer_t){.body = body};
}

static answer_t fail(firc_err_t err)
{
    return (answer_t){.err = err};
}

static void add(answer_t *arr, int *n, answer_t a)
{
    arr[(*n)++] = a;
}

static void note_intent(fake_t *f)
{
    char *t = slurp(f->path);
    char cur[512];
    snprintf(cur, sizeof cur, "%s", t != NULL ? t : "");
    free(t);
    size_t len = strlen(cur);
    if (len > 0 && cur[len - 1] == '\n') { cur[len - 1] = '\0'; }
    if (strcmp(cur, f->seen_intent) != 0 && f->n < MAX_LINES) {
        snprintf(f->seen_intent, sizeof f->seen_intent, "%s", cur);
        f->at[f->n] = f->now;
        snprintf(f->lines[f->n++], sizeof f->lines[0], "INTENT %s", cur);
    }
}

static void say_line(fake_t *f, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void say_line(fake_t *f, const char *fmt, ...)
{
    pthread_mutex_lock(&f->mu);
    note_intent(f);
    char line[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (f->n < MAX_LINES) {
        f->at[f->n] = f->now;
        snprintf(f->lines[f->n++], sizeof f->lines[0], "%s", line);
    }
    pthread_mutex_unlock(&f->mu);
    if (f->hook != NULL) { f->hook(f, line); }
}

static void park(fake_t *f)
{
    atomic_store(&f->parked, true);
    for (int i = 0; i < 2500 && !atomic_load(&f->stop); i++) {
        struct timespec ts = {0, 2 * 1000000L};
        nanosleep(&ts, NULL);
    }
    atomic_store(&f->stop, true);
}

static firc_err_t answer(fake_t *f, answer_t *arr, int n, int *i, char **out)
{
    *out = NULL;
    if (*i >= n) {
        park(f);
        return FIRC_ERR_CANCELED;
    }
    answer_t *a = &arr[(*i)++];
    f->now += a->cost_ms;
    if (a->err == FIRC_ERR_CANCELED) {
        park(f);
        return FIRC_ERR_CANCELED;
    }
    if (a->err != FIRC_OK) { return a->err; }
    *out = strdup(a->body);
    return FIRC_OK;
}

static firc_err_t f_get(void *ud, const char *path, char **body)
{
    fake_t *f = ud;
    if (strcmp(path, FIRC_OPKGTUN_LIST_PATH) == 0) {
        say_line(f, "L");
        return answer(f, f->lists, f->n_lists, &f->i_lists, body);
    }
    if (strcmp(path, FIRC_OPKGTUN_NS_PATH) == 0) {
        say_line(f, "GET name-server");
        return answer(f, f->ns, f->n_ns, &f->i_ns, body);
    }
    say_line(f, "GET %s", path);
    *body = NULL;
    return FIRC_ERR_UPSTREAM;
}

static firc_err_t f_post(void *ud, const char *body, long timeout_s, char **out)
{
    fake_t *f = ud;
    say_line(f, "POST %s T=%ld", body, timeout_s);
    return answer(f, f->posts, f->n_posts, &f->i_posts, out);
}

static bool f_dev(void *ud, const char *dev)
{
    fake_t *f = ud;
    say_line(f, "DEV %s", dev);
    return f->i_devs < f->n_devs ? f->devs[f->i_devs++] : false;
}

static firc_err_t f_unpersist(void *ud, const char *dev)
{
    fake_t *f = ud;
    say_line(f, "UNPERSIST %s", dev);
    return f->unpersist_err;
}

static bool f_hold(void *ud, int n, const char *own, char out[16])
{
    fake_t *f = ud;
    say_line(f, "HOLD %d %s", n, own);
    snprintf(out, 16, "%s", f->holder);
    return f->holder[0] != '\0';
}

static int64_t f_now(void *ud)
{
    fake_t *f = ud;
    while (atomic_load(&f->gate) && !atomic_load(&f->stop)) {
        struct timespec ts = {0, 1000000L};
        nanosleep(&ts, NULL);
    }
    return f->now;
}

static bool f_sleep(void *ud, int ms)
{
    fake_t *f = ud;
    say_line(f, "SLEEP %d", ms);
    if (f->now + ms > f->limit_ms) {
        park(f);
        return false;
    }
    f->now += ms;
    return !atomic_load(&f->stop);
}

static fake_t *fake_new(void)
{
    fake_t *f = calloc(1, sizeof *f);
    pthread_mutex_init(&f->mu, NULL);
    f->limit_ms = 200000;
    snprintf(f->dir, sizeof f->dir, "/tmp/firc_opkg_XXXXXX");
    if (mkdtemp(f->dir) == NULL) { abort(); }
    snprintf(f->path, sizeof f->path, "%s/opkgtun", f->dir);
    return f;
}

static void fake_intent(fake_t *f, const char *text)
{
    FILE *o = fopen(f->path, "w");
    fputs(text, o);
    fclose(o);
    snprintf(f->seen_intent, sizeof f->seen_intent, "%s", text);
    size_t len = strlen(f->seen_intent);
    if (len > 0 && f->seen_intent[len - 1] == '\n') { f->seen_intent[len - 1] = '\0'; }
}

static firc_opkgtun_io_t fake_io(fake_t *f)
{
    return (firc_opkgtun_io_t){.get = f_get,
                               .post = f_post,
                               .dev_exists = f_dev,
                               .unpersist = f_unpersist,
                               .addr_holder = f_hold,
                               .now_ms = f_now,
                               .sleep_ms = f_sleep,
                               .intent_path = f->path,
                               .stop = &f->stop,
                               .ud = f};
}

static firc_opkgtun_t *fake_start(fake_t *f)
{
    atomic_store(&f->gate, true);
    firc_opkgtun_io_t io = fake_io(f);
    f->m = firc_opkgtun_start(&io);
    return f->m;
}

static void fake_go(fake_t *f)
{
    atomic_store(&f->gate, false);
}

static bool fake_settle(fake_t *f)
{
    for (int i = 0; i < 5000; i++) {
        if (atomic_load(&f->parked) || firc_opkgtun_idle_for_test(f->m)) {
            pthread_mutex_lock(&f->mu);
            note_intent(f);
            pthread_mutex_unlock(&f->mu);
            return true;
        }
        struct timespec ts = {0, 1000000L};
        nanosleep(&ts, NULL);
    }
    return false;
}

static void free_answers(answer_t *a, int n)
{
    for (int i = 0; i < n; i++) { free(a[i].body); }
}

static void fake_end(fake_t *f)
{
    if (f->m != NULL) { firc_opkgtun_stop(f->m); }
    free_answers(f->lists, f->n_lists);
    free_answers(f->posts, f->n_posts);
    free_answers(f->ns, f->n_ns);
    char cmd[96];
    snprintf(cmd, sizeof cmd, "rm -rf %s", f->dir);
    int rc = system(cmd);
    (void)rc;
    pthread_mutex_destroy(&f->mu);
    free(f);
}

static bool log_is(fake_t *f, bool sleeps, const char *const *want)
{
    int k = 0;
    bool same = true;
    for (int i = 0; i < f->n; i++) {
        if (!sleeps && strncmp(f->lines[i], "SLEEP ", 6) == 0) { continue; }
        if (want[k] == NULL || strcmp(want[k], f->lines[i]) != 0) { same = false; }
        if (want[k] != NULL) { k++; }
    }
    if (want[k] != NULL) { same = false; }
    if (!same) {
        fprintf(stderr, "log:\n");
        for (int i = 0; i < f->n; i++) { fprintf(stderr, "  @%lld %s\n", (long long)f->at[i], f->lines[i]); }
        fprintf(stderr, "want:\n");
        for (int i = 0; want[i] != NULL; i++) { fprintf(stderr, "  %s\n", want[i]); }
    }
    return same;
}

static int count(fake_t *f, const char *prefix)
{
    int c = 0;
    for (int i = 0; i < f->n; i++) { c += strncmp(f->lines[i], prefix, strlen(prefix)) == 0; }
    return c;
}

static int64_t time_of(fake_t *f, const char *line)
{
    for (int i = 0; i < f->n; i++) {
        if (strcmp(f->lines[i], line) == 0) { return f->at[i]; }
    }
    return -1;
}

static firc_opkgtun_seen_t seen_of(fake_t *f)
{
    firc_opkgtun_seen_t s[4];
    memset(s, 0, sizeof s);
    size_t n = firc_opkgtun_seen(f->m, s, 4);
    if (n == 0) { s[0].state = (firc_opkg_state_t)-1; }
    return s[0];
}

static firc_opkgtun_want_t want3(void)
{
    firc_opkgtun_want_t w = {.name = "OpkgTun3", .device = "opkgtun3", .n = 3, .mark = "firc:t1",
                             .desc = "firc:t1 PRAW-1", .present = true};
    return w;
}

static firc_opkgtun_want_t gone3(void)
{
    firc_opkgtun_want_t w = want3();
    w.present = false;
    return w;
}

static void want1(fake_t *f, firc_opkgtun_want_t w)
{
    firc_opkgtun_want(f->m, &w, 1);
}

static void record_seen(fake_t *f, const char *line)
{
    (void)line;
    if (f->n_hook_seen < 8) {
        firc_opkgtun_seen_t s[1];
        if (firc_opkgtun_seen(f->m, s, 1) == 1) { f->hook_seen[f->n_hook_seen++] = s[0]; }
    }
}

static void seen_at_save(fake_t *f, const char *line)
{
    if (strncmp(line, "POST", 4) == 0 || strcmp(line, "L") == 0) { record_seen(f, line); }
}

/* catches: an outcome read from a named GET or the HTTP status instead of the list's keys */
TEST classify_reads_the_captures(void)
{
    firc_opkgtun_rc_t rc;
    char *t = fx("rc-list-without.json");
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(t, "OpkgTun9", &rc));
    ASSERT_EQ(FIRC_OPKG_RC_ABSENT, rc.kind);
    free(t);
    t = fx("not-known.txt");
    ASSERT_EQ(FIRC_ERR_PROTO, firc_opkgtun_classify(t, "OpkgTun9", &rc));
    free(t);
    t = fx("rc-name-absent.json");
    ASSERT_EQ(FIRC_ERR_PROTO, firc_opkgtun_classify(t, "OpkgTun9", &rc));
    free(t);
    t = fx("rc-list-created.json");
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(t, "OpkgTun9", &rc));
    ASSERT_EQ(FIRC_OPKG_RC_OURS, rc.kind);
    ASSERT_STR_EQ("firc:e5", rc.mark);
    ASSERT(rc.public_level);
    ASSERT_STR_EQ("", rc.address);
    ASSERT_FALSE(rc.up);
    free(t);
    t = fx("rc-list-ours.json");
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(t, "OpkgTun9", &rc));
    ASSERT_EQ(FIRC_OPKG_RC_OURS, rc.kind);
    ASSERT_STR_EQ("firc:e5", rc.mark);
    ASSERT_STR_EQ("firc:e5 \xd0\xa2\xd0\xb5\xd1\x81\xd1\x82 \"q\"", rc.description);
    ASSERT(rc.public_level);
    ASSERT_STR_EQ("203.0.113.250", rc.address);
    ASSERT_STR_EQ("255.255.255.255", rc.mask);
    ASSERT(rc.up);
    free(t);
    t = fx("rc-list-foreign.json");
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(t, "OpkgTun9", &rc));
    ASSERT_EQ(FIRC_OPKG_RC_FOREIGN, rc.kind);
    ASSERT_STR_EQ("hand", rc.description);
    free(t);
    PASS();
}

/* catches: an error object read as absent */
TEST a_200_that_is_not_a_list_is_not_known(void)
{
    firc_opkgtun_rc_t rc;
    char *t = fx("l-not-a-list.json");
    ASSERT_EQ(FIRC_ERR_PROTO, firc_opkgtun_classify(t, "NoSuch0", &rc));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_opkgtun_classify(t, "OpkgTun3", &rc));
    free(t);
    PASS();
}

/* catches: an outcome taken from the HTTP status, or from the first status entry only */
TEST item_outcomes_read_the_status_tree(void)
{
    firc_opkg_item_t out[4];
    char err[160];
    char *t = fx("create-ok.json");
    ASSERT_EQ(1, firc_opkgtun_items(t, out, 4, err, sizeof err));
    ASSERT_EQ(FIRC_OPKG_ITEM_APPLIED, out[0]);
    free(t);
    t = fx("create-index-too-large.json");
    ASSERT_EQ(1, firc_opkgtun_items(t, out, 4, err, sizeof err));
    ASSERT_EQ(FIRC_OPKG_ITEM_REFUSED, out[0]);
    free(t);
    t = fx("create-desc-refused.json");
    ASSERT_EQ(1, firc_opkgtun_items(t, out, 4, err, sizeof err));
    ASSERT_EQ(FIRC_OPKG_ITEM_PARTIAL, out[0]);
    ASSERT_STR_EQ("\"OpkgTun9\": description length exceeds 256 bytes.", err);
    free(t);
    t = fx("delete-absent.json");
    ASSERT_EQ(1, firc_opkgtun_items(t, out, 4, err, sizeof err));
    ASSERT_EQ(FIRC_OPKG_ITEM_REFUSED, out[0]);
    free(t);
    t = fx("configure-ok.json");
    ASSERT_EQ(4, firc_opkgtun_items(t, out, 4, err, sizeof err));
    for (int i = 0; i < 4; i++) { ASSERT_EQ(FIRC_OPKG_ITEM_APPLIED, out[i]); }
    ASSERT_STR_EQ("", err);
    free(t);
    ASSERT_EQ(-1, firc_opkgtun_items("{\"status\":[]}", out, 4, err, sizeof err));
    PASS();
}

/* catches: a refusal inside an HTTP 200 read as success, or its message lost */
TEST a_refusal_is_read_from_the_batch(void)
{
    firc_opkg_item_t out[1];
    char err[160];
    char *t = fx("create-index-too-large.json");
    ASSERT_EQ(1, firc_opkgtun_items(t, out, 1, err, sizeof err));
    free(t);
    ASSERT_EQ(FIRC_OPKG_ITEM_REFUSED, out[0]);
    ASSERT_STR_EQ("index 17 is too large for \"OpkgTun\" interface.", err);
    PASS();
}

/* catches: a mark matched by prefix, case or any word */
TEST ownership_is_the_mark(void)
{
    ASSERT(firc_opkgtun_ours("firc:t1 x"));
    ASSERT(firc_opkgtun_ours("firc:t1"));
    ASSERT(firc_opkgtun_ours("firc:a_b-9"));
    ASSERT_FALSE(firc_opkgtun_ours("firc"));
    ASSERT_FALSE(firc_opkgtun_ours("firc:"));
    ASSERT_FALSE(firc_opkgtun_ours("Firc:t1"));
    ASSERT(firc_opkgtun_ours("firc:t 1"));
    ASSERT_FALSE(firc_opkgtun_ours("firc:t.1"));
    ASSERT_FALSE(firc_opkgtun_ours("awgm Home"));
    ASSERT_FALSE(firc_opkgtun_ours(""));
    ASSERT_FALSE(firc_opkgtun_ours(NULL));
    PASS();
}

/* catches: a cut, or a dropped space */
TEST the_longest_description_is_kept_whole(void)
{
    char desc[64];
    memset(desc, 'a', 63);
    desc[63] = '\0';
    char *d = firc_opkgtun_description("abcdefghijklmno", desc);
    ASSERT_EQ(84, strlen(d));
    ASSERT_EQ(0, strncmp(d, "firc:abcdefghijklmno ", 21));
    ASSERT_EQ('a', d[83]);
    ASSERT_EQ(63, strspn(d + 21, "a"));
    free(d);
    d = firc_opkgtun_description("t1", "");
    ASSERT_STR_EQ("firc:t1", d);
    free(d);
    char more[65];
    memset(more, 'a', 64);
    more[64] = '\0';
    ASSERT_EQ(NULL, firc_opkgtun_description("t1", more));
    ASSERT_EQ(NULL, firc_opkgtun_description("abcdefghijklmnop", ""));
    PASS();
}

/* catches: an empty description, or a missing description key, read as ours or foreign */
TEST classify_unmarked_both_shapes(void)
{
    firc_opkgtun_rc_t rc;
    char *t = fx("rc-list-after-refused.json");
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(t, "OpkgTun9", &rc));
    free(t);
    ASSERT_EQ(FIRC_OPKG_RC_UNMARKED, rc.kind);
    char *e = rc_from("rc-list-after-refused.json", "OpkgTun9", "", NULL, NULL, -1, false);
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(e, "OpkgTun9", &rc));
    free(e);
    ASSERT_EQ(FIRC_OPKG_RC_UNMARKED, rc.kind);
    PASS();
}

/* catches: {} read as a good list, or a non-OpkgTun key taken as a record */
TEST a_good_list_is_non_empty_and_only_opkgtun_keys_count(void)
{
    firc_opkgtun_rc_t rc;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_opkgtun_classify("{}", "OpkgTun3", &rc));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_opkgtun_classify("{\"OpkgTun3\":\"x\"}", "OpkgTun3", &rc));
    const char *l = "{\"Wireguard0\":{\"description\":\"firc:x\"},\"OpkgTun17\":{\"description\":\"firc:y\"},"
                    "\"OpkgTun03\":{\"description\":\"firc:z\"}}";
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(l, "Wireguard0", &rc));
    ASSERT(rc.kind != FIRC_OPKG_RC_OURS);
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(l, "OpkgTun17", &rc));
    ASSERT(rc.kind != FIRC_OPKG_RC_OURS);
    ASSERT_EQ(FIRC_OK, firc_opkgtun_classify(l, "OpkgTun03", &rc));
    ASSERT(rc.kind != FIRC_OPKG_RC_OURS);
    PASS();
}

static void base_script(fake_t *f)
{
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(created3()));
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->posts, &f->n_posts, ok(fx("create-ok.json")));
    add(f->posts, &f->n_posts, ok(p5_answer()));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
}

/* catches: an unmarked create, no creating line before the POST, no read-back, ready before the device, a needless
   security item, the timeouts left at 2 */
TEST a_new_record_is_created_marked_configured_and_waits_for_its_device(void)
{
    fake_t *f = fake_new();
    base_script(f);
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = true;
    f->hook = seen_at_save;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",
                                       "DEV opkgtun3",
                                       "HOLD 3 opkgtun3",
                                       "INTENT creating OpkgTun3\ndirty",
                                       CREATE3,
                                       "L",
                                       "INTENT dirty",
                                       P5_3,
                                       "L",
                                       "DEV opkgtun3",
                                       "SLEEP 500",
                                       "DEV opkgtun3",
                                       "SLEEP 1000",
                                       SAVE,
                                       "INTENT ",
                                       NULL};
    ASSERT(log_is(f, true, want));
    ASSERT_EQ(1500, time_of(f, SAVE));
    ASSERT_EQ(FIRC_OPKG_PENDING, f->hook_seen[0].state);
    ASSERT_EQ(FIRC_OPKG_READY, f->hook_seen[f->n_hook_seen - 1].state);
    ASSERT_FALSE(f->hook_seen[f->n_hook_seen - 1].saved);
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_READY, s.state);
    ASSERT(s.saved);
    ASSERT_STR_EQ("", s.error);
    fake_end(f);
    PASS();
}

/* catches: HOLD after a write */
TEST a_held_address_sends_no_write(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    snprintf(f->holder, sizeof f->holder, "ezcfg0");
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "DEV opkgtun3", "HOLD 3 opkgtun3", "L", NULL};
    ASSERT(log_is(f, false, want));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FAILED, s.state);
    ASSERT_STR_EQ("203.0.113.4 is already on ezcfg0", s.error);
    ASSERT_EQ(0, count(f, "INTENT"));
    fake_end(f);
    PASS();
}

/* catches: a write to a record that already matches */
TEST an_adopted_record_that_matches_writes_nothing(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(ours3()));
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "DEV opkgtun3", NULL};
    ASSERT(log_is(f, true, want));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_READY, s.state);
    ASSERT(s.saved);
    fake_end(f);
    PASS();
}

/* catches: an adopted record left with another tunnel's mark, or its change not saved */
TEST an_adopted_record_that_differs_is_reconfigured_and_saved(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists,
        ok(rc_from("rc-list-ours.json", "OpkgTun3", "firc:t9 old", "203.0.113.4", "255.255.255.255", 1, false)));
    add(f->lists, &f->n_lists, ok(ours3()));
    static const int idx[] = {0};
    add(f->posts, &f->n_posts, ok(pick("configure-ok.json", idx, 1)));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "INTENT dirty", "POST [" DESC3 "] T=10", "L", "DEV opkgtun3",
                                       SAVE, "INTENT ", NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(1000, time_of(f, SAVE));
    ASSERT(seen_of(f).saved);
    fake_end(f);
    PASS();
}

/* catches: an up-only P5 that saves */
TEST an_up_only_restore_saves_nothing(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists,
        ok(rc_from("rc-list-ours.json", "OpkgTun3", "firc:t1 PRAW-1", "203.0.113.4", "255.255.255.255", 0, false)));
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->posts, &f->n_posts, ok(fx("configure-up-only.json")));
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "POST [" UP3 "] T=10", "L", "DEV opkgtun3", NULL};
    ASSERT(log_is(f, true, want));
    ASSERT_EQ(FIRC_OPKG_READY, seen_of(f).state);
    ASSERT(seen_of(f).saved);
    fake_end(f);
    PASS();
}

/* catches: a refused create that leaves dirty set with nothing pending */
TEST a_refused_create_leaves_nothing_dirty(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->posts, &f->n_posts, ok(fx("create-index-too-large.json")));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3, "INTENT ", NULL};
    ASSERT(log_is(f, true, want));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FAILED, s.state);
    ASSERT_STR_EQ("index 17 is too large for \"OpkgTun\" interface.", s.error);
    fake_end(f);
    PASS();
}

/* catches: a refusal that keeps its creating line */
TEST a_refusal_removes_its_creating_line(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->posts, &f->n_posts, ok(fx("create-index-too-large.json")));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    char *t = slurp(f->path);
    ASSERT(t != NULL);
    ASSERT_STR_EQ("", t);
    free(t);
    fake_end(f);
    PASS();
}

/* catches: a timeout taken as failure */
TEST a_timed_out_create_whose_record_exists_is_adopted(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(created3()));
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->posts, &f->n_posts, fail(FIRC_ERR_TIMEOUT));
    add(f->posts, &f->n_posts, ok(p5_answer()));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",  "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3, "L", "INTENT dirty", P5_3, "L", "DEV opkgtun3", SAVE, "INTENT ",
                                       NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(FIRC_OPKG_READY, seen_of(f).state);
    fake_end(f);
    PASS();
}

/* catches: a timed-out create whose record is not listed cleared or given up */
TEST a_timed_out_create_with_no_record_keeps_dirty(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->posts, &f->n_posts, fail(FIRC_ERR_TIMEOUT));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3, "L", "INTENT dirty", "SLEEP 1000", "L", NULL};
    ASSERT(log_is(f, true, want));
    ASSERT_EQ(FIRC_OPKG_FAILED, seen_of(f).state);
    fake_end(f);
    PASS();
}

/* catches: a failed intent write that still POSTs */
TEST a_failed_intent_write_sends_nothing(void)
{
    fake_t *f = fake_new();
    snprintf(f->path, sizeof f->path, "%s/gone/opkgtun", f->dir);
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    ASSERT_EQ(0, count(f, "POST"));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FAILED, s.state);
    char msg[200];
    snprintf(msg, sizeof msg, "cannot write %s", f->path);
    ASSERT_STR_EQ(msg, s.error);
    fake_end(f);
    PASS();
}

/* catches: a foreign record touched */
TEST a_foreign_description_is_not_touched(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists,
        ok(rc_from("rc-list-foreign.json", "OpkgTun3", "hand", "203.0.113.4", "255.255.255.255", 1, false)));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", NULL};
    ASSERT(log_is(f, true, want));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FOREIGN, s.state);
    ASSERT(strstr(s.error, "\"hand\"") != NULL);
    fake_end(f);
    PASS();
}

/* catches: a create over a device someone else made */
TEST a_device_without_a_record_is_foreign(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "DEV opkgtun3", NULL};
    ASSERT(log_is(f, true, want));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FOREIGN, s.state);
    ASSERT_STR_EQ("opkgtun3 exists and is not a router interface", s.error);
    fake_end(f);
    PASS();
}

/* catches: no read-back, or a read-back that trusts the answer */
TEST a_mismatched_read_back_fails(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(created3()));
    add(f->lists, &f->n_lists,
        ok(rc_from("rc-list-ours.json", "OpkgTun3", "firc:t1 PRAW-1", "203.0.113.4", "255.255.255.0", 1, false)));
    add(f->posts, &f->n_posts, ok(fx("create-ok.json")));
    add(f->posts, &f->n_posts, ok(p5_answer()));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3, "L", "INTENT dirty", P5_3, "L", "L", NULL};
    ASSERT(log_is(f, false, want));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FAILED, s.state);
    ASSERT_STR_EQ("the router kept mask 255.255.255.0", s.error);
    ASSERT_EQ(0, count(f, SAVE));
    fake_end(f);
    PASS();
}

/* catches: the name-server filter by address only, or a removal that leaves its name servers */
TEST a_removal_clears_its_name_servers_first(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->ns, &f->n_ns,
        ok(strdup("[{\"address\":\"1.1.1.1\",\"domain\":\"\",\"interface\":\"Wireguard1\"},"
                  "{\"address\":\"192.0.2.53\",\"domain\":\"\",\"interface\":\"OpkgTun3\"},"
                  "{\"address\":\"8.8.8.8\",\"domain\":\"\"}]")));
    add(f->posts, &f->n_posts, ok(fx("ns-remove-ok.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    want1(f, gone3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {
        "L",
        "GET name-server",
        "INTENT dirty",
        "POST [{\"ip\":{\"name-server\":{\"no\":true,\"address\":\"192.0.2.53\",\"domain\":\"\",\"interface\":"
        "\"OpkgTun3\"}}}] T=10",
        DELETE3,
        "DEV opkgtun3",
        SAVE,
        "INTENT ",
        NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(5000, time_of(f, SAVE));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_READY, s.state);
    ASSERT(s.removing);
    ASSERT(s.saved);
    fake_end(f);
    PASS();
}

/* catches: unpersist before the delete, or a leftover device kept */
TEST a_device_left_behind_is_unpersisted_after_the_record(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    for (int i = 0; i < 5; i++) { f->devs[f->n_devs++] = true; }
    fake_start(f);
    want1(f, gone3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",          "GET name-server", "INTENT dirty", DELETE3,      "DEV opkgtun3",
                                       "SLEEP 500",  "DEV opkgtun3",    "SLEEP 500",    "DEV opkgtun3", "SLEEP 500",
                                       "DEV opkgtun3", "SLEEP 500",     "DEV opkgtun3", "UNPERSIST opkgtun3",
                                       "SLEEP 1000", "SLEEP 1000",      "SLEEP 1000",   SAVE,         "INTENT ",
                                       NULL};
    ASSERT(log_is(f, true, want));
    fake_end(f);
    PASS();
}

/* catches: wants applied one by one instead of the latest set */
TEST wants_coalesce(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    fake_start(f);
    want1(f, want3());
    want1(f, gone3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", NULL};
    ASSERT(log_is(f, true, want));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_READY, s.state);
    ASSERT(s.removing);
    fake_end(f);
    PASS();
}

static char *sweep_list(void)
{
    char *t = fx("rc-list-ours.json");
    cJSON *root = cJSON_Parse(t);
    free(t);
    cJSON *base = cJSON_DetachItemFromObjectCaseSensitive(root, "OpkgTun9");
    const char *names[] = {"OpkgTun1", "OpkgTun2", "OpkgTun3"};
    const char *descs[] = {"firc:a", "firc:b", "awgm"};
    const char *addrs[] = {"203.0.113.2", "203.0.113.3", "203.0.113.4"};
    for (int i = 0; i < 3; i++) {
        cJSON *it = cJSON_Duplicate(base, true);
        cJSON_ReplaceItemInObjectCaseSensitive(it, "description", cJSON_CreateString(descs[i]));
        cJSON *a = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(it, "ip"), "address");
        cJSON_ReplaceItemInObjectCaseSensitive(a, "address", cJSON_CreateString(addrs[i]));
        cJSON_AddItemToObject(root, names[i], it);
    }
    cJSON_Delete(base);
    cJSON *wg = cJSON_GetObjectItemCaseSensitive(root, "Wireguard0");
    cJSON_ReplaceItemInObjectCaseSensitive(wg, "description", cJSON_CreateString("firc:x"));
    char *out = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return out;
}

/* catches: the keep set taken at queue time, or a non-OpkgTun record removed */
TEST the_sweep_keeps_what_is_wanted_when_it_runs(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(sweep_list()));
    add(f->lists, &f->n_lists, ok(sweep_list()));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = true;
    f->devs[f->n_devs++] = false;
    fake_start(f);
    firc_opkgtun_want(f->m, NULL, 0);
    firc_opkgtun_sweep_now(f->m);
    firc_opkgtun_want_t b = {.name = "OpkgTun2", .device = "opkgtun2", .n = 2, .mark = "firc:b", .desc = "firc:b",
                             .present = true};
    want1(f, b);
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",
                                       "DEV opkgtun2",
                                       "L",
                                       "GET name-server",
                                       "INTENT dirty",
                                       "POST [{\"interface\":{\"name\":\"OpkgTun1\",\"no\":true}}] T=10",
                                       "DEV opkgtun1",
                                       SAVE,
                                       "INTENT ",
                                       NULL};
    ASSERT(log_is(f, false, want));
    fake_end(f);
    PASS();
}

/* catches: a stop that waits out the device poll or unpersists on the way out */
TEST a_stop_during_the_device_poll_returns_at_once(void)
{
    fake_t *f = fake_new();
    f->limit_ms = 0;
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    for (int i = 0; i < 5; i++) { f->devs[f->n_devs++] = true; }
    fake_start(f);
    want1(f, gone3());
    fake_go(f);
    ASSERT(fake_settle(f));
    ASSERT(atomic_load(&f->parked));
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    firc_opkgtun_stop(f->m);
    f->m = NULL;
    clock_gettime(CLOCK_MONOTONIC, &b);
    ASSERT((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < 1000);
    ASSERT_EQ(0, count(f, "UNPERSIST"));
    ASSERT_STR_EQ("SLEEP 500", f->lines[f->n - 1]);
    fake_end(f);
    PASS();
}

/* catches: a host build that starts a worker or leaves the state pending */
TEST the_host_build_answers_without_a_thread(void)
{
#ifdef FIRC_ENTWARE_KN
    SKIP();
#else
    firc_opkgtun_reach_for_test(false);
    fake_t *f = fake_new();
    firc_opkgtun_io_t io = fake_io(f);
    f->m = firc_opkgtun_start(&io);
    firc_opkgtun_reach_for_test(true);
    ASSERT(f->m != NULL);
    want1(f, want3());
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FAILED, s.state);
    ASSERT_STR_EQ("this build cannot reach the router", s.error);
    ASSERT_EQ(0, f->n);
    fake_end(f);
    PASS();
#endif
}

static void seen_at_list(fake_t *f, const char *line)
{
    if (strcmp(line, "L") == 0) { record_seen(f, line); }
}

/* catches: a create after a failed read */
TEST a_failed_read_is_never_absence(void)
{
    fake_t *f = fake_new();
    for (int i = 0; i < 3; i++) { add(f->lists, &f->n_lists, fail(FIRC_ERR_UPSTREAM)); }
    add(f->lists, &f->n_lists, ok(ours3()));
    f->devs[f->n_devs++] = true;
    f->hook = seen_at_list;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "L", "L", "L", "DEV opkgtun3", NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(0, count(f, "POST"));
    int64_t t[4];
    int k = 0;
    for (int i = 0; i < f->n && k < 4; i++) {
        if (strcmp(f->lines[i], "L") == 0) { t[k++] = f->at[i]; }
    }
    ASSERT_EQ(0, t[0]);
    ASSERT_EQ(1000, t[1]);
    ASSERT_EQ(3000, t[2]);
    ASSERT_EQ(7000, t[3]);
    ASSERT_EQ(FIRC_OPKG_PENDING, f->hook_seen[3].state);
    ASSERT_EQ(FIRC_OPKG_READY, seen_of(f).state);
    fake_end(f);
    PASS();
}

/* catches: slow-create absent taken as foreign */
TEST a_slow_create_read_as_absent_with_its_device_is_retried(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(created3()));
    add(f->posts, &f->n_posts, ok(fx("create-ok.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",      "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3,  "L",            "INTENT dirty",    "L",
                                       "DEV opkgtun3", SAVE,     "INTENT ",         "L",
                                       "HOLD 3 opkgtun3", "INTENT dirty", P5_3,  NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(FIRC_OPKG_PENDING, seen_of(f).state);
    fake_end(f);
    PASS();
}

/* catches: a save owed from before the restart being dropped */
TEST a_refusal_after_a_dirty_start_still_saves(void)
{
    fake_t *f = fake_new();
    fake_intent(f, "dirty\n");
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->posts, &f->n_posts, ok(fx("create-index-too-large.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",    "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3, "INTENT dirty", SAVE, "INTENT ", NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(10000, time_of(f, "L"));
    fake_end(f);
    PASS();
}

/* catches: clearing after a batch that partly applied */
TEST a_partly_refused_batch_keeps_dirty(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(rc_from("rc-list-created.json", "OpkgTun3", "firc:t9 old", NULL, NULL, -1, true)));
    char *ok4 = fx("configure-ok.json");
    char *bad = fx("desc-long.json");
    cJSON *a = cJSON_Parse(ok4);
    cJSON *b = cJSON_Parse(bad);
    cJSON_ReplaceItemInArray(a, 2, cJSON_Duplicate(cJSON_GetArrayItem(b, 0), true));
    add(f->posts, &f->n_posts, ok(cJSON_PrintUnformatted(a)));
    cJSON_Delete(a);
    cJSON_Delete(b);
    free(ok4);
    free(bad);
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "HOLD 3 opkgtun3", "INTENT dirty",
                                       "POST [" DESC3 "," LEVEL3 "," ADDR3 "," UP3 "] T=10", SAVE, "INTENT ", NULL};
    ASSERT(log_is(f, false, want));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FAILED, s.state);
    ASSERT_STR_EQ("\"OpkgTun9\": description length exceeds 256 bytes.", s.error);
    fake_end(f);
    PASS();
}

/* catches: clear-on-refusal ignoring another name's timeout */
TEST a_timeout_elsewhere_keeps_dirty(void)
{
    fake_t *f = fake_new();
    char *l2 = rc_from("rc-list-ours.json", "OpkgTun2", "firc:t9 old", "203.0.113.3", "255.255.255.255", 1, false);
    add(f->lists, &f->n_lists, ok(strdup(l2)));
    add(f->lists, &f->n_lists, ok(strdup(l2)));
    add(f->lists, &f->n_lists, ok(l2));
    add(f->posts, &f->n_posts, fail(FIRC_ERR_TIMEOUT));
    add(f->posts, &f->n_posts, ok(fx("create-index-too-large.json")));
    fake_start(f);
    firc_opkgtun_want_t w[2] = {{.name = "OpkgTun2", .device = "opkgtun2", .n = 2, .mark = "firc:t2",
                                 .desc = "firc:t2 B", .present = true},
                                want3()};
    firc_opkgtun_want(f->m, w, 2);
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",
                                       "INTENT dirty",
                                       "POST [{\"interface\":{\"name\":\"OpkgTun2\",\"description\":\"firc:t2 B\"}}] T=10",
                                       "L",
                                       "L",
                                       "DEV opkgtun3",
                                       "HOLD 3 opkgtun3",
                                       "INTENT creating OpkgTun3\ndirty",
                                       CREATE3,
                                       "INTENT dirty",
                                       "L",
                                       NULL};
    ASSERT(log_is(f, false, want));
    fake_end(f);
    PASS();
}

/* catches: a P5 timeout failing without a read-back */
TEST a_timed_out_configure_reads_back_before_failing(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(created3()));
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->posts, &f->n_posts, ok(fx("create-ok.json")));
    add(f->posts, &f->n_posts, fail(FIRC_ERR_TIMEOUT));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",  "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3, "L", "INTENT dirty", P5_3, "L", "DEV opkgtun3", SAVE, "INTENT ",
                                       NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(FIRC_OPKG_READY, seen_of(f).state);
    fake_end(f);

    f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(created3()));
    add(f->lists, &f->n_lists, ok(created3()));
    add(f->posts, &f->n_posts, ok(fx("create-ok.json")));
    add(f->posts, &f->n_posts, fail(FIRC_ERR_TIMEOUT));
    f->devs[f->n_devs++] = false;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want2[] = {"L", "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                        CREATE3, "L", "INTENT dirty", P5_3, "L", "L", NULL};
    ASSERT(log_is(f, false, want2));
    firc_opkgtun_seen_t s = seen_of(f);
    ASSERT_EQ(FIRC_OPKG_FAILED, s.state);
    ASSERT_STR_EQ("the router kept address none", s.error);
    fake_end(f);
    PASS();
}

/* catches: an A3 timeout retrying a delete that already happened */
TEST a_timed_out_delete_whose_record_is_gone_goes_on(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    add(f->posts, &f->n_posts, (answer_t){.err = FIRC_ERR_TIMEOUT, .cost_ms = 10000});
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    want1(f, gone3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "GET name-server", "INTENT dirty", DELETE3, "L", "DEV opkgtun3",
                                       SAVE, "INTENT ", NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(15000, time_of(f, SAVE));
    fake_end(f);
    PASS();
}

/* catches: a refused delete of an absent record retried forever */
TEST a_refused_delete_of_an_absent_record_goes_on(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-absent.json")));
    fake_start(f);
    want1(f, gone3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "GET name-server", "INTENT dirty", DELETE3, "INTENT ", "L",
                                       "DEV opkgtun3", NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(FIRC_OPKG_READY, seen_of(f).state);
    fake_end(f);
    PASS();
}

/* catches: a line that later claims a stranger's empty record */
TEST an_absent_list_read_removes_a_stale_creating_line(void)
{
    fake_t *f = fake_new();
    fake_intent(f, "creating OpkgTun3\ndirty\n");
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    firc_opkgtun_sweep_now(f->m);
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "INTENT dirty", SAVE, "INTENT ", NULL};
    ASSERT(log_is(f, false, want));
    fake_end(f);
    PASS();
}

static void remove_on_create(fake_t *f, const char *line)
{
    if (strcmp(line, CREATE3) == 0 && f->hook_fired++ == 0) { want1(f, gone3()); }
}

/* catches: a pending round with no save */
TEST a_pending_round_schedules_a_save(void)
{
    fake_t *f = fake_new();
    for (int i = 0; i < 3; i++) { add(f->lists, &f->n_lists, ok(fx("rc-list-without.json"))); }
    add(f->posts, &f->n_posts, fail(FIRC_ERR_TIMEOUT));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->hook = remove_on_create;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",  "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3, "L", "INTENT dirty", "L", SAVE, "INTENT ", NULL};
    ASSERT(log_is(f, false, want));
    fake_end(f);
    PASS();
}

/* catches: the 5000 ms rule bound only to the Absent path */
TEST no_save_within_five_seconds_of_a_delete_whoever_asks(void)
{
    fake_t *f = fake_new();
    char *both = rc_from("rc-list-ours.json", "OpkgTun3", "firc:t1 PRAW-1", "203.0.113.4", "255.255.255.255", 1,
                         false);
    add(f->lists, &f->n_lists, ok(strdup(both)));
    add(f->lists, &f->n_lists, ok(both));
    add(f->lists, &f->n_lists, ok(rc_from("rc-list-created.json", "OpkgTun5", "firc:t5", NULL, NULL, -1, false)));
    add(f->lists, &f->n_lists,
        ok(rc_from("rc-list-ours.json", "OpkgTun5", "firc:t5 E", "203.0.113.6", "255.255.255.255", 1, false)));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    add(f->posts, &f->n_posts, (answer_t){.body = fx("create-ok.json"), .cost_ms = 200});
    add(f->posts, &f->n_posts, ok(p5_answer()));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = true;
    fake_start(f);
    firc_opkgtun_want_t w[2] = {gone3(), {.name = "OpkgTun5", .device = "opkgtun5", .n = 5, .mark = "firc:t5",
                                          .desc = "firc:t5 E", .present = true}};
    firc_opkgtun_want(f->m, w, 2);
    fake_go(f);
    ASSERT(fake_settle(f));
    ASSERT_EQ(0, time_of(f, DELETE3));
    ASSERT_EQ(1, count(f, SAVE));
    ASSERT_EQ(5000, time_of(f, SAVE));
    firc_opkgtun_seen_t s[2];
    ASSERT_EQ(2, firc_opkgtun_seen(f->m, s, 2));
    ASSERT_EQ(FIRC_OPKG_READY, s[1].state);
    int64_t ready = -1;
    for (int i = 0; i < f->n; i++) {
        if (strcmp(f->lines[i], "DEV opkgtun5") == 0) { ready = f->at[i]; }
    }
    ASSERT_EQ(1200, ready);
    fake_end(f);
    PASS();
}

/* catches: no 10 s wait, or dirty not saved at start */
TEST a_dirty_start_waits_ten_seconds(void)
{
    fake_t *f = fake_new();
    fake_intent(f, "dirty\n");
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {SAVE, "INTENT ", NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(10000, time_of(f, SAVE));
    fake_end(f);
    PASS();
}

/* catches: a stop that waits for a save in flight, or a save taken as done */
TEST a_stop_during_a_save_returns_within_a_second(void)
{
    fake_t *f = fake_new();
    fake_intent(f, "dirty\n");
    add(f->posts, &f->n_posts, fail(FIRC_ERR_CANCELED));
    fake_start(f);
    fake_go(f);
    ASSERT(fake_settle(f));
    ASSERT(atomic_load(&f->parked));
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    firc_opkgtun_stop(f->m);
    f->m = NULL;
    clock_gettime(CLOCK_MONOTONIC, &b);
    ASSERT((b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000 < 1000);
    char *t = slurp(f->path);
    ASSERT_STR_EQ("dirty\n", t);
    free(t);
    fake_end(f);
    PASS();
}

/* catches: a partial item taken as refused, or the record left foreign */
TEST a_partial_create_leaves_a_claimable_record(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(half3()));
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->posts, &f->n_posts, ok(fx("create-desc-refused.json")));
    add(f->posts, &f->n_posts, ok(p5_answer()));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",  "DEV opkgtun3", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty",
                                       CREATE3, "L", P5_3, "L", "INTENT dirty", "DEV opkgtun3", SAVE, "INTENT ",
                                       NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(FIRC_OPKG_READY, seen_of(f).state);
    fake_end(f);
    PASS();
}

/* catches: a half-made record left foreign although its creating line names it */
TEST a_half_made_record_is_claimed_when_wanted(void)
{
    fake_t *f = fake_new();
    fake_intent(f, "creating OpkgTun3\n");
    add(f->lists, &f->n_lists, ok(half3()));
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->posts, &f->n_posts, ok(p5_answer()));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = true;
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "HOLD 3 opkgtun3", "INTENT creating OpkgTun3\ndirty", P5_3, "L",
                                       "INTENT dirty", "DEV opkgtun3", SAVE, "INTENT ", NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(FIRC_OPKG_READY, seen_of(f).state);
    fake_end(f);

    f = fake_new();
    add(f->lists, &f->n_lists, ok(half3()));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const alone[] = {"L", NULL};
    ASSERT(log_is(f, true, alone));
    ASSERT_EQ(FIRC_OPKG_FOREIGN, seen_of(f).state);
    fake_end(f);
    PASS();
}

/* catches: the sweep deleting a half-made record, or keeping it in silence */
TEST the_sweep_warns_about_a_half_made_record_and_keeps_it(void)
{
    char logpath[] = "/tmp/firc_opkg_log_XXXXXX";
    int fd = mkstemp(logpath);
    ASSERT(fd >= 0);
    firc_log_set_output_floor(FIRC_LOG_WARN);
    firc_log_set_fd(fd);
    fake_t *f = fake_new();
    fake_intent(f, "creating OpkgTun3\n");
    add(f->lists, &f->n_lists, ok(half3()));
    fake_start(f);
    firc_opkgtun_sweep_now(f->m);
    fake_go(f);
    bool settled = fake_settle(f);
    firc_log_set_fd(1);
    firc_log_set_output_floor(FIRC_LOG_ERROR);
    char text[4096] = "";
    ssize_t n = pread(fd, text, sizeof text - 1, 0);
    close(fd);
    unlink(logpath);
    text[n > 0 ? n : 0] = '\0';
    ASSERT(settled);
    static const char *const want[] = {"L", NULL};
    ASSERT(log_is(f, true, want));
    ASSERT(strstr(text, "OpkgTun3 has no description and may be firc's; delete it in the router if it is not") !=
           NULL);
    fake_end(f);
    PASS();
}

/* catches: the creating line dropped by a save */
TEST a_save_keeps_creating_lines(void)
{
    fake_t *f = fake_new();
    fake_intent(f, "creating OpkgTun2\ndirty\n");
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {SAVE, "INTENT creating OpkgTun2", NULL};
    ASSERT(log_is(f, false, want));
    fake_end(f);
    PASS();
}

/* catches: one refusal clearing every creating line */
TEST two_names_in_flight(void)
{
    fake_t *f = fake_new();
    fake_intent(f, "creating OpkgTun2\ncreating OpkgTun3\ndirty\n");
    add(f->lists, &f->n_lists, ok(rc_from("rc-list-after-refused.json", "OpkgTun2", NULL, NULL, NULL, -1, false)));
    add(f->posts, &f->n_posts, ok(fx("create-index-too-large.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L",
                                       "INTENT creating OpkgTun2\ndirty",
                                       "DEV opkgtun3",
                                       "HOLD 3 opkgtun3",
                                       "INTENT creating OpkgTun2\ncreating OpkgTun3\ndirty",
                                       CREATE3,
                                       "INTENT creating OpkgTun2\ndirty",
                                       SAVE,
                                       "INTENT creating OpkgTun2",
                                       NULL};
    ASSERT(log_is(f, false, want));
    fake_end(f);
    PASS();
}

/* catches: a creating line lost by a stop, so a restart leaves its half-made record foreign */
TEST a_restart_keeps_a_creating_line(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->posts, &f->n_posts, fail(FIRC_ERR_CANCELED));
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    ASSERT(fake_settle(f));
    firc_opkgtun_stop(f->m);
    f->m = NULL;
    char *t = slurp(f->path);
    ASSERT_STR_EQ("creating OpkgTun3\ndirty\n", t);
    free(t);

    fake_t *g = fake_new();
    snprintf(g->path, sizeof g->path, "%s", f->path);
    snprintf(g->seen_intent, sizeof g->seen_intent, "creating OpkgTun3\ndirty");
    add(g->lists, &g->n_lists, ok(half3()));
    add(g->lists, &g->n_lists, ok(ours3()));
    add(g->posts, &g->n_posts, ok(p5_answer()));
    add(g->posts, &g->n_posts, ok(strdup(SAVE_OK)));
    g->devs[g->n_devs++] = true;
    fake_start(g);
    want1(g, want3());
    fake_go(g);
    ASSERT(fake_settle(g));
    static const char *const want[] = {"L", "HOLD 3 opkgtun3", P5_3, "L", "INTENT dirty", "DEV opkgtun3", SAVE,
                                       "INTENT ", NULL};
    ASSERT(log_is(g, false, want));
    ASSERT_EQ(10000, time_of(g, "L"));
    fake_end(g);
    fake_end(f);
    PASS();
}

/* catches: a description written into the body without escaping */
TEST a_quote_is_escaped(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists,
        ok(rc_from("rc-list-ours.json", "OpkgTun3", "firc:t1 x", "203.0.113.4", "255.255.255.255", 1, false)));
    static const int idx[] = {0};
    add(f->posts, &f->n_posts, ok(pick("configure-ok.json", idx, 1)));
    fake_start(f);
    firc_opkgtun_want_t w = want3();
    snprintf(w.desc, sizeof w.desc, "firc:t1 a\"b");
    want1(f, w);
    fake_go(f);
    ASSERT(fake_settle(f));
    ASSERT_EQ(1, count(f, "POST [{\"interface\":{\"name\":\"OpkgTun3\",\"description\":\"firc:t1 a\\\"b\"}}] T=10"));
    fake_end(f);
    PASS();
}

/* catches: a one-pass sweep that saves with nothing removed and nothing dirty, or retries a dead list */
TEST the_one_pass_sweep_removes_then_saves(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(sweep_list()));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    firc_opkgtun_io_t io = fake_io(f);
    firc_opkgtun_want_t keep = {.name = "OpkgTun1"};
    size_t removed = 0;
    ASSERT_EQ(FIRC_OK, firc_opkgtun_sweep(&io, &keep, 1, &removed, NULL));
    ASSERT_EQ(1, removed);
    pthread_mutex_lock(&f->mu);
    note_intent(f);
    pthread_mutex_unlock(&f->mu);
    static const char *const want[] = {"L",
                                       "GET name-server",
                                       "INTENT dirty",
                                       "POST [{\"interface\":{\"name\":\"OpkgTun2\",\"no\":true}}] T=10",
                                       "DEV opkgtun2",
                                       SAVE,
                                       "INTENT ",
                                       NULL};
    ASSERT(log_is(f, false, want));
    ASSERT_EQ(5000, time_of(f, SAVE));
    fake_end(f);

    f = fake_new();
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    io = fake_io(f);
    ASSERT_EQ(FIRC_OK, firc_opkgtun_sweep(&io, NULL, 0, &removed, NULL));
    ASSERT_EQ(0, removed);
    ASSERT_EQ(1, f->n);
    fake_end(f);

    f = fake_new();
    add(f->lists, &f->n_lists, fail(FIRC_ERR_UPSTREAM));
    fake_intent(f, "dirty\n");
    io = fake_io(f);
    ASSERT_EQ(FIRC_ERR_UPSTREAM, firc_opkgtun_sweep(&io, NULL, 0, &removed, NULL));
    static const char *const dead[] = {"L", NULL};
    ASSERT(log_is(f, true, dead));
    fake_end(f);
    PASS();
}

/* catches: a want waiting on its backoff blocking another tunnel's save */
TEST a_stuck_want_does_not_block_another_tunnels_save(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, fail(FIRC_ERR_UPSTREAM));
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    add(f->lists, &f->n_lists, ok(created3()));
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->lists, &f->n_lists, fail(FIRC_ERR_UPSTREAM));
    add(f->posts, &f->n_posts, ok(fx("create-ok.json")));
    add(f->posts, &f->n_posts, ok(p5_answer()));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = true;
    fake_start(f);
    firc_opkgtun_want_t w[2] = {{.name = "OpkgTun2", .device = "opkgtun2", .n = 2, .mark = "firc:t2",
                                 .desc = "firc:t2", .present = true},
                                want3()};
    firc_opkgtun_want(f->m, w, 2);
    fake_go(f);
    ASSERT(fake_settle(f));
    ASSERT_EQ(1, count(f, SAVE));
    ASSERT_EQ(1000, time_of(f, SAVE));
    firc_opkgtun_seen_t s[2];
    ASSERT_EQ(2, firc_opkgtun_seen(f->m, s, 2));
    ASSERT_EQ(FIRC_OPKG_PENDING, s[0].state);
    ASSERT_EQ(FIRC_OPKG_READY, s[1].state);
    ASSERT(s[1].saved);
    fake_end(f);
    PASS();
}

/* catches: a creating line kept under a record someone else owns */
TEST a_foreign_record_drops_its_creating_line(void)
{
    fake_t *f = fake_new();
    fake_intent(f, "creating OpkgTun3\n");
    add(f->lists, &f->n_lists,
        ok(rc_from("rc-list-foreign.json", "OpkgTun3", "hand", "203.0.113.4", "255.255.255.255", 1, false)));
    fake_start(f);
    firc_opkgtun_sweep_now(f->m);
    fake_go(f);
    ASSERT(fake_settle(f));
    static const char *const want[] = {"L", "INTENT ", NULL};
    ASSERT(log_is(f, true, want));
    fake_end(f);
    PASS();
}

/* catches: a set past the cap, or with a name twice, taking the place of the last good one */
TEST a_bad_want_set_keeps_the_previous_one(void)
{
    firc_opkgtun_reach_for_test(false);
    fake_t *f = fake_new();
    firc_opkgtun_io_t io = fake_io(f);
    f->m = firc_opkgtun_start(&io);
    firc_opkgtun_reach_for_test(true);
    want1(f, want3());
    firc_opkgtun_want_t two[2] = {want3(), gone3()};
    firc_opkgtun_want(f->m, two, 2);
    firc_opkgtun_seen_t s[4];
    ASSERT_EQ(1, firc_opkgtun_seen(f->m, s, 4));
    ASSERT_STR_EQ("OpkgTun3", s[0].name);
    ASSERT_FALSE(s[0].removing);
    firc_opkgtun_want_t many[FIRC_OPKGTUN_MAX_WANTS + 1];
    for (int i = 0; i <= FIRC_OPKGTUN_MAX_WANTS; i++) {
        many[i] = gone3();
        snprintf(many[i].name, sizeof many[i].name, "OpkgTun%d", 100 + i);
    }
    firc_opkgtun_want(f->m, many, FIRC_OPKGTUN_MAX_WANTS + 1);
    ASSERT_EQ(1, firc_opkgtun_seen(f->m, s, 4));
    ASSERT_STR_EQ("OpkgTun3", s[0].name);
    firc_opkgtun_want(f->m, many, FIRC_OPKGTUN_MAX_WANTS);
    ASSERT_EQ(4, firc_opkgtun_seen(f->m, s, 4));
    ASSERT_STR_EQ("OpkgTun100", s[0].name);
    fake_end(f);
    PASS();
}

static atomic_bool g_fail_threads;

int __real_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg);
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg);
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*fn)(void *), void *arg)
{
    if (atomic_load(&g_fail_threads)) { return EAGAIN; }
    return __real_pthread_create(t, a, fn, arg);
}

/* catches: a failed thread start raising the stop flag the caller shares with other RCI users */
TEST a_failed_thread_start_leaves_the_callers_flag(void)
{
    fake_t *f = fake_new();
    firc_opkgtun_io_t io = fake_io(f);
    atomic_store(&g_fail_threads, true);
    firc_opkgtun_t *m = firc_opkgtun_start(&io);
    atomic_store(&g_fail_threads, false);
    ASSERT_EQ(NULL, m);
    ASSERT_FALSE(atomic_load(&f->stop));
    fake_end(f);
    PASS();
}

/* catches: a name server the router would not unbind passed over in silence */
TEST a_refused_name_server_removal_is_warned(void)
{
    char logpath[] = "/tmp/firc_opkg_log_XXXXXX";
    int fd = mkstemp(logpath);
    ASSERT(fd >= 0);
    firc_log_set_output_floor(FIRC_LOG_WARN);
    firc_log_set_fd(fd);
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(ours3()));
    add(f->ns, &f->n_ns, ok(strdup("[{\"address\":\"192.0.2.53\",\"domain\":\"\",\"interface\":\"OpkgTun3\"}]")));
    add(f->posts, &f->n_posts, ok(fx("delete-absent.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    fake_start(f);
    want1(f, gone3());
    fake_go(f);
    bool settled = fake_settle(f);
    firc_log_set_fd(1);
    firc_log_set_output_floor(FIRC_LOG_ERROR);
    char text[4096] = "";
    ssize_t n = pread(fd, text, sizeof text - 1, 0);
    close(fd);
    unlink(logpath);
    text[n > 0 ? n : 0] = '\0';
    ASSERT(settled);
    ASSERT_EQ(1, count(f, DELETE3));
    ASSERT(strstr(text, "name server 192.0.2.53 on OpkgTun3 was not removed") != NULL);
    fake_end(f);
    PASS();
}

/* catches: a sweep whose removals tunrun never hears of, so a tunvless tunnel stays in bad_config behind them */
TEST the_sweep_reports_what_it_removed(void)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists, ok(sweep_list()));
    add(f->lists, &f->n_lists, ok(sweep_list()));
    add(f->ns, &f->n_ns, ok(fx("name-server-after.json")));
    add(f->posts, &f->n_posts, ok(fx("delete-ok.json")));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = true;
    f->devs[f->n_devs++] = false;
    fake_start(f);
    firc_opkgtun_want(f->m, NULL, 0);
    firc_opkgtun_sweep_now(f->m);
    firc_opkgtun_want_t b = {.name = "OpkgTun2", .device = "opkgtun2", .n = 2, .mark = "firc:b", .desc = "firc:b",
                             .present = true};
    want1(f, b);
    ASSERT_EQ(0u, firc_opkgtun_swept(f->m));
    fake_go(f);
    ASSERT(fake_settle(f));
    ASSERT_EQ(1u << 1, firc_opkgtun_swept(f->m));
    ASSERT_EQ(0u, firc_opkgtun_swept(f->m));
    fake_end(f);
    PASS();
}

static int mute_listener(char *url, size_t cap)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof a;
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) != 0 || listen(fd, 8) != 0 ||
        getsockname(fd, (struct sockaddr *)&a, &len) != 0) {
        return -1;
    }
    snprintf(url, cap, "http://127.0.0.1:%u", (unsigned)ntohs(a.sin_port));
    return fd;
}

static void *raise_soon(void *ud)
{
    struct timespec ts = {0, 200 * 1000000L};
    nanosleep(&ts, NULL);
    atomic_store((atomic_bool *)ud, true);
    return NULL;
}

static int64_t mono_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* catches: a real get or post that is not handed io.stop, so a stop waits out a silent router */
TEST the_real_get_and_post_end_on_the_io_s_stop(void)
{
    char url[64];
    int lfd = mute_listener(url, sizeof url);
    ASSERT(lfd >= 0);
    firc_opkgtun_rci_t r;
    firc_opkgtun_io_t io;
    firc_opkgtun_rci_io(&r, url, "/nonexistent/opkgtun", &io);
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, raise_soon, io.stop));
    int64_t t0 = mono_now();
    char *body = NULL;
    ASSERT_EQ(FIRC_ERR_CANCELED, io.get(io.ud, FIRC_OPKGTUN_LIST_PATH, &body));
    ASSERT(mono_now() - t0 < 1500);
    pthread_join(th, NULL);
    firc_opkgtun_rci_io(&r, url, "/nonexistent/opkgtun", &io);
    ASSERT_EQ(0, pthread_create(&th, NULL, raise_soon, io.stop));
    t0 = mono_now();
    ASSERT_EQ(FIRC_ERR_CANCELED, io.post(io.ud, "[]", 10, &body));
    ASSERT(mono_now() - t0 < 1500);
    pthread_join(th, NULL);
    close(lfd);
    PASS();
}

/* catches: a real sleep that waits its full time after a stop */
TEST the_real_sleep_returns_early_on_stop(void)
{
    firc_opkgtun_rci_t r;
    firc_opkgtun_io_t io;
    firc_opkgtun_rci_io(&r, "http://127.0.0.1:1", "/nonexistent/opkgtun", &io);
    ASSERT(io.sleep_ms(io.ud, 60));
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, raise_soon, io.stop));
    int64_t t0 = mono_now();
    ASSERT_FALSE(io.sleep_ms(io.ud, 5000));
    ASSERT(mono_now() - t0 < 600);
    pthread_join(th, NULL);
    PASS();
}

/* catches: one stop flag shared by two RCI users, so stopping the worker cancels another caller's calls */
TEST each_real_io_has_a_stop_of_its_own(void)
{
    firc_opkgtun_rci_t r1, r2;
    firc_opkgtun_io_t a, b;
    firc_opkgtun_rci_io(&r1, "http://127.0.0.1:1", "/nonexistent/opkgtun", &a);
    firc_opkgtun_rci_io(&r2, "http://127.0.0.1:1", "/nonexistent/opkgtun", &b);
    ASSERT(a.stop != b.stop);
    atomic_store(a.stop, true);
    ASSERT_FALSE(a.sleep_ms(a.ud, 50));
    ASSERT(b.sleep_ms(b.ud, 50));
    PASS();
}

static firc_opkgtun_want_t g_rewant;

static void recheck_on_save(fake_t *f, const char *line)
{
    if (strcmp(line, SAVE) == 0 && f->hook_fired++ == 0) {
        g_rewant.recheck++;
        want1(f, g_rewant);
    }
}

static bool settles_after_one_write(const char *sent, const char *kept)
{
    fake_t *f = fake_new();
    add(f->lists, &f->n_lists,
        ok(rc_from("rc-list-ours.json", "OpkgTun3", "firc:t1 old", "203.0.113.4", "255.255.255.255", 1, false)));
    for (int i = 0; i < 2; i++) {
        add(f->lists, &f->n_lists,
            ok(rc_from("rc-list-ours.json", "OpkgTun3", kept, "203.0.113.4", "255.255.255.255", 1, false)));
    }
    static const int idx[] = {0};
    add(f->posts, &f->n_posts, ok(pick("configure-ok.json", idx, 1)));
    add(f->posts, &f->n_posts, ok(strdup(SAVE_OK)));
    f->devs[f->n_devs++] = true;
    f->devs[f->n_devs++] = true;
    g_rewant = want3();
    snprintf(g_rewant.desc, sizeof g_rewant.desc, "%s", sent);
    f->hook = recheck_on_save;
    fake_start(f);
    want1(f, g_rewant);
    fake_go(f);
    bool settled = fake_settle(f);
    char post[256];
    snprintf(post, sizeof post, "POST [{\"interface\":{\"name\":\"OpkgTun3\",\"description\":\"%s\"}}] T=10", sent);
    const char *const want[] = {"L", "INTENT dirty", post, "L", "DEV opkgtun3", SAVE, "INTENT ", "L", "DEV opkgtun3",
                                NULL};
    bool same = settled && log_is(f, false, want) && seen_of(f).state == FIRC_OPKG_READY &&
                seen_of(f).rechecked == 1 && seen_of(f).saved;
    fake_end(f);
    return same;
}

/* catches: a description the router keeps in its own form sent and saved again on every recheck */
TEST a_description_the_router_rewrites_is_sent_once(void)
{
    ASSERT(settles_after_one_write("firc:t1 PRAW-1 ", "firc:t1 PRAW-1"));
    ASSERT(settles_after_one_write("firc:t1 PRAW  1", "firc:t1 PRAW 1"));
    PASS();
}

static int sweep_waits_said(const char *intent)
{
    char logpath[] = "/tmp/firc_opkg_log_XXXXXX";
    int fd = mkstemp(logpath);
    if (fd < 0) { return -1; }
    firc_log_set_output_floor(FIRC_LOG_WARN);
    firc_log_set_fd(fd);
    fake_t *f = fake_new();
    if (intent != NULL) { fake_intent(f, intent); }
    for (int i = 0; i < 3; i++) { add(f->lists, &f->n_lists, fail(FIRC_ERR_UPSTREAM)); }
    add(f->lists, &f->n_lists, ok(fx("rc-list-without.json")));
    fake_start(f);
    firc_opkgtun_sweep_now(f->m);
    fake_go(f);
    bool settled = fake_settle(f);
    int lists = count(f, "L");
    fake_end(f);
    firc_log_set_fd(1);
    firc_log_set_output_floor(FIRC_LOG_ERROR);
    char text[4096] = "";
    ssize_t n = pread(fd, text, sizeof text - 1, 0);
    close(fd);
    unlink(logpath);
    text[n > 0 ? n : 0] = '\0';
    if (!settled || lists != 4) { return -1; }
    int said = 0;
    for (const char *p = strstr(text, "the sweep waits"); p != NULL; p = strstr(p + 1, "the sweep waits")) { said++; }
    return said;
}

/* catches: a sweep RCI refuses warned on every retry, or warned on a router where firc never made a record */
TEST an_unreachable_sweep_warns_once_and_only_with_something_to_sweep(void)
{
    ASSERT_EQ(0, sweep_waits_said(NULL));
    ASSERT_EQ(1, sweep_waits_said("creating OpkgTun3\n"));
    PASS();
}

static bool held_by(const char *holder)
{
    fake_t *f = fake_new();
    base_script(f);
    f->devs[f->n_devs++] = false;
    f->devs[f->n_devs++] = true;
    snprintf(f->holder, sizeof f->holder, "%s", holder);
    fake_start(f);
    want1(f, want3());
    fake_go(f);
    bool settled = fake_settle(f);
    bool created = settled && count(f, CREATE3) == 1 && seen_of(f).state == FIRC_OPKG_READY;
    fake_end(f);
    return created;
}

/* catches: the tunnel's own tunvless device, still up during a swap to OpkgTun, taken as a holder of its address */
TEST the_tunnels_own_tunvless_device_does_not_hold_its_address(void)
{
    ASSERT(held_by("tunvless3"));
    ASSERT_FALSE(held_by("tunvless4"));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    firc_log_set_output_floor(FIRC_LOG_ERROR);
    firc_opkgtun_reach_for_test(true);
    RUN_TEST(classify_reads_the_captures);
    RUN_TEST(a_200_that_is_not_a_list_is_not_known);
    RUN_TEST(item_outcomes_read_the_status_tree);
    RUN_TEST(a_refusal_is_read_from_the_batch);
    RUN_TEST(ownership_is_the_mark);
    RUN_TEST(the_longest_description_is_kept_whole);
    RUN_TEST(classify_unmarked_both_shapes);
    RUN_TEST(a_good_list_is_non_empty_and_only_opkgtun_keys_count);
    RUN_TEST(a_new_record_is_created_marked_configured_and_waits_for_its_device);
    RUN_TEST(a_held_address_sends_no_write);
    RUN_TEST(an_adopted_record_that_matches_writes_nothing);
    RUN_TEST(an_adopted_record_that_differs_is_reconfigured_and_saved);
    RUN_TEST(an_up_only_restore_saves_nothing);
    RUN_TEST(a_refused_create_leaves_nothing_dirty);
    RUN_TEST(a_refusal_removes_its_creating_line);
    RUN_TEST(a_timed_out_create_whose_record_exists_is_adopted);
    RUN_TEST(a_timed_out_create_with_no_record_keeps_dirty);
    RUN_TEST(a_failed_intent_write_sends_nothing);
    RUN_TEST(a_foreign_description_is_not_touched);
    RUN_TEST(a_device_without_a_record_is_foreign);
    RUN_TEST(a_mismatched_read_back_fails);
    RUN_TEST(a_removal_clears_its_name_servers_first);
    RUN_TEST(a_device_left_behind_is_unpersisted_after_the_record);
    RUN_TEST(wants_coalesce);
    RUN_TEST(the_sweep_keeps_what_is_wanted_when_it_runs);
    RUN_TEST(the_sweep_reports_what_it_removed);
    RUN_TEST(the_real_get_and_post_end_on_the_io_s_stop);
    RUN_TEST(the_real_sleep_returns_early_on_stop);
    RUN_TEST(each_real_io_has_a_stop_of_its_own);
    RUN_TEST(a_stop_during_the_device_poll_returns_at_once);
    RUN_TEST(the_host_build_answers_without_a_thread);
    RUN_TEST(a_failed_read_is_never_absence);
    RUN_TEST(a_slow_create_read_as_absent_with_its_device_is_retried);
    RUN_TEST(a_refusal_after_a_dirty_start_still_saves);
    RUN_TEST(a_partly_refused_batch_keeps_dirty);
    RUN_TEST(a_timeout_elsewhere_keeps_dirty);
    RUN_TEST(a_timed_out_configure_reads_back_before_failing);
    RUN_TEST(a_timed_out_delete_whose_record_is_gone_goes_on);
    RUN_TEST(a_refused_delete_of_an_absent_record_goes_on);
    RUN_TEST(an_absent_list_read_removes_a_stale_creating_line);
    RUN_TEST(a_pending_round_schedules_a_save);
    RUN_TEST(no_save_within_five_seconds_of_a_delete_whoever_asks);
    RUN_TEST(a_dirty_start_waits_ten_seconds);
    RUN_TEST(a_stop_during_a_save_returns_within_a_second);
    RUN_TEST(a_partial_create_leaves_a_claimable_record);
    RUN_TEST(a_half_made_record_is_claimed_when_wanted);
    RUN_TEST(the_sweep_warns_about_a_half_made_record_and_keeps_it);
    RUN_TEST(a_save_keeps_creating_lines);
    RUN_TEST(two_names_in_flight);
    RUN_TEST(a_restart_keeps_a_creating_line);
    RUN_TEST(a_quote_is_escaped);
    RUN_TEST(the_one_pass_sweep_removes_then_saves);
    RUN_TEST(a_stuck_want_does_not_block_another_tunnels_save);
    RUN_TEST(a_foreign_record_drops_its_creating_line);
    RUN_TEST(a_bad_want_set_keeps_the_previous_one);
    RUN_TEST(a_failed_thread_start_leaves_the_callers_flag);
    RUN_TEST(a_refused_name_server_removal_is_warned);
    RUN_TEST(a_description_the_router_rewrites_is_sent_once);
    RUN_TEST(an_unreachable_sweep_warns_once_and_only_with_something_to_sweep);
    RUN_TEST(the_tunnels_own_tunvless_device_does_not_hold_its_address);
    GREATEST_MAIN_END();
}
