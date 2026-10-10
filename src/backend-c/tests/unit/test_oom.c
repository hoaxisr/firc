#include "greatest.h"

#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "firc/app.h"
#include "firc/dnspipeline.h"
#include "firc/log.h"
#include "firc/rulesnap.h"
#include "firc/ruleset.h"
#include "firc/models.h"
#include "firc/subparse.h"
#include "firc/sub_fetch.h"
#include "firc/sub_worker.h"
#include "firc/yamlio.h"
#include "firc/tapreport.h"
#include "firc/taprules.h"
#include "firc/netfilter_cleaner.h"
#include "fake_iptables.h"
#include "fake_nflog.h"

void *__wrap_malloc(size_t n);
void *__wrap_calloc(size_t a, size_t b);
void *__wrap_realloc(void *p, size_t n);
char *__wrap_strdup(const char *s);

extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);
extern char *__real_strdup(const char *);

static volatile long g_fail_at = -1;
static volatile long g_seen = 0;
static volatile bool g_fail_after = false;

static bool should_fail(void) {
    if (g_fail_at < 0) { return false; }
    long i = g_seen++;
    return g_fail_after ? i >= g_fail_at : i == g_fail_at;
}

void *__wrap_malloc(size_t n) { return should_fail() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t a, size_t b) { return should_fail() ? NULL : __real_calloc(a, b); }
void *__wrap_realloc(void *p, size_t n) { return should_fail() ? NULL : __real_realloc(p, n); }
char *__wrap_strdup(const char *s) { return should_fail() ? NULL : __real_strdup(s); }

static void arm(long at) {
    g_seen = 0;
    g_fail_after = false;
    g_fail_at = at;
}

/* Fails every allocation from the `at`-th on, so a path that retries after a failure fails too. */
static void arm_from(long at) {
    arm(at);
    g_fail_after = true;
}

static void disarm(void) {
    g_fail_at = -1;
    g_fail_after = false;
}

/* How many allocations the last sweep intercepted; zero means the wrapping stopped applying. */
static long intercepted(void) { return g_seen; }

/* Catches: an allocation failure in the parse dropping a rule as junk and returning OK. */
TEST an_allocation_failure_is_never_reported_as_a_bad_line(void) {
    static const char list[] = "^ads[0-9]{1,3}\\.example\\.com$\n";
    long bad = -1;
    for (long at = 0; at < 200; at++) {
        firc_sub_rules_t rules;
        firc_sub_rules_init(&rules);
        size_t dropped = 0;
        arm(at);
        firc_err_t err = firc_sub_parse_rules_counted(list, &rules, &dropped);
        long seen = intercepted();
        disarm();
        ASSERTm("the allocator seam intercepted nothing -- the test proves nothing",
                seen > 0);
        if (err == FIRC_OK && rules.n == 0) {
            bad = at;
        }
        firc_sub_rules_free(&rules);
        if (bad >= 0) { break; }
    }
    ASSERT_EQ_FMTm("an allocation failure came back as FIRC_OK with the rule gone", -1L, bad, "%ld");
    PASS();
}

TEST a_failure_never_shortens_the_list_silently(void) {
    static const char list[] = "a.example.com\n"
                               "b.example.com\n"
                               "10.0.0.0/8\n"
                               "^ok\\.example\\.com$\n";
    long bad = -1;
    for (long at = 0; at < 400; at++) {
        firc_sub_rules_t rules;
        firc_sub_rules_init(&rules);
        arm(at);
        firc_err_t err = firc_sub_parse_rules(list, &rules);
        long seen = intercepted();
        disarm();
        ASSERTm("the allocator seam intercepted nothing -- the test proves nothing",
                seen > 0);
        if (err == FIRC_OK && rules.n != 4) { bad = at; }
        firc_sub_rules_free(&rules);
        if (bad >= 0) { break; }
    }
    ASSERT_EQ_FMTm("a short list came back as success", -1L, bad, "%ld");
    PASS();
}

static void typeless(firc_sub_rules_t *rs, const char *pattern, uint8_t id_byte, bool enable) {
    firc_sub_rules_push(rs, pattern, "", enable, (firc_id_t){{id_byte, 0, 0, 0}});
}

TEST a_comparison_that_could_not_be_made_is_neither_answer(void) {
    firc_sub_rules_t a, b, c;
    firc_sub_rules_init(&a);
    firc_sub_rules_init(&b);
    firc_sub_rules_init(&c);
    static const char *pat[] = {"a.example.com", "^ok\\.example\\.com$", "10.0.0.0/8"};
    for (size_t i = 0; i < 3; i++) {
        typeless(&a, pat[i], (uint8_t)(i + 1), true);
        typeless(&b, pat[i], (uint8_t)(i + 1), true);
    }
    for (size_t i = 0; i < 3; i++) { typeless(&c, pat[i], (uint8_t)(i + 1), i != 1); }
    ASSERT(a.n == 3 && b.n == 3 && c.n == 3);

    long said_changed = -1, said_same = -1;
    for (long at = 0; at < 300; at++) {
        bool same = false;
        arm(at);
        firc_err_t err = firc_sub_same_rules_checked(&a, &b, &same);
        long seen = intercepted();
        disarm();
        ASSERTm("the allocator seam intercepted nothing -- the test proves nothing", seen > 0);
        if (err == FIRC_OK && !same && said_changed < 0) { said_changed = at; }

        arm(at);
        err = firc_sub_same_rules_checked(&a, &c, &same);
        disarm();
        if (err == FIRC_OK && same && said_same < 0) { said_same = at; }
        if (said_changed >= 0 && said_same >= 0) { break; }
    }
    firc_sub_rules_free(&a);
    firc_sub_rules_free(&b);
    firc_sub_rules_free(&c);
    ASSERT_EQ_FMTm("an allocation failure came back as a rules change", -1L, said_changed, "%ld");
    ASSERT_EQ_FMTm("an allocation failure hid a real rules change", -1L, said_same, "%ld");
    PASS();
}

typedef struct {
    char buf[2048];
    size_t len;
} oom_said_t;

static void oom_collect(const char *sentence, void *ud) {
    oom_said_t *s = ud;
    int w = snprintf(s->buf + s->len, sizeof(s->buf) - s->len, "%s\n", sentence);
    if (w > 0 && (size_t)w < sizeof(s->buf) - s->len) { s->len += (size_t)w; }
}

TEST a_flow_that_cannot_be_remembered_is_reported_anyway(void) {
    firc_ip_t client = {0};
    client.len = 4;
    client.b[0] = 192; client.b[1] = 168; client.b[2] = 1; client.b[3] = 42;

    long missed = -1, mislabelled = -1, uncounted = -1;
    for (long at = 0; at < 8; at++) {
        firc_tap_report_t *r = firc_tap_report_new(16);
        if (r == NULL) { continue; }
        arm(at);
        bool reported = firc_tap_report_admit(r, &client, "example.com", 1000, NULL);
        long seen = intercepted();
        disarm();
        ASSERTm("the allocator seam intercepted nothing -- the test proves nothing", seen > 0);
        if (!reported && missed < 0) { missed = at; }

        static oom_said_t said;
        memset(&said, 0, sizeof(said));
        firc_tap_report_sentences(r, true, oom_collect, &said);
        if (strstr(said.buf, "table filled") != NULL && mislabelled < 0) { mislabelled = at; }
        if (reported && strstr(said.buf, "1 bypass reported") == NULL && uncounted < 0) {
            uncounted = at;
        }
        firc_tap_report_free(r);
    }
    ASSERT_EQ_FMTm("a bypass went unreported because there was no memory", -1L, missed, "%ld");
    ASSERT_EQ_FMTm("an allocation failure was reported as a full table", -1L, mislabelled,
                   "%ld");
    ASSERT_EQ_FMTm("a bypass reported was missing from the count", -1L, uncounted, "%ld");
    PASS();
}

/* Catches: an override's type check that failed for memory read as an unusable type. */
TEST an_override_is_never_dropped_because_memory_ran_out(void) {
    static const char doc[] =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 5eba1111\n"
        "    name: ads\n"
        "    list:\n"
        "      url: 'https://example.invalid/l.txt'\n"
        "      overrides:\n"
        "        - rule: '^ads[0-9]{1,3}\\.example\\.com$'\n"
        "          type: regex\n";
    long bad = -1, lied = -1;
    bool reached_end = false;
    firc_err_t lied_err = FIRC_OK;
    for (long at = 0; at < 4000 && bad < 0; at++) {
        firc_config_t cfg;
        if (firc_config_init_defaults(&cfg) != FIRC_OK) { continue; }
        arm(at);
        firc_err_t err = firc_config_load_buffer(&cfg, doc, sizeof(doc) - 1);
        long seen = intercepted();
        disarm();
        ASSERTm("the allocator seam intercepted nothing -- the test proves nothing", seen > 0);
        if (err == FIRC_OK && (cfg.n_groups != 1 || cfg.groups[0]->list == NULL ||
                               cfg.groups[0]->list->n_overrides == 0)) {
            bad = at;
        }
        if (err != FIRC_OK && err != FIRC_ERR_NOMEM) {
            lied = at;
            lied_err = err;
        }
        firc_config_clear(&cfg);
        if (lied >= 0) { break; }
        if (seen <= at) {
            reached_end = true;
            break;
        }
    }
    ASSERT_EQ_FMTm("an allocation failure came back as FIRC_OK with the override gone",
                   -1L, bad, "%ld");
    ASSERTm("the load has allocations the loop never failed", reached_end || bad >= 0 || lied >= 0);
    if (lied >= 0) {
        FAILm(firc_err_str(lied_err));
    }
    PASS();
}

/* A group whose list holds "ads.example.com", added and published. */
static firc_group_t *published_list_group(firc_app_t *app, firc_dns_pipeline_t *p) {
    firc_group_t *g = firc_group_new();
    if (g == NULL) { return NULL; }
    g->id = (firc_id_t){{0x0a, 0x0b, 0x0c, 0x0d}};
    g->enable = true;
    g->list = firc_group_list_new();
    if (g->list == NULL || firc_strset(&g->iface, "eth0") != FIRC_OK ||
        firc_strset(&g->list->url, "https://example.invalid/l.txt") != FIRC_OK ||
        firc_sub_rules_push(&g->list->rules, "ads.example.com", "namespace", true,
                            firc_id_random()) != FIRC_OK) {
        firc_group_free(g);
        return NULL;
    }
    g->list->has_body_hash = true;
    firc_id_t id = g->id;
    if (firc_app_add_group(app, g) != FIRC_OK) { return NULL; }
    if (firc_app_republish_dns_snapshot(app) != FIRC_OK) { return NULL; }
    if (firc_ruleset_snapshot_first_match(firc_dns_pipeline_snapshot(p), "a.ads.example.com") ==
        NULL) {
        return NULL;
    }
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, id);
    return rs != NULL ? firc_ruleset_group_mut(rs) : NULL;
}

/* Whether the snapshot still answers for the list's name once no group holds that list. */
static bool a_dropped_list_still_owns_the_name(firc_app_t *app, firc_dns_pipeline_t *p) {
    const firc_ruleset_snapshot_t *snap = firc_dns_pipeline_snapshot(p);
    const firc_group_snapshot_t *owner =
        snap != NULL ? firc_ruleset_snapshot_first_match(snap, "a.ads.example.com") : NULL;
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, (firc_id_t){{0x0a, 0x0b, 0x0c, 0x0d}});
    bool list_there = rs != NULL && firc_ruleset_group(rs)->list != NULL;
    return owner != NULL && !list_there;
}

/* Catches: a delete whose republish fails leaving the snapshot on freed list text. */
TEST a_snapshot_never_outlives_the_list_it_borrows(void) {
    long seen_any = 0;
    for (long at = 0; at < 200; at++) {
        firc_config_t cfg;
        if (firc_config_init_defaults(&cfg) != FIRC_OK) { continue; }
        firc_dns_pipeline_t *p = firc_dns_pipeline_create();
        firc_app_deps_t deps = {.cfg = &cfg, .pipeline = p};
        firc_app_t *app = firc_app_create(&deps);
        ASSERT(app != NULL);
        ASSERT(published_list_group(app, p) != NULL);

        arm(at);
        (void)firc_app_remove_group_by_id(app, (firc_id_t){{0x0a, 0x0b, 0x0c, 0x0d}});
        long seen = intercepted();
        disarm();
        if (seen > 0) { seen_any++; }

        bool stale = a_dropped_list_still_owns_the_name(app, p);
        firc_app_destroy(app);
        firc_dns_pipeline_destroy(p);
        firc_config_clear(&cfg);
        if (stale) { FAILm("a removed group's list still owns a name"); }
        if (seen == 0 && at > 0) { break; }
    }
    ASSERTm("the allocator seam intercepted nothing -- the test proves nothing", seen_any > 0);
    PASS();
}

/* Catches: a replace that drops a list leaving the snapshot on its freed text. */
TEST a_replace_that_drops_a_list_never_leaves_a_snapshot_on_it(void) {
    long seen_any = 0;
    for (long at = 0; at < 200; at++) {
        firc_config_t cfg;
        if (firc_config_init_defaults(&cfg) != FIRC_OK) { continue; }
        firc_dns_pipeline_t *p = firc_dns_pipeline_create();
        firc_app_deps_t deps = {.cfg = &cfg, .pipeline = p};
        firc_app_t *app = firc_app_create(&deps);
        ASSERT(app != NULL);
        ASSERT(published_list_group(app, p) != NULL);

        firc_group_t *bare = firc_group_new();
        firc_group_t **arr = calloc(1, sizeof(*arr));
        ASSERT(bare != NULL && arr != NULL);
        bare->id = (firc_id_t){{0x0a, 0x0b, 0x0c, 0x0d}};
        bare->enable = true;
        arr[0] = bare;

        arm_from(at);
        (void)firc_app_replace_groups(app, arr, 1);
        long seen = intercepted();
        disarm();
        if (seen > 0) { seen_any++; }

        bool stale = a_dropped_list_still_owns_the_name(app, p);
        firc_app_destroy(app);
        firc_dns_pipeline_destroy(p);
        firc_config_clear(&cfg);
        if (stale) { FAILm("a dropped list still owns a name"); }
        if (seen <= at && at > 0) { break; }
    }
    ASSERTm("the allocator seam intercepted nothing -- the test proves nothing", seen_any > 0);
    PASS();
}

#define OOM_PORT 18130
static const char g_oom_response[] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 23\r\n"
    "Connection: close\r\n\r\none.example\ntwo.example";

static int g_stub_fd = -1;
static volatile int g_stub_stop = 0;

static void *stub_main(void *unused) {
    (void)unused;
    while (!g_stub_stop) {
        int c = accept(g_stub_fd, NULL, NULL);
        if (c < 0) { continue; }
        char req[1024];
        (void)recv(c, req, sizeof(req), 0);
        ssize_t off = 0;
        ssize_t total = (ssize_t)(sizeof(g_oom_response) - 1);
        while (off < total) {
            ssize_t n = send(c, g_oom_response + off, (size_t)(total - off), MSG_NOSIGNAL);
            if (n <= 0) { break; }
            off += n;
        }
        close(c);
    }
    return NULL;
}

static pthread_t g_stub_thread;

static bool stub_start(void) {
    g_stub_stop = 0;
    g_stub_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_stub_fd < 0) { return false; }
    int one = 1;
    setsockopt(g_stub_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct timeval tv = {.tv_sec = 0, .tv_usec = 100 * 1000};
    setsockopt(g_stub_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(OOM_PORT);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(g_stub_fd, (struct sockaddr *)&a, sizeof(a)) != 0) { return false; }
    if (listen(g_stub_fd, 8) != 0) { return false; }
    return pthread_create(&g_stub_thread, NULL, stub_main, NULL) == 0;
}

static void stub_stop(void) {
    g_stub_stop = 1;
    pthread_join(g_stub_thread, NULL);
    close(g_stub_fd);
    g_stub_fd = -1;
}

typedef struct job_sink {
    int n_started;
    int n_result;
    firc_sub_result_kind_t result;
    firc_err_t err;
    size_t n_rules;
} job_sink_t;

static void job_sink_emit(void *ud, firc_sub_event_t *ev) {
    job_sink_t *s = ud;
    if (ev->kind == FIRC_SUB_EV_STARTED) {
        s->n_started++;
    }
    if (ev->kind == FIRC_SUB_EV_RESULT) {
        s->n_result++;
        s->result = ev->result;
        s->err = ev->err;
        s->n_rules = ev->rules.n;
    }
    firc_sub_event_free(ev);
}

/* Catches: a job that posted STARTED unable to post its result for lack of memory. */
TEST a_start_is_always_followed_by_an_end(void) {
    ASSERTm("the stub list server did not start", stub_start());
    static char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/list", OOM_PORT);

    job_sink_t warm = {0};
    firc_sub_job_t probe = {.group_id = {{5, 6, 7, 8}}, .url = strdup(url), .seq = 0};
    arm(LONG_MAX);
    firc_sub_job_run(&probe, NULL, job_sink_emit, &warm);
    long total = intercepted();
    disarm();
    free(probe.url);
    if (total <= 0 || warm.n_started != 1 || warm.n_result != 1) {
        stub_stop();
        FAILm("the probe job did not start and finish -- the sweep would prove nothing");
    }

    long orphaned_at = -1;
    bool silent_run_seen = false;
    for (long at = 0; at < total; at++) {
        job_sink_t s = {0};
        firc_sub_job_t job = {.group_id = {{5, 6, 7, 8}}, .url = strdup(url), .seq = (uint64_t)at};
        if (job.url == NULL) { break; }
        arm(at);
        firc_sub_job_run(&job, NULL, job_sink_emit, &s);
        disarm();
        free(job.url);

        if (s.n_started > 0 && s.n_result == 0) { orphaned_at = at; break; }
        if (s.n_started == 0 && s.n_result == 0) { silent_run_seen = true; }
    }
    stub_stop();

    ASSERT_EQ_FMTm("a job said it started and never said how it ended", -1L, orphaned_at, "%ld");
    ASSERTm("no run failed the result event's own allocation -- the case is untested",
            silent_run_seen);
    PASS();
}

TEST a_job_that_ran_out_of_memory_says_so(void) {
    ASSERTm("the stub list server did not start", stub_start());
    static char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%d/list", OOM_PORT);

    job_sink_t warm = {0};
    firc_sub_job_t probe = {.group_id = {{1, 2, 3, 4}}, .url = strdup(url), .seq = 0};
    arm(LONG_MAX);
    firc_sub_job_run(&probe, NULL, job_sink_emit, &warm);
    long total = intercepted();
    disarm();
    free(probe.url);
    if (warm.n_result != 1 || warm.result != FIRC_SUB_RESULT_PARSED) {
        stub_stop();
        FAILm("the stub list was not fetched and parsed -- the sweep would prove nothing");
    }
    if (total <= 0) {
        stub_stop();
        FAILm("the allocator seam intercepted nothing -- the sweep would prove nothing");
    }

    bool nomem_seen = false;
    long lied_at = -1;
    long shortened_at = -1;
    for (long at = 0; at < total; at++) {
        job_sink_t s = {0};
        firc_sub_job_t job = {.group_id = {{1, 2, 3, 4}}, .url = strdup(url), .seq = (uint64_t)at};
        if (job.url == NULL) { break; }
        arm(at);
        firc_sub_job_run(&job, NULL, job_sink_emit, &s);
        disarm();
        free(job.url);

        if (s.n_result == 0) { continue; }
        if (s.result == FIRC_SUB_RESULT_ERROR) {
            if (s.err == FIRC_ERR_NOMEM) { nomem_seen = true; }
            if (s.err == FIRC_ERR_INVAL || s.err == FIRC_ERR_PROTO) { lied_at = at; }
        } else if (s.result == FIRC_SUB_RESULT_PARSED && s.n_rules != 2) {
            shortened_at = at;
        }
        if (lied_at >= 0 || shortened_at >= 0) { break; }
    }
    stub_stop();

    ASSERT_EQ_FMTm("an allocation failure came back as a malformed list", -1L, lied_at, "%ld");
    ASSERT_EQ_FMTm("a parse that lost a rule came back as a complete list", -1L, shortened_at,
                   "%ld");
    ASSERTm("no allocation failure in the whole job was reported as FIRC_ERR_NOMEM",
            nomem_seen);
    PASS();
}

static fake_nflog_t *g_oom_kernel[2];

static firc_nflog_t *oom_nflog_open(uint16_t group, uint16_t copy_range) {
    int w = group == FIRC_TAP_GROUP_NEW ? 0 : 1;
    fake_nflog_stop(g_oom_kernel[w]);
    int fd = -1;
    g_oom_kernel[w] = fake_nflog_start(&fd);
    if (g_oom_kernel[w] == NULL) { return NULL; }
    firc_nflog_t *n = firc_nflog_open_fd(fd, group, copy_range);
    if (n == NULL) { close(fd); }
    return n;
}

TEST a_capture_that_could_not_be_staged_leaves_no_chain(void) {
    firc_fakeip_cfg_t pc = {0};
    pc.v4.base.len = 4; pc.v4.base.b[0] = 198; pc.v4.base.b[1] = 18;
    pc.v4.pool_cidr = 15; pc.v4.chunk_cidr = 24;
    pc.v6.base.len = 16; pc.v6.base.b[0] = 0xfd; pc.v6.base.b[1] = 0x37;
    pc.v6.pool_cidr = 48; pc.v6.chunk_cidr = 64;
    pc.max_names = 64; pc.idle_secs = 86400; pc.clamp_secs = 300;

    long failed = 0, left_behind = -1, at = 0;
    for (;; at++) {
        firc_config_t cfg;
        firc_config_init_defaults(&cfg);
        firc_fakeip_t *pool = NULL;
        ASSERT_EQ(FIRC_OK, firc_fakeip_new(&pc, &pool));
        firc_fake_ipt_t *fake[2] = {firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4),
                                    firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6)};
        firc_ipt_t *ipt[2] = {firc_ipt_new(firc_fake_ipt_as_executable(fake[0]), firc_fake_ipt_as_xt(fake[0])),
                              firc_ipt_new(firc_fake_ipt_as_executable(fake[1]), firc_fake_ipt_as_xt(fake[1]))};
        firc_netfilter_register_base_chains(ipt[0], ipt[1]);
        firc_app_deps_t deps = {.cfg = &cfg,
                                .ipt4 = ipt[0],
                                .ipt6 = ipt[1],
                                .pool = pool,
                                .nflog_open = oom_nflog_open};
        firc_app_t *app = firc_app_create(&deps);
        ASSERT(app != NULL);

        arm(at);
        firc_err_t err = firc_app_capture_start(app, 1000, NULL);
        long seen = intercepted();
        disarm();
        ASSERTm("the allocator seam intercepted nothing -- the test proves nothing", seen > 0);

        bool done = seen <= at;
        if (done) { ASSERT_EQ_FMT(FIRC_OK, err, "%d"); }
        if (err != FIRC_OK) {
            failed++;
            for (int e = 0; e < 2; e++) {
                (void)firc_ipt_commit(ipt[e]);
                if (firc_fake_ipt_chain_exists(fake[e], "mangle", "FIRC_TAP") && left_behind < 0) {
                    left_behind = at;
                }
            }
        }
        firc_app_destroy(app);
        for (int w = 0; w < 2; w++) {
            fake_nflog_stop(g_oom_kernel[w]);
            g_oom_kernel[w] = NULL;
        }
        firc_ipt_free(ipt[0]);
        firc_ipt_free(ipt[1]);
        firc_fakeip_free(pool);
        firc_config_clear(&cfg);
        if (done || at > 20000) { break; }
    }
    ASSERTm("the sweep never got past the start's last allocation", at <= 20000);
    ASSERTm("no allocation of a start was ever failed", failed > 0);
    ASSERT_EQ_FMTm("a failed start left a capture chain for the next commit", -1L, left_behind,
                   "%ld");
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    firc_log_set_level(FIRC_LOG_ERROR);
    firc_sub_fetch_global_init();
    GREATEST_MAIN_BEGIN();
    RUN_TEST(an_allocation_failure_is_never_reported_as_a_bad_line);
    RUN_TEST(an_override_is_never_dropped_because_memory_ran_out);
    RUN_TEST(a_snapshot_never_outlives_the_list_it_borrows);
    RUN_TEST(a_replace_that_drops_a_list_never_leaves_a_snapshot_on_it);
    RUN_TEST(a_failure_never_shortens_the_list_silently);
    RUN_TEST(a_comparison_that_could_not_be_made_is_neither_answer);
    RUN_TEST(a_flow_that_cannot_be_remembered_is_reported_anyway);
    RUN_TEST(a_capture_that_could_not_be_staged_leaves_no_chain);
    RUN_TEST(a_job_that_ran_out_of_memory_says_so);
    RUN_TEST(a_start_is_always_followed_by_an_end);
    GREATEST_MAIN_END();
}
