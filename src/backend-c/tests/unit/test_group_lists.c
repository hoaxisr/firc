#include "greatest.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fake_iptables.h"
#include "fake_conntrack.h"
#include "fake_rtnl.h"

#include "firc/app.h"
#include "firc/dnspipeline.h"
#include "firc/fakeip.h"
#include "firc/httpd.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/models.h"
#include "firc/netfilter_cleaner.h"
#include "firc/port_remap.h"
#include "firc/ruleset.h"
#include "firc/yamlio.h"

#define URL_A "http://127.0.0.1:1/a"
#define URL_B "http://127.0.0.1:1/b"

typedef struct fixture {
    firc_loop_t *loop;
    firc_dns_pipeline_t *pipeline;
    firc_config_t cfg;
    firc_app_t *app;
} fixture_t;

typedef struct heard {
    int calls;
    firc_id_t owner;
    bool done;
    char error[256];
} heard_t;

static heard_t g_heard;

static void listener(void *ud, firc_id_t owner, const firc_group_list_t *list, bool done) {
    (void)ud;
    g_heard.calls++;
    g_heard.owner = owner;
    g_heard.done = done;
    snprintf(g_heard.error, sizeof(g_heard.error), "%s", list->sync_error);
}

static fixture_t g_fx;
static bool g_fx_open = false;

static bool fixture_up_ex(fixture_t *f, bool with_worker) {
    memset(f, 0, sizeof(*f));
    memset(&g_heard, 0, sizeof(g_heard));
    if (firc_config_init_defaults(&f->cfg) != FIRC_OK) { return false; }
    if (firc_loop_create(&f->loop) != FIRC_OK) { return false; }
    f->pipeline = firc_dns_pipeline_create();
    if (f->pipeline == NULL) { return false; }
    firc_app_deps_t deps = {.cfg = &f->cfg, .loop = f->loop, .pipeline = f->pipeline};
    f->app = firc_app_create(&deps);
    if (f->app == NULL) { return false; }
    if (with_worker && firc_app_start_list_worker(f->app) != FIRC_OK) { return false; }
    firc_app_set_sync_listener(f->app, listener, NULL);
    g_fx_open = true;
    return true;
}

static bool fixture_up(fixture_t *f) { return fixture_up_ex(f, true); }

/* A fixture without the list worker, whose failed fetch logs could land in another test's capture. */
static bool fixture_up_no_worker(fixture_t *f) { return fixture_up_ex(f, false); }

static void fixture_down(fixture_t *f) {
    if (f->app != NULL) {
        firc_app_stop_list_worker(f->app);
        firc_app_destroy(f->app);
    }
    if (f->loop != NULL) { firc_loop_destroy(f->loop); }
    if (f->pipeline != NULL) { firc_dns_pipeline_destroy(f->pipeline); }
    firc_config_clear(&f->cfg);
    memset(f, 0, sizeof(*f));
}

static bool g_nf_open = false;

static firc_id_t id_of(uint8_t tag) { return (firc_id_t){{tag, tag, tag, tag}}; }

/* A group with a list at `url` and nothing else, as a reload or the WebUI's Save hands it to the app. */
static firc_group_t *group_with_list(uint8_t tag, const char *url, uint32_t interval) {
    firc_group_t *g = firc_group_new();
    if (g == NULL) { return NULL; }
    g->id = id_of(tag);
    g->enable = true;
    if (firc_strset(&g->name, "g") != FIRC_OK || firc_strset(&g->iface, "br0") != FIRC_OK) {
        firc_group_free(g);
        return NULL;
    }
    g->list = firc_group_list_new();
    if (g->list == NULL || firc_strset(&g->list->url, url) != FIRC_OK) {
        firc_group_free(g);
        return NULL;
    }
    g->list->interval = interval;
    return g;
}

/* A list group as a sync leaves it: `rule` in the list, a body hash and a last_update. */
static firc_group_t *synced_group(uint8_t tag, const char *url, const char *rule) {
    firc_group_t *g = group_with_list(tag, url, 3600);
    if (g == NULL) { return NULL; }
    if (firc_sub_rules_push(&g->list->rules, rule, FIRC_RULE_NAMESPACE, true, firc_id_random()) !=
        FIRC_OK) {
        firc_group_free(g);
        return NULL;
    }
    memset(g->list->body_hash, tag, sizeof(g->list->body_hash));
    g->list->has_body_hash = true;
    g->list->last_update = 1234;
    return g;
}

static firc_group_t *live(firc_id_t id) {
    firc_ruleset_t *rs = firc_app_find_group_by_id(g_fx.app, id);
    return rs != NULL ? firc_ruleset_group_mut(rs) : NULL;
}

static firc_err_t replace2(firc_group_t *a, firc_group_t *b) {
    size_t n = b != NULL ? 2 : 1;
    firc_group_t **arr = calloc(n, sizeof(*arr));
    if (arr == NULL) { return FIRC_ERR_NOMEM; }
    arr[0] = a;
    if (b != NULL) { arr[1] = b; }
    return firc_app_replace_groups(g_fx.app, arr, n);
}

/* Catches: a reorder not carrying each list's rules, hash and last_update by id. */
TEST a_replace_that_reorders_keeps_every_list(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, synced_group(1, URL_A, "one.example")));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, synced_group(2, URL_B, "two.example")));

    ASSERT_EQ(FIRC_OK, replace2(group_with_list(2, URL_B, 7200), group_with_list(1, URL_A, 600)));

    firc_group_t *a = live(id_of(1)), *b = live(id_of(2));
    ASSERT(a != NULL && a->list != NULL && b != NULL && b->list != NULL);
    ASSERT_EQ(1, a->list->rules.n);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&a->list->rules, 0));
    ASSERT_EQ(1, b->list->rules.n);
    ASSERT_STR_EQ("two.example", firc_sub_rules_text(&b->list->rules, 0));
    ASSERT(a->list->has_body_hash && b->list->has_body_hash);
    ASSERT_EQ(1, a->list->body_hash[0]);
    ASSERT_EQ(2, b->list->body_hash[0]);
    ASSERT_EQ(1234, a->list->last_update);
    ASSERT_EQ(1234, b->list->last_update);
    ASSERT_EQ(600, a->list->interval);
    ASSERT_EQ(7200, b->list->interval);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, a->list->sync_state);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, b->list->sync_state);
    ASSERT_EQ(0, g_heard.calls);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Loads `doc` into a fresh config and replaces the app's groups with it, as a SIGHUP does. */
static firc_err_t load_groups_into_app(const char *doc) {
    firc_config_t c;
    firc_err_t err = firc_config_init_defaults(&c);
    if (err == FIRC_OK) { err = firc_config_load_buffer(&c, doc, strlen(doc)); }
    if (err == FIRC_OK) {
        firc_group_t **groups = c.groups;
        size_t n = c.n_groups;
        c.groups = NULL;
        c.n_groups = 0;
        err = firc_app_replace_groups(g_fx.app, groups, n);
    }
    firc_config_clear(&c);
    return err;
}

TEST a_reload_keeps_the_lists_it_already_has(void) {
    static const char doc[] = "configVersion: 0.7.0\n"
                              "groups:\n"
                              "  - id: 01010101\n"
                              "    name: ads\n"
                              "    interface: br0\n"
                              "    enable: true\n"
                              "    list:\n"
                              "      url: '" URL_A "'\n"
                              "      interval: 3600\n"
                              "      last_update: 1700000000\n";
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, load_groups_into_app(doc));

    firc_group_t *g = live(id_of(1));
    ASSERT(g != NULL && g->list != NULL);
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&g->list->rules, "one.example", FIRC_RULE_NAMESPACE,
                                           true, firc_id_random()));
    memset(g->list->body_hash, 0x5a, sizeof(g->list->body_hash));
    g->list->has_body_hash = true;
    g->list->last_update = 1800000000;
    ASSERT_EQ((int)FIRC_SUB_SYNC_QUEUED, (int)g->list->sync_state);
    g->list->sync_state = FIRC_SUB_SYNC_IDLE;
    const char *text = g->list->rules.text;

    ASSERT_EQ(FIRC_OK, load_groups_into_app(doc));

    g = live(id_of(1));
    ASSERT(g != NULL && g->list != NULL);
    ASSERT_EQ_FMTm("the arena is kept", (size_t)1, g->list->rules.n, "%zu");
    ASSERTm("moved, not copied", g->list->rules.text == text);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&g->list->rules, 0));
    ASSERTm("the hash is kept", g->list->has_body_hash);
    uint8_t want[sizeof(g->list->body_hash)];
    memset(want, 0x5a, sizeof(want));
    ASSERT_MEM_EQ(want, g->list->body_hash, sizeof(want));
    ASSERT_EQ_FMTm("last_update is the daemon's, not the file's", (uint32_t)1800000000,
                   g->list->last_update, "%u");
    ASSERT_EQ_FMTm("nothing is asked for", (int)FIRC_SUB_SYNC_IDLE, (int)g->list->sync_state, "%d");
    ASSERT_EQ(0, g_heard.calls);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: a changed url carrying the old rules, the old stream left open, or no sync queued. */
TEST a_replace_with_a_changed_url_starts_empty_and_queues_one_sync(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, synced_group(1, URL_A, "one.example")));
    ASSERT_EQ(FIRC_OK, firc_app_request_sync(g_fx.app, id_of(1)));
    uint64_t seq = live(id_of(1))->list->sync_seq;
    ASSERTm("fixture: the old list's sync is in flight",
            live(id_of(1))->list->sync_state == FIRC_SUB_SYNC_QUEUED);

    ASSERT_EQ(FIRC_OK, replace2(group_with_list(1, URL_B, 3600), NULL));

    firc_group_t *a = live(id_of(1));
    ASSERT(a != NULL && a->list != NULL);
    ASSERT_STR_EQ(URL_B, a->list->url);
    ASSERT_EQ(0, a->list->rules.n);
    ASSERT_FALSE(a->list->has_body_hash);
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, a->list->sync_state);
    ASSERT_EQ_FMT((unsigned long long)seq + 1, (unsigned long long)a->list->sync_seq, "%llu");

    ASSERT_EQ(1, g_heard.calls);
    ASSERT(firc_id_equal(id_of(1), g_heard.owner));
    ASSERT(g_heard.done);
    ASSERT_STR_EQ("list url changed", g_heard.error);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: a replace that adds a list group queueing no sync, or two. */
TEST a_replace_that_adds_a_list_group_queues_its_sync(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, synced_group(1, URL_A, "one.example")));
    ASSERT_EQ(FIRC_OK, firc_app_request_sync(g_fx.app, id_of(1)));
    uint64_t seq = live(id_of(1))->list->sync_seq;

    ASSERT_EQ(FIRC_OK, replace2(group_with_list(1, URL_A, 3600), group_with_list(2, URL_B, 3600)));

    firc_group_t *b = live(id_of(2));
    ASSERT(b != NULL && b->list != NULL);
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, b->list->sync_state);
    ASSERT_EQ_FMT((unsigned long long)seq + 1, (unsigned long long)b->list->sync_seq, "%llu");
    ASSERT_EQ_FMT((unsigned long long)seq, (unsigned long long)live(id_of(1))->list->sync_seq,
                  "%llu");
    ASSERT_EQ(0, g_heard.calls);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: a replace that drops a list leaving its sync stream open. */
TEST a_replace_that_drops_a_list_ends_its_stream(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, synced_group(1, URL_A, "one.example")));
    ASSERT_EQ(FIRC_OK, firc_app_request_sync(g_fx.app, id_of(1)));

    firc_group_t *bare = group_with_list(1, URL_A, 3600);
    ASSERT(bare != NULL);
    firc_group_list_free(bare->list);
    bare->list = NULL;
    ASSERT_EQ(FIRC_OK, replace2(bare, NULL));

    firc_group_t *a = live(id_of(1));
    ASSERT(a != NULL);
    ASSERT_EQ(NULL, a->list);
    ASSERT_EQ(1, g_heard.calls);
    ASSERT(firc_id_equal(id_of(1), g_heard.owner));
    ASSERT(g_heard.done);
    ASSERT_STR_EQ("list removed", g_heard.error);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: deleting a list group leaving its sync stream open. */
TEST deleting_a_list_group_mid_sync_ends_its_stream(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, synced_group(1, URL_A, "one.example")));
    live(id_of(1))->list->sync_state = FIRC_SUB_SYNC_FETCHING;

    ASSERT(firc_app_remove_group_by_id(g_fx.app, id_of(1)));

    ASSERT_EQ(NULL, live(id_of(1)));
    ASSERT_EQ(1, g_heard.calls);
    ASSERT(firc_id_equal(id_of(1), g_heard.owner));
    ASSERT(g_heard.done);
    ASSERT_STR_EQ("group removed", g_heard.error);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: a same-url update dropping the list's rules or not taking the new metadata. */
TEST an_update_with_the_same_url_keeps_the_arena(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, synced_group(1, URL_A, "one.example")));

    firc_group_t *built = group_with_list(1, URL_A, 7200);
    ASSERT(built != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&built->name, "renamed"));
    ASSERT_EQ(FIRC_OK, firc_app_update_group(g_fx.app, id_of(1), built));

    firc_group_t *a = live(id_of(1));
    ASSERT(a != NULL && a->list != NULL);
    ASSERT_STR_EQ("renamed", a->name);
    ASSERT_EQ(7200, a->list->interval);
    ASSERT_EQ(1, a->list->rules.n);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&a->list->rules, 0));
    ASSERT(a->list->has_body_hash);
    ASSERT_EQ(1234, a->list->last_update);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, a->list->sync_state);
    ASSERT_EQ(0, g_heard.calls);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: an update without a list keeping the old one, losing hand rules, or leaking the list. */
TEST an_update_that_removes_the_list_keeps_the_hand_rules(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, synced_group(1, URL_A, "one.example")));

    firc_group_t *built = group_with_list(1, URL_A, 3600);
    ASSERT(built != NULL);
    firc_group_list_free(built->list);
    built->list = NULL;
    firc_rule_t *r = firc_rule_new();
    ASSERT(r != NULL);
    r->id = id_of(9);
    r->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&r->type, FIRC_RULE_DOMAIN));
    ASSERT_EQ(FIRC_OK, firc_strset(&r->rule, "hand.example"));
    ASSERT_EQ(FIRC_OK, firc_group_add_rule(built, r));
    ASSERT_EQ(FIRC_OK, firc_app_update_group(g_fx.app, id_of(1), built));

    firc_group_t *a = live(id_of(1));
    ASSERT(a != NULL);
    ASSERT_EQ(NULL, a->list);
    ASSERT_EQ(1, a->n_rules);
    ASSERT_STR_EQ("hand.example", a->rules[0]->rule);
    ASSERT_EQ(1, g_heard.calls);
    ASSERT_STR_EQ("list removed", g_heard.error);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: a new list group not queued for its first sync. */
TEST adding_a_group_with_a_list_queues_its_sync(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, group_with_list(1, URL_A, 3600)));

    firc_group_t *a = live(id_of(1));
    ASSERT(a != NULL && a->list != NULL);
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, a->list->sync_state);
    ASSERT_EQ_FMT(1ULL, (unsigned long long)a->list->sync_seq, "%llu");

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

static firc_sub_event_t *group_parsed_event(firc_id_t id, uint64_t seq) {
    firc_sub_event_t *ev = calloc(1, sizeof(*ev));
    ev->kind = FIRC_SUB_EV_RESULT;
    ev->group_id = id;
    ev->seq = seq;
    ev->result = FIRC_SUB_RESULT_PARSED;
    firc_sub_rules_init(&ev->rules);
    return ev;
}

/* Catches: a Save mid-sync dropping the running job's result, so its rules never install. */
TEST a_save_mid_sync_keeps_the_running_job(void) {
    ASSERT(fixture_up(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, group_with_list(1, URL_A, 3600)));
    ASSERT_EQ(FIRC_OK, firc_app_request_sync(g_fx.app, id_of(1)));
    uint64_t seq = live(id_of(1))->list->sync_seq;
    ASSERT_EQ(FIRC_SUB_SYNC_QUEUED, live(id_of(1))->list->sync_state);

    ASSERT_EQ(FIRC_OK, replace2(group_with_list(1, URL_A, 3600), NULL));
    ASSERT_EQ_FMTm("the same id and url: the queued seq is carried, not reset",
                   (unsigned long long)seq, (unsigned long long)live(id_of(1))->list->sync_seq, "%llu");
    ASSERT_EQ_FMTm("no stream ended: the replace kept this list", 0, g_heard.calls, "%d");

    firc_sub_event_t *ev = group_parsed_event(id_of(1), seq);
    firc_sub_rules_push(&ev->rules, "one.example", "namespace", true, firc_id_random());
    firc_app_on_sync_event(g_fx.app, ev, 1000);

    firc_group_t *a = live(id_of(1));
    ASSERT(a != NULL && a->list != NULL);
    ASSERT_EQ_FMTm("the rules applied to the (replaced) group", 1u, (unsigned)a->list->rules.n, "%u");
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&a->list->rules, 0));
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, a->list->sync_state);
    ASSERT_EQ_FMTm("the listener heard applying, then done", 2, g_heard.calls, "%d");
    ASSERT(firc_id_equal(id_of(1), g_heard.owner));
    ASSERTm("the last call in is the terminal one", g_heard.done);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

static size_t capture_apply(firc_app_t *app, firc_sub_event_t *ev, char *out, size_t cap,
                            bool *out_changed) {
    int fds[2];
    if (pipe(fds) != 0) { return (size_t)-1; }
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    bool changed = false;
    firc_app_apply_sync_result(app, ev, 1000, &changed);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    ssize_t n = read(fds[0], out, cap - 1);
    close(fds[0]);
    if (n < 0) { n = 0; }
    out[(size_t)n] = '\0';
    if (out_changed != NULL) { *out_changed = changed; }
    return (size_t)n;
}

static int count_lines(const char *s) {
    int n = 0;
    for (; *s; s++) {
        if (*s == '\n') { n++; }
    }
    return n;
}

/* Catches: unusable list lines unreported, reported per rule, or with the wrong count or example. */
TEST a_list_full_of_junk_says_it_once(void) {
    ASSERT(fixture_up_no_worker(&g_fx));
    firc_group_t *g = group_with_list(1, URL_A, 3600);
    ASSERT(g != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&g->name, "adblock"));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, g));

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev->rules, "010.0.0.1", "subnet", true, firc_id_random());
    firc_sub_rules_push(&ev->rules, "aa:bb:cc:dd:ee:ff", "subnet6", true, firc_id_random());
    firc_sub_rules_push(&ev->rules, "^[a-z", "regex", true, firc_id_random());
    firc_sub_rules_push(&ev->rules, "example.com", "namespace", true, firc_id_random());

    char out[4096];
    bool changed = false;
    size_t n = capture_apply(g_fx.app, ev, out, sizeof(out), &changed);
    firc_sub_event_free(ev);
    ASSERT(n != (size_t)-1);
    ASSERTm("the apply actually ran (not dropped as gone)", changed);
    firc_group_t *cur = live(id_of(1));
    ASSERT(cur != NULL && cur->list != NULL);
    ASSERT_EQ_FMTm("every line installed, junk included -- only netfilter/the "
                   "matcher skip the unusable ones",
                   4u, (unsigned)cur->list->rules.n, "%u");

    ASSERT_EQ_FMTm("one line for the count, one for the matcher's own check", 2, count_lines(out),
                   "%d");
    ASSERTm("the count", strstr(out, "3 line(s)") != NULL);
    ASSERTm("names the group", strstr(out, "adblock") != NULL);
    ASSERTm("the first example", strstr(out, "010.0.0.1") != NULL);
    ASSERTm("...and the reason", strstr(out, "an IPv4 address or prefix") != NULL);
    ASSERTm("the matcher's own line names the same regex",
            strstr(out, "do not compile") != NULL && strstr(out, "^[a-z") != NULL);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

TEST a_clean_list_says_nothing(void) {
    ASSERT(fixture_up_no_worker(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, group_with_list(1, URL_A, 3600)));

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev->rules, "example.com", "namespace", true, firc_id_random());
    firc_sub_rules_push(&ev->rules, "a.example.com", "domain", true, firc_id_random());

    char out[4096];
    bool changed = false;
    size_t n = capture_apply(g_fx.app, ev, out, sizeof(out), &changed);
    firc_sub_event_free(ev);
    ASSERT_EQ_FMTm("silence when there is nothing to say", (size_t)0, n, "%zu");
    ASSERTm("the apply actually ran (not dropped as gone)", changed);
    firc_group_t *cur = live(id_of(1));
    ASSERT(cur != NULL && cur->list != NULL);
    ASSERT_EQ_FMTm("both clean lines installed", 2u, (unsigned)cur->list->rules.n, "%u");

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: a disabled unusable rule counted as a problem. */
TEST a_disabled_junk_line_is_not_counted(void) {
    ASSERT(fixture_up_no_worker(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, group_with_list(1, URL_A, 3600)));

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev->rules, "^[a-z", "regex", false, firc_id_random());

    char out[4096];
    bool changed = false;
    size_t n = capture_apply(g_fx.app, ev, out, sizeof(out), &changed);
    firc_sub_event_free(ev);
    ASSERT_EQ_FMTm("a rule the operator turned off is not junk", (size_t)0, n, "%zu");
    ASSERTm("the apply actually ran (not dropped as gone)", changed);
    firc_group_t *cur = live(id_of(1));
    ASSERT(cur != NULL && cur->list != NULL);
    ASSERT_EQ_FMTm("the disabled line is still installed, just off", 1u,
                   (unsigned)cur->list->rules.n, "%u");
    ASSERT_FALSEm("and stays off", firc_sub_rules_enable(&cur->list->rules, 0));

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: lines the parser dropped left unreported, or reported without the group's name. */
TEST dropped_lines_are_said_with_the_group_s_name(void) {
    ASSERT(fixture_up_no_worker(&g_fx));
    firc_group_t *g = group_with_list(1, URL_A, 3600);
    ASSERT(g != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&g->name, "adblock"));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, g));

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev->rules, "example.com", "namespace", true, firc_id_random());
    ev->dropped = 2;

    char out[4096];
    bool changed = false;
    size_t n = capture_apply(g_fx.app, ev, out, sizeof(out), &changed);
    firc_sub_event_free(ev);
    ASSERT(n != (size_t)-1);
    ASSERTm("the apply actually ran", changed);
    ASSERT_EQ_FMT(1, count_lines(out), "%d");
    ASSERTm("the count", strstr(out, "2 entr(y/ies)") != NULL);
    ASSERTm("names the group", strstr(out, "\"adblock\"") != NULL);
    ASSERTm("no longer calls it a subscription", strstr(out, "subscription") == NULL);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Catches: a failed sync not logged, or logged without the group and the server's answer. */
TEST a_failed_sync_is_said_with_the_group_s_name(void) {
    ASSERT(fixture_up_no_worker(&g_fx));
    firc_group_t *g = group_with_list(1, URL_A, 3600);
    ASSERT(g != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&g->name, "adblock"));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, g));

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    ev->result = FIRC_SUB_RESULT_ERROR;
    ev->err = FIRC_ERR_PROTO;
    ev->http_status = 404;

    char out[4096];
    size_t n = capture_apply(g_fx.app, ev, out, sizeof(out), NULL);
    firc_sub_event_free(ev);
    ASSERT(n != (size_t)-1);
    ASSERT_EQ_FMT(1, count_lines(out), "%d");
    ASSERTm("names the group", strstr(out, "\"adblock\"") != NULL);
    ASSERTm("says what the server answered", strstr(out, "HTTP 404") != NULL);
    firc_group_t *cur = live(id_of(1));
    ASSERT(cur != NULL && cur->list != NULL);
    ASSERTm("and the list records it", strstr(cur->list->sync_error, "HTTP 404") != NULL);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

typedef struct list_body {
    const char *body;
} list_body_t;

static void h_list_body(firc_http_req_t *req, firc_http_res_t *res, void *ud) {
    (void)req;
    list_body_t *l = ud;
    firc_http_res_write(res, 200, "text/plain", (const uint8_t *)l->body, strlen(l->body));
}

static list_body_t g_httpsync_body_a = {.body = "one.example\ntwo.example"};

#define HTTPSYNC_PORT 18129

typedef struct httpsync_fixture {
    firc_loop_t *loop;
    firc_httpd_t *srv;
    pthread_t thread;
    firc_config_t cfg;
    firc_dns_pipeline_t *pipeline;
    firc_app_t *app;
} httpsync_fixture_t;

static httpsync_fixture_t g_hsx;

static void *httpsync_loop_thread(void *ud) {
    httpsync_fixture_t *h = ud;
    firc_loop_run(h->loop);
    return NULL;
}

static char g_httpsync_url[128];
static const char *httpsync_url(const char *path) {
    snprintf(g_httpsync_url, sizeof(g_httpsync_url), "http://127.0.0.1:%d%s", HTTPSYNC_PORT, path);
    return g_httpsync_url;
}

static bool g_hsx_open = false;

static bool httpsync_up(httpsync_fixture_t *h) {
    memset(h, 0, sizeof(*h));
    if (firc_config_init_defaults(&h->cfg) != FIRC_OK) { return false; }
    if (firc_loop_create(&h->loop) != FIRC_OK) { return false; }
    if (firc_httpd_create(h->loop, &h->srv) != FIRC_OK) { return false; }
    firc_httpd_route(h->srv, "GET", "/a", h_list_body, &g_httpsync_body_a);
    if (firc_httpd_listen_tcp(h->srv, "127.0.0.1", HTTPSYNC_PORT) != FIRC_OK) { return false; }
    pthread_create(&h->thread, NULL, httpsync_loop_thread, h);
    h->pipeline = firc_dns_pipeline_create();
    if (h->pipeline == NULL) { return false; }
    firc_app_deps_t deps = {.cfg = &h->cfg, .loop = h->loop, .pipeline = h->pipeline};
    h->app = firc_app_create(&deps);
    if (h->app == NULL) { return false; }
    g_hsx_open = true;
    return true;
}

static void httpsync_down(httpsync_fixture_t *h) {
    g_hsx_open = false;
    firc_loop_stop(h->loop);
    pthread_join(h->thread, NULL);
    firc_httpd_destroy(h->srv);
    firc_loop_destroy(h->loop);
    firc_app_destroy(h->app);
    firc_dns_pipeline_destroy(h->pipeline);
    firc_config_clear(&h->cfg);
}

static firc_group_t *live_in(firc_app_t *app, firc_id_t id) {
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, id);
    return rs != NULL ? firc_ruleset_group_mut(rs) : NULL;
}

TEST first_sync_fetches_and_marks_changed(void) {
    ASSERT(httpsync_up(&g_hsx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_hsx.app, group_with_list(1, httpsync_url("/a"), 3600)));

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(g_hsx.app, id_of(1), 1000, NULL, &changed));
    ASSERT(changed);

    firc_group_t *cur = live_in(g_hsx.app, id_of(1));
    ASSERT(cur != NULL && cur->list != NULL);
    ASSERT_EQ(2u, cur->list->rules.n);
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&cur->list->rules, 0));
    ASSERT_STR_EQ("two.example", firc_sub_rules_text(&cur->list->rules, 1));
    ASSERT_EQ((uint32_t)1000, cur->list->last_update);
    ASSERT_EQ((uint32_t)1000, cur->list->last_check);
    ASSERT_EQ(FIRC_SUB_SYNC_IDLE, cur->list->sync_state);

    httpsync_down(&g_hsx);
    PASS();
}

TEST resync_same_content_is_unchanged_but_bumps_last_check(void) {
    ASSERT(httpsync_up(&g_hsx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_hsx.app, group_with_list(1, httpsync_url("/a"), 3600)));

    bool changed = true;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(g_hsx.app, id_of(1), 1000, NULL, &changed));
    ASSERT(changed);

    changed = true;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(g_hsx.app, id_of(1), 2000, NULL, &changed));
    ASSERT_FALSE(changed);

    firc_group_t *cur = live_in(g_hsx.app, id_of(1));
    ASSERT(cur != NULL);
    ASSERT_EQ((uint32_t)1000, cur->list->last_update);
    ASSERT_EQ((uint32_t)2000, cur->list->last_check);
    ASSERT_EQ(2u, cur->list->rules.n);

    httpsync_down(&g_hsx);
    PASS();
}

TEST a_sync_applies_the_overrides_to_what_it_fetched(void) {
    ASSERT(httpsync_up(&g_hsx));
    firc_group_t *g = group_with_list(1, httpsync_url("/a"), 3600);
    ASSERT(g != NULL);
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           g->list, &(firc_sub_rule_key_t){.text = "two.example"}, "domain", &off));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_hsx.app, g));

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(g_hsx.app, id_of(1), 1000, NULL, &changed));
    ASSERT(changed);

    firc_group_t *cur = live_in(g_hsx.app, id_of(1));
    ASSERT(cur != NULL);
    ASSERT_EQ(2u, cur->list->rules.n);
    ASSERT_STR_EQm("the untouched line keeps the guesser's type", "namespace",
                   firc_sub_rules_type(&cur->list->rules, 0));
    ASSERTm("and stays enabled", firc_sub_rules_enable(&cur->list->rules, 0));
    ASSERT_STR_EQm("the edited line carries the override's type", "domain",
                   firc_sub_rules_type(&cur->list->rules, 1));
    ASSERT_FALSEm("and the override's enable", firc_sub_rules_enable(&cur->list->rules, 1));

    httpsync_down(&g_hsx);
    PASS();
}

/* Catches: a result from an older sync request applied after a newer one. */
TEST a_result_with_a_stale_seq_is_dropped(void) {
    ASSERT(httpsync_up(&g_hsx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_hsx.app, group_with_list(1, httpsync_url("/a"), 3600)));

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(g_hsx.app, id_of(1), 1000, NULL, &changed));
    ASSERT(changed);
    firc_group_t *before = live_in(g_hsx.app, id_of(1));
    ASSERT(before != NULL);
    uint64_t seq = before->list->sync_seq;
    uint32_t before_last_check = before->list->last_check;
    ASSERT(seq > 0);

    firc_sub_event_t *ev = group_parsed_event(id_of(1), seq - 1);
    firc_sub_rules_push(&ev->rules, "x.example", "namespace", true, firc_id_random());
    bool applied_changed = true;
    firc_err_t err = firc_app_apply_sync_result(g_hsx.app, ev, 2000, &applied_changed);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_FALSEm("a superseded result changes nothing", applied_changed);
    firc_sub_event_free(ev);

    firc_group_t *after = live_in(g_hsx.app, id_of(1));
    ASSERT_EQ_FMTm("the list the newer job installed is still there", 2u,
                   (unsigned)after->list->rules.n, "%u");
    ASSERT_STR_EQ("one.example", firc_sub_rules_text(&after->list->rules, 0));
    ASSERT_EQ(before_last_check, after->list->last_check);

    httpsync_down(&g_hsx);
    PASS();
}

TEST a_result_for_a_deleted_group_is_dropped(void) {
    ASSERT(httpsync_up(&g_hsx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_hsx.app, group_with_list(1, httpsync_url("/a"), 3600)));

    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_sync_list_now(g_hsx.app, id_of(1), 1000, NULL, &changed));
    uint64_t seq = live_in(g_hsx.app, id_of(1))->list->sync_seq;

    ASSERT(firc_app_remove_group_by_id(g_hsx.app, id_of(1)));
    ASSERT_EQ(NULL, live_in(g_hsx.app, id_of(1)));

    firc_sub_event_t *ev = group_parsed_event(id_of(1), seq + 1);
    firc_sub_rules_push(&ev->rules, "x.example", "namespace", true, firc_id_random());
    firc_app_on_sync_event(g_hsx.app, ev, 3000);

    ASSERT_EQ_FMTm("nothing came back from the dead", (void *)NULL, (void *)live_in(g_hsx.app, id_of(1)),
                   "%p");

    httpsync_down(&g_hsx);
    PASS();
}

typedef struct nf_fixture {
    firc_fakeip_t *pool;
    firc_dns_pipeline_t *pipeline;
    firc_fake_ipt_t *fake, *fake6;
    firc_ipt_t *ipt, *ipt6;
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    fake_ct_t *ctk;
    firc_ct_t *ct;
    firc_port_remap_t *remap;
    firc_config_t cfg;
    firc_app_t *app;
} nf_fixture_t;

static nf_fixture_t g_nfx;

/* `with_committer` false leaves no committer, so a list sync writes only its own chain at once. */
static bool nf_fixture_up_ex(nf_fixture_t *f, bool with_committer) {
    memset(f, 0, sizeof(*f));
    if (firc_config_init_defaults(&f->cfg) != FIRC_OK) { return false; }
    firc_fakeip_cfg_t pc = {0};
    pc.v4.base.len = 4; pc.v4.base.b[0] = 198; pc.v4.base.b[1] = 18;
    pc.v4.pool_cidr = 15; pc.v4.chunk_cidr = 24;
    pc.v6.base.len = 16; pc.v6.base.b[0] = 0xfd; pc.v6.base.b[1] = 0x37;
    pc.v6.pool_cidr = 48; pc.v6.chunk_cidr = 64;
    pc.max_names = 64; pc.idle_secs = 86400; pc.clamp_secs = 300;
    if (firc_fakeip_new(&pc, &f->pool) != FIRC_OK) { return false; }
    f->pipeline = firc_dns_pipeline_create();
    if (f->pipeline == NULL) { return false; }
    f->fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    f->ipt = firc_ipt_new(firc_fake_ipt_as_executable(f->fake), firc_fake_ipt_as_xt(f->fake));
    f->fake6 = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    f->ipt6 = firc_ipt_new(firc_fake_ipt_as_executable(f->fake6), firc_fake_ipt_as_xt(f->fake6));
    firc_netfilter_register_base_chains(f->ipt, f->ipt6);
    f->kernel = fake_rtnl_start(&f->rtnl);
    if (f->kernel == NULL) { return false; }
    fake_rtnl_set_link_flags(f->kernel, 0x1 | 0x10);
    f->ctk = fake_ct_start(&f->ct);
    if (f->ctk == NULL) { return false; }
    firc_app_deps_t deps = {.cfg = &f->cfg, .ipt4 = f->ipt, .ipt6 = f->ipt6, .rtnl = f->rtnl,
                            .ct = f->ct, .pipeline = f->pipeline, .pool = f->pool};
    f->app = firc_app_create(&deps);
    if (f->app == NULL) { return false; }
    f->remap = firc_port_remap_new(f->cfg.app.netfilter.iptables.chain_prefix, 53, 3553, NULL, 0,
                                   f->ipt, NULL);
    if (firc_port_remap_enable(f->remap) != FIRC_OK) { return false; }
    firc_fake_ipt_reset(f->fake);
    firc_app_set_port_remap(f->app, f->remap);
    firc_app_set_running(f->app, true);
    if (with_committer && firc_app_start_netfilter_committer(f->app) != FIRC_OK) { return false; }
    g_nf_open = true;
    return true;
}

static bool nf_fixture_up(nf_fixture_t *f) { return nf_fixture_up_ex(f, true); }
static bool nf_fixture_up_no_committer(nf_fixture_t *f) { return nf_fixture_up_ex(f, false); }

static void nf_fixture_down(nf_fixture_t *f) {
    g_nf_open = false;
    firc_app_destroy(f->app);
    firc_ct_close(f->ct);
    fake_ct_stop(f->ctk);
    firc_port_remap_free(f->remap);
    firc_rtnl_close(f->rtnl);
    fake_rtnl_stop(f->kernel);
    firc_ipt_free(f->ipt);
    firc_ipt_free(f->ipt6);
    firc_dns_pipeline_destroy(f->pipeline);
    firc_fakeip_free(f->pool);
    firc_config_clear(&f->cfg);
}

static void nf_sleep_ms(long ms) {
    struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static bool nf_wait_passes(const firc_app_t *app, uint64_t want) {
    for (int i = 0; i < 500; i++) {
        if (firc_app_nf_passes_for_test(app) >= want) { return true; }
        nf_sleep_ms(10);
    }
    return false;
}

static void nf_chain_name(const firc_config_t *cfg, firc_id_t id, char *out, size_t cap) {
    char idbuf[FIRC_ID_STR_LEN];
    firc_id_format(id, idbuf);
    snprintf(out, cap, "%s%s", cfg->app.netfilter.iptables.chain_prefix, idbuf);
}

static bool nf_any_arg_equals(firc_fake_ipt_t *f, const char *table, const char *chain,
                              const char *needle) {
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    if (!firc_fake_ipt_get_rules(f, table, chain, &rules, &n)) { return false; }
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < rules[i]->n_parts; j++) {
            if (strcmp(rules[i]->parts[j], needle) == 0) { return true; }
        }
    }
    return false;
}

TEST a_list_sync_resyncs_only_its_own_group(void) {
    ASSERT(nf_fixture_up(&g_nfx));

    firc_group_t *g1 = firc_group_new();
    ASSERT(g1 != NULL);
    g1->id = id_of(1);
    g1->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->name, "listed"));
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->iface, "lo"));
    g1->list = firc_group_list_new();
    ASSERT(g1->list != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->list->url, URL_A));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_nfx.app, g1));

    firc_group_t *g2 = firc_group_new();
    ASSERT(g2 != NULL);
    g2->id = id_of(2);
    g2->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&g2->name, "plain"));
    ASSERT_EQ(FIRC_OK, firc_strset(&g2->iface, "lo"));
    firc_rule_t *r2 = firc_rule_new();
    ASSERT(r2 != NULL);
    r2->id = firc_id_random();
    r2->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&r2->type, FIRC_RULE_SUBNET));
    ASSERT_EQ(FIRC_OK, firc_strset(&r2->rule, "10.0.0.0/8"));
    ASSERT_EQ(FIRC_OK, firc_group_add_rule(g2, r2));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_nfx.app, g2));

    nf_sleep_ms(600);

    char chain1[64], chain2[64];
    nf_chain_name(&g_nfx.cfg, id_of(1), chain1, sizeof(chain1));
    nf_chain_name(&g_nfx.cfg, id_of(2), chain2, sizeof(chain2));

    firc_ipt_rule_t *const *rules2 = NULL;
    size_t n2_before = 0;
    ASSERT(firc_fake_ipt_get_rules(g_nfx.fake, "mangle", chain2, &rules2, &n2_before));
    ASSERT(n2_before > 0);
    char *s2_before = firc_ipt_rule_string(rules2[0]);
    ASSERT(s2_before != NULL);
    char rule2_before[256];
    snprintf(rule2_before, sizeof(rule2_before), "%s", s2_before);
    free(s2_before);
    ASSERTm("group 2 starts with its own subnet mark rule",
            nf_any_arg_equals(g_nfx.fake, "mangle", chain2, "10.0.0.0/8"));
    ASSERT_FALSEm("group 1 starts with no subnet of its own",
                  nf_any_arg_equals(g_nfx.fake, "mangle", chain1, "10.9.0.0/16"));

    uint64_t before = firc_app_nf_passes_for_test(g_nfx.app);

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev->rules, "10.9.0.0/16", FIRC_RULE_SUBNET, true, firc_id_random());
    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_apply_sync_result(g_nfx.app, ev, 1000, &changed));
    ASSERTm("the KNOWN GAP this task closes: the result actually applied", changed);
    firc_sub_event_free(ev);

    ASSERTm("the resync asked the committer for one more pass",
            nf_wait_passes(g_nfx.app, before + 1));
    nf_sleep_ms(300);
    ASSERT_EQ_FMTm("exactly one pass, not a rebuild's worth", (unsigned long long)(before + 1),
                   (unsigned long long)firc_app_nf_passes_for_test(g_nfx.app), "%llu");

    ASSERTm("group 1's own chain now carries the new subnet",
            nf_any_arg_equals(g_nfx.fake, "mangle", chain1, "10.9.0.0/16"));

    size_t n2_after = 0;
    ASSERT(firc_fake_ipt_get_rules(g_nfx.fake, "mangle", chain2, &rules2, &n2_after));
    ASSERT_EQ_FMTm("group 2's chain has exactly as many rules as before", n2_before, n2_after, "%zu");
    char *s2_after = firc_ipt_rule_string(rules2[0]);
    ASSERT(s2_after != NULL);
    ASSERT_STR_EQm("and the same rule, unchanged", rule2_before, s2_after);
    free(s2_after);

    nf_fixture_down(&g_nfx);
    PASS();
}

TEST a_list_sync_without_a_committer_names_only_its_own_chain(void) {
    ASSERT(nf_fixture_up_no_committer(&g_nfx));

    firc_group_t *g1 = firc_group_new();
    ASSERT(g1 != NULL);
    g1->id = id_of(1);
    g1->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->name, "listed"));
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->iface, "lo"));
    g1->list = firc_group_list_new();
    ASSERT(g1->list != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->list->url, URL_A));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_nfx.app, g1));

    firc_group_t *g2 = firc_group_new();
    ASSERT(g2 != NULL);
    g2->id = id_of(2);
    g2->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&g2->name, "plain"));
    ASSERT_EQ(FIRC_OK, firc_strset(&g2->iface, "lo"));
    firc_rule_t *r2 = firc_rule_new();
    ASSERT(r2 != NULL);
    r2->id = firc_id_random();
    r2->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&r2->type, FIRC_RULE_SUBNET));
    ASSERT_EQ(FIRC_OK, firc_strset(&r2->rule, "10.0.0.0/8"));
    ASSERT_EQ(FIRC_OK, firc_group_add_rule(g2, r2));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_nfx.app, g2));

    char chain1[64], chain2[64];
    nf_chain_name(&g_nfx.cfg, id_of(1), chain1, sizeof(chain1));
    nf_chain_name(&g_nfx.cfg, id_of(2), chain2, sizeof(chain2));

    const char *log_so_far = firc_fake_ipt_restore_log(g_nfx.fake);
    ASSERT(log_so_far != NULL);
    ASSERTm("group 2's chain landed without a committer",
            strstr(log_so_far, chain2) != NULL);
    char *log_before = strdup(log_so_far);
    ASSERT(log_before != NULL);
    size_t before_len = strlen(log_before);

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev->rules, "10.9.0.0/16", FIRC_RULE_SUBNET, true, firc_id_random());
    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_apply_sync_result(g_nfx.app, ev, 1000, &changed));
    ASSERT(changed);
    firc_sub_event_free(ev);

    const char *log_after = firc_fake_ipt_restore_log(g_nfx.fake);
    ASSERT(log_after != NULL);
    size_t after_len = strlen(log_after);
    ASSERTm("the sync committed something", after_len > before_len);
    ASSERT_EQ_FMTm("the log is append-only: the old text is still there, unchanged", 0,
                   strncmp(log_before, log_after, before_len), "%d");
    const char *delta = log_after + before_len;

    ASSERTm("the new commit names the syncing group's own chain",
            strstr(delta, chain1) != NULL);
    ASSERTm("...and NEVER the other group's -- not merely unchanged, absent",
            strstr(delta, chain2) == NULL);

    free(log_before);
    nf_fixture_down(&g_nfx);
    PASS();
}

/* Catches: a refused resync leaving a changed list or chain, hiding the error, or no snapshot. */
TEST a_failed_resync_rolls_back_the_list_and_the_chain(void) {
    ASSERT(nf_fixture_up_no_committer(&g_nfx));

    firc_group_t *g1 = firc_group_new();
    ASSERT(g1 != NULL);
    g1->id = id_of(1);
    g1->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->name, "listed"));
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->iface, "lo"));
    g1->list = firc_group_list_new();
    ASSERT(g1->list != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&g1->list->url, URL_A));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_nfx.app, g1));

    char chain1[64];
    nf_chain_name(&g_nfx.cfg, id_of(1), chain1, sizeof(chain1));

    firc_sub_event_t *ev1 = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev1->rules, "10.1.0.0/16", FIRC_RULE_SUBNET, true, firc_id_random());
    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_apply_sync_result(g_nfx.app, ev1, 1000, &changed));
    ASSERT(changed);
    firc_sub_event_free(ev1);

    firc_group_t *before = live_in(g_nfx.app, id_of(1));
    ASSERT(before != NULL && before->list != NULL);
    ASSERT_EQ_FMTm("one good subnet installed", 1u, (unsigned)before->list->rules.n, "%u");
    ASSERT_STR_EQ("10.1.0.0/16", firc_sub_rules_text(&before->list->rules, 0));
    uint32_t prev_last_update = before->list->last_update;
    ASSERT(before->list->has_body_hash);
    uint8_t prev_hash[32];
    memcpy(prev_hash, before->list->body_hash, sizeof(prev_hash));
    ASSERTm("the good subnet landed in the chain",
            nf_any_arg_equals(g_nfx.fake, "mangle", chain1, "10.1.0.0/16"));

    firc_fake_ipt_refuse_rules_containing(g_nfx.fake, "10.9.0.0/16");

    firc_sub_event_t *ev2 = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev2->rules, "10.9.0.0/16", FIRC_RULE_SUBNET, true, firc_id_random());
    changed = false;
    firc_err_t err = firc_app_apply_sync_result(g_nfx.app, ev2, 2000, &changed);
    ASSERTm("a refused write is reported, not swallowed", err != FIRC_OK);
    firc_sub_event_free(ev2);

    firc_group_t *after = live_in(g_nfx.app, id_of(1));
    ASSERT(after != NULL && after->list != NULL);
    ASSERT_EQ_FMTm("the old rules are back", 1u, (unsigned)after->list->rules.n, "%u");
    ASSERT_STR_EQm("the old rule text, not the refused one", "10.1.0.0/16",
                   firc_sub_rules_text(&after->list->rules, 0));
    ASSERT_EQ_FMTm("last_update restored", prev_last_update, after->list->last_update, "%u");
    ASSERT_EQ(FIRC_SUB_SYNC_ERROR, after->list->sync_state);
    ASSERT_EQ_FMTm("the hash was never overwritten", 0,
                   memcmp(prev_hash, after->list->body_hash, sizeof(prev_hash)), "%d");

    ASSERT_FALSEm("the refused prefix never reached the chain",
                  nf_any_arg_equals(g_nfx.fake, "mangle", chain1, "10.9.0.0/16"));
    ASSERTm("the chain, as committed, still carries the old subnet",
            nf_any_arg_equals(g_nfx.fake, "mangle", chain1, "10.1.0.0/16"));

    ASSERTm("a snapshot is still published even though the resync failed",
            firc_dns_pipeline_snapshot(g_nfx.pipeline) != NULL);

    firc_ruleset_t *rs1 = firc_app_find_group_by_id(g_nfx.app, id_of(1));
    ASSERT(rs1 != NULL);
    ASSERT_EQ_FMTm("the link was handed the restored rules, not the refused ones",
                   FIRC_OK, firc_ruleset_rewrite_chains(rs1), "%d");
    ASSERT_FALSEm("...and writing it again still never carries the refused prefix",
                  nf_any_arg_equals(g_nfx.fake, "mangle", chain1, "10.9.0.0/16"));

    nf_fixture_down(&g_nfx);
    PASS();
}

/* Catches: an unusable list subnet line warned on every resync instead of once per change. */
TEST a_routed_group_warns_once_not_on_every_resync(void) {
    ASSERT(nf_fixture_up_no_committer(&g_nfx));

    firc_group_t *g = firc_group_new();
    ASSERT(g != NULL);
    g->id = id_of(1);
    g->enable = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&g->name, "adblock"));
    ASSERT_EQ(FIRC_OK, firc_strset(&g->iface, "lo"));
    g->list = firc_group_list_new();
    ASSERT(g->list != NULL);
    ASSERT_EQ(FIRC_OK, firc_strset(&g->list->url, URL_A));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_nfx.app, g));

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev->rules, "010.0.0.1", "subnet", true, firc_id_random());
    firc_sub_rules_push(&ev->rules, "one.example", "namespace", true, firc_id_random());

    char out[4096];
    bool changed = false;
    size_t n = capture_apply(g_nfx.app, ev, out, sizeof(out), &changed);
    firc_sub_event_free(ev);
    ASSERT(n != (size_t)-1);
    ASSERT(changed);
    ASSERT_EQ_FMTm("one WARN for the changed list", 1, count_lines(out), "%d");
    ASSERTm("names the one junk line", strstr(out, "1 line(s)") != NULL);

    firc_ruleset_t *rs = firc_app_find_group_by_id(g_nfx.app, id_of(1));
    ASSERT(rs != NULL);
    int fds[2];
    ASSERT(pipe(fds) == 0);
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    ASSERT_EQ(FIRC_OK, firc_app_sync_group(g_nfx.app, rs));
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    char out2[4096];
    ssize_t n2 = read(fds[0], out2, sizeof(out2) - 1);
    close(fds[0]);
    if (n2 < 0) { n2 = 0; }
    out2[n2] = '\0';
    ASSERT_EQ_FMTm("a resync of the SAME junk says nothing more", (size_t)0, (size_t)n2, "%zu");

    nf_fixture_down(&g_nfx);
    PASS();
}

/* Catches: the body hash stored after the republish, leaving one more provisional snapshot. */
TEST a_first_changed_sync_clears_provisional_at_once(void) {
    ASSERT(fixture_up_no_worker(&g_fx));
    ASSERT_EQ(FIRC_OK, firc_app_add_group(g_fx.app, group_with_list(1, URL_A, 3600)));

    firc_sub_event_t *ev = group_parsed_event(id_of(1), 0);
    firc_sub_rules_push(&ev->rules, "one.example", "namespace", true, firc_id_random());
    bool changed = false;
    ASSERT_EQ(FIRC_OK, firc_app_apply_sync_result(g_fx.app, ev, 1000, &changed));
    ASSERT(changed);
    firc_sub_event_free(ev);

    firc_ruleset_snapshot_t *snap = firc_dns_pipeline_snapshot(g_fx.pipeline);
    ASSERT(snap != NULL);
    ASSERT_FALSEm("the first list this group ever got is not provisional any more",
                  snap->provisional);

    g_fx_open = false;
    fixture_down(&g_fx);
    PASS();
}

/* Closes whichever global fixture a failed assertion left open. */
static void close_open_fixture(void *unused) {
    (void)unused;
    if (g_fx_open) {
        g_fx_open = false;
        fixture_down(&g_fx);
    }
    if (g_hsx_open) { httpsync_down(&g_hsx); }
    if (g_nf_open) { nf_fixture_down(&g_nfx); }
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(close_open_fixture, NULL);
    RUN_TEST(a_replace_that_reorders_keeps_every_list);
    RUN_TEST(a_reload_keeps_the_lists_it_already_has);
    RUN_TEST(a_replace_with_a_changed_url_starts_empty_and_queues_one_sync);
    RUN_TEST(a_replace_that_adds_a_list_group_queues_its_sync);
    RUN_TEST(a_replace_that_drops_a_list_ends_its_stream);
    RUN_TEST(deleting_a_list_group_mid_sync_ends_its_stream);
    RUN_TEST(an_update_with_the_same_url_keeps_the_arena);
    RUN_TEST(an_update_that_removes_the_list_keeps_the_hand_rules);
    RUN_TEST(a_save_mid_sync_keeps_the_running_job);
    RUN_TEST(a_list_full_of_junk_says_it_once);
    RUN_TEST(a_clean_list_says_nothing);
    RUN_TEST(a_disabled_junk_line_is_not_counted);
    RUN_TEST(dropped_lines_are_said_with_the_group_s_name);
    RUN_TEST(a_failed_sync_is_said_with_the_group_s_name);
    RUN_TEST(first_sync_fetches_and_marks_changed);
    RUN_TEST(resync_same_content_is_unchanged_but_bumps_last_check);
    RUN_TEST(a_sync_applies_the_overrides_to_what_it_fetched);
    RUN_TEST(a_result_with_a_stale_seq_is_dropped);
    RUN_TEST(a_result_for_a_deleted_group_is_dropped);
    RUN_TEST(a_list_sync_resyncs_only_its_own_group);
    RUN_TEST(a_list_sync_without_a_committer_names_only_its_own_chain);
    RUN_TEST(a_failed_resync_rolls_back_the_list_and_the_chain);
    RUN_TEST(a_routed_group_warns_once_not_on_every_resync);
    RUN_TEST(a_first_changed_sync_clears_provisional_at_once);
    RUN_TEST(adding_a_group_with_a_list_queues_its_sync);
    GREATEST_MAIN_END();
}
