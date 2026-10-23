#include "greatest.h"

#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fake_rtnl.h"
#include "firc/events.h"
#include "firc/ifwatch.h"
#include "firc/logrep.h"
#include "firc/mark.h"
#include "firc/models.h"
#include "firc/rtnl.h"

static int64_t g_now;
static int64_t clock_ms(void) { return g_now; }
static uint64_t clock_u(void) { return (uint64_t)g_now; }

static firc_group_t *g_groups[8];
static size_t g_n;
static size_t n_groups(void *ud) {
    (void)ud;
    return g_n;
}
static const firc_group_t *group_at(void *ud, size_t i) {
    (void)ud;
    return g_groups[i];
}

typedef struct {
    firc_id_t id;
    size_t to;
    bool blocked;
} move_t;
static move_t g_moves[16];
static size_t g_n_moves;
static firc_err_t g_move_err;
static firc_err_t record_move(void *ud, firc_id_t id, size_t to, bool blocked) {
    (void)ud;
    if (g_n_moves < 16) { g_moves[g_n_moves++] = (move_t){id, to, blocked}; }
    return g_move_err;
}

static const char *g_down;
static bool link_up(void *ud, const char *name) {
    (void)ud;
    return g_down == NULL || strcmp(name, g_down) != 0;
}
static const char *g_tunnel;
static bool g_tunnel_is_down;
static bool tunnel_known(void *ud, const char *dev) {
    (void)ud;
    return g_tunnel != NULL && strcmp(dev, g_tunnel) == 0;
}
static bool g_starting;
static int64_t g_started_ms;
static bool tunnel_down(void *ud, const char *dev) {
    (void)ud;
    (void)dev;
    return g_tunnel_is_down || g_starting;
}
static bool tunnel_starting(void *ud, const char *dev, int64_t *since_ms) {
    (void)ud;
    if (!g_starting || g_tunnel == NULL || strcmp(dev, g_tunnel) != 0) { return false; }
    *since_ms = g_started_ms;
    return true;
}

static char g_queued[64][16];
static uint32_t g_queued_gen[64];
static size_t g_n_queued;
static firc_err_t record_queue(void *ud, const char *name, uint32_t mark, uint32_t gen) {
    (void)ud;
    (void)mark;
    snprintf(g_queued[g_n_queued % 64], sizeof(g_queued[0]), "%s", name);
    g_queued_gen[g_n_queued % 64] = gen;
    g_n_queued++;
    return FIRC_OK;
}
static uint32_t last_gen(const char *name) {
    uint32_t gen = 0;
    for (size_t i = 0; i < g_n_queued && i < 64; i++) {
        if (strcmp(g_queued[i], name) == 0) { gen = g_queued_gen[i]; }
    }
    return gen;
}
static size_t times_queued(const char *name) {
    size_t c = 0;
    for (size_t i = 0; i < g_n_queued && i < 64; i++) { c += strcmp(g_queued[i], name) == 0 ? 1u : 0u; }
    return c;
}

static const char *const AB[] = {"up0", "up1"};
static const firc_id_t G1 = {{1, 1, 1, 1}};

static firc_group_t *grp(uint8_t tag, const char *const *names, size_t n) {
    firc_group_t *g = firc_group_new();
    g->id = (firc_id_t){{tag, tag, tag, tag}};
    g->name = strdup("G");
    g->enable = true;
    firc_group_set_ifaces(g, names, n);
    return g;
}

static fake_rtnl_t *g_kernel;
static firc_rtnl_t *g_rtnl;
static unsigned three_links(const char *name) {
    if (strcmp(name, "up0") == 0) { return 7; }
    if (strcmp(name, "up1") == 0) { return 8; }
    if (strcmp(name, "up2") == 0) { return 9; }
    if (name[0] == 'c' && name[1] >= 'a' && name[1] <= 'z' && name[2] == '\0') { return 20u + (unsigned)(name[1] - 'a'); }
    return 0;
}

static size_t check_rules(uint16_t type) {
    fake_rtnl_msg_t m[256];
    size_t n = fake_rtnl_messages(g_kernel, m, 256), c = 0;
    for (size_t i = 0; i < n; i++) {
        c += m[i].type == type && m[i].priority == FIRC_RULE_PRIORITY_TUNNEL ? 1u : 0u;
    }
    return c;
}

static firc_ifwatch_t *fresh(void) {
    g_move_err = FIRC_OK;
    g_n_moves = 0;
    g_n_queued = 0;
    g_n = 0;
    g_now = 1000;
    g_down = NULL;
    g_tunnel = NULL;
    g_tunnel_is_down = false;
    g_starting = false;
    firc_event_reset_for_test();
    firc_logrep_set_clock_for_test(clock_u);
    g_kernel = fake_rtnl_start(&g_rtnl);
    fake_rtnl_set_link_flags(g_kernel, 0x1 | 0x10);
    firc_rtnl_set_nametoindex_for_test(three_links);
    firc_ifwatch_deps_t d = {.rtnl = g_rtnl,
                             .start_table = 500,
                             .n_groups = n_groups,
                             .group_at = group_at,
                             .move = record_move,
                             .link_up = link_up,
                             .tunnel_known = tunnel_known,
                             .tunnel_down = tunnel_down,
                             .tunnel_starting = tunnel_starting,
                             .queue = record_queue,
                             .now_ms = clock_ms};
    firc_ifwatch_t *w = firc_ifwatch_new(&d);
    firc_app_config_t a;
    firc_app_config_init_defaults(&a);
    firc_ifwatch_configure(w, &a);
    firc_app_config_clear(&a);
    return w;
}

static void kernel_done(void) {
    for (size_t i = 0; i < g_n; i++) { firc_group_free(g_groups[i]); }
    g_n = 0;
    firc_rtnl_set_nametoindex_for_test(NULL);
    firc_rtnl_close(g_rtnl);
    fake_rtnl_stop(g_kernel);
    firc_logrep_set_clock_for_test(NULL);
}

static void done(firc_ifwatch_t *w) {
    firc_ifwatch_free(w);
    kernel_done();
}

static void result_as(firc_ifwatch_t *w, const char *name, bool passed, bool guarded, bool wan, uint32_t gen,
                      const char *error) {
    firc_ifcheck_result_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.iface, sizeof(r.iface), "%s", name);
    r.gen = gen;
    r.passed = passed;
    r.control_failed = guarded;
    r.control_ran = !passed && wan;
    snprintf(r.error, sizeof(r.error), "%s", passed ? "" : error);
    firc_ifwatch_results(w, &r, 1);
}

static void result(firc_ifwatch_t *w, const char *name, bool passed, bool guarded) {
    result_as(w, name, passed, guarded, true, last_gen(name), "timed out");
}

static size_t times_said(firc_log_level_t level, const char *part) {
    firc_event_t out[64];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, out, 64, &next, &dropped), c = 0;
    for (size_t i = 0; i < n; i++) {
        if (out[i].kind == FIRC_EVENT_LOG && out[i].u.log.level == level && strstr(out[i].u.log.text, part) != NULL) {
            c++;
        }
    }
    return c;
}

static bool said(firc_log_level_t level, const char *part) { return times_said(level, part) > 0; }

static bool last_move_is(size_t to, bool blocked) {
    return g_n_moves > 0 && firc_id_equal(g_moves[g_n_moves - 1].id, G1) && g_moves[g_n_moves - 1].to == to &&
           g_moves[g_n_moves - 1].blocked == blocked;
}

static firc_ifwatch_t *both_alive(void) {
    firc_ifwatch_t *w = fresh();
    g_groups[g_n++] = grp(1, AB, 2);
    firc_ifwatch_tick(w);
    result(w, "up0", true, false);
    result(w, "up1", true, false);
    return w;
}

TEST a_list_s_interfaces_are_checked_at_once_and_a_single_one_never(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const C[] = {"up2"};
    g_groups[g_n++] = grp(1, AB, 2);
    g_groups[g_n++] = grp(2, C, 1);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)1, times_queued("up0"), "%zu");
    ASSERT_EQ_FMT((size_t)1, times_queued("up1"), "%zu");
    ASSERT_EQ_FMT((size_t)0, times_queued("up2"), "%zu");
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("nothing is queued twice while in flight", (size_t)2, g_n_queued, "%zu");
    done(w);
    PASS();
}

TEST the_confirm_is_asked_3_s_later_and_the_second_failure_moves(void) {
    firc_ifwatch_t *w = both_alive();
    result(w, "up0", false, false);
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    g_now += 2999;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)1, times_queued("up0"), "%zu");
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    result(w, "up0", false, false);
    ASSERT(last_move_is(1, false));
    ASSERT(said(FIRC_LOG_WARN, "group G moved from up0 to up1: timed out"));
    ASSERT(said(FIRC_LOG_WARN, "interface up0 is dead: timed out"));
    done(w);
    PASS();
}

TEST a_regular_check_waits_the_interval_and_a_shorter_one_brings_it_forward(void) {
    firc_ifwatch_t *w = both_alive();
    g_now += 29999;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)1, times_queued("up0"), "%zu");
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    ASSERT_EQ_FMTm("the second interface comes a second later", (size_t)1, times_queued("up1"), "%zu");
    g_now += 1000;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up1"), "%zu");
    result(w, "up0", true, false);
    firc_app_config_t a;
    firc_app_config_init_defaults(&a);
    a.check.interval = 10 * FIRC_DURATION_SEC;
    firc_ifwatch_configure(w, &a);
    firc_app_config_clear(&a);
    g_now += 9999;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("the shorter interval holds from the change", (size_t)3, times_queued("up0"), "%zu");
    done(w);
    PASS();
}

TEST the_group_moves_back_after_120_s_of_passes_and_not_before(void) {
    firc_ifwatch_t *w = both_alive();
    result(w, "up0", false, false);
    g_now += 3000;
    result(w, "up0", false, false);
    ASSERT(last_move_is(1, false));
    g_now += 6000;
    result(w, "up0", true, false);
    ASSERT_EQ_FMT((size_t)1, g_n_moves, "%zu");
    g_now += 119999;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)1, g_n_moves, "%zu");
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT(last_move_is(0, false));
    ASSERT(said(FIRC_LOG_INFO, "group G moved back from up1 to up0"));
    done(w);
    PASS();
}

TEST a_move_up_the_list_off_a_dead_entry_is_a_warning(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const ABC[] = {"up0", "up1", "up2"};
    g_groups[g_n++] = grp(1, ABC, 3);
    firc_ifwatch_tick(w);
    result(w, "up0", true, false);
    result(w, "up1", true, false);
    result(w, "up2", true, false);
    result(w, "up0", false, false);
    g_now += 3000;
    result(w, "up0", false, false);
    ASSERT(last_move_is(1, false));
    g_now += 6000;
    result(w, "up0", true, false);
    result(w, "up1", false, false);
    g_now += 3000;
    result(w, "up1", false, false);
    ASSERT(last_move_is(0, false));
    ASSERT(said(FIRC_LOG_WARN, "group G moved from up1 to up0: timed out"));
    ASSERT_FALSE(said(FIRC_LOG_INFO, "moved back"));
    done(w);
    PASS();
}

TEST a_link_down_moves_at_once_without_a_check(void) {
    firc_ifwatch_t *w = both_alive();
    firc_ifwatch_link(w, "up0", false);
    ASSERT(last_move_is(1, false));
    size_t queued = g_n_queued;
    firc_ifwatch_link(w, "up0", true);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("a link up asks for a check at once", queued + 1, g_n_queued, "%zu");
    done(w);
    PASS();
}

TEST a_link_up_leaves_a_pending_confirm_where_it_is(void) {
    firc_ifwatch_t *w = both_alive();
    result(w, "up0", false, false);
    g_now += 1000;
    firc_ifwatch_link(w, "up0", true);
    g_now += 1999;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)1, times_queued("up0"), "%zu");
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    done(w);
    PASS();
}

TEST a_chatty_link_pulls_a_check_forward_once_per_interval(void) {
    firc_ifwatch_t *w = both_alive();
    firc_ifwatch_link(w, "up0", true);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    g_now += 15000;
    result(w, "up0", true, false);
    g_now += 4000;
    firc_ifwatch_link(w, "up0", true);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("a second link up inside the interval asks nothing", (size_t)2, times_queued("up0"), "%zu");
    g_now += 10999;
    firc_ifwatch_link(w, "up0", true);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    g_now += 1;
    firc_ifwatch_link(w, "up0", true);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)3, times_queued("up0"), "%zu");
    done(w);
    PASS();
}

TEST a_refresh_reads_the_link_and_finds_it_gone(void) {
    firc_ifwatch_t *w = both_alive();
    g_down = "up0";
    firc_ifwatch_refresh(w, "up1");
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    firc_ifwatch_refresh(w, NULL);
    ASSERT(last_move_is(1, false));
    done(w);
    PASS();
}

TEST a_tunnel_entry_follows_its_status_and_is_never_queued(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const T[] = {"tunvless0", "up1"};
    g_tunnel = "tunvless0";
    g_groups[g_n++] = grp(1, T, 2);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)0, times_queued("tunvless0"), "%zu");
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "tunvless0", &v));
    ASSERT_EQ(FIRC_IF_ALIVE, v.state);
    g_tunnel_is_down = true;
    firc_ifwatch_tick(w);
    ASSERT(last_move_is(1, false));
    done(w);
    PASS();
}

static firc_ifwatch_t *tunnel_first_both_alive(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const T[] = {"tunvless0", "up1"};
    g_tunnel = "tunvless0";
    g_groups[g_n++] = grp(1, T, 2);
    firc_ifwatch_tick(w);
    result(w, "up1", true, false);
    return w;
}

/* Catches: an NDM event that asks no check, asks one on every event, or decides the entry's state itself. */
TEST an_ndm_event_pulls_a_check_forward_once_per_interval(void) {
    firc_ifwatch_t *w = both_alive();
    firc_ifwatch_nudge(w, "up0");
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    g_now += 15000;
    result(w, "up0", true, false);
    g_now += 4000;
    firc_ifwatch_nudge(w, "up0");
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("a second event inside the interval asks nothing", (size_t)2, times_queued("up0"), "%zu");
    g_now += 10999;
    firc_ifwatch_nudge(w, "up0");
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    g_now += 1;
    firc_ifwatch_nudge(w, "up0");
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)3, times_queued("up0"), "%zu");
    ASSERT(firc_ifwatch_pick(w, g_groups[0]).active == 0);
    done(w);
    PASS();
}

/* Catches: an NDM event spending the budget a kernel link-up needs to ask its own check. */
TEST an_ndm_event_never_holds_back_a_link_up(void) {
    firc_ifwatch_t *w = both_alive();
    firc_ifwatch_nudge(w, "up0");
    firc_ifwatch_tick(w);
    g_now += 2000;
    result(w, "up0", true, false);
    g_now += 1000;
    firc_ifwatch_link(w, "up0", true);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)3, times_queued("up0"), "%zu");
    done(w);
    PASS();
}

/* Catches: an NDM event on a tunnel entry, which is never checked, queuing a check. */
TEST an_ndm_event_on_a_tunnel_entry_asks_nothing(void) {
    firc_ifwatch_t *w = tunnel_first_both_alive();
    size_t before = times_queued("tunvless0");
    firc_ifwatch_nudge(w, "tunvless0");
    firc_ifwatch_nudge(w, "nosuch0");
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT(before, times_queued("tunvless0"), "%zu");
    done(w);
    PASS();
}


TEST a_tunnel_removed_from_the_config_is_dead_and_the_group_moves(void) {
    firc_ifwatch_t *w = tunnel_first_both_alive();
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    g_tunnel = NULL;
    firc_ifwatch_tick(w);
    ASSERT(last_move_is(1, false));
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "tunvless0", &v));
    ASSERT_EQ(FIRC_IF_DEAD, v.state);
    ASSERT_STR_EQ("no configured tunnel uses this device", v.error);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("never checked by HTTP", (size_t)0, times_queued("tunvless0"), "%zu");
    done(w);
    PASS();
}

static firc_ifwatch_t *booting_tunnel_first(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const T[] = {"tunvless0", "up1"};
    g_tunnel = "tunvless0";
    g_starting = true;
    g_started_ms = g_now;
    g_down = "tunvless0";
    g_groups[g_n++] = grp(1, T, 2);
    firc_ifwatch_tick(w);
    result(w, "up1", true, false);
    return w;
}

TEST a_starting_tunnel_keeps_its_group_for_30_s_then_dies(void) {
    firc_ifwatch_t *w = booting_tunnel_first();
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "tunvless0", &v));
    ASSERT_EQ(FIRC_IF_UNKNOWN, v.state);
    g_now += 29999;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT(last_move_is(1, false));
    ASSERT(firc_ifwatch_view(w, "tunvless0", &v));
    ASSERT_EQ(FIRC_IF_DEAD, v.state);
    done(w);
    PASS();
}

TEST a_tunnel_up_within_30_s_keeps_its_group(void) {
    firc_ifwatch_t *w = booting_tunnel_first();
    g_now += 10000;
    g_starting = false;
    g_down = NULL;
    firc_ifwatch_tick(w);
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "tunvless0", &v));
    ASSERT_EQ(FIRC_IF_ALIVE, v.state);
    g_now += 30000;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    done(w);
    PASS();
}

TEST a_restarting_tunnel_is_unknown_again(void) {
    firc_ifwatch_t *w = tunnel_first_both_alive();
    g_starting = true;
    g_started_ms = g_now;
    g_down = "tunvless0";
    firc_ifwatch_link(w, "tunvless0", false);
    ASSERT_EQ_FMTm("the old device going away kills nothing", (size_t)0, g_n_moves, "%zu");
    firc_ifwatch_tick(w);
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "tunvless0", &v));
    ASSERT_EQ(FIRC_IF_UNKNOWN, v.state);
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    g_now += 30000;
    firc_ifwatch_tick(w);
    ASSERT(last_move_is(1, false));
    done(w);
    PASS();
}

TEST a_starting_tunnel_without_its_device_stays_unknown_then_dies(void) {
    firc_ifwatch_t *w = booting_tunnel_first();
    g_now += 5000;
    firc_ifwatch_link(w, "tunvless0", false);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "tunvless0", &v));
    ASSERT_EQ(FIRC_IF_UNKNOWN, v.state);
    g_now += 25000;
    firc_ifwatch_link(w, "tunvless0", false);
    ASSERT(last_move_is(1, false));
    done(w);
    PASS();
}

TEST a_starting_entry_never_unblocks_and_the_error_comes_at_5_min(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const T[] = {"tunvless0", "up1"};
    g_tunnel = "tunvless0";
    g_tunnel_is_down = true;
    g_down = "tunvless0";
    g_groups[g_n++] = grp(1, T, 2);
    firc_ifwatch_tick(w);
    firc_ifwatch_link(w, "up1", false);
    ASSERT(last_move_is(1, true));
    size_t moves = g_n_moves;
    for (int cycle = 0; cycle < 10; cycle++) {
        g_starting = true;
        g_started_ms = g_now;
        firc_ifwatch_tick(w);
        ASSERTm("an enable while it starts stays blocked", firc_ifwatch_pick(w, g_groups[0]).all_dead);
        g_now += 20000;
        firc_ifwatch_tick(w);
        g_starting = false;
        g_now += 10000;
        firc_ifwatch_tick(w);
    }
    ASSERT_EQ_FMTm("a crash loop never unblocks the group", moves, g_n_moves, "%zu");
    ASSERT_FALSE(said(FIRC_LOG_INFO, "group G is back on"));
    ASSERT(said(FIRC_LOG_ERROR, "group G: every interface of its list is dead"));
    done(w);
    PASS();
}

TEST a_tunvless_name_with_no_tunnel_is_dead_from_the_start(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const T[] = {"tunvless3", "up1"};
    g_groups[g_n++] = grp(1, T, 2);
    firc_ifwatch_tick(w);
    ASSERT(last_move_is(1, false));
    ASSERT_EQ_FMT((size_t)0, times_queued("tunvless3"), "%zu");
    done(w);
    PASS();
}

TEST only_tunvless_and_a_number_is_a_tunnel_entry(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const A[] = {"tunvless1a", "tunvless05"};
    static const char *const B[] = {"tunvless123", "tunvlessx"};
    g_groups[g_n++] = grp(1, A, 2);
    g_groups[g_n++] = grp(2, B, 2);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)1, times_queued("tunvless1a"), "%zu");
    ASSERT_EQ_FMT((size_t)1, times_queued("tunvless05"), "%zu");
    ASSERT_EQ_FMT((size_t)1, times_queued("tunvless123"), "%zu");
    ASSERT_EQ_FMT((size_t)1, times_queued("tunvlessx"), "%zu");
    done(w);
    PASS();
}

TEST a_tunnel_entry_dies_with_its_link(void) {
    firc_ifwatch_t *w = tunnel_first_both_alive();
    g_down = "tunvless0";
    firc_ifwatch_link(w, "tunvless0", false);
    ASSERT(last_move_is(1, false));
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("a tunnel still configured does not revive a gone device", (size_t)1, g_n_moves, "%zu");
    g_now += 120000;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("nor brings the group back after a hold", (size_t)1, g_n_moves, "%zu");
    done(w);
    PASS();
}

TEST a_failed_control_moves_nothing_and_says_the_check_fails(void) {
    firc_ifwatch_t *w = both_alive();
    result(w, "up0", false, true);
    g_now += 3000;
    result(w, "up0", false, true);
    result(w, "up1", false, true);
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    ASSERT(said(FIRC_LOG_WARN, "the interface check fails, even through the WAN: timed out"));
    done(w);
    PASS();
}

TEST a_round_that_ran_no_control_does_not_blame_the_wan(void) {
    firc_ifwatch_t *w = both_alive();
    result_as(w, "up0", false, true, false, last_gen("up0"), "the socket refused the check's mark");
    ASSERT(said(FIRC_LOG_WARN, "the interface check cannot run: the socket refused the check's mark"));
    ASSERT_FALSE(said(FIRC_LOG_WARN, "even through the WAN"));
    ASSERT_EQ_FMT((size_t)0, g_n_moves, "%zu");
    done(w);
    PASS();
}

/* Catches: a round that checked some entries said to be one where the check cannot run. */
TEST a_round_with_a_pass_names_the_entries_it_could_not_check(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const ABC[] = {"up0", "up1", "up2"};
    g_groups[g_n++] = grp(1, ABC, 3);
    firc_ifwatch_tick(w);
    firc_ifcheck_result_t r[3];
    memset(r, 0, sizeof(r));
    for (size_t i = 0; i < 3; i++) {
        snprintf(r[i].iface, sizeof(r[i].iface), "%s", ABC[i]);
        r[i].gen = last_gen(ABC[i]);
        r[i].control_failed = i > 0;
        snprintf(r[i].error, sizeof(r[i].error), "%s", i > 0 ? "the check's host a.test does not resolve" : "");
    }
    r[0].passed = true;
    firc_ifwatch_results(w, r, 3);
    ASSERT(said(FIRC_LOG_WARN, "cannot check up1, up2: the check's host a.test does not resolve"));
    ASSERT_FALSE(said(FIRC_LOG_WARN, "the interface check cannot run"));
    done(w);
    PASS();
}

TEST a_result_from_before_a_forget_is_dropped(void) {
    firc_ifwatch_t *w = fresh();
    g_groups[g_n++] = grp(1, AB, 2);
    firc_ifwatch_tick(w);
    uint32_t old = last_gen("up0");
    firc_group_free(g_groups[0]);
    g_n = 0;
    firc_ifwatch_tick(w);
    g_groups[g_n++] = grp(1, AB, 2);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    ASSERT(last_gen("up0") != old);
    result_as(w, "up0", true, false, true, old, "");
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "up0", &v));
    ASSERT_EQm("the old check says nothing of the new record", FIRC_IF_UNKNOWN, v.state);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("and leaves the new check in flight", (size_t)2, times_queued("up0"), "%zu");
    result(w, "up0", true, false);
    ASSERT(firc_ifwatch_view(w, "up0", &v));
    ASSERT_EQ(FIRC_IF_ALIVE, v.state);
    done(w);
    PASS();
}

TEST every_entry_dead_blocks_the_group_and_errors_after_5_min(void) {
    firc_ifwatch_t *w = both_alive();
    firc_ifwatch_link(w, "up0", false);
    firc_ifwatch_link(w, "up1", false);
    ASSERT(last_move_is(1, true));
    ASSERT(said(FIRC_LOG_WARN, "group G: every interface of its list is dead"));
    ASSERT_FALSE(said(FIRC_LOG_ERROR, "group G: every interface of its list is dead"));
    g_now += 300000;
    firc_ifwatch_tick(w);
    ASSERT(said(FIRC_LOG_ERROR, "group G: every interface of its list is dead"));
    firc_event_reset_for_test();
    result(w, "up0", true, false);
    ASSERT(last_move_is(0, false));
    ASSERT(said(FIRC_LOG_INFO, "group G is back on up0"));
    ASSERT_EQ_FMTm("one line for the unblock", (size_t)1, times_said(FIRC_LOG_INFO, "group G"), "%zu");
    ASSERT_EQ_FMT((size_t)0, times_said(FIRC_LOG_WARN, "group G"), "%zu");
    done(w);
    PASS();
}

TEST an_unblock_by_pick_ends_the_all_dead_run(void) {
    firc_ifwatch_t *w = both_alive();
    firc_ifwatch_link(w, "up0", false);
    firc_ifwatch_link(w, "up1", false);
    ASSERT(last_move_is(1, true));
    g_now += 200000;
    static const char *const CB[] = {"up2", "up1"};
    firc_group_set_ifaces(g_groups[0], CB, 2);
    firc_event_reset_for_test();
    firc_ifchoice_t c = firc_ifwatch_pick(w, g_groups[0]);
    ASSERT_FALSE(c.all_dead);
    ASSERT(said(FIRC_LOG_INFO, "group G is back on up2"));
    firc_ifwatch_link(w, "up2", false);
    ASSERT(last_move_is(0, true));
    ASSERTm("a new run starts at WARN", said(FIRC_LOG_WARN, "group G: every interface of its list is dead"));
    g_now += 299999;
    firc_ifwatch_tick(w);
    ASSERT_FALSEm("and waits its own 5 min", said(FIRC_LOG_ERROR, "group G: every interface of its list is dead"));
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT(said(FIRC_LOG_ERROR, "group G: every interface of its list is dead"));
    done(w);
    PASS();
}

TEST an_edited_list_keeps_the_active_entry_by_name(void) {
    firc_ifwatch_t *w = both_alive();
    firc_ifwatch_link(w, "up0", false);
    ASSERT(last_move_is(1, false));
    static const char *const CB[] = {"up2", "up1"};
    firc_group_set_ifaces(g_groups[0], CB, 2);
    firc_ifchoice_t c = firc_ifwatch_pick(w, g_groups[0]);
    ASSERT_EQ_FMT((size_t)1, c.active, "%zu");
    ASSERT_FALSE(c.all_dead);
    done(w);
    PASS();
}

TEST pick_puts_a_new_group_on_its_first_entry_that_is_not_dead(void) {
    firc_ifwatch_t *w = fresh();
    g_down = "up0";
    firc_group_t *g = grp(1, AB, 2);
    firc_ifchoice_t c = firc_ifwatch_pick(w, g);
    ASSERT_EQ_FMT((size_t)1, c.active, "%zu");
    firc_group_free(g);
    done(w);
    PASS();
}

TEST pick_knows_a_tunnel_entry_before_any_tick(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const T[] = {"tunvless3", "up1"};
    firc_group_t *g = grp(1, T, 2);
    firc_ifchoice_t c = firc_ifwatch_pick(w, g);
    ASSERT_EQ_FMT((size_t)1, c.active, "%zu");
    firc_group_free(g);
    done(w);
    PASS();
}

TEST a_refused_move_is_asked_again_on_the_next_tick(void) {
    firc_ifwatch_t *w = both_alive();
    g_move_err = FIRC_ERR_IO;
    firc_ifwatch_link(w, "up0", false);
    ASSERT_EQ_FMT((size_t)1, g_n_moves, "%zu");
    ASSERT(said(FIRC_LOG_WARN, "group G: the move to up1 failed"));
    g_move_err = FIRC_OK;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, g_n_moves, "%zu");
    ASSERT(last_move_is(1, false));
    result(w, "up0", true, false);
    g_move_err = FIRC_ERR_IO;
    ASSERT_EQm("a refused button says so", FIRC_ERR_IO, firc_ifwatch_move_up(w, G1));
    g_move_err = FIRC_OK;
    done(w);
    PASS();
}

TEST a_move_that_keeps_failing_is_an_error_after_a_minute(void) {
    firc_ifwatch_t *w = both_alive();
    g_move_err = FIRC_ERR_IO;
    firc_ifwatch_link(w, "up0", false);
    ASSERT(said(FIRC_LOG_WARN, "group G: the move to up1 failed"));
    g_now += 59999;
    firc_ifwatch_tick(w);
    ASSERT_FALSE(said(FIRC_LOG_ERROR, "group G: the move to up1 failed"));
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT(said(FIRC_LOG_ERROR, "group G: the move to up1 failed"));
    done(w);
    PASS();
}

TEST a_dead_interface_s_reminder_counts_every_dead_result(void) {
    firc_ifwatch_t *w = both_alive();
    result(w, "up0", false, false);
    g_now += 3000;
    result(w, "up0", false, false);
    ASSERT(said(FIRC_LOG_WARN, "interface up0 is dead: timed out"));
    for (int i = 0; i < 3; i++) {
        g_now += 30000;
        result(w, "up0", false, false);
    }
    g_now += 510000;
    result(w, "up0", false, false);
    ASSERT(said(FIRC_LOG_WARN, "interface up0 is dead: timed out (still failing, 5 times for 10 min)"));
    done(w);
    PASS();
}

TEST a_move_of_an_unrouted_group_is_kept_but_not_said(void) {
    firc_ifwatch_t *w = both_alive();
    g_move_err = FIRC_ERR_NOENT;
    firc_ifwatch_link(w, "up0", false);
    ASSERT(last_move_is(1, false));
    ASSERT_FALSE(said(FIRC_LOG_WARN, "group G moved"));
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMTm("the entry is kept for the next enable", (size_t)1, g_n_moves, "%zu");
    result(w, "up0", true, false);
    ASSERT_EQm("the button says the group is not routed", FIRC_ERR_AGAIN, firc_ifwatch_move_up(w, G1));
    ASSERT_FALSE(said(FIRC_LOG_INFO, "group G moved"));
    done(w);
    PASS();
}

TEST move_up_needs_the_first_entry_alive(void) {
    firc_ifwatch_t *w = both_alive();
    firc_ifwatch_link(w, "up0", false);
    ASSERT_EQ(FIRC_ERR_STATE, firc_ifwatch_move_up(w, G1));
    result(w, "up0", true, false);
    ASSERT(last_move_is(1, false));
    ASSERT_EQ(FIRC_OK, firc_ifwatch_move_up(w, G1));
    ASSERT(last_move_is(0, false));
    ASSERT_EQ(FIRC_ERR_NOENT, firc_ifwatch_move_up(w, (firc_id_t){{9, 9, 9, 9}}));
    done(w);
    PASS();
}

TEST a_removed_group_s_interfaces_are_forgotten(void) {
    firc_ifwatch_t *w = both_alive();
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "up0", &v));
    ASSERT_EQ_FMTm("fixture: both check rules are in", (size_t)2, check_rules(RTM_NEWRULE), "%zu");
    firc_group_free(g_groups[0]);
    g_n = 0;
    firc_ifwatch_tick(w);
    ASSERT_FALSE(firc_ifwatch_view(w, "up0", &v));
    ASSERT_EQ_FMTm("a forgotten interface takes its check rule back", (size_t)2, check_rules(RTM_DELRULE), "%zu");
    done(w);
    PASS();
}

TEST free_takes_every_check_rule_back(void) {
    firc_ifwatch_t *w = both_alive();
    ASSERT_EQ_FMT((size_t)2, check_rules(RTM_NEWRULE), "%zu");
    firc_ifwatch_free(w);
    ASSERT_EQ_FMT((size_t)2, check_rules(RTM_DELRULE), "%zu");
    kernel_done();
    PASS();
}

TEST a_lost_check_is_queued_again_after_two_minutes(void) {
    firc_ifwatch_t *w = fresh();
    g_groups[g_n++] = grp(1, AB, 2);
    firc_ifwatch_tick(w);
    g_now += FIRC_IFWATCH_LOST_MS - 1;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)1, times_queued("up0"), "%zu");
    g_now += 1;
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)2, times_queued("up0"), "%zu");
    done(w);
    PASS();
}

static size_t distinct_queued(void) {
    size_t c = 0;
    for (size_t i = 0; i < g_n_queued && i < 64; i++) {
        bool first = true;
        for (size_t j = 0; j < i; j++) { first = first && strcmp(g_queued[i], g_queued[j]) != 0; }
        c += first ? 1u : 0u;
    }
    return c;
}

TEST the_seventeenth_interface_is_not_checked_and_said_once(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const L[5][4] = {{"ca", "cb", "cc", "cd"},
                                        {"ce", "cf", "cg", "ch"},
                                        {"ci", "cj", "ck", "cl"},
                                        {"cm", "cn", "co", "cp"},
                                        {"cq", "cr", NULL, NULL}};
    for (uint8_t i = 0; i < 5; i++) { g_groups[g_n++] = grp((uint8_t)(i + 1), L[i], i < 4 ? 4u : 2u); }
    firc_ifwatch_tick(w);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)16, distinct_queued(), "%zu");
    ASSERT_EQ_FMT((size_t)16, check_rules(RTM_NEWRULE), "%zu");
    firc_if_view_t v;
    ASSERT(firc_ifwatch_view(w, "cp", &v));
    ASSERT_FALSE(firc_ifwatch_view(w, "cq", &v));
    ASSERT_FALSE(firc_ifwatch_view(w, "cr", &v));
    ASSERT(said(FIRC_LOG_ERROR, "interface lists name more than 16 interfaces; cq is not checked"));
    ASSERT_FALSEm("said once", said(FIRC_LOG_ERROR, "cr is not checked") || said(FIRC_LOG_WARN, "cr is not checked"));
    ASSERT_FALSE(said(FIRC_LOG_DEBUG, "is not checked"));
    firc_group_free(g_groups[--g_n]);
    static const char *const OUT[] = {"ca", "cb"};
    firc_group_set_ifaces(g_groups[0], OUT, 2);
    firc_ifwatch_tick(w);
    firc_group_set_ifaces(g_groups[0], L[0], 4);
    g_groups[g_n++] = grp(5, L[4], 2);
    firc_event_reset_for_test();
    firc_ifwatch_tick(w);
    ASSERTm("an overflow after room came back is said again",
            said(FIRC_LOG_ERROR, "interface lists name more than 16 interfaces; cq is not checked"));
    done(w);
    PASS();
}

TEST a_swapped_name_at_the_cap_takes_the_freed_slot_at_once(void) {
    firc_ifwatch_t *w = fresh();
    static const char *const L[4][4] = {
        {"ca", "cb", "cc", "cd"}, {"ce", "cf", "cg", "ch"}, {"ci", "cj", "ck", "cl"}, {"cm", "cn", "co", "cp"}};
    for (uint8_t i = 0; i < 4; i++) { g_groups[g_n++] = grp((uint8_t)(i + 1), L[i], 4); }
    firc_ifwatch_tick(w);
    static const char *const S[] = {"ca", "cb", "cc", "cq"};
    firc_group_set_ifaces(g_groups[0], S, 4);
    firc_ifwatch_tick(w);
    ASSERT_EQ_FMT((size_t)1, times_queued("cq"), "%zu");
    ASSERT_FALSE(said(FIRC_LOG_ERROR, "is not checked") || said(FIRC_LOG_WARN, "is not checked"));
    done(w);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_list_s_interfaces_are_checked_at_once_and_a_single_one_never);
    RUN_TEST(the_confirm_is_asked_3_s_later_and_the_second_failure_moves);
    RUN_TEST(a_regular_check_waits_the_interval_and_a_shorter_one_brings_it_forward);
    RUN_TEST(the_group_moves_back_after_120_s_of_passes_and_not_before);
    RUN_TEST(a_move_up_the_list_off_a_dead_entry_is_a_warning);
    RUN_TEST(a_link_down_moves_at_once_without_a_check);
    RUN_TEST(a_link_up_leaves_a_pending_confirm_where_it_is);
    RUN_TEST(a_chatty_link_pulls_a_check_forward_once_per_interval);
    RUN_TEST(an_ndm_event_pulls_a_check_forward_once_per_interval);
    RUN_TEST(an_ndm_event_on_a_tunnel_entry_asks_nothing);
    RUN_TEST(an_ndm_event_never_holds_back_a_link_up);
    RUN_TEST(a_refresh_reads_the_link_and_finds_it_gone);
    RUN_TEST(a_tunnel_entry_follows_its_status_and_is_never_queued);
    RUN_TEST(a_tunnel_removed_from_the_config_is_dead_and_the_group_moves);
    RUN_TEST(a_starting_tunnel_keeps_its_group_for_30_s_then_dies);
    RUN_TEST(a_tunnel_up_within_30_s_keeps_its_group);
    RUN_TEST(a_restarting_tunnel_is_unknown_again);
    RUN_TEST(a_starting_tunnel_without_its_device_stays_unknown_then_dies);
    RUN_TEST(a_starting_entry_never_unblocks_and_the_error_comes_at_5_min);
    RUN_TEST(a_tunvless_name_with_no_tunnel_is_dead_from_the_start);
    RUN_TEST(only_tunvless_and_a_number_is_a_tunnel_entry);
    RUN_TEST(a_tunnel_entry_dies_with_its_link);
    RUN_TEST(a_failed_control_moves_nothing_and_says_the_check_fails);
    RUN_TEST(a_round_that_ran_no_control_does_not_blame_the_wan);
    RUN_TEST(a_round_with_a_pass_names_the_entries_it_could_not_check);
    RUN_TEST(a_result_from_before_a_forget_is_dropped);
    RUN_TEST(every_entry_dead_blocks_the_group_and_errors_after_5_min);
    RUN_TEST(an_unblock_by_pick_ends_the_all_dead_run);
    RUN_TEST(an_edited_list_keeps_the_active_entry_by_name);
    RUN_TEST(pick_puts_a_new_group_on_its_first_entry_that_is_not_dead);
    RUN_TEST(pick_knows_a_tunnel_entry_before_any_tick);
    RUN_TEST(a_refused_move_is_asked_again_on_the_next_tick);
    RUN_TEST(a_move_that_keeps_failing_is_an_error_after_a_minute);
    RUN_TEST(a_dead_interface_s_reminder_counts_every_dead_result);
    RUN_TEST(a_move_of_an_unrouted_group_is_kept_but_not_said);
    RUN_TEST(move_up_needs_the_first_entry_alive);
    RUN_TEST(a_removed_group_s_interfaces_are_forgotten);
    RUN_TEST(free_takes_every_check_rule_back);
    RUN_TEST(a_lost_check_is_queued_again_after_two_minutes);
    RUN_TEST(the_seventeenth_interface_is_not_checked_and_said_once);
    RUN_TEST(a_swapped_name_at_the_cap_takes_the_freed_slot_at_once);
    GREATEST_MAIN_END();
}
