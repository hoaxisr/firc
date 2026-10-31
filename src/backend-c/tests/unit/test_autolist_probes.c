#include "greatest.h"

#include <stdio.h>
#include <string.h>

#include "firc/autolistprobes.h"

static firc_autolist_result_t res(uint8_t v, bool shortb) {
    firc_autolist_result_t r;
    memset(&r, 0, sizeof(r));
    r.verdict = v;
    r.short_body = shortb;
    return r;
}

static bool take(firc_al_probes_t *p, int64_t now, char *h, bool *re) { return firc_al_probes_next(p, now, h, 256, true, re, NULL); }

TEST budget_spent_queues_not_runs(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char n[32], h[256];
    bool re;
    for (int i = 0; i < 31; i++) {
        snprintf(n, sizeof(n), "h%d.example", i);
        firc_al_probes_nominate(p, n, false, 1000);
    }
    firc_autolist_result_t r = res(FIRC_AUTOLIST_BLOCKED, false);
    for (int i = 0; i < 30; i++) {
        ASSERT(take(p, 1000 + i, h, &re));
        firc_al_probes_done(p, h, &r, 1000 + i);
    }
    ASSERT_FALSE(take(p, 1100, h, &re));
    uint32_t used, queued;
    firc_al_probes_counts(p, 1100, &used, &queued);
    ASSERT_EQ(30, used);
    ASSERT_EQ(1, queued);
    ASSERT_FALSE(take(p, 1000 + 3599, h, &re));
    ASSERT(take(p, 1000 + 3600, h, &re));
    firc_al_probes_free(p);
    PASS();
}

TEST user_request_jumps_queue(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re = true;
    firc_al_probes_nominate(p, "a.example", false, 10);
    firc_al_probes_nominate(p, "a.example", false, 10);
    firc_al_probes_nominate(p, "b.example", false, 10);
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "c.example", 10));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "d.example", 11));
    ASSERT(take(p, 20, h, &re));
    ASSERT_STR_EQ("c.example", h);
    ASSERT_FALSE(re);
    ASSERT(take(p, 20, h, &re));
    ASSERT_STR_EQ("d.example", h);
    ASSERT(take(p, 20, h, &re));
    ASSERT_STR_EQ("a.example", h);
    ASSERT(take(p, 20, h, &re));
    ASSERT_STR_EQ("b.example", h);
    ASSERT_FALSE(take(p, 20, h, &re));
    firc_al_probes_free(p);
    PASS();
}

TEST most_noted_goes_before_fewer(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re;
    firc_al_probes_nominate(p, "few.example", false, 1);
    firc_al_probes_nominate(p, "many.example", false, 1);
    firc_al_probes_nominate(p, "many.example", false, 2);
    ASSERT(take(p, 3, h, &re));
    ASSERT_STR_EQ("many.example", h);
    firc_al_probes_free(p);
    PASS();
}

TEST open_is_cached_a_day(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re;
    firc_al_probes_nominate(p, "a.example", false, 100);
    ASSERT(take(p, 100, h, &re));
    firc_autolist_result_t r = res(FIRC_AUTOLIST_REACHABLE, true);
    firc_al_probes_done(p, "a.example", &r, 100);
    ASSERT_EQ(FIRC_AL_ASK_CACHED, firc_al_probes_nominate(p, "a.example", false, 100 + 86399));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "a.example", false, 100 + 86400));
    int64_t at = 0;
    ASSERT_EQ(NULL, firc_al_probes_result(p, "a.example", 100 + 86400, &at));
    const firc_autolist_result_t *got = firc_al_probes_result(p, "a.example", 100 + 86399, &at);
    ASSERT(got != NULL);
    ASSERT_EQ(100, at);
    ASSERT(got->short_body);
    firc_al_probes_free(p);
    PASS();
}

TEST unknown_cached_an_hour(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re;
    firc_al_probes_nominate(p, "a.example", false, 5);
    ASSERT(take(p, 5, h, &re));
    firc_autolist_result_t r = res(FIRC_AUTOLIST_UNKNOWN, false);
    firc_al_probes_done(p, "a.example", &r, 5);
    ASSERT_EQ(FIRC_AL_ASK_CACHED, firc_al_probes_nominate(p, "a.example", false, 5 + 3599));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "a.example", false, 5 + 3600));
    firc_al_probes_free(p);
    PASS();
}

TEST blocked_not_cached(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re;
    firc_al_probes_nominate(p, "a.example", false, 5);
    ASSERT(take(p, 5, h, &re));
    firc_autolist_result_t r = res(FIRC_AUTOLIST_BLOCKED, false);
    firc_al_probes_done(p, "a.example", &r, 5);
    int64_t at = 0;
    const firc_autolist_result_t *got = firc_al_probes_result(p, "a.example", 5 + 3599, &at);
    ASSERT(got != NULL);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, got->verdict);
    ASSERT_EQ(5, at);
    ASSERT_EQ(NULL, firc_al_probes_result(p, "a.example", 5 + 3600, NULL));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "a.example", false, 6));
    firc_al_probes_free(p);
    PASS();
}

TEST queue_drops_oldest_at_65(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char n[32], h[256];
    bool re;
    for (int i = 0; i < 65; i++) {
        snprintf(n, sizeof(n), "h%d.example", i);
        firc_al_probes_nominate(p, n, false, 1);
    }
    uint32_t used, queued;
    firc_al_probes_counts(p, 1, &used, &queued);
    ASSERT_EQ(64, queued);
    ASSERT(take(p, 2, h, &re));
    ASSERT_STR_EQ("h1.example", h);
    firc_al_probes_free(p);
    PASS();
}

TEST recheck_ignores_cache_and_counts(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re = false;
    firc_al_probes_nominate(p, "a.example", false, 10);
    ASSERT(take(p, 10, h, &re));
    firc_autolist_result_t r = res(FIRC_AUTOLIST_REACHABLE, false);
    firc_al_probes_done(p, "a.example", &r, 10);
    ASSERT_EQ(FIRC_AL_ASK_CACHED, firc_al_probes_nominate(p, "a.example", false, 11));
    firc_al_probes_nominate(p, "n.example", false, 11);
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_recheck(p, "a.example", 12));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "u.example", 12));
    ASSERT(take(p, 13, h, &re));
    ASSERT_STR_EQ("u.example", h);
    ASSERT_FALSE(re);
    ASSERT(take(p, 14, h, &re));
    ASSERT_STR_EQ("a.example", h);
    ASSERT(re);
    uint32_t used, queued;
    firc_al_probes_counts(p, 14, &used, &queued);
    ASSERT_EQ(3, used);
    ASSERT_EQ(1, queued);
    firc_al_probes_free(p);
    PASS();
}

TEST same_host_within_ten_minutes_busy(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re;
    firc_al_probes_nominate(p, "a.example", false, 1000);
    ASSERT(take(p, 1000, h, &re));
    firc_autolist_result_t r = res(FIRC_AUTOLIST_BLOCKED, false);
    firc_al_probes_done(p, "a.example", &r, 1000);
    ASSERT_EQ(FIRC_AL_ASK_BUSY, firc_al_probes_request(p, "a.example", 1599));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "a.example", 1600));
    firc_al_probes_free(p);
    PASS();
}

TEST request_is_full_when_hour_spent(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char n[32], h[256];
    bool re;
    firc_autolist_result_t r = res(FIRC_AUTOLIST_BLOCKED, false);
    for (int i = 0; i < 30; i++) {
        snprintf(n, sizeof(n), "h%d.example", i);
        firc_al_probes_nominate(p, n, false, 100);
        ASSERT(take(p, 100, h, &re));
        firc_al_probes_done(p, h, &r, 100);
    }
    ASSERT_EQ(FIRC_AL_ASK_FULL, firc_al_probes_request(p, "x.example", 200));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "x.example", 100 + 3600));
    firc_al_probes_free(p);
    PASS();
}

TEST handed_out_host_is_not_issued_twice(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re;
    firc_al_probes_nominate(p, "a.example", false, 1);
    ASSERT(take(p, 1, h, &re));
    firc_al_probes_nominate(p, "a.example", false, 2);
    ASSERT_EQ(FIRC_AL_ASK_BUSY, firc_al_probes_recheck(p, "a.example", 2));
    ASSERT_FALSE(take(p, 3, h, &re));
    ASSERT_EQ(FIRC_AL_ASK_BUSY, firc_al_probes_request(p, "a.example", 3));
    firc_autolist_result_t r = res(FIRC_AUTOLIST_BLOCKED, false);
    firc_al_probes_done(p, "a.example", &r, 4);
    firc_al_probes_nominate(p, "a.example", false, 5);
    ASSERT(take(p, 5, h, &re));
    firc_al_probes_free(p);
    PASS();
}

TEST cache_evicts_least_recently_stored(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char n[32], h[256];
    bool re;
    firc_autolist_result_t r = res(FIRC_AUTOLIST_REACHABLE, false);
    for (int i = 0; i < 257; i++) {
        snprintf(n, sizeof(n), "h%d.example", i);
        firc_al_probes_nominate(p, n, false, 10 + i * 200);
        ASSERT(firc_al_probes_next(p, 10 + i * 200, h, 256, true, &re, NULL));
        firc_al_probes_done(p, h, &r, 10 + i * 200);
    }
    ASSERT_EQ(NULL, firc_al_probes_result(p, "h0.example", 52000, NULL));
    ASSERT(firc_al_probes_result(p, "h1.example", 52000, NULL) != NULL);
    ASSERT(firc_al_probes_result(p, "h256.example", 52000, NULL) != NULL);
    firc_al_probes_free(p);
    PASS();
}

TEST small_buffer_keeps_the_host_queued(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[4];
    bool re;
    firc_al_probes_nominate(p, "a.example", false, 1);
    ASSERT_FALSE(firc_al_probes_next(p, 1, h, sizeof(h), true, &re, NULL));
    uint32_t used, queued;
    firc_al_probes_counts(p, 1, &used, &queued);
    ASSERT_EQ(0, used);
    ASSERT_EQ(1, queued);
    ASSERT_EQ(FIRC_AL_ASK_BUSY, firc_al_probes_nominate(p, "", false, 1));
    firc_al_probes_free(p);
    PASS();
}

TEST queue_never_evicts_a_user_request(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char n[32], h[256];
    bool re;
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "user.example", 1));
    for (int i = 0; i < 63; i++) {
        snprintf(n, sizeof(n), "h%d.example", i);
        ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, n, false, 1));
    }
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "late.example", false, 1));
    uint32_t used, queued;
    firc_al_probes_counts(p, 1, &used, &queued);
    ASSERT_EQ(64, queued);
    ASSERT(take(p, 2, h, &re));
    ASSERT_STR_EQ("user.example", h);
    ASSERT(take(p, 2, h, &re));
    ASSERT_STR_EQ("h1.example", h);
    firc_al_probes_free(p);
    PASS();
}

TEST full_queue_of_rechecks_takes_only_a_request(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char n[32];
    for (int i = 0; i < 64; i++) {
        snprintf(n, sizeof(n), "u%d.example", i);
        ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_recheck(p, n, 1));
    }
    ASSERT_EQ(FIRC_AL_ASK_FULL, firc_al_probes_nominate(p, "n.example", false, 1));
    ASSERT_EQ(FIRC_AL_ASK_FULL, firc_al_probes_recheck(p, "c.example", 1));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "r.example", 1));
    ASSERT_EQ(FIRC_AL_ASK_FULL, firc_al_probes_nominate(p, "n.example", false, 1));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "u0.example", 1));
    firc_al_probes_free(p);
    PASS();
}

TEST inflight_slot_expires_after_two_minutes(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re;
    firc_al_probes_nominate(p, "a.example", false, 1000);
    ASSERT(take(p, 1000, h, &re));
    firc_al_probes_nominate(p, "a.example", false, 1119);
    ASSERT_EQ(FIRC_AL_ASK_BUSY, firc_al_probes_request(p, "a.example", 1119));
    ASSERT_FALSE(take(p, 1119, h, &re));
    ASSERT_FALSE(take(p, 1120, h, &re));
    firc_al_probes_nominate(p, "a.example", false, 1120);
    ASSERT(take(p, 1120, h, &re));
    ASSERT_STR_EQ("a.example", h);
    firc_al_probes_free(p);
    PASS();
}

TEST results_list_every_shown_verdict_newest_first(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    firc_autolist_result_t blocked = res(FIRC_AUTOLIST_BLOCKED, false);
    blocked.why = 3;
    blocked.bytes = 16384;
    firc_autolist_result_t open = res(FIRC_AUTOLIST_REACHABLE, true);
    firc_autolist_result_t unknown = res(FIRC_AUTOLIST_UNKNOWN, false);
    firc_al_probes_done(p, "old.example", &unknown, 1000);
    firc_al_probes_done(p, "a.example", &blocked, 2000);
    firc_al_probes_done(p, "b.example", &open, 2100);
    firc_al_probe_seen_t seen[4];
    ASSERT_EQ(3u, firc_al_probes_results(p, 2200, seen, 4));
    ASSERT_STR_EQ("b.example", seen[0].host);
    ASSERT_EQ(2100, seen[0].at);
    ASSERT(seen[0].result.short_body);
    ASSERT_STR_EQ("a.example", seen[1].host);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, seen[1].result.verdict);
    ASSERT_EQ(3, seen[1].result.why);
    ASSERT_EQ(16384u, seen[1].result.bytes);
    ASSERT_STR_EQ("old.example", seen[2].host);
    ASSERT_EQ(1u, firc_al_probes_results(p, 2200, seen, 1));
    ASSERT_STR_EQ("b.example", seen[0].host);
    ASSERT_EQ(2u, firc_al_probes_results(p, 1000 + 3600, seen, 4));
    ASSERT_EQ(1u, firc_al_probes_results(p, 2000 + 3600, seen, 4));
    ASSERT_STR_EQ("b.example", seen[0].host);
    ASSERT_EQ(0u, firc_al_probes_results(NULL, 2200, seen, 4));
    firc_al_probes_free(p);
    PASS();
}

TEST next_without_notes_skips_nominations(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re = false;
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "note.example", false, 1000));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_recheck(p, "re.example", 1000));
    ASSERT(firc_al_probes_next(p, 1000, h, sizeof(h), false, &re, NULL));
    ASSERT_STR_EQ("re.example", h);
    ASSERT(re);
    ASSERT_FALSE(firc_al_probes_next(p, 1000, h, sizeof(h), false, &re, NULL));
    uint32_t used, queued;
    firc_al_probes_counts(p, 1000, &used, &queued);
    ASSERT_EQ(1, used);
    ASSERT_EQ(1, queued);
    ASSERT(firc_al_probes_next(p, 1000, h, sizeof(h), true, &re, NULL));
    ASSERT_STR_EQ("note.example", h);
    ASSERT_FALSE(re);
    firc_al_probes_free(p);
    PASS();
}

TEST request_evicts_a_recheck_when_full(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char n[32], h[256];
    bool re = false;
    for (int i = 0; i < FIRC_AUTOLIST_PROBES_QUEUE - 1; i++) {
        snprintf(n, sizeof(n), "r%d.example", i);
        ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_recheck(p, n, 1000));
    }
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "note.example", false, 1000));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "u1.example", 1000));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "u2.example", 1000));
    uint32_t used, queued;
    firc_al_probes_counts(p, 1000, &used, &queued);
    ASSERT_EQ(FIRC_AUTOLIST_PROBES_QUEUE, queued);
    ASSERT(take(p, 1000, h, &re));
    ASSERT_STR_EQ("u1.example", h);
    ASSERT(take(p, 1000, h, &re));
    ASSERT_STR_EQ("u2.example", h);
    ASSERT(take(p, 1000, h, &re));
    ASSERTm("the oldest recheck went", strcmp(h, "r1.example") == 0);
    firc_autolist_result_t r = res(FIRC_AUTOLIST_BLOCKED, false);
    for (int i = 0; i < 61; i++) {
        int64_t at = 1000 + 3600 * (i / 29 + 1);
        ASSERT(take(p, at, h, &re));
        ASSERT(re);
        firc_al_probes_done(p, h, &r, at);
    }
    ASSERT_FALSE(take(p, 1000 + 3600 * 4, h, &re));
    firc_al_probes_free(p);
    p = firc_al_probes_new();
    for (int i = 0; i < FIRC_AUTOLIST_PROBES_QUEUE; i++) {
        snprintf(n, sizeof(n), "u%d.example", i);
        ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, n, 1000));
    }
    ASSERT_EQ(FIRC_AL_ASK_FULL, firc_al_probes_request(p, "more.example", 1000));
    ASSERT_EQ(FIRC_AL_ASK_FULL, firc_al_probes_recheck(p, "re.example", 1000));
    firc_al_probes_free(p);
    PASS();
}

TEST rechecking_is_true_only_while_a_recheck_is_queued(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char n[32], h[256];
    bool re = false;
    ASSERT_FALSE(firc_al_probes_rechecking(p));
    ASSERT_FALSE(firc_al_probes_rechecking(NULL));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "note.example", false, 1000));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "user.example", 1000));
    ASSERT_FALSE(firc_al_probes_rechecking(p));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_recheck(p, "re.example", 1000));
    ASSERT(firc_al_probes_rechecking(p));
    ASSERT(take(p, 1000, h, &re));
    ASSERT_STR_EQ("user.example", h);
    ASSERT(firc_al_probes_rechecking(p));
    ASSERT(take(p, 1000, h, &re));
    ASSERT(re);
    ASSERT_FALSE(firc_al_probes_rechecking(p));
    firc_al_probes_free(p);
    p = firc_al_probes_new();
    for (int i = 0; i < FIRC_AUTOLIST_PROBES_QUEUE; i++) {
        snprintf(n, sizeof(n), "r%d.example", i);
        ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_recheck(p, n, 1000));
    }
    for (int i = 0; i < FIRC_AUTOLIST_PROBES_QUEUE - 1; i++) {
        snprintf(n, sizeof(n), "u%d.example", i);
        ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, n, 1000));
        ASSERT(firc_al_probes_rechecking(p));
    }
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "last.example", 1000));
    ASSERT_FALSE(firc_al_probes_rechecking(p));
    firc_al_probes_free(p);
    PASS();
}

TEST next_hands_out_the_latest_nominations_domain_flag(void) {
    firc_al_probes_t *p = firc_al_probes_new();
    char h[256];
    bool re = false, dom = false;
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "many.example", true, 1000));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "many.example", 1000));
    ASSERT(firc_al_probes_next(p, 1000, h, sizeof(h), true, &re, &dom));
    ASSERT_STR_EQ("many.example", h);
    ASSERTm("a request on a domain nomination keeps the flag", dom);
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "a.two.example", true, 1000));
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_nominate(p, "a.two.example", false, 1001));
    ASSERT(firc_al_probes_next(p, 1001, h, sizeof(h), true, &re, &dom));
    ASSERT_STR_EQ("a.two.example", h);
    ASSERTm("the latest nomination wins", !dom);
    ASSERT_EQ(FIRC_AL_ASK_QUEUED, firc_al_probes_request(p, "user.example", 1002));
    dom = true;
    ASSERT(firc_al_probes_next(p, 1002, h, sizeof(h), true, &re, &dom));
    ASSERT_FALSE(dom);
    firc_al_probes_free(p);
    PASS();
}

SUITE(autolist_probes_suite) {
    RUN_TEST(budget_spent_queues_not_runs);
    RUN_TEST(user_request_jumps_queue);
    RUN_TEST(most_noted_goes_before_fewer);
    RUN_TEST(open_is_cached_a_day);
    RUN_TEST(unknown_cached_an_hour);
    RUN_TEST(blocked_not_cached);
    RUN_TEST(queue_drops_oldest_at_65);
    RUN_TEST(recheck_ignores_cache_and_counts);
    RUN_TEST(same_host_within_ten_minutes_busy);
    RUN_TEST(request_is_full_when_hour_spent);
    RUN_TEST(handed_out_host_is_not_issued_twice);
    RUN_TEST(cache_evicts_least_recently_stored);
    RUN_TEST(small_buffer_keeps_the_host_queued);
    RUN_TEST(queue_never_evicts_a_user_request);
    RUN_TEST(full_queue_of_rechecks_takes_only_a_request);
    RUN_TEST(inflight_slot_expires_after_two_minutes);
    RUN_TEST(results_list_every_shown_verdict_newest_first);
    RUN_TEST(next_without_notes_skips_nominations);
    RUN_TEST(request_evicts_a_recheck_when_full);
    RUN_TEST(rechecking_is_true_only_while_a_recheck_is_queued);
    RUN_TEST(next_hands_out_the_latest_nominations_domain_flag);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(autolist_probes_suite);
    GREATEST_MAIN_END();
}
