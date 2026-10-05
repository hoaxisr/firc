#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "firc/events.h"

static firc_event_t dns_event(const char *name) {
    firc_event_t e;
    memset(&e, 0, sizeof(e));
    e.kind = FIRC_EVENT_DNS;
    e.at = 1000;
    snprintf(e.u.dns.name, sizeof(e.u.dns.name), "%s", name);
    return e;
}

static firc_event_t bypass_event(const char *name) {
    firc_event_t e;
    memset(&e, 0, sizeof(e));
    e.kind = FIRC_EVENT_BYPASS;
    e.at = 1000;
    snprintf(e.u.bypass.name, sizeof(e.u.bypass.name), "%s", name);
    return e;
}

/* Catches: a seq that does not rise, a cursor that repeats the last event, or kinds mixed up. */
TEST events_come_back_in_order_by_cursor(void) {
    firc_event_reset_for_test();
    firc_event_put_log(FIRC_LOG_INFO, 999, "started");
    firc_event_t d = dns_event("example.com");
    firc_event_put(&d);

    firc_event_t out[4];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)2, firc_event_read(0, out, 4, &next, &dropped), "%zu");
    ASSERT_EQ(FIRC_EVENT_LOG, out[0].kind);
    ASSERT_STR_EQ("started", out[0].u.log.text);
    ASSERT_EQ_FMT(999LL, (long long)out[0].at, "%lld");
    ASSERT_EQ(FIRC_EVENT_DNS, out[1].kind);
    ASSERT_STR_EQ("example.com", out[1].u.dns.name);
    ASSERTm("the sequence rises", out[0].seq + 1 == out[1].seq);
    ASSERT_EQ_FMT((unsigned long long)out[1].seq, (unsigned long long)next, "%llu");
    ASSERT_EQ_FMT(0ULL, (unsigned long long)dropped, "%llu");
    ASSERT_EQ_FMTm("nothing new since the cursor", (size_t)0,
                   firc_event_read(next, out, 4, &next, &dropped), "%zu");
    PASS();
}

/* Catches: the dropped count wrong after a wrap, or the oldest kept event not the one after the hole. */
TEST a_reader_that_fell_behind_is_told_how_many_events_it_missed(void) {
    firc_event_reset_for_test();
    for (int i = 0; i < FIRC_EVENTS_RING + 10; i++) {
        char name[32];
        snprintf(name, sizeof(name), "n%d.example", i);
        firc_event_t d = dns_event(name);
        firc_event_put(&d);
    }
    firc_event_t *out = malloc(sizeof(*out) * FIRC_EVENTS_RING);
    ASSERT(out != NULL);
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(1, out, FIRC_EVENTS_RING, &next, &dropped);
    ASSERT_EQ_FMT((size_t)FIRC_EVENTS_RING, n, "%zu");
    ASSERT_EQ_FMTm("seqs 2..10 are gone", 9ULL, (unsigned long long)dropped, "%llu");
    ASSERT_STR_EQ("n10.example", out[0].u.dns.name);
    free(out);
    PASS();
}

/* Catches: a read that ignores `cap`, or a cursor that skips events past it. */
TEST a_page_smaller_than_the_backlog_continues_where_it_stopped(void) {
    firc_event_reset_for_test();
    for (int i = 0; i < 5; i++) { firc_event_put_log(FIRC_LOG_INFO, 1, "x"); }
    firc_event_t out[2];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)2, firc_event_read(0, out, 2, &next, &dropped), "%zu");
    ASSERT_EQ_FMT(2ULL, (unsigned long long)next, "%llu");
    ASSERT_EQ_FMT((size_t)2, firc_event_read(next, out, 2, &next, &dropped), "%zu");
    ASSERT_EQ_FMT(3ULL, (unsigned long long)out[0].seq, "%llu");
    ASSERT_EQ_FMT((size_t)1, firc_event_read(next, out, 2, &next, &dropped), "%zu");
    ASSERT_EQ_FMT(5ULL, (unsigned long long)out[0].seq, "%llu");
    PASS();
}

/* Catches: a long text overrunning its slot, or the event dropped instead of cut. */
TEST a_long_text_is_cut_not_dropped(void) {
    firc_event_reset_for_test();
    char big[FIRC_EVENT_TEXT * 2];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    firc_event_put_log(FIRC_LOG_WARN, 1, big);
    firc_event_t out[1];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)1, firc_event_read(0, out, 1, &next, &dropped), "%zu");
    ASSERT_EQ_FMT((size_t)FIRC_EVENT_TEXT - 1, strlen(out[0].u.log.text), "%zu");
    PASS();
}

/* Catches: one shared ring, so DNS traffic evicts the daemon's own lines. */
TEST a_log_line_survives_any_number_of_dns_events(void) {
    firc_event_reset_for_test();
    firc_event_put_log(FIRC_LOG_INFO, 1, "started");
    for (int i = 0; i < 10000; i++) {
        firc_event_t d = dns_event("busy.example");
        firc_event_put(&d);
    }
    firc_event_t *out = malloc(sizeof(*out) * (FIRC_EVENTS_RING + 1));
    ASSERT(out != NULL);
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, out, FIRC_EVENTS_RING + 1, &next, &dropped);
    ASSERT_EQ_FMTm("the line and the whole dns ring", (size_t)FIRC_EVENTS_RING + 1, n, "%zu");
    ASSERT_EQ(FIRC_EVENT_LOG, out[0].kind);
    ASSERT_STR_EQ("started", out[0].u.log.text);
    ASSERT_EQ_FMT(1ULL, (unsigned long long)out[0].seq, "%llu");
    ASSERT_EQ_FMTm("the oldest kept dns event follows it", 10001ULL - FIRC_EVENTS_RING + 1,
                   (unsigned long long)out[1].seq, "%llu");
    ASSERT_EQ_FMT(10001ULL, (unsigned long long)next, "%llu");
    free(out);
    PASS();
}

/* Catches: the two rings concatenated instead of merged in seq order. */
TEST both_kinds_come_back_in_one_seq_order(void) {
    firc_event_reset_for_test();
    const char *pattern = "LDDLDLLD";
    for (const char *c = pattern; *c != '\0'; c++) {
        if (*c == 'L') {
            firc_event_put_log(FIRC_LOG_INFO, 1, "l");
        } else {
            firc_event_t d = dns_event("d");
            firc_event_put(&d);
        }
    }
    firc_event_t out[16];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)8, firc_event_read(0, out, 16, &next, &dropped), "%zu");
    for (size_t i = 0; i < 8; i++) {
        ASSERT_EQ_FMT((unsigned long long)i + 1, (unsigned long long)out[i].seq, "%llu");
        ASSERT_EQ(pattern[i] == 'L' ? FIRC_EVENT_LOG : FIRC_EVENT_DNS, out[i].kind);
    }
    PASS();
}

/* Catches: a cursor restarting one ring, or skipping the other ring's events between pages. */
TEST pages_continue_across_both_rings(void) {
    firc_event_reset_for_test();
    const char *pattern = "LDDLDLLDDL";
    for (const char *c = pattern; *c != '\0'; c++) {
        if (*c == 'L') {
            firc_event_put_log(FIRC_LOG_INFO, 1, "l");
        } else {
            firc_event_t d = dns_event("d");
            firc_event_put(&d);
        }
    }
    firc_event_t out[3];
    uint64_t since = 0, next = 0, dropped = 0;
    uint64_t want = 1;
    size_t pages = 0;
    for (;;) {
        size_t n = firc_event_read(since, out, 3, &next, &dropped);
        if (n == 0) { break; }
        pages++;
        ASSERT_EQ_FMT(0ULL, (unsigned long long)dropped, "%llu");
        for (size_t i = 0; i < n; i++) {
            ASSERT_EQ_FMT((unsigned long long)want, (unsigned long long)out[i].seq, "%llu");
            ASSERT_EQ(pattern[want - 1] == 'L' ? FIRC_EVENT_LOG : FIRC_EVENT_DNS, out[i].kind);
            want++;
        }
        ASSERT_EQ_FMT((unsigned long long)out[n - 1].seq, (unsigned long long)next, "%llu");
        since = next;
    }
    ASSERT_EQ_FMT(11ULL, (unsigned long long)want, "%llu");
    ASSERT_EQ_FMT((size_t)4, pages, "%zu");
    PASS();
}

/* Catches: the dropped count taken from one ring's oldest or from the total. */
TEST dropped_counts_exactly_the_missing_seqs_in_a_mixed_wrap(void) {
    firc_event_reset_for_test();
    firc_event_put_log(FIRC_LOG_INFO, 1, "one");
    firc_event_put_log(FIRC_LOG_INFO, 1, "two");
    firc_event_put_log(FIRC_LOG_INFO, 1, "three");
    for (int i = 0; i < FIRC_EVENTS_RING + 5; i++) {
        firc_event_t d = dns_event("d");
        firc_event_put(&d);
    }
    firc_event_t out[4];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)4, firc_event_read(1, out, 4, &next, &dropped), "%zu");
    ASSERT_EQ_FMT(2ULL, (unsigned long long)out[0].seq, "%llu");
    ASSERT_EQ_FMT(3ULL, (unsigned long long)out[1].seq, "%llu");
    ASSERT_EQ_FMT(9ULL, (unsigned long long)out[2].seq, "%llu");
    ASSERT_EQ_FMT(10ULL, (unsigned long long)out[3].seq, "%llu");
    ASSERT_EQ_FMT(5ULL, (unsigned long long)dropped, "%llu");
    ASSERT_EQ_FMT(10ULL, (unsigned long long)next, "%llu");
    ASSERT_EQ_FMT((size_t)4, firc_event_read(next, out, 4, &next, &dropped), "%zu");
    ASSERT_EQ_FMTm("the hole is told once", 0ULL, (unsigned long long)dropped, "%llu");
    ASSERT_EQ_FMT(11ULL, (unsigned long long)out[0].seq, "%llu");
    PASS();
}

/* Catches: a first read from cursor 0 reporting events lost. */
TEST a_first_read_reports_nothing_dropped(void) {
    firc_event_reset_for_test();
    for (int i = 0; i < FIRC_EVENTS_RING + 50; i++) {
        firc_event_t d = dns_event("d");
        firc_event_put(&d);
    }
    firc_event_t out[1];
    uint64_t next = 0, dropped = 99;
    ASSERT_EQ_FMT((size_t)1, firc_event_read(0, out, 1, &next, &dropped), "%zu");
    ASSERT_EQ_FMT(51ULL, (unsigned long long)out[0].seq, "%llu");
    ASSERT_EQ_FMT(0ULL, (unsigned long long)dropped, "%llu");
    PASS();
}

/* Catches: bypass events routed to a ring of their own. */
TEST a_bypass_event_shares_the_dns_ring_and_its_order(void) {
    firc_event_reset_for_test();
    firc_event_put_log(FIRC_LOG_INFO, 1, "started");
    firc_event_t d1 = dns_event("first.example");
    firc_event_put(&d1);
    firc_event_t b = bypass_event("bypassed.example");
    firc_event_put(&b);
    firc_event_t d2 = dns_event("second.example");
    firc_event_put(&d2);

    firc_event_t out[4];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)4, firc_event_read(0, out, 4, &next, &dropped), "%zu");
    ASSERT_EQ(FIRC_EVENT_LOG, out[0].kind);
    ASSERT_EQ(FIRC_EVENT_DNS, out[1].kind);
    ASSERT_STR_EQ("first.example", out[1].u.dns.name);
    ASSERT_EQ(FIRC_EVENT_BYPASS, out[2].kind);
    ASSERT_STR_EQ("bypassed.example", out[2].u.bypass.name);
    ASSERT_EQ(FIRC_EVENT_DNS, out[3].kind);
    ASSERT_STR_EQ("second.example", out[3].u.dns.name);
    for (size_t i = 0; i + 1 < 4; i++) {
        ASSERTm("the sequence rises across kinds", out[i].seq + 1 == out[i + 1].seq);
    }

    firc_event_reset_for_test();
    firc_event_put_log(FIRC_LOG_INFO, 1, "started");
    firc_event_t first_dns = dns_event("first.example");
    firc_event_put(&first_dns);
    for (int i = 0; i < FIRC_EVENTS_RING; i++) {
        firc_event_t bp = bypass_event("push.example");
        firc_event_put(&bp);
    }
    firc_event_t *out2 = malloc(sizeof(*out2) * (FIRC_EVENTS_RING + 1));
    ASSERT(out2 != NULL);
    uint64_t next2 = 0, dropped2 = 0;
    size_t n2 = firc_event_read(0, out2, FIRC_EVENTS_RING + 1, &next2, &dropped2);
    ASSERT_EQ_FMTm("the log line survives the bypass flood", (size_t)FIRC_EVENTS_RING + 1, n2, "%zu");
    ASSERT_EQ(FIRC_EVENT_LOG, out2[0].kind);
    ASSERT_STR_EQ("started", out2[0].u.log.text);
    for (size_t i = 1; i < n2; i++) {
        ASSERTm("4096 bypass events pushed the earlier dns event out of the shared ring",
                out2[i].kind == FIRC_EVENT_BYPASS);
    }
    free(out2);
    PASS();
}

SUITE(events) {
    RUN_TEST(events_come_back_in_order_by_cursor);
    RUN_TEST(a_reader_that_fell_behind_is_told_how_many_events_it_missed);
    RUN_TEST(a_page_smaller_than_the_backlog_continues_where_it_stopped);
    RUN_TEST(a_long_text_is_cut_not_dropped);
    RUN_TEST(a_log_line_survives_any_number_of_dns_events);
    RUN_TEST(both_kinds_come_back_in_one_seq_order);
    RUN_TEST(pages_continue_across_both_rings);
    RUN_TEST(dropped_counts_exactly_the_missing_seqs_in_a_mixed_wrap);
    RUN_TEST(a_first_read_reports_nothing_dropped);
    RUN_TEST(a_bypass_event_shares_the_dns_ring_and_its_order);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(events);
    GREATEST_MAIN_END();
}
