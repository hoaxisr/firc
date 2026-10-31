#include "greatest.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "firc/autolist.h"

static firc_autolist_flow_t flow(uint8_t client_last, uint16_t client_port) {
    firc_autolist_flow_t f;
    memset(&f, 0, sizeof(f));
    f.client.len = 4;
    f.client.b[0] = 192; f.client.b[1] = 168; f.client.b[2] = 1; f.client.b[3] = client_last;
    f.server.len = 4;
    f.server.b[0] = 203; f.server.b[1] = 0; f.server.b[2] = 113; f.server.b[3] = 7;
    f.client_port = client_port;
    f.server_port = 443;
    return f;
}

static firc_autolist_flow_t flow_to(uint16_t client_port, uint8_t server_last) {
    firc_autolist_flow_t f = flow(10, client_port);
    f.server.b[3] = server_last;
    return f;
}

static bool hello_times(firc_autolist_t *a, const firc_autolist_flow_t *f, const char *sni, int times, int64_t now,
                        firc_autolist_failure_t *out) {
    if (sni != NULL && sni[0] != '\0') { firc_autolist_hint(a, &f->client, sni, &f->server, 1, now); }
    bool failed = false;
    for (int i = 0; i < times; i++) { failed = firc_autolist_hello(a, f, 1000, 0, sni, now + i, out) || failed; }
    return failed;
}

static bool bare_hello_times(firc_autolist_t *a, const firc_autolist_flow_t *f, const char *sni, int times,
                             int64_t now, firc_autolist_failure_t *out) {
    bool failed = false;
    for (int i = 0; i < times; i++) { failed = firc_autolist_hello(a, f, 1000, 0, sni, now + i, out) || failed; }
    return failed;
}

TEST a_hello_sent_once_is_no_failure(void) {
    firc_autolist_t *a = firc_autolist_new();
    ASSERT(a != NULL);
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(hello_times(a, &f, "blocked.example", 1, 100, &out));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 100));
    firc_autolist_free(a);
    PASS();
}

TEST three_sendings_again_make_a_failure_once(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(hello_times(a, &f, "blocked.example", 3, 100, &out));
    ASSERT(hello_times(a, &f, "blocked.example", 1, 110, &out));
    ASSERT_STR_EQ("blocked.example", out.host);
    ASSERT_EQ(1u, out.fails);
    ASSERT_EQ(FIRC_AUTOLIST_RETRANS, out.why);
    ASSERT_FALSE(out.listed);
    ASSERTm("a fifth sending counts nothing more", !hello_times(a, &f, "blocked.example", 1, 111, &out));
    firc_autolist_free(a);
    PASS();
}

TEST three_failed_connections_list_the_host(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    for (uint16_t i = 0; i < 3; i++) {
        firc_autolist_flow_t f = flow(10, (uint16_t)(50000 + i));
        ASSERT(hello_times(a, &f, "blocked.example", 4, 100 + i * 10, &out));
    }
    ASSERT(out.listed);
    ASSERT_EQ(3u, out.fails);
    firc_autolist_flow_t next = flow(10, 50003);
    ASSERT(hello_times(a, &next, "blocked.example", 4, 130, &out));
    ASSERTm("the count starts over once listed", out.fails == 1 && !out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST failures_too_far_apart_start_over(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t f1 = flow(10, 50001), f2 = flow(10, 50002), f3 = flow(10, 50003);
    ASSERT(hello_times(a, &f1, "slow.example", 4, 100, &out));
    ASSERT(hello_times(a, &f2, "slow.example", 4, 150, &out));
    ASSERT_EQ(2u, out.fails);
    ASSERT(hello_times(a, &f3, "slow.example", 4, 150 + FIRC_AUTOLIST_FAIL_SECS + 10, &out));
    ASSERT_EQ(1u, out.fails);
    ASSERT_FALSE(out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST an_early_reset_is_a_failure(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(hello_times(a, &f, "reset.example", 1, 100, &out));
    ASSERT(firc_autolist_reply(a, &f, true, 101, &out));
    ASSERT_EQ(FIRC_AUTOLIST_RESET, out.why);
    ASSERT_STR_EQ("reset.example", out.host);
    ASSERTm("one verdict per connection", !firc_autolist_reply(a, &f, true, 102, &out));
    firc_autolist_free(a);
    PASS();
}

TEST a_working_connection_clears_the_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t f1 = flow(10, 50001), f2 = flow(10, 50002), f3 = flow(10, 50003), f4 = flow(10, 50004);
    ASSERT(hello_times(a, &f1, "flaky.example", 4, 100, &out));
    ASSERT(hello_times(a, &f2, "flaky.example", 4, 105, &out));
    ASSERT_FALSE(hello_times(a, &f3, "flaky.example", 1, 110, &out));
    ASSERT_FALSE(firc_autolist_reply(a, &f3, false, 111, &out));
    ASSERT(hello_times(a, &f4, "flaky.example", 4, 112, &out));
    ASSERT_EQ(1u, out.fails);
    ASSERT_FALSE(out.listed);
    ASSERTm("and a reset after it worked is no failure", !firc_autolist_reply(a, &f3, true, 113, &out));
    firc_autolist_free(a);
    PASS();
}

TEST a_working_address_does_not_clear_another_s_failures(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t bad1 = flow_to(50001, 41), good = flow_to(50002, 215), bad2 = flow_to(50003, 41),
                         bad3 = flow_to(50004, 41);
    ASSERT(hello_times(a, &bad1, "www.linkedin.com", 4, 100, &out));
    ASSERT_FALSE(hello_times(a, &good, "www.linkedin.com", 1, 110, &out));
    ASSERT_FALSE(firc_autolist_reply(a, &good, false, 111, &out));
    ASSERT(hello_times(a, &bad2, "www.linkedin.com", 4, 112, &out));
    ASSERT_EQ(2u, out.fails);
    ASSERT(hello_times(a, &bad3, "www.linkedin.com", 4, 120, &out));
    ASSERT(out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST a_failed_address_that_works_again_clears_the_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t on_a = flow_to(50001, 41), on_b = flow_to(50002, 215), b_again = flow_to(50003, 215),
                         later = flow_to(50004, 41);
    ASSERT(hello_times(a, &on_a, "x.example", 4, 100, &out));
    ASSERT(hello_times(a, &on_b, "x.example", 4, 105, &out));
    ASSERT_EQ(2u, out.fails);
    ASSERT_FALSE(hello_times(a, &b_again, "x.example", 1, 110, &out));
    ASSERT_FALSE(firc_autolist_reply(a, &b_again, false, 111, &out));
    ASSERT(hello_times(a, &later, "x.example", 4, 112, &out));
    ASSERT_EQ(1u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST a_reply_to_a_connection_never_seen_is_ignored(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT_FALSE(firc_autolist_reply(a, &f, true, 100, &out));
    firc_autolist_free(a);
    PASS();
}

TEST a_hello_without_sni_takes_its_name_from_the_dns_answer(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "named.example", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT(hello_times(a, &f, NULL, 4, 100, &out));
    ASSERT_STR_EQ("named.example", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST another_device_s_answer_makes_a_bypass(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_flow_t other = flow(11, 50000);
    firc_autolist_hint(a, &other.client, "named.example", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT(hello_times(a, &f, NULL, 4, 100, &out));
    ASSERT(out.bypass);
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 104));
    firc_autolist_free(a);
    PASS();
}

TEST a_stale_answer_makes_a_bypass(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "named.example", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT(hello_times(a, &f, NULL, 4, 90 + FIRC_AUTOLIST_HINT_SECS + 1, &out));
    ASSERT(out.bypass);
    firc_autolist_free(a);
    PASS();
}

TEST a_new_handshake_on_a_reused_port_starts_its_own_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    firc_autolist_hint(a, &f.client, "x.example", &f.server, 1, 100);
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "x.example", 100, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "x.example", 101, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, 0, "x.example", 102, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, 0, "x.example", 103, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 2000, 0, "x.example", 104, &out));
    ASSERT(firc_autolist_hello(a, &f, 2000, 0, "x.example", 105, &out));
    ASSERT_FALSE(out.bypass);
    firc_autolist_free(a);
    PASS();
}

TEST the_thresholds_can_be_set(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_params_t p = {1, 0, 1};
    firc_autolist_set_params(a, &p);
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT(hello_times(a, &f, "fast.example", 2, 100, &out));
    ASSERT(out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST more_connections_than_slots_do_not_break_it(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    for (uint32_t i = 0; i < FIRC_AUTOLIST_FLOWS * 2; i++) {
        firc_autolist_flow_t f = flow((uint8_t)(i % 200), (uint16_t)(10000 + i));
        char name[32];
        snprintf(name, sizeof(name), "h%u.example", (unsigned)(i % (FIRC_AUTOLIST_HOSTS * 2)));
        (void)firc_autolist_hello(a, &f, i, 0, name, 100, &out);
    }
    firc_autolist_flow_t f = flow(250, 60000);
    ASSERT(hello_times(a, &f, "late.example", 4, 100, &out));
    ASSERT_STR_EQ("late.example", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST no_hint_is_bypass_not_failure(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "a.test", 4, 100, &out));
    ASSERT(out.bypass);
    ASSERT_FALSE(out.listed);
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 104));
    firc_ip_t clients[4];
    uint32_t fails[4];
    ASSERT_EQ(1u, (unsigned)firc_autolist_bypassed(a, 104, clients, fails, 4));
    ASSERT_EQ(4, clients[0].len);
    ASSERT_EQ(0, memcmp(clients[0].b, f.client.b, 4));
    ASSERT_EQ(1u, fails[0]);
    firc_autolist_free(a);
    PASS();
}

TEST hint_with_other_name_is_bypass(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "b.test", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "a.test", 4, 100, &out));
    ASSERT(out.bypass);
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 104));
    firc_autolist_free(a);
    PASS();
}

TEST two_names_on_one_address_both_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "a.test", &f.server, 1, 90);
    firc_autolist_hint(a, &f.client, "b.test", &f.server, 1, 91);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "a.test", 4, 100, &out));
    ASSERT_FALSE(out.bypass);
    ASSERT_STR_EQ("a.test", out.host);
    ASSERT_EQ(1u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST failures_day_counts_and_expires(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    const int64_t t = 3600 * 1000;
    for (uint16_t i = 0; i < 3; i++) {
        firc_autolist_flow_t f = flow(10, (uint16_t)(50000 + i));
        firc_autolist_hint(a, &f.client, "day.test", &f.server, 1, t);
        ASSERT(bare_hello_times(a, &f, "day.test", 4, t, &out));
    }
    ASSERT_EQ(3u, firc_autolist_failures_day(a, t + 86399));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, t + 86400));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, t + 86400 + 3600));
    firc_autolist_free(a);
    PASS();
}

TEST hint_same_name_counts(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    for (uint16_t i = 0; i < 3; i++) {
        firc_autolist_flow_t f = flow(10, (uint16_t)(50000 + i));
        firc_autolist_hint(a, &f.client, "a.test", &f.server, 1, 100);
        ASSERT(bare_hello_times(a, &f, "a.test", 4, 100 + i * 20, &out));
        ASSERT_FALSE(out.bypass);
    }
    ASSERT(out.listed);
    ASSERT_STR_EQ("a.test", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST no_sni_uses_hint(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "a.test", &f.server, 1, 90);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "", 4, 100, &out));
    ASSERT_FALSE(out.bypass);
    ASSERT_STR_EQ("a.test", out.host);
    firc_autolist_free(a);
    PASS();
}

static bool stalled(firc_autolist_t *a, uint16_t port, uint32_t ack0, uint32_t fin_ack, int64_t at, int64_t held,
                    firc_autolist_nomination_t *nom) {
    firc_autolist_flow_t f = flow(10, port);
    firc_autolist_hint(a, &f.client, "freeze.test", &f.server, 1, at);
    firc_autolist_failure_t out;
    (void)firc_autolist_hello(a, &f, 7, ack0, "freeze.test", at, &out);
    (void)firc_autolist_reply(a, &f, false, at + 1, &out);
    return firc_autolist_fin(a, &f, fin_ack, at + held, nom);
}

TEST fin_in_window_after_ten_seconds_notes(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 11, &nom));
    ASSERT(stalled(a, 50002, 1000, 1000 + 16384, 150, 11, &nom));
    ASSERT_STR_EQ("freeze.test", nom.host);
    ASSERT_EQ(16384u, nom.received);
    ASSERT_EQ(10, nom.client.b[3]);
    ASSERTm("the notes are cleared", !stalled(a, 50003, 1000, 1000 + 16384, 170, 11, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST fin_too_soon_is_no_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 9, &nom));
    ASSERT_FALSE(stalled(a, 50002, 1000, 1000 + 16384, 150, 9, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST fin_outside_window_is_no_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 4096, 100, 11, &nom));
    ASSERT_FALSE(stalled(a, 50002, 1000, 1000 + 4096, 150, 11, &nom));
    ASSERT_FALSE(stalled(a, 50003, 1000, 1000 + 40000, 160, 11, &nom));
    ASSERT_FALSE(stalled(a, 50004, 1000, 1000 + 40000, 170, 11, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST fin_window_edges_are_in(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 8192, 100, 10, &nom));
    ASSERT(stalled(a, 50002, 1000, 1000 + 32768, 150, 10, &nom));
    ASSERT_EQ(32768u, nom.received);
    firc_autolist_free(a);
    PASS();
}

TEST fin_wraps_mod_2_32(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 0xfffff000u, 0x00003000u, 100, 11, &nom));
    ASSERT(stalled(a, 50002, 0xfffff000u, 0x00003000u, 150, 11, &nom));
    ASSERT_EQ(0x4000u, nom.received);
    firc_autolist_free(a);
    PASS();
}

TEST notes_older_than_two_minutes_do_not_pair(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 11, &nom));
    ASSERT_FALSE(stalled(a, 50002, 1000, 1000 + 16384, 100 + 121, 11, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST notes_two_minutes_apart_pair(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 11, &nom));
    ASSERT(stalled(a, 50002, 1000, 1000 + 16384, 100 + 120, 11, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST a_bypass_flow_s_fin_is_no_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    firc_autolist_failure_t out;
    for (uint16_t port = 50001; port <= 50002; port++) {
        firc_autolist_flow_t f = flow(10, port);
        (void)firc_autolist_hello(a, &f, 7, 1000, "freeze.test", 100 + port - 50001, &out);
        ASSERT_FALSE(firc_autolist_fin(a, &f, 1000 + 16384, 120 + port - 50001, &nom));
    }
    firc_autolist_free(a);
    PASS();
}

TEST a_fin_sent_again_is_one_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    firc_autolist_flow_t f = flow(10, 50001);
    ASSERT_FALSE(stalled(a, 50001, 1000, 1000 + 16384, 100, 11, &nom));
    ASSERT_FALSE(firc_autolist_fin(a, &f, 1000 + 16384, 112, &nom));
    firc_autolist_free(a);
    PASS();
}

static firc_autolist_flow_t flow_at(uint16_t client_port, uint8_t server_last) {
    firc_autolist_flow_t f = flow(10, client_port);
    f.server.b[2] = 114;
    f.server.b[3] = server_last;
    return f;
}

static void set_threshold(firc_autolist_t *a, uint32_t threshold) {
    firc_autolist_params_t p = {threshold, 0, 0};
    firc_autolist_set_params(a, &p);
}

static bool failed_on(firc_autolist_t *a, const char *host, uint16_t port, uint8_t server_last, int64_t at,
                      firc_autolist_failure_t *out) {
    firc_autolist_flow_t f = flow_at(port, server_last);
    return hello_times(a, &f, host, 4, at, out);
}

static bool syns(firc_autolist_t *a, const firc_autolist_flow_t *f, const int64_t *at, size_t n,
                 firc_autolist_nomination_t *nom) {
    bool named = false;
    for (size_t i = 0; i < n; i++) { named = firc_autolist_syn(a, f, 999, at[i], nom) || named; }
    return named;
}

static bool unanswered_on(firc_autolist_t *a, const char *host, uint16_t port, uint8_t server_last, int64_t at,
                          firc_autolist_nomination_t *nom) {
    firc_autolist_flow_t f = flow_at(port, server_last);
    firc_autolist_hint(a, &f.client, host, &f.server, 1, at);
    const int64_t times[] = {at + 1, at + 3};
    return syns(a, &f, times, 2, nom);
}

TEST syns_logged_at_one_and_three_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_on(a, "www.instagram.com", 50001, 1, 100, &nom));
    ASSERT_FALSE(unanswered_on(a, "www.instagram.com", 50002, 1, 110, &nom));
    memset(&nom, 0x5a, sizeof(nom));
    ASSERT(unanswered_on(a, "www.instagram.com", 50003, 1, 120, &nom));
    ASSERT_EQ(FIRC_AL_NOM_NO_CONNECT, nom.kind);
    ASSERT_STR_EQ("www.instagram.com", nom.host);
    ASSERT_STR_EQ("", nom.domain);
    ASSERT_EQ(10, nom.client.b[3]);
    ASSERT_EQ(0u, nom.received);
    ASSERTm("the count starts over once nominated", !unanswered_on(a, "www.instagram.com", 50004, 1, 130, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST span_of_one_second_is_not_enough(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    for (uint16_t i = 0; i < 3; i++) {
        firc_autolist_flow_t f = flow_at((uint16_t)(50001 + i), 1);
        firc_autolist_hint(a, &f.client, "www.instagram.com", &f.server, 1, 100);
        const int64_t times[] = {101 + i * 10, 102 + i * 10};
        ASSERT_FALSE(syns(a, &f, times, 2, &nom));
    }
    firc_autolist_free(a);
    PASS();
}

TEST a_syn_flow_counts_once(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 2);
    firc_autolist_nomination_t nom;
    firc_autolist_flow_t f = flow_at(50001, 1);
    firc_autolist_hint(a, &f.client, "web.telegram.org", &f.server, 1, 100);
    const int64_t times[] = {100, 102, 104, 106};
    ASSERT_FALSE(syns(a, &f, times, 4, &nom));
    ASSERT(unanswered_on(a, "web.telegram.org", 50002, 1, 110, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST hello_after_syns_ends_no_connect(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 1);
    firc_autolist_nomination_t nom;
    firc_autolist_failure_t out;
    firc_autolist_flow_t connected = flow_at(50001, 1), silent = flow_at(50002, 1);
    firc_autolist_hint(a, &connected.client, "x.example", &connected.server, 1, 90);
    ASSERT_FALSE(firc_autolist_syn(a, &connected, 999, 100, &nom));
    ASSERT_FALSE(firc_autolist_syn(a, &connected, 999, 101, &nom));
    ASSERT_FALSE(firc_autolist_hello(a, &connected, 1000, 0, "x.example", 102, &out));
    ASSERT_FALSE(firc_autolist_syn(a, &connected, 999, 103, &nom));
    const int64_t times[] = {100, 101, 103};
    ASSERTm("the same SYNs without the hello make a no-connect flow", syns(a, &silent, times, 3, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST syn_named_by_the_only_hint(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 1);
    firc_autolist_nomination_t nom;
    ASSERT(unanswered_on(a, "only.example", 50001, 1, 100, &nom));
    ASSERT_STR_EQ("only.example", nom.host);
    ASSERT_EQ(0u, firc_autolist_ambiguous_day(a, 103));
    firc_autolist_free(a);
    PASS();
}

TEST syn_with_two_names_is_ambiguous(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 1);
    firc_autolist_nomination_t nom;
    firc_autolist_flow_t f = flow_at(50001, 1);
    firc_autolist_hint(a, &f.client, "one.example", &f.server, 1, 90);
    firc_autolist_hint(a, &f.client, "two.example", &f.server, 1, 91);
    const int64_t times[] = {101, 103};
    ASSERT_FALSE(syns(a, &f, times, 2, &nom));
    ASSERT_EQ(1u, firc_autolist_ambiguous_day(a, 103));
    ASSERT_EQ(0u, (unsigned)firc_autolist_bypassed(a, 103, NULL, NULL, 4));
    firc_autolist_free(a);
    PASS();
}

TEST syn_without_hint_is_bypass(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 1);
    firc_autolist_nomination_t nom;
    firc_autolist_flow_t f = flow_at(50001, 1);
    const int64_t times[] = {101, 103};
    memset(&nom, 0, sizeof(nom));
    ASSERT(syns(a, &f, times, 2, &nom));
    ASSERT(nom.bypass);
    ASSERT_EQ(10, nom.client.b[3]);
    uint32_t fails[4] = {0};
    ASSERT_EQ(1u, (unsigned)firc_autolist_bypassed(a, 103, NULL, fails, 4));
    ASSERT_EQ(1u, fails[0]);
    ASSERT_EQ(0u, firc_autolist_ambiguous_day(a, 103));
    firc_autolist_free(a);
    PASS();
}

TEST sniless_without_hint_is_bypass(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_failure_t out;
    ASSERT(bare_hello_times(a, &f, "", 4, 100, &out));
    ASSERT(out.bypass);
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 104));
    firc_autolist_free(a);
    PASS();
}

TEST sniless_with_two_hints_is_ambiguous_not_newest(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "a.test", &f.server, 1, 90);
    firc_autolist_hint(a, &f.client, "b.test", &f.server, 1, 91);
    firc_autolist_failure_t out;
    ASSERT_FALSE(bare_hello_times(a, &f, "", 4, 100, &out));
    ASSERT_EQ(1u, firc_autolist_ambiguous_day(a, 104));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 104));
    ASSERT_EQ(0u, (unsigned)firc_autolist_bypassed(a, 104, NULL, NULL, 4));
    firc_autolist_free(a);
    PASS();
}

TEST ambiguous_day_expires(void) {
    firc_autolist_t *a = firc_autolist_new();
    const int64_t t = 3600 * 1000;
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "a.test", &f.server, 1, t);
    firc_autolist_hint(a, &f.client, "b.test", &f.server, 1, t);
    firc_autolist_failure_t out;
    ASSERT_FALSE(bare_hello_times(a, &f, "", 4, t, &out));
    ASSERT_EQ(1u, firc_autolist_ambiguous_day(a, t + 86399));
    ASSERT_EQ(0u, firc_autolist_ambiguous_day(a, t + 86400));
    firc_autolist_free(a);
    PASS();
}

TEST domain_counts_over_distinct_hosts(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    ASSERT(failed_on(a, "rr1---sn-a.googlevideo.com", 50001, 1, 100, &out));
    ASSERT_FALSE(out.listed);
    ASSERT(failed_on(a, "rr2---sn-b.googlevideo.com", 50002, 2, 110, &out));
    ASSERT_FALSE(out.listed);
    ASSERT(failed_on(a, "rr3---sn-c.googlevideo.com", 50003, 3, 120, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("googlevideo.com", out.domain);
    ASSERT_STR_EQ("rr1---sn-a.googlevideo.com", out.host);
    ASSERT_EQ(3u, out.fails);
    ASSERTm("the domain's count starts over once listed",
            failed_on(a, "rr4---sn-d.googlevideo.com", 50004, 4, 130, &out) && !out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST domain_marker_is_the_most_failed_host(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 4);
    firc_autolist_failure_t out;
    ASSERT(failed_on(a, "a.googlevideo.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "b.googlevideo.com", 50002, 2, 105, &out));
    ASSERT(failed_on(a, "b.googlevideo.com", 50003, 2, 110, &out));
    ASSERT_FALSE(out.listed);
    ASSERT(failed_on(a, "c.googlevideo.com", 50004, 3, 115, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("googlevideo.com", out.domain);
    ASSERT_STR_EQ("b.googlevideo.com", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST a_host_s_own_listing_names_no_domain(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    ASSERT(failed_on(a, "www.linkedin.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "www.linkedin.com", 50002, 1, 110, &out));
    ASSERT(failed_on(a, "www.linkedin.com", 50003, 1, 120, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("www.linkedin.com", out.host);
    ASSERT_STR_EQ("", out.domain);
    ASSERTm("and the domain's count went with it",
            failed_on(a, "static.linkedin.com", 50004, 2, 130, &out) && !out.listed);
    firc_autolist_free(a);
    PASS();
}

TEST answered_host_restarts_domain(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    ASSERT(failed_on(a, "rr1.googlevideo.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "rr2.googlevideo.com", 50002, 2, 110, &out));
    firc_autolist_flow_t good = flow_at(50003, 9);
    ASSERT_FALSE(hello_times(a, &good, "www.googlevideo.com", 1, 115, &out));
    ASSERT_FALSE(firc_autolist_reply(a, &good, false, 116, &out));
    ASSERT(failed_on(a, "rr3.googlevideo.com", 50004, 3, 120, &out));
    ASSERT_FALSE(out.listed);
    ASSERT_EQ(1u, out.fails);
    firc_autolist_free(a);
    PASS();
}

static bool stalled_on(firc_autolist_t *a, const char *host, uint16_t port, int64_t at,
                       firc_autolist_nomination_t *nom) {
    firc_autolist_flow_t f = flow_at(port, (uint8_t)port);
    firc_autolist_hint(a, &f.client, host, &f.server, 1, at);
    firc_autolist_failure_t out;
    (void)firc_autolist_hello(a, &f, 7, 1000, host, at, &out);
    (void)firc_autolist_reply(a, &f, false, at + 1, &out);
    return firc_autolist_fin(a, &f, 1000 + 16384, at + 11, nom);
}

TEST stalls_on_two_hosts_nominate_the_domain(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled_on(a, "a.freeze.test", 50001, 100, &nom));
    memset(&nom, 0x5a, sizeof(nom));
    ASSERT(stalled_on(a, "b.freeze.test", 50002, 150, &nom));
    ASSERT_EQ(FIRC_AL_NOM_STALL, nom.kind);
    ASSERT_STR_EQ("freeze.test", nom.domain);
    ASSERT_STR_EQ("a.freeze.test", nom.host);
    ASSERT_EQ(16384u, nom.received);
    ASSERTm("the domain's notes are cleared", !stalled_on(a, "c.freeze.test", 50003, 170, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST a_host_s_own_stalls_name_no_domain(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(stalled_on(a, "a.freeze.test", 50001, 100, &nom));
    ASSERT(stalled_on(a, "a.freeze.test", 50002, 150, &nom));
    ASSERT_EQ(FIRC_AL_NOM_STALL, nom.kind);
    ASSERT_STR_EQ("a.freeze.test", nom.host);
    ASSERT_STR_EQ("", nom.domain);
    ASSERTm("and the domain's notes went with them", !stalled_on(a, "b.freeze.test", 50003, 170, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST no_connect_on_three_hosts_nominates_the_domain(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 4);
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_on(a, "www.instagram.com", 50001, 1, 100, &nom));
    ASSERT_FALSE(unanswered_on(a, "i.instagram.com", 50002, 2, 110, &nom));
    ASSERT_FALSE(unanswered_on(a, "i.instagram.com", 50003, 2, 115, &nom));
    ASSERT(unanswered_on(a, "scontent.instagram.com", 50004, 3, 120, &nom));
    ASSERT_EQ(FIRC_AL_NOM_NO_CONNECT, nom.kind);
    ASSERT_STR_EQ("instagram.com", nom.domain);
    ASSERT_STR_EQ("i.instagram.com", nom.host);
    firc_autolist_free(a);
    PASS();
}

TEST no_connect_and_failures_count_apart(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_on(a, "x.example", 50001, 1, 100, &nom));
    ASSERT_FALSE(unanswered_on(a, "x.example", 50002, 1, 110, &nom));
    ASSERT(failed_on(a, "x.example", 50003, 1, 115, &out));
    ASSERT_FALSE(out.listed);
    ASSERT_EQ(1u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST multitenant_suffix_never_counts_as_domain(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT(failed_on(a, "p.alice.github.io", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "q.alice.github.io", 50002, 2, 110, &out));
    ASSERT(failed_on(a, "r.alice.github.io", 50003, 3, 120, &out));
    ASSERT_FALSE(out.listed);
    ASSERT_FALSE(unanswered_on(a, "a.cdn.akamaized.net", 50004, 4, 100, &nom));
    ASSERT_FALSE(unanswered_on(a, "b.cdn.akamaized.net", 50005, 5, 110, &nom));
    ASSERT_FALSE(unanswered_on(a, "c.cdn.akamaized.net", 50006, 6, 120, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST a_reset_to_a_syn_is_no_failure(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 1);
    firc_autolist_flow_t f = flow_at(50001, 1);
    firc_autolist_hint(a, &f.client, "refused.example", &f.server, 1, 100);
    firc_autolist_nomination_t nom;
    firc_autolist_failure_t out;
    ASSERT_FALSE(firc_autolist_syn(a, &f, 999, 101, &nom));
    ASSERT_FALSE(firc_autolist_reply(a, &f, true, 101, &out));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 101));
    firc_autolist_free(a);
    PASS();
}

TEST a_close_of_a_syn_flow_is_no_note(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    for (uint16_t port = 50001; port <= 50002; port++) {
        firc_autolist_flow_t f = flow_at(port, 1);
        firc_autolist_hint(a, &f.client, "freeze.test", &f.server, 1, 100);
        ASSERT_FALSE(firc_autolist_syn(a, &f, 999, 100, &nom));
        ASSERT_FALSE(firc_autolist_fin(a, &f, 16384, 100 + 20 * (port - 50000), &nom));
    }
    firc_autolist_free(a);
    PASS();
}

TEST a_late_syn_keeps_the_connected_flow(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_flow_t f = flow(10, 50000);
    firc_autolist_hint(a, &f.client, "late.example", &f.server, 1, 100);
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "late.example", 100, &out));
    ASSERT_FALSE(firc_autolist_syn(a, &f, 999, 101, &nom));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "late.example", 102, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "late.example", 103, &out));
    ASSERT(firc_autolist_hello(a, &f, 1000, 0, "late.example", 104, &out));
    ASSERT_STR_EQ("late.example", out.host);
    firc_autolist_free(a);
    PASS();
}

static void hint_both(firc_autolist_t *a, const firc_autolist_flow_t *f, const char *one, const char *two, int64_t at) {
    firc_autolist_hint(a, &f->client, one, &f->server, 1, at);
    firc_autolist_hint(a, &f->client, two, &f->server, 1, at);
}

static bool unanswered_pair(firc_autolist_t *a, const char *one, const char *two, uint16_t port, int64_t at,
                            firc_autolist_nomination_t *nom) {
    firc_autolist_flow_t f = flow_at(port, 1);
    hint_both(a, &f, one, two, at);
    const int64_t times[] = {at + 1, at + 3};
    return syns(a, &f, times, 2, nom);
}

TEST two_names_of_one_domain_count_toward_it(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50001, 100, &nom));
    ASSERT_FALSE(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50002, 110, &nom));
    memset(&nom, 0x5a, sizeof(nom));
    ASSERT(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50003, 120, &nom));
    ASSERT_FALSE(nom.bypass);
    ASSERT_EQ(FIRC_AL_NOM_NO_CONNECT, nom.kind);
    ASSERT_STR_EQ("instagram.com", nom.domain);
    ASSERT_STR_EQ("instagram.com", nom.host);
    ASSERT_EQ(0u, firc_autolist_ambiguous_day(a, 123));
    ASSERTm("the domain's count starts over",
            !unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50004, 130, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST sniless_hellos_on_one_domain_s_names_list_it(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    for (uint16_t i = 0; i < 3; i++) {
        firc_autolist_flow_t f = flow_at((uint16_t)(50001 + i), 1);
        hint_both(a, &f, "www.instagram.com", "instagram.com", 100);
        ASSERT(bare_hello_times(a, &f, "", 4, 100 + i * 10, &out));
        ASSERT_FALSE(out.bypass);
    }
    ASSERT(out.listed);
    ASSERT_STR_EQ("instagram.com", out.domain);
    ASSERT_STR_EQ("instagram.com", out.host);
    ASSERT_EQ(3u, out.fails);
    ASSERT_EQ(0u, firc_autolist_ambiguous_day(a, 130));
    firc_autolist_free(a);
    PASS();
}

TEST names_of_one_shared_domain_stay_ambiguous(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 1);
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_pair(a, "p.alice.github.io", "q.alice.github.io", 50001, 100, &nom));
    ASSERT_FALSE(unanswered_pair(a, "www.instagram.com", "web.telegram.org", 50002, 110, &nom));
    ASSERT_EQ(2u, firc_autolist_ambiguous_day(a, 113));
    firc_autolist_free(a);
    PASS();
}

TEST a_domain_listing_restarts_its_hosts(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    ASSERT(failed_on(a, "www.example.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "www.example.com", 50002, 1, 105, &out));
    ASSERT(failed_on(a, "cdn.example.com", 50003, 2, 110, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("example.com", out.domain);
    ASSERT_STR_EQ("www.example.com", out.host);
    ASSERTm("the marker host starts over with its domain", failed_on(a, "www.example.com", 50004, 1, 115, &out));
    ASSERT_FALSE(out.listed);
    ASSERT_EQ(1u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST a_domain_nomination_restarts_its_hosts(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_on(a, "www.example.com", 50001, 1, 100, &nom));
    ASSERT_FALSE(unanswered_on(a, "www.example.com", 50002, 1, 105, &nom));
    ASSERT(unanswered_on(a, "cdn.example.com", 50003, 2, 110, &nom));
    ASSERT_STR_EQ("example.com", nom.domain);
    ASSERT_STR_EQ("www.example.com", nom.host);
    ASSERTm("no second nomination of the marker host", !unanswered_on(a, "www.example.com", 50004, 1, 115, &nom));
    ASSERT_FALSE(stalled_on(a, "a.freeze.test", 50011, 200, &nom));
    ASSERT(stalled_on(a, "b.freeze.test", 50012, 220, &nom));
    ASSERT_STR_EQ("freeze.test", nom.domain);
    ASSERTm("the stall notes of its hosts go too", !stalled_on(a, "a.freeze.test", 50013, 240, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST marker_follows_the_kind_that_triggered(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT(failed_on(a, "www.example.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "www.example.com", 50002, 1, 102, &out));
    ASSERT_FALSE(out.listed);
    ASSERT_FALSE(unanswered_on(a, "cdn.example.com", 50003, 2, 104, &nom));
    ASSERT_FALSE(unanswered_on(a, "www.example.com", 50004, 1, 106, &nom));
    ASSERT(unanswered_on(a, "cdn.example.com", 50005, 2, 108, &nom));
    ASSERT_STR_EQ("example.com", nom.domain);
    ASSERT_STR_EQ("cdn.example.com", nom.host);
    firc_autolist_free(a);
    PASS();
}

TEST an_answered_flow_named_by_its_domain_restarts_it(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    for (uint16_t i = 0; i < 2; i++) {
        firc_autolist_flow_t f = flow_at((uint16_t)(50001 + i), 1);
        hint_both(a, &f, "www.instagram.com", "i.instagram.com", 100);
        ASSERT(bare_hello_times(a, &f, "", 4, 100 + i * 10, &out));
    }
    firc_autolist_flow_t good = flow_at(50003, 1);
    ASSERT_FALSE(bare_hello_times(a, &good, "", 1, 120, &out));
    ASSERT_FALSE(firc_autolist_reply(a, &good, false, 121, &out));
    firc_autolist_flow_t f = flow_at(50004, 1);
    ASSERT(bare_hello_times(a, &f, "", 4, 125, &out));
    ASSERT_FALSE(out.listed);
    ASSERT_EQ(1u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST a_returning_host_starts_from_fresh_counts(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    ASSERT(failed_on(a, "www.example.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "www.example.com", 50002, 1, 102, &out));
    ASSERT(failed_on(a, "www.example.com", 50003, 1, 200, &out));
    ASSERT(failed_on(a, "cdn.example.com", 50004, 2, 205, &out));
    ASSERT_FALSE(out.listed);
    ASSERT(failed_on(a, "cdn.example.com", 50005, 2, 210, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("example.com", out.domain);
    ASSERT_STR_EQ("cdn.example.com", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST passing_flows_of_one_domain_s_names_evict_no_domain(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 2);
    firc_autolist_failure_t out;
    for (uint32_t i = 0; i < FIRC_AUTOLIST_DOMAINS; i++) {
        char host[32];
        snprintf(host, sizeof(host), "www.d%u.test", (unsigned)i);
        firc_autolist_flow_t f = flow_to((uint16_t)(10000 + i), (uint8_t)(i % 250 + 1));
        ASSERT(hello_times(a, &f, host, 4, 100, &out));
        ASSERT_FALSE(out.listed);
    }
    for (uint16_t i = 0; i < 4; i++) {
        firc_autolist_flow_t f = flow_at((uint16_t)(30000 + i), (uint8_t)(200 + i));
        hint_both(a, &f, "www.newsite.test", "i.newsite.test", 104);
        ASSERT_FALSE(bare_hello_times(a, &f, "", 1, 104, &out));
        ASSERT_FALSE(firc_autolist_reply(a, &f, false, 105, &out));
    }
    ASSERT(failed_on(a, "cdn.d0.test", 40000, 9, 106, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("d0.test", out.domain);
    firc_autolist_free(a);
    PASS();
}

TEST host_less_counts_can_mark_the_domain_itself(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_on(a, "graph.instagram.com", 50001, 2, 100, &nom));
    ASSERT_FALSE(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50002, 105, &nom));
    ASSERT(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50003, 110, &nom));
    ASSERT_STR_EQ("instagram.com", nom.domain);
    ASSERT_STR_EQ("instagram.com", nom.host);
    firc_autolist_free(a);
    PASS();
}

TEST a_domain_named_flow_that_loses_its_domain_is_ambiguous(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_flow_t f = flow_at(50001, 1);
    hint_both(a, &f, "www.instagram.com", "i.instagram.com", 100);
    ASSERT_FALSE(bare_hello_times(a, &f, "", 1, 100, &out));
    firc_autolist_hint(a, &f.client, "web.telegram.org", &f.server, 1, 101);
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "", 102, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "", 103, &out));
    ASSERT_FALSE(firc_autolist_hello(a, &f, 1000, 0, "", 104, &out));
    ASSERT_EQ(1u, firc_autolist_ambiguous_day(a, 104));
    ASSERT_EQ(0u, firc_autolist_failures_day(a, 104));
    firc_autolist_free(a);
    PASS();
}

TEST host_less_counts_start_over_with_their_domain(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50001, 100, &nom));
    ASSERT_FALSE(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50002, 105, &nom));
    ASSERT(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50003, 110, &nom));
    ASSERT_STR_EQ("instagram.com", nom.host);
    ASSERT_FALSE(unanswered_on(a, "graph.instagram.com", 50004, 2, 115, &nom));
    ASSERT_FALSE(unanswered_on(a, "graph.instagram.com", 50005, 2, 120, &nom));
    ASSERT(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50006, 125, &nom));
    ASSERT_STR_EQ("instagram.com", nom.domain);
    ASSERT_STR_EQ("graph.instagram.com", nom.host);
    firc_autolist_free(a);
    PASS();
}

TEST a_host_s_no_connect_nomination_keeps_the_domain_s_failures(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 3);
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT(failed_on(a, "www.example.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "api.example.com", 50002, 2, 105, &out));
    ASSERT_FALSE(out.listed);
    ASSERT_FALSE(unanswered_on(a, "cdn.example.com", 50003, 3, 110, &nom));
    ASSERT_FALSE(unanswered_on(a, "cdn.example.com", 50004, 3, 115, &nom));
    ASSERT(unanswered_on(a, "cdn.example.com", 50005, 3, 120, &nom));
    ASSERT_STR_EQ("cdn.example.com", nom.host);
    ASSERT_STR_EQ("", nom.domain);
    ASSERT(failed_on(a, "img.example.com", 50006, 4, 125, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("example.com", out.domain);
    ASSERT_EQ(3u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST a_host_listing_keeps_the_domain_s_no_connect_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 3);
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_on(a, "www.example.com", 50001, 1, 100, &nom));
    ASSERT_FALSE(unanswered_on(a, "api.example.com", 50002, 2, 105, &nom));
    ASSERT(failed_on(a, "cdn.example.com", 50003, 3, 110, &out));
    ASSERT(failed_on(a, "cdn.example.com", 50004, 3, 112, &out));
    ASSERT(failed_on(a, "cdn.example.com", 50005, 3, 114, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("", out.domain);
    ASSERT(unanswered_on(a, "img.example.com", 50006, 4, 120, &nom));
    ASSERT_STR_EQ("example.com", nom.domain);
    ASSERTm("a host listing restarts the domain's failures",
            failed_on(a, "www.example.com", 50007, 1, 125, &out) && !out.listed && out.fails == 1);
    firc_autolist_free(a);
    PASS();
}

TEST a_host_s_stall_nomination_keeps_the_domain_s_no_connect_count(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 3);
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_on(a, "x.freeze.test", 50001, 1, 100, &nom));
    ASSERT_FALSE(unanswered_on(a, "y.freeze.test", 50002, 2, 105, &nom));
    ASSERT_FALSE(stalled_on(a, "a.freeze.test", 50011, 110, &nom));
    ASSERT(stalled_on(a, "a.freeze.test", 50012, 115, &nom));
    ASSERT_EQ(FIRC_AL_NOM_STALL, nom.kind);
    ASSERT_STR_EQ("", nom.domain);
    ASSERT(unanswered_on(a, "z.freeze.test", 50003, 3, 130, &nom));
    ASSERT_EQ(FIRC_AL_NOM_NO_CONNECT, nom.kind);
    ASSERT_STR_EQ("freeze.test", nom.domain);
    ASSERTm("the stall restarted the domain's notes", !stalled_on(a, "b.freeze.test", 50013, 140, &nom));
    firc_autolist_free(a);
    PASS();
}

TEST a_domain_nomination_keeps_the_domain_s_failures(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 3);
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT(failed_on(a, "www.example.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "www.example.com", 50002, 1, 102, &out));
    ASSERT_FALSE(unanswered_on(a, "a.example.com", 50003, 2, 104, &nom));
    ASSERT_FALSE(unanswered_on(a, "b.example.com", 50004, 3, 106, &nom));
    ASSERT(unanswered_on(a, "c.example.com", 50005, 4, 108, &nom));
    ASSERT_STR_EQ("example.com", nom.domain);
    ASSERT(failed_on(a, "www.example.com", 50006, 1, 110, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("www.example.com", out.host);
    ASSERT_EQ(3u, out.fails);
    firc_autolist_free(a);
    PASS();
}

TEST a_domain_nomination_keeps_failures_counted_on_other_hosts(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 3);
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT(failed_on(a, "www.example.com", 50001, 1, 100, &out));
    ASSERT(failed_on(a, "api.example.com", 50002, 2, 102, &out));
    ASSERT_FALSE(unanswered_on(a, "a.example.com", 50003, 3, 104, &nom));
    ASSERT_FALSE(unanswered_on(a, "b.example.com", 50004, 4, 106, &nom));
    ASSERT(unanswered_on(a, "c.example.com", 50005, 5, 108, &nom));
    ASSERT_STR_EQ("example.com", nom.domain);
    ASSERT(failed_on(a, "img.example.com", 50006, 6, 112, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("example.com", out.domain);
    firc_autolist_free(a);
    PASS();
}

TEST a_domain_listing_forgets_which_host_failed_most(void) {
    firc_autolist_t *a = firc_autolist_new();
    set_threshold(a, 3);
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT_FALSE(unanswered_on(a, "www.example.com", 50001, 1, 100, &nom));
    ASSERT(failed_on(a, "www.example.com", 50002, 1, 104, &out));
    ASSERT(failed_on(a, "www.example.com", 50003, 1, 106, &out));
    ASSERT(failed_on(a, "cdn.example.com", 50004, 2, 108, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("www.example.com", out.host);
    ASSERT(failed_on(a, "cdn.example.com", 50005, 2, 110, &out));
    ASSERT(failed_on(a, "img.example.com", 50006, 3, 112, &out));
    ASSERT(failed_on(a, "img.example.com", 50007, 3, 114, &out));
    ASSERT(out.listed);
    ASSERT_STR_EQ("example.com", out.domain);
    ASSERT_STR_EQ("img.example.com", out.host);
    firc_autolist_free(a);
    PASS();
}

TEST a_domain_nomination_forgets_its_host_less_counts(void) {
    firc_autolist_t *a = firc_autolist_new();
    firc_autolist_failure_t out;
    firc_autolist_nomination_t nom;
    ASSERT(failed_on(a, "www.instagram.com", 50001, 9, 100, &out));
    ASSERT_FALSE(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50002, 102, &nom));
    ASSERT_FALSE(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50003, 104, &nom));
    ASSERT(unanswered_on(a, "graph.instagram.com", 50004, 2, 106, &nom));
    ASSERT_STR_EQ("instagram.com", nom.domain);
    ASSERT_STR_EQ("instagram.com", nom.host);
    ASSERT_FALSE(unanswered_on(a, "graph.instagram.com", 50005, 2, 110, &nom));
    ASSERT_FALSE(unanswered_on(a, "graph.instagram.com", 50006, 2, 112, &nom));
    ASSERT(unanswered_pair(a, "www.instagram.com", "i.instagram.com", 50007, 114, &nom));
    ASSERT_STR_EQ("instagram.com", nom.domain);
    ASSERT_STR_EQ("graph.instagram.com", nom.host);
    firc_autolist_free(a);
    PASS();
}

static bool local_at(const char *text, const firc_autolist_net_t *pools, size_t n) {
    firc_ip_t ip = {{0}, 4};
    if (inet_pton(AF_INET, text, ip.b) != 1) {
        ip.len = 16;
        if (inet_pton(AF_INET6, text, ip.b) != 1) { return false; }
    }
    return firc_autolist_local(&ip, pools, n);
}

static firc_autolist_net_t net(const char *text, uint8_t prefix) {
    firc_autolist_net_t n = {{{0}, 4}, prefix};
    if (inet_pton(AF_INET, text, n.base.b) != 1) {
        n.base.len = 16;
        (void)inet_pton(AF_INET6, text, n.base.b);
    }
    return n;
}

TEST local_v4_ranges_end_where_they_should(void) {
    static const char *const in[] = {"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0",
                                     "192.168.255.255", "169.254.0.1", "169.254.255.255", "127.0.0.1", "127.255.0.1",
                                     "100.64.0.0", "100.127.255.255", "198.18.0.0", "198.19.255.255",
                                     "0.0.0.0", "0.255.255.255"};
    static const char *const out[] = {"9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255",
                                      "192.169.0.0", "169.253.255.255", "169.255.0.0", "126.255.255.255", "128.0.0.0",
                                      "100.63.255.255", "100.128.0.0", "198.17.255.255", "198.20.0.0", "203.0.113.7",
                                      "8.8.8.8", "1.0.0.0"};
    for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); i++) { ASSERTm(in[i], local_at(in[i], NULL, 0)); }
    for (size_t i = 0; i < sizeof(out) / sizeof(out[0]); i++) { ASSERT_FALSEm(out[i], local_at(out[i], NULL, 0)); }
    PASS();
}

TEST local_v6_ranges_end_where_they_should(void) {
    static const char *const in[] = {"fc00::", "fdff:ffff::1", "fe80::1", "febf:ffff::1", "::1", "::ffff:192.168.1.10",
                                     "::ffff:100.64.0.1", "::", "::ffff:0.0.0.0"};
    static const char *const out[] = {"fbff:ffff::1", "fe00::1", "fec0::1", "::2", "2001:db8::1", "::ffff:8.8.8.8",
                                      "2a00:1450::1", "::2:0"};
    for (size_t i = 0; i < sizeof(in) / sizeof(in[0]); i++) { ASSERTm(in[i], local_at(in[i], NULL, 0)); }
    for (size_t i = 0; i < sizeof(out) / sizeof(out[0]); i++) { ASSERT_FALSEm(out[i], local_at(out[i], NULL, 0)); }
    PASS();
}

TEST the_configured_pool_is_local(void) {
    firc_autolist_net_t pools[2] = {net("11.0.0.0", 16), net("2001:db8:1::", 48)};
    ASSERT(local_at("11.0.255.9", pools, 2));
    ASSERT(local_at("2001:db8:1:ffff::1", pools, 2));
    ASSERT_FALSE(local_at("11.1.0.0", pools, 2));
    ASSERT_FALSE(local_at("2001:db8:2::1", pools, 2));
    ASSERT_FALSEm("a pool counts only after its own length", local_at("11.0.255.9", pools, 0));
    ASSERT_FALSEm("a v4 pool says nothing of a v6 address with the same first bytes", local_at("b00::1", pools, 1));
    firc_autolist_net_t odd[1] = {net("11.0.0.0", 9)};
    ASSERT(local_at("11.127.0.1", odd, 1));
    ASSERT_FALSE(local_at("11.128.0.1", odd, 1));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_hello_sent_once_is_no_failure);
    RUN_TEST(three_sendings_again_make_a_failure_once);
    RUN_TEST(three_failed_connections_list_the_host);
    RUN_TEST(failures_too_far_apart_start_over);
    RUN_TEST(an_early_reset_is_a_failure);
    RUN_TEST(a_working_connection_clears_the_count);
    RUN_TEST(a_working_address_does_not_clear_another_s_failures);
    RUN_TEST(a_failed_address_that_works_again_clears_the_count);
    RUN_TEST(a_reply_to_a_connection_never_seen_is_ignored);
    RUN_TEST(a_hello_without_sni_takes_its_name_from_the_dns_answer);
    RUN_TEST(another_device_s_answer_makes_a_bypass);
    RUN_TEST(a_stale_answer_makes_a_bypass);
    RUN_TEST(a_new_handshake_on_a_reused_port_starts_its_own_count);
    RUN_TEST(the_thresholds_can_be_set);
    RUN_TEST(more_connections_than_slots_do_not_break_it);
    RUN_TEST(no_hint_is_bypass_not_failure);
    RUN_TEST(hint_with_other_name_is_bypass);
    RUN_TEST(two_names_on_one_address_both_count);
    RUN_TEST(failures_day_counts_and_expires);
    RUN_TEST(hint_same_name_counts);
    RUN_TEST(no_sni_uses_hint);
    RUN_TEST(fin_in_window_after_ten_seconds_notes);
    RUN_TEST(fin_too_soon_is_no_note);
    RUN_TEST(fin_outside_window_is_no_note);
    RUN_TEST(fin_window_edges_are_in);
    RUN_TEST(fin_wraps_mod_2_32);
    RUN_TEST(notes_older_than_two_minutes_do_not_pair);
    RUN_TEST(notes_two_minutes_apart_pair);
    RUN_TEST(a_bypass_flow_s_fin_is_no_note);
    RUN_TEST(a_fin_sent_again_is_one_note);
    RUN_TEST(syns_logged_at_one_and_three_count);
    RUN_TEST(span_of_one_second_is_not_enough);
    RUN_TEST(a_syn_flow_counts_once);
    RUN_TEST(hello_after_syns_ends_no_connect);
    RUN_TEST(syn_named_by_the_only_hint);
    RUN_TEST(syn_with_two_names_is_ambiguous);
    RUN_TEST(syn_without_hint_is_bypass);
    RUN_TEST(sniless_without_hint_is_bypass);
    RUN_TEST(sniless_with_two_hints_is_ambiguous_not_newest);
    RUN_TEST(ambiguous_day_expires);
    RUN_TEST(domain_counts_over_distinct_hosts);
    RUN_TEST(domain_marker_is_the_most_failed_host);
    RUN_TEST(a_host_s_own_listing_names_no_domain);
    RUN_TEST(answered_host_restarts_domain);
    RUN_TEST(stalls_on_two_hosts_nominate_the_domain);
    RUN_TEST(a_host_s_own_stalls_name_no_domain);
    RUN_TEST(no_connect_on_three_hosts_nominates_the_domain);
    RUN_TEST(no_connect_and_failures_count_apart);
    RUN_TEST(multitenant_suffix_never_counts_as_domain);
    RUN_TEST(a_reset_to_a_syn_is_no_failure);
    RUN_TEST(a_close_of_a_syn_flow_is_no_note);
    RUN_TEST(a_late_syn_keeps_the_connected_flow);
    RUN_TEST(two_names_of_one_domain_count_toward_it);
    RUN_TEST(sniless_hellos_on_one_domain_s_names_list_it);
    RUN_TEST(names_of_one_shared_domain_stay_ambiguous);
    RUN_TEST(a_domain_listing_restarts_its_hosts);
    RUN_TEST(a_domain_nomination_restarts_its_hosts);
    RUN_TEST(marker_follows_the_kind_that_triggered);
    RUN_TEST(an_answered_flow_named_by_its_domain_restarts_it);
    RUN_TEST(a_returning_host_starts_from_fresh_counts);
    RUN_TEST(passing_flows_of_one_domain_s_names_evict_no_domain);
    RUN_TEST(host_less_counts_can_mark_the_domain_itself);
    RUN_TEST(a_domain_named_flow_that_loses_its_domain_is_ambiguous);
    RUN_TEST(host_less_counts_start_over_with_their_domain);
    RUN_TEST(a_host_s_no_connect_nomination_keeps_the_domain_s_failures);
    RUN_TEST(a_host_listing_keeps_the_domain_s_no_connect_count);
    RUN_TEST(a_host_s_stall_nomination_keeps_the_domain_s_no_connect_count);
    RUN_TEST(a_domain_nomination_keeps_the_domain_s_failures);
    RUN_TEST(a_domain_nomination_keeps_failures_counted_on_other_hosts);
    RUN_TEST(a_domain_listing_forgets_which_host_failed_most);
    RUN_TEST(a_domain_nomination_forgets_its_host_less_counts);
    RUN_TEST(local_v4_ranges_end_where_they_should);
    RUN_TEST(local_v6_ranges_end_where_they_should);
    RUN_TEST(the_configured_pool_is_local);
    GREATEST_MAIN_END();
}
