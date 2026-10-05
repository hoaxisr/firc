#include "greatest.h"

#include <stdint.h>
#include <string.h>

#include "firc/tapreport.h"
#include "firc/taprules.h"

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {0};
    ip.len = 4;
    ip.b[0] = a; ip.b[1] = b; ip.b[2] = c; ip.b[3] = d;
    return ip;
}

typedef struct {
    char buf[4096];
    size_t len;
    size_t n;
    bool too_long;
    bool no_headroom;
} said_t;

static void collect(const char *sentence, void *ud) {
    said_t *s = ud;
    size_t n = strlen(sentence);
    if (n > FIRC_TAP_SENTENCE_MAX || n == 0) { s->too_long = true; }
    if (strchr(sentence, '\n') != NULL) { s->too_long = true; }
    int w = snprintf(s->buf + s->len, sizeof(s->buf) - s->len, "%s\n", sentence);
    if (w > 0 && (size_t)w < sizeof(s->buf) - s->len) { s->len += (size_t)w; }
    s->n++;
    size_t runs = 0;
    for (size_t i = 0; i < n; i++) {
        if (sentence[i] >= '0' && sentence[i] <= '9' &&
            (i == 0 || sentence[i - 1] < '0' || sentence[i - 1] > '9')) {
            runs++;
        }
    }
    if (n + runs * 19 > FIRC_TAP_SENTENCE_MAX) { s->no_headroom = true; }
}

static said_t say(const firc_tap_report_t *r, bool final) {
    said_t s;
    memset(&s, 0, sizeof(s));
    firc_tap_report_sentences(r, final, collect, &s);
    return s;
}

TEST the_first_bypass_of_a_pair_is_an_event(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    firc_ip_t client = v4(192, 168, 1, 42);
    uint32_t repeats = 99;
    ASSERT(firc_tap_report_admit(r, &client, "example.com", 1000, &repeats));
    ASSERT_EQ_FMT(0u, repeats, "%u");
    firc_tap_report_free(r);
    PASS();
}

/* Catches: more than one event a minute per pair, or the minute counted from the last flow. */
TEST repeats_inside_a_minute_are_folded_into_the_next_event(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    firc_ip_t c = v4(192, 168, 1, 42);
    uint32_t rep = 99;
    ASSERT(firc_tap_report_admit(r, &c, "example.com", 0, &rep));
    ASSERT_EQ_FMT(0u, rep, "%u");
    ASSERT_FALSE(firc_tap_report_admit(r, &c, "example.com", 10, &rep));
    ASSERT_FALSE(firc_tap_report_admit(r, &c, "example.com", 20, &rep));
    rep = 99;
    ASSERT(firc_tap_report_admit(r, &c, "example.com", 61, &rep));
    ASSERT_EQ_FMTm("the two in between", 2u, rep, "%u");

    ASSERT_FALSEm("the minute restarts at the event, not at the first flow",
                  firc_tap_report_admit(r, &c, "example.com", 120, &rep));
    rep = 99;
    ASSERTm("sixty seconds after the last event is the next one",
            firc_tap_report_admit(r, &c, "example.com", 121, &rep));
    ASSERT_EQ_FMTm("and carries only what came since that event", 1u, rep, "%u");
    firc_tap_report_free(r);
    PASS();
}

/* Catches: a pair keyed on the client only or the name only. */
TEST a_pair_is_per_client_and_per_name(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    firc_ip_t a = v4(192, 168, 1, 42), b = v4(192, 168, 1, 43);
    uint32_t rep = 0;
    ASSERT(firc_tap_report_admit(r, &a, "example.com", 0, &rep));
    ASSERTm("another client", firc_tap_report_admit(r, &b, "example.com", 1, &rep));
    ASSERTm("another name", firc_tap_report_admit(r, &a, "other.example.com", 2, &rep));
    ASSERT_FALSEm("the first pair again", firc_tap_report_admit(r, &a, "example.com", 3, &rep));
    firc_tap_report_free(r);
    PASS();
}

/* Catches: a bypass swallowed when the pair table is full. */
TEST a_full_table_still_reports(void) {
    firc_tap_report_t *r = firc_tap_report_new(2);
    ASSERT(r != NULL);
    firc_ip_t a = v4(10, 0, 0, 1), b = v4(10, 0, 0, 2), c = v4(10, 0, 0, 3);
    uint32_t rep = 99;
    ASSERT(firc_tap_report_admit(r, &a, "one.example.com", 0, &rep));
    ASSERT(firc_tap_report_admit(r, &b, "two.example.com", 0, &rep));
    ASSERT_FALSEm("what is in the table still folds",
                  firc_tap_report_admit(r, &a, "one.example.com", 1, &rep));
    rep = 99;
    ASSERTm("what does not fit is an event", firc_tap_report_admit(r, &c, "x.example.com", 1, &rep));
    ASSERT_EQ_FMT(0u, rep, "%u");
    ASSERTm("every time", firc_tap_report_admit(r, &c, "x.example.com", 2, &rep));
    ASSERTm("and with no report at all", firc_tap_report_admit(NULL, &c, "x.example.com", 2, &rep));
    rep = 99;
    ASSERTm("and with no client", firc_tap_report_admit(r, NULL, "x.example.com", 2, &rep));
    ASSERT_EQ_FMT(0u, rep, "%u");
    rep = 99;
    ASSERTm("and with no name", firc_tap_report_admit(r, &c, NULL, 2, &rep));
    ASSERT_EQ_FMT(0u, rep, "%u");

    static said_t s;
    s = say(r, true);
    ASSERTm("and the summary says the table filled", strstr(s.buf, "table filled at 2") != NULL);
    ASSERTm(s.buf, strstr(s.buf, "4 bypasses reported, 1 repeat") != NULL);
    firc_tap_report_free(r);
    PASS();
}

/* Catches: a second at the rate limit counted more than once, or across sockets. */
TEST a_second_at_the_limit_is_counted_once(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    firc_tap_report_saw_packet(r);
    for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC - 1; i++) { firc_tap_report_saw_at(r, 0, 100); }
    static said_t s;
    s = say(r, true);
    ASSERT_FALSEm("one short of the limit is not the limit", strstr(s.buf, "limit") != NULL);

    firc_tap_report_saw_at(r, 0, 100);
    for (int i = 0; i < 700; i++) { firc_tap_report_saw_at(r, 0, 100); }
    s = say(r, true);
    ASSERTm("one second, however far past", strstr(s.buf, "at least 1 second on the new-connection") != NULL);

    for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC - 1; i++) { firc_tap_report_saw_at(r, 0, 101); }
    for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC; i++) { firc_tap_report_saw_at(r, 0, 102); }
    for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC - 1; i++) { firc_tap_report_saw_at(r, 1, 102); }
    s = say(r, true);
    ASSERTm("two seconds now", strstr(s.buf, "at least 2 seconds on the new-connection") != NULL);
    ASSERT_FALSEm("the hello socket never reached it", strstr(s.buf, "ClientHello capture") != NULL);
    firc_tap_report_free(r);
    PASS();
}

/* Catches: the summary claiming more than that a rule may have been capped. */
TEST the_summary_says_the_limit_was_reached(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    firc_tap_report_saw_packet(r);
    for (int64_t sec = 10; sec < 13; sec++) {
        for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC; i++) { firc_tap_report_saw_at(r, 1, sec); }
    }
    for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC; i++) { firc_tap_report_saw_at(r, 0, 10); }
    static said_t s;
    s = say(r, true);
    ASSERT_FALSE(s.too_long);
    ASSERTm(s.buf, strstr(s.buf, "\nA rule's limit of 500/s may have been reached in at least 1 "
                                  "second on the new-connection capture: some flows may not "
                                  "have been seen.\n") != NULL);
    ASSERTm(s.buf, strstr(s.buf, "\nA rule's limit of 500/s may have been reached in at least 3 "
                                  "seconds on the ClientHello capture: some flows may not have "
                                  "been seen.\n") != NULL);
    ASSERT_FALSEm("a capture that may have missed flows is not a clean one",
                  strstr(s.buf, "No bypass") != NULL);
    firc_tap_report_free(r);
    PASS();
}

TEST the_summary_says_the_recall_was_cold(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    firc_tap_report_saw_packet(r);
    static said_t s;
    s = say(r, true);
    ASSERT_FALSE(strstr(s.buf, "recorded no real address") != NULL);
    firc_tap_report_saw_cold_recall(r);
    s = say(r, true);
    ASSERTm(s.buf, strstr(s.buf, "\nfirc had recorded no real address when the capture started; "
                                  "bypasses were recognised by SNI only until clients asked.\n")
                       != NULL);
    firc_tap_report_free(r);
    PASS();
}

/* Catches: two ways of finding nothing reported with the same sentence. */
TEST the_sentences_separate_the_ways_of_finding_nothing(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    firc_ip_t client = v4(192, 168, 1, 42);
    for (int i = 0; i < 7; i++) { firc_tap_report_saw_packet(r); }
    for (int i = 0; i < 3; i++) { firc_tap_report_saw_no_name(r); }
    firc_tap_report_saw_loss(r);
    firc_tap_report_saw_loss(r);
    ASSERT(firc_tap_report_admit(r, &client, "example.com", 0, NULL));
    ASSERT_FALSE(firc_tap_report_admit(r, &client, "example.com", 1, NULL));

    static said_t s;
    s = say(r, true);
    ASSERT_FALSE(s.too_long);
    static const char first[] = "7 packets read, 1 bypass reported, 1 repeat not reported on "
                                "its own.\n";
    ASSERTm(s.buf, strncmp(s.buf, first, strlen(first)) == 0);
    ASSERTm(s.buf, strstr(s.buf, "\n3 packets carried no server name") != NULL);
    ASSERTm(s.buf, strstr(s.buf, "\n2 times packets were lost") != NULL);
    ASSERT_FALSE(strstr(s.buf, "No bypass") != NULL);
    firc_tap_report_free(r);
    PASS();
}

TEST the_two_ways_of_finding_nothing_are_different_sentences_too(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    static said_t s;
    s = say(r, true);
    ASSERTm(s.buf, strstr(s.buf, "No packet reached the capture at all") != NULL);
    ASSERT_FALSE(strstr(s.buf, "No bypass") != NULL);
    s = say(r, false);
    ASSERT_FALSEm("no verdict on a capture still running",
                  strstr(s.buf, "No packet reached") != NULL);
    firc_tap_report_free(r);

    r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    for (int i = 0; i < 4; i++) { firc_tap_report_saw_packet(r); }
    s = say(r, true);
    ASSERTm(s.buf, strstr(s.buf, "No bypass") != NULL);
    ASSERT_FALSE(strstr(s.buf, "No packet reached") != NULL);
    s = say(r, false);
    ASSERT_FALSEm("no verdict on a capture still running", strstr(s.buf, "No bypass") != NULL);
    firc_tap_report_free(r);
    PASS();
}

/* Catches: "No bypass" said of a capture that lost packets, names, interfaces or the recall. */
TEST no_bypass_is_not_said_of_a_capture_that_was_not_whole(void) {
    static said_t s;
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    for (int i = 0; i < 4; i++) { firc_tap_report_saw_packet(r); }
    s = say(r, true);
    ASSERTm("the control says it", strstr(s.buf, "No bypass") != NULL);
    firc_tap_report_free(r);

    for (int k = 0; k < 5; k++) {
        r = firc_tap_report_new(16);
        ASSERT(r != NULL);
        for (int i = 0; i < 4; i++) { firc_tap_report_saw_packet(r); }
        static const char *const what[5] = {"lost", "no name", "iface gone", "iface back",
                                            "cold recall"};
        switch (k) {
        case 0: firc_tap_report_saw_loss(r); break;
        case 1: firc_tap_report_saw_no_name(r); break;
        case 2: firc_tap_report_saw_iface_gone(r); break;
        case 3:
            firc_tap_report_saw_iface_gone(r);
            firc_tap_report_saw_iface_there(r);
            break;
        default: firc_tap_report_saw_cold_recall(r); break;
        }
        s = say(r, true);
        ASSERT_FALSEm(what[k], strstr(s.buf, "No bypass") != NULL);
        firc_tap_report_free(r);
    }
    PASS();
}

TEST an_interface_gone_or_back_and_rules_gone_are_sentences(void) {
    firc_tap_report_t *r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    for (int i = 0; i < 4; i++) { firc_tap_report_saw_packet(r); }
    firc_tap_report_saw_unparsed(r);
    firc_tap_report_saw_iface_gone(r);
    static said_t s;
    s = say(r, true);
    const char *iface = strstr(s.buf, "does not exist");
    const char *packets = strstr(s.buf, "packets read");
    const char *unparsed = strstr(s.buf, "could not be read as IPv4");
    ASSERT(iface != NULL && packets != NULL && unparsed != NULL);
    ASSERTm("after the number it is about", packets < iface);
    ASSERTm("and before the ones it invalidates", iface < unparsed);
    ASSERT(strstr(s.buf, "watched nothing") != NULL);

    firc_tap_report_saw_iface_there(r);
    s = say(r, true);
    ASSERT_FALSE(strstr(s.buf, "does not exist") != NULL);
    ASSERT(strstr(s.buf, "went away") != NULL);
    firc_tap_report_free(r);

    r = firc_tap_report_new(16);
    ASSERT(r != NULL);
    for (int i = 0; i < 4; i++) { firc_tap_report_saw_packet(r); }
    firc_tap_report_saw_rules_gone(r);
    s = say(r, true);
    ASSERT_FALSE(strstr(s.buf, "No bypass") != NULL);
    ASSERT(strstr(s.buf, "1 netfilter pass failed") != NULL);
    ASSERT(strstr(s.buf, "not watched") != NULL);
    firc_tap_report_free(r);
    PASS();
}

/* Catches: a summary sentence cut mid-number at the largest counter values. */
TEST every_sentence_fits_a_log_event(void) {
    firc_tap_report_t *r = firc_tap_report_new(SIZE_MAX / 2);
    ASSERT(r != NULL);
    firc_ip_t c = v4(10, 0, 0, 1);
    firc_tap_report_t *small = firc_tap_report_new(1);
    ASSERT(small != NULL);
    ASSERT(firc_tap_report_admit(small, &c, "a.example.com", 0, NULL));
    ASSERT(firc_tap_report_admit(small, &c, "b.example.com", 0, NULL));
    static said_t s;
    s = say(small, true);
    ASSERT_FALSE(s.too_long);
    ASSERT_FALSE(s.no_headroom);
    ASSERTm(s.buf, strstr(s.buf, "table filled at 1") != NULL);
    firc_tap_report_free(small);

    firc_tap_report_saw_packet(r);
    firc_tap_report_saw_no_name(r);
    firc_tap_report_saw_loss(r);
    firc_tap_report_saw_rules_gone(r);
    firc_tap_report_saw_unparsed(r);
    firc_tap_report_saw_stranger(r);
    firc_tap_report_saw_cold_recall(r);
    firc_tap_report_saw_iface_gone(r);
    for (int w = 0; w < 2; w++) {
        for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC; i++) { firc_tap_report_saw_at(r, w, 5); }
    }
    ASSERT(firc_tap_report_admit(r, &c, "a.example.com", 0, NULL));
    ASSERT_FALSE(firc_tap_report_admit(r, &c, "a.example.com", 1, NULL));
    s = say(r, true);
    ASSERT_FALSEm(s.buf, s.too_long);
    ASSERT_FALSEm(s.buf, s.no_headroom);
    ASSERT_EQ_FMTm("counts, iface, rules, two limits, cold, unparsed, no name, lost, "
                   "strangers", (size_t)10, s.n, "%zu");
    firc_tap_report_free(r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_first_bypass_of_a_pair_is_an_event);
    RUN_TEST(repeats_inside_a_minute_are_folded_into_the_next_event);
    RUN_TEST(a_pair_is_per_client_and_per_name);
    RUN_TEST(a_full_table_still_reports);
    RUN_TEST(a_second_at_the_limit_is_counted_once);
    RUN_TEST(the_summary_says_the_limit_was_reached);
    RUN_TEST(the_summary_says_the_recall_was_cold);
    RUN_TEST(the_sentences_separate_the_ways_of_finding_nothing);
    RUN_TEST(the_two_ways_of_finding_nothing_are_different_sentences_too);
    RUN_TEST(no_bypass_is_not_said_of_a_capture_that_was_not_whole);
    RUN_TEST(an_interface_gone_or_back_and_rules_gone_are_sentences);
    RUN_TEST(every_sentence_fits_a_log_event);
    GREATEST_MAIN_END();
}
