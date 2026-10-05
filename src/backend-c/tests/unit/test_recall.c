#include "greatest.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "firc/events.h"
#include "firc/recall.h"

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {{a, b, c, d}, 4};
    return ip;
}

/* The n-th of a run of distinct v4 addresses, 10.x.y.z. */
static firc_ip_t nth(uint32_t n) {
    return v4(10, (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n);
}

static const char G1[FIRC_ID_STR_LEN] = "0a0b0c0d";
static const char G2[FIRC_ID_STR_LEN] = "01020304";

static bool known(const firc_recall_t *r, const firc_ip_t *ip) {
    char name[256], group[FIRC_ID_STR_LEN];
    return firc_recall_by_real(r, ip, name, sizeof(name), group);
}

/* Catches: the name or the group not kept, or swapped. */
TEST a_real_address_names_its_name_and_group(void) {
    firc_recall_t *r = firc_recall_new(16, 16, 60);
    ASSERT(r != NULL);
    firc_ip_t a = v4(93, 184, 216, 34);
    firc_recall_real(r, &a, "shop.example.com", G1, 100);
    char name[256] = "x", group[FIRC_ID_STR_LEN] = "x";
    ASSERT(firc_recall_by_real(r, &a, name, sizeof(name), group));
    ASSERT_STR_EQ("shop.example.com", name);
    ASSERT_STR_EQ(G1, group);
    ASSERT_EQ_FMT((size_t)1, firc_recall_real_count(r), "%zu");
    firc_recall_free(r);
    PASS();
}

/* Catches: a lookup answering true on an empty or unrelated slot. */
TEST an_unknown_address_is_unknown(void) {
    firc_recall_t *r = firc_recall_new(16, 16, 60);
    firc_ip_t a = v4(93, 184, 216, 34), b = v4(93, 184, 216, 35);
    ASSERTm("empty", !known(r, &a));
    firc_recall_real(r, &a, "shop.example.com", G1, 100);
    ASSERTm("a neighbour", !known(r, &b));
    firc_recall_free(r);
    PASS();
}

/* Catches: a refresh inserting a second entry, or keeping the old data. */
TEST a_refreshed_address_takes_the_new_name(void) {
    firc_recall_t *r = firc_recall_new(16, 16, 60);
    firc_ip_t a = v4(93, 184, 216, 34);
    firc_recall_real(r, &a, "shop.example.com", G1, 100);
    firc_recall_real(r, &a, "cdn.other.net", G2, 101);
    char name[256], group[FIRC_ID_STR_LEN];
    ASSERT(firc_recall_by_real(r, &a, name, sizeof(name), group));
    ASSERT_STR_EQ("cdn.other.net", name);
    ASSERT_STR_EQ(G2, group);
    ASSERT_EQ_FMTm("one entry, not two", (size_t)1, firc_recall_real_count(r), "%zu");
    firc_recall_free(r);
    PASS();
}

/* Catches: FIFO instead of LRU, no eviction, or the wrong key removed from the index. */
TEST the_least_recently_used_address_goes_first_when_full(void) {
    firc_recall_t *r = firc_recall_new(3, 3, 60);
    firc_ip_t a = nth(1), b = nth(2), c = nth(3), d = nth(4);
    firc_recall_real(r, &a, "a.example", G1, 1);
    firc_recall_real(r, &b, "b.example", G1, 2);
    firc_recall_real(r, &c, "c.example", G1, 3);
    firc_recall_real(r, &a, "a.example", G1, 4);
    firc_recall_real(r, &d, "d.example", G1, 5);
    ASSERTm("b was the oldest", !known(r, &b));
    ASSERTm("a was refreshed", known(r, &a));
    ASSERT(known(r, &c));
    ASSERT(known(r, &d));
    ASSERT_EQ_FMT((size_t)3, firc_recall_real_count(r), "%zu");
    char name[256], group[FIRC_ID_STR_LEN];
    ASSERT(firc_recall_by_real(r, &d, name, sizeof(name), group));
    ASSERT_STR_EQm("the reused slot holds d's name", "d.example", name);
    firc_recall_free(r);
    PASS();
}

/* Catches: a key compared or hashed without its length. */
TEST v4_and_v6_with_the_same_leading_bytes_are_different_keys(void) {
    firc_recall_t *r = firc_recall_new(16, 16, 60);
    firc_ip_t a = v4(1, 2, 3, 4);
    firc_ip_t b = {{1, 2, 3, 4}, 16};
    firc_recall_real(r, &a, "four.example", G1, 1);
    ASSERTm("the v6 one was never recorded", !known(r, &b));
    firc_recall_real(r, &b, "six.example", G2, 2);
    char name[256], group[FIRC_ID_STR_LEN];
    ASSERT(firc_recall_by_real(r, &a, name, sizeof(name), group));
    ASSERT_STR_EQ("four.example", name);
    ASSERT(firc_recall_by_real(r, &b, name, sizeof(name), group));
    ASSERT_STR_EQ("six.example", name);
    ASSERT_EQ_FMT((size_t)2, firc_recall_real_count(r), "%zu");
    firc_recall_free(r);
    PASS();
}

/* Catches: no horizon, or one measured from the wrong end. */
TEST an_answer_is_remembered_inside_the_horizon_and_not_after(void) {
    firc_recall_t *r = firc_recall_new(16, 16, 60);
    firc_ip_t client = v4(192, 168, 1, 42), fake = v4(198, 18, 0, 1);
    firc_recall_answer(r, &client, "shop.example.com", FIRC_RECALL_V4, FIRC_DNS_ISSUED, &fake, 0);
    firc_recall_answer_t out;
    memset(&out, 0xff, sizeof(out));
    ASSERT(firc_recall_last_answer(r, &client, "shop.example.com", FIRC_RECALL_V4, 59, &out));
    ASSERT_EQ_FMT((long long)0, (long long)out.at, "%lld");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)out.decision, "%u");
    ASSERT_EQ_FMT(4u, (unsigned)out.fake.len, "%u");
    ASSERT_MEM_EQ(fake.b, out.fake.b, 4);
    ASSERTm("past the horizon", !firc_recall_last_answer(r, &client, "shop.example.com", FIRC_RECALL_V4, 61, &out));
    firc_recall_free(r);
    PASS();
}

/* Catches: a pair keyed on the client only or the name only, or a NULL fake left stale. */
TEST answers_are_per_client_and_per_name(void) {
    firc_recall_t *r = firc_recall_new(16, 16, 1800);
    firc_ip_t c1 = v4(192, 168, 1, 42), c2 = v4(192, 168, 1, 43), fake = v4(198, 18, 0, 9);
    firc_recall_answer(r, &c1, "a.example", FIRC_RECALL_V4, FIRC_DNS_ISSUED, &fake, 10);
    firc_recall_answer(r, &c1, "b.example", FIRC_RECALL_V4, FIRC_DNS_NO_MATCH, NULL, 11);
    firc_recall_answer(r, &c2, "a.example", FIRC_RECALL_V4, FIRC_DNS_NOT_COVERED, NULL, 12);
    firc_recall_answer(r, &c2, "b.example", FIRC_RECALL_V4, FIRC_DNS_PASSED, NULL, 13);
    struct { const firc_ip_t *c; const char *n; uint8_t d; int64_t at; unsigned fl; } want[] = {
        {&c1, "a.example", FIRC_DNS_ISSUED, 10, 4},
        {&c1, "b.example", FIRC_DNS_NO_MATCH, 11, 0},
        {&c2, "a.example", FIRC_DNS_NOT_COVERED, 12, 0},
        {&c2, "b.example", FIRC_DNS_PASSED, 13, 0},
    };
    for (size_t i = 0; i < 4; i++) {
        firc_recall_answer_t out;
        memset(&out, 0xff, sizeof(out));
        ASSERT(firc_recall_last_answer(r, want[i].c, want[i].n, FIRC_RECALL_V4, 20, &out));
        ASSERT_EQ_FMT((unsigned)want[i].d, (unsigned)out.decision, "%u");
        ASSERT_EQ_FMT((long long)want[i].at, (long long)out.at, "%lld");
        ASSERT_EQ_FMT(want[i].fl, (unsigned)out.fake.len, "%u");
    }
    firc_recall_answer_t out;
    ASSERTm("a name nobody asked", !firc_recall_last_answer(r, &c1, "c.example", FIRC_RECALL_V4, 20, &out));
    firc_recall_free(r);
    PASS();
}

/* Catches: a pair keyed without the family, so the AAAA answer overwrites the A one. */
TEST each_family_keeps_its_own_answer(void) {
    firc_recall_t *r = firc_recall_new(16, 16, 1800);
    firc_ip_t c = v4(192, 168, 1, 42), fake4 = v4(198, 18, 0, 5);
    firc_recall_answer(r, &c, "shop.example.com", FIRC_RECALL_V4, FIRC_DNS_ISSUED, &fake4, 10);
    firc_recall_answer(r, &c, "shop.example.com", FIRC_RECALL_V6, FIRC_DNS_ISSUED, &fake4, 11);
    firc_recall_answer_t out;
    memset(&out, 0xff, sizeof(out));
    ASSERT(firc_recall_last_answer(r, &c, "shop.example.com", FIRC_RECALL_V4, 20, &out));
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)out.decision, "%u");
    ASSERT_EQ_FMT((long long)10, (long long)out.at, "%lld");
    ASSERT_EQ_FMT(4u, (unsigned)out.fake.len, "%u");
    ASSERT_MEM_EQ(fake4.b, out.fake.b, 4);
    memset(&out, 0xff, sizeof(out));
    ASSERT(firc_recall_last_answer(r, &c, "shop.example.com", FIRC_RECALL_V6, 20, &out));
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)out.decision, "%u");
    ASSERT_EQ_FMT((long long)11, (long long)out.at, "%lld");
    ASSERT_EQ_FMTm("a v4 fake is not the v6 answer's", 0u, (unsigned)out.fake.len, "%u");

    firc_recall_answer(r, &c, "other.example", 0u, FIRC_DNS_ISSUED, NULL, 12);
    firc_recall_answer(r, &c, "other.example", 16u, FIRC_DNS_ISSUED, NULL, 12);
    ASSERTm("no family 0", !firc_recall_last_answer(r, &c, "other.example", 0u, 20, &out));
    ASSERTm("nor v4 from it", !firc_recall_last_answer(r, &c, "other.example", FIRC_RECALL_V4, 20, &out));
    ASSERTm("nor v6 from it", !firc_recall_last_answer(r, &c, "other.example", FIRC_RECALL_V6, 20, &out));
    firc_recall_free(r);
    PASS();
}

/* Catches: the pair table unbounded, or FIFO instead of LRU. */
TEST the_least_recently_used_pair_goes_first_when_full(void) {
    firc_recall_t *r = firc_recall_new(3, 3, 1800);
    firc_ip_t c = v4(192, 168, 1, 42);
    firc_recall_answer(r, &c, "a.example", FIRC_RECALL_V4, FIRC_DNS_ISSUED, NULL, 1);
    firc_recall_answer(r, &c, "b.example", FIRC_RECALL_V4, FIRC_DNS_ISSUED, NULL, 2);
    firc_recall_answer(r, &c, "c.example", FIRC_RECALL_V4, FIRC_DNS_ISSUED, NULL, 3);
    firc_recall_answer(r, &c, "a.example", FIRC_RECALL_V4, FIRC_DNS_PASSED, NULL, 4);
    firc_recall_answer(r, &c, "d.example", FIRC_RECALL_V4, FIRC_DNS_ISSUED, NULL, 5);
    firc_recall_answer_t out;
    ASSERTm("b was the oldest", !firc_recall_last_answer(r, &c, "b.example", FIRC_RECALL_V4, 6, &out));
    ASSERT(firc_recall_last_answer(r, &c, "a.example", FIRC_RECALL_V4, 6, &out));
    ASSERT_EQ_FMTm("the refresh rewrote the answer", (unsigned)FIRC_DNS_PASSED,
                   (unsigned)out.decision, "%u");
    ASSERT(firc_recall_last_answer(r, &c, "c.example", FIRC_RECALL_V4, 6, &out));
    ASSERT(firc_recall_last_answer(r, &c, "d.example", FIRC_RECALL_V4, 6, &out));
    ASSERT_EQ_FMT((long long)5, (long long)out.at, "%lld");
    firc_recall_free(r);
    PASS();
}

/* Catches: an entry point dereferencing a NULL recall. */
TEST a_null_recall_is_harmless(void) {
    firc_ip_t a = v4(1, 2, 3, 4);
    char name[256] = "untouched", group[FIRC_ID_STR_LEN] = "x";
    firc_recall_answer_t out;
    firc_recall_real(NULL, &a, "a.example", G1, 1);
    ASSERT(!firc_recall_by_real(NULL, &a, name, sizeof(name), group));
    firc_recall_answer(NULL, &a, "a.example", FIRC_RECALL_V4, FIRC_DNS_ISSUED, &a, 1);
    ASSERT(!firc_recall_last_answer(NULL, &a, "a.example", FIRC_RECALL_V4, 1, &out));
    ASSERT_EQ_FMT((size_t)0, firc_recall_real_count(NULL), "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_recall_probe_max_for_test(NULL), "%zu");
    firc_recall_free(NULL);
    PASS();
}

/* Catches: deletes that degrade the index toward a full scan, or lose a survivor. */
TEST two_hundred_thousand_inserts_keep_the_bound_and_the_probes_short(void) {
    enum { MAX = 8192, N = 200000 };
    firc_recall_t *r = firc_recall_new(MAX, MAX, 1800);
    ASSERT(r != NULL);
    firc_ip_t client = v4(192, 168, 1, 42);
    char name[64];
    alarm(30);
    for (uint32_t i = 0; i < N; i++) {
        firc_ip_t a = nth(i);
        snprintf(name, sizeof(name), "n%u.example", (unsigned)i);
        firc_recall_real(r, &a, name, G1, (int64_t)i);
        firc_recall_answer(r, &client, name, FIRC_RECALL_V4, FIRC_DNS_ISSUED, NULL, 0);
    }
    alarm(0);
    ASSERT(firc_recall_real_count(r) <= MAX);
    for (uint32_t i = N - MAX; i < N; i++) {
        firc_ip_t a = nth(i);
        char got[256], group[FIRC_ID_STR_LEN];
        snprintf(name, sizeof(name), "n%u.example", (unsigned)i);
        if (!firc_recall_by_real(r, &a, got, sizeof(got), group)) { FAILm("a survivor was lost"); }
        ASSERT_STR_EQ(name, got);
        firc_recall_answer_t out;
        if (!firc_recall_last_answer(r, &client, name, FIRC_RECALL_V4, 0, &out)) { FAILm("a surviving pair was lost"); }
    }
    for (uint32_t i = 0; i < N - MAX; i++) {
        firc_ip_t a = nth(i);
        if (known(r, &a)) { FAILm("an evicted address is still known"); }
    }
    firc_recall_answer_t out;
    ASSERTm("the first pair went", !firc_recall_last_answer(r, &client, "n0.example", FIRC_RECALL_V4, 0, &out));
    size_t probe = firc_recall_probe_max_for_test(r);
    printf("longest probe run: %zu\n", probe);
    ASSERT(probe > 0);
    ASSERT_LT(probe, (size_t)64);
    firc_recall_free(r);
    alarm(0);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_real_address_names_its_name_and_group);
    RUN_TEST(an_unknown_address_is_unknown);
    RUN_TEST(a_refreshed_address_takes_the_new_name);
    RUN_TEST(the_least_recently_used_address_goes_first_when_full);
    RUN_TEST(v4_and_v6_with_the_same_leading_bytes_are_different_keys);
    RUN_TEST(an_answer_is_remembered_inside_the_horizon_and_not_after);
    RUN_TEST(answers_are_per_client_and_per_name);
    RUN_TEST(each_family_keeps_its_own_answer);
    RUN_TEST(the_least_recently_used_pair_goes_first_when_full);
    RUN_TEST(a_null_recall_is_harmless);
    RUN_TEST(two_hundred_thousand_inserts_keep_the_bound_and_the_probes_short);
    GREATEST_MAIN_END();
}
