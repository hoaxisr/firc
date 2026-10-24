#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "firc/dnsstat.h"

#define H 3600
#define T0 ((int64_t)1000 * H)

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {{a, b, c, d}, 4};
    return ip;
}

static firc_ip_t nth(uint32_t n) {
    return v4(10, (uint8_t)(n >> 16), (uint8_t)(n >> 8), (uint8_t)n);
}

static const firc_id_t NONE = {{0, 0, 0, 0}};
static const firc_id_t G1 = {{0x0a, 0x0b, 0x0c, 0x0d}};
static const firc_id_t G2 = {{0x01, 0x02, 0x03, 0x04}};

typedef struct row {
    uint32_t slot;
    char name[256];
    firc_ip_t client;
    firc_dnsstat_count_t c;
    int64_t last;
    firc_id_t owner;
    bool last_blocked;
} row_t;

typedef struct rows {
    row_t r[64];
    size_t n;
} rows_t;

static bool collect(void *ud, uint32_t name_slot, const char *name, const firc_ip_t *client, firc_dnsstat_count_t c,
                    int64_t last_mono, firc_id_t owner, bool last_blocked) {
    rows_t *rs = ud;
    if (rs->n == sizeof(rs->r) / sizeof(rs->r[0])) { return false; }
    row_t *r = &rs->r[rs->n++];
    r->slot = name_slot;
    snprintf(r->name, sizeof(r->name), "%s", name);
    r->client = *client;
    r->c = c;
    r->last = last_mono;
    r->owner = owner;
    r->last_blocked = last_blocked;
    return true;
}

static rows_t read_rows(const firc_dnsstat_t *s, int64_t now) {
    rows_t rs;
    memset(&rs, 0, sizeof(rs));
    firc_dnsstat_each(s, now, collect, &rs);
    return rs;
}

static const row_t *find(const rows_t *rs, const char *name, const firc_ip_t *client) {
    for (size_t i = 0; i < rs->n; i++) {
        const row_t *r = &rs->r[i];
        if (strcmp(r->name, name) == 0 && r->client.len == client->len &&
            memcmp(r->client.b, client->b, client->len) == 0) {
            return r;
        }
    }
    return NULL;
}

static void note_n(firc_dnsstat_t *s, const char *name, const firc_ip_t *c, unsigned n, int64_t now) {
    for (unsigned i = 0; i < n; i++) { firc_dnsstat_note(s, name, c, NONE, false, now); }
}

/* Catches: a key on the name or the client alone, a query counted twice, or a NULL argument dereferenced. */
TEST a_query_counts_once_for_its_name_and_client(void) {
    ASSERT_EQ(NULL, firc_dnsstat_new(0));
    firc_dnsstat_t *s = firc_dnsstat_new(16);
    ASSERT(s != NULL);
    firc_ip_t c1 = v4(192, 168, 1, 2), c2 = v4(192, 168, 1, 3);
    firc_dnsstat_note(NULL, "a.example", &c1, NONE, false, T0);
    firc_dnsstat_note(s, "a.example", NULL, NONE, false, T0);
    firc_dnsstat_note(s, NULL, &c1, NONE, false, T0);
    firc_dnsstat_note(s, "", &c1, NONE, false, T0);
    firc_dnsstat_note(s, "a.example", &c1, NONE, false, T0);
    firc_dnsstat_note(s, "a.example", &c2, NONE, false, T0 + 1);
    firc_dnsstat_note(s, "b.example", &c1, NONE, false, T0 + 2);
    rows_t rs = read_rows(s, T0 + 3);
    ASSERT_EQ_FMT((size_t)3, rs.n, "%zu");
    const row_t *a1 = find(&rs, "a.example", &c1), *a2 = find(&rs, "a.example", &c2), *b1 = find(&rs, "b.example", &c1);
    ASSERT(a1 != NULL && a2 != NULL && b1 != NULL);
    ASSERT_EQ_FMT(1u, a1->c.queries, "%u");
    ASSERT_EQ_FMT(1u, a2->c.queries, "%u");
    ASSERT_EQ_FMT(1u, b1->c.queries, "%u");
    ASSERT_EQ_FMT(0u, a1->c.blocked, "%u");
    ASSERT_EQ_FMT((long long)T0, (long long)a1->last, "%lld");
    ASSERT_EQ_FMT((long long)(T0 + 1), (long long)a2->last, "%lld");
    firc_dnsstat_count_t t = firc_dnsstat_totals(s, T0 + 3);
    ASSERT_EQ_FMT(3u, t.queries, "%u");
    ASSERT_EQ_FMT(0u, t.blocked, "%u");
    ASSERT_EQ_FMT((size_t)3, firc_dnsstat_keys(s), "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_dnsstat_keys(NULL), "%zu");
    firc_dnsstat_each(NULL, T0, collect, &rs);
    firc_dnsstat_sweep(NULL, T0);
    firc_dnsstat_free(NULL);
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: blocked not counted, counted as an extra query, or not kept apart per key. */
TEST blocked_queries_are_counted_apart(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(16);
    firc_ip_t c1 = v4(192, 168, 1, 2), c2 = v4(192, 168, 1, 3);
    firc_dnsstat_note(s, "ads.example", &c1, G1, true, T0);
    firc_dnsstat_note(s, "ads.example", &c1, G1, true, T0 + 1);
    firc_dnsstat_note(s, "ads.example", &c1, NONE, false, T0 + 2);
    firc_dnsstat_note(s, "ads.example", &c2, NONE, false, T0 + 3);
    rows_t rs = read_rows(s, T0 + 4);
    const row_t *r1 = find(&rs, "ads.example", &c1), *r2 = find(&rs, "ads.example", &c2);
    ASSERT(r1 != NULL && r2 != NULL);
    ASSERT_EQ_FMT(3u, r1->c.queries, "%u");
    ASSERT_EQ_FMT(2u, r1->c.blocked, "%u");
    ASSERT_EQ_FMT(1u, r2->c.queries, "%u");
    ASSERT_EQ_FMT(0u, r2->c.blocked, "%u");
    firc_dnsstat_count_t t = firc_dnsstat_totals(s, T0 + 4);
    ASSERT_EQ_FMT(4u, t.queries, "%u");
    ASSERT_EQ_FMT(2u, t.blocked, "%u");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: a window shorter or longer than 24 hours, for a key or for the totals. */
TEST a_query_stays_in_the_window_for_24_h(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(16);
    firc_ip_t c1 = v4(192, 168, 1, 2);
    int64_t t = T0 + 100;
    firc_dnsstat_note(s, "a.example", &c1, NONE, true, t);
    rows_t rs = read_rows(s, t + 23 * H);
    ASSERT_EQ_FMT((size_t)1, rs.n, "%zu");
    ASSERT_EQ_FMT(1u, rs.r[0].c.queries, "%u");
    ASSERT_EQ_FMT(1u, rs.r[0].c.blocked, "%u");
    firc_dnsstat_count_t in = firc_dnsstat_totals(s, t + 23 * H);
    ASSERT_EQ_FMT(1u, in.queries, "%u");
    ASSERT_EQ_FMT(1u, in.blocked, "%u");
    rs = read_rows(s, t + 24 * H + 1);
    ASSERT_EQ_FMTm("gone from the rows", (size_t)0, rs.n, "%zu");
    firc_dnsstat_count_t out = firc_dnsstat_totals(s, t + 24 * H + 1);
    ASSERT_EQ_FMT(0u, out.queries, "%u");
    ASSERT_EQ_FMT(0u, out.blocked, "%u");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: FIFO or LRU eviction instead of fewest queries, or a key not re-sifted after a note. */
TEST a_full_store_evicts_the_key_with_fewest_queries(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(4);
    firc_ip_t c = v4(192, 168, 1, 2);
    note_n(s, "n1.example", &c, 5, T0 + 1);
    note_n(s, "n2.example", &c, 1, T0 + 2);
    note_n(s, "n3.example", &c, 3, T0 + 3);
    note_n(s, "n4.example", &c, 2, T0 + 4);
    note_n(s, "n5.example", &c, 1, T0 + 5);
    rows_t rs = read_rows(s, T0 + 6);
    ASSERT_EQ_FMT((size_t)4, rs.n, "%zu");
    ASSERTm("the 1-query key went", find(&rs, "n2.example", &c) == NULL);
    ASSERT(find(&rs, "n1.example", &c) != NULL);
    ASSERT(find(&rs, "n3.example", &c) != NULL);
    ASSERT(find(&rs, "n4.example", &c) != NULL);
    note_n(s, "n5.example", &c, 3, T0 + 6);
    note_n(s, "n6.example", &c, 1, T0 + 7);
    rs = read_rows(s, T0 + 8);
    ASSERT_EQ_FMT((size_t)4, rs.n, "%zu");
    ASSERTm("the 2-query key went", find(&rs, "n4.example", &c) == NULL);
    const row_t *n5 = find(&rs, "n5.example", &c);
    ASSERTm("n5 grew to 4 and stayed", n5 != NULL);
    ASSERT_EQ_FMT(4u, n5->c.queries, "%u");
    ASSERT(find(&rs, "n1.example", &c) != NULL);
    ASSERT(find(&rs, "n3.example", &c) != NULL);
    ASSERT(find(&rs, "n6.example", &c) != NULL);
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: a tie broken by insertion order or slot, not by the time last asked. */
TEST ties_evict_the_key_asked_longest_ago(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(3);
    firc_ip_t c = v4(192, 168, 1, 2);
    note_n(s, "a.example", &c, 1, T0 + 1);
    note_n(s, "b.example", &c, 1, T0 + 2);
    note_n(s, "c.example", &c, 1, T0 + 3);
    note_n(s, "b.example", &c, 1, T0 + 4);
    note_n(s, "c.example", &c, 1, T0 + 5);
    note_n(s, "a.example", &c, 1, T0 + 6);
    note_n(s, "d.example", &c, 1, T0 + 7);
    rows_t rs = read_rows(s, T0 + 8);
    ASSERT_EQ_FMT((size_t)3, rs.n, "%zu");
    ASSERTm("b was asked longest ago", find(&rs, "b.example", &c) == NULL);
    ASSERT(find(&rs, "a.example", &c) != NULL);
    ASSERT(find(&rs, "c.example", &c) != NULL);
    ASSERT(find(&rs, "d.example", &c) != NULL);
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: totals summed from the keys, so an eviction takes its queries with it. */
TEST totals_survive_eviction(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(2);
    firc_ip_t c = v4(192, 168, 1, 2);
    firc_dnsstat_note(s, "a.example", &c, NONE, true, T0 + 1);
    firc_dnsstat_note(s, "b.example", &c, NONE, false, T0 + 2);
    firc_dnsstat_note(s, "c.example", &c, NONE, false, T0 + 3);
    firc_dnsstat_note(s, "d.example", &c, NONE, true, T0 + 4);
    firc_dnsstat_note(s, "e.example", &c, NONE, false, T0 + 5);
    ASSERT_EQ_FMT((size_t)2, firc_dnsstat_keys(s), "%zu");
    firc_dnsstat_count_t t = firc_dnsstat_totals(s, T0 + 6);
    ASSERT_EQ_FMT(5u, t.queries, "%u");
    ASSERT_EQ_FMT(2u, t.blocked, "%u");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: reverse lookups not totalled apart, a name merely containing arpa taken for one, or their total lost to eviction. */
TEST arpa_totals_survive_eviction(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(2);
    firc_ip_t c = v4(192, 168, 1, 2);
    firc_dnsstat_note(s, "1.0.0.10.in-addr.arpa", &c, NONE, true, T0 + 1);
    firc_dnsstat_note(s, "2.0.0.10.in-addr.arpa", &c, NONE, false, T0 + 2);
    note_n(s, "a.example", &c, 3, T0 + 3);
    note_n(s, "b.example", &c, 2, T0 + 4);
    firc_dnsstat_note(s, "arpa.example", &c, NONE, false, T0 + 5);
    firc_dnsstat_note(s, "x.notarpa", &c, NONE, false, T0 + 6);
    firc_dnsstat_note(s, "arpa", &c, NONE, false, T0 + 7);
    ASSERT_EQ_FMT((size_t)2, firc_dnsstat_keys(s), "%zu");
    firc_dnsstat_count_t t = firc_dnsstat_totals(s, T0 + 8);
    ASSERT_EQ_FMT(10u, t.queries, "%u");
    ASSERT_EQ_FMT(1u, t.blocked, "%u");
    firc_dnsstat_count_t a = firc_dnsstat_totals_arpa(s, T0 + 8);
    ASSERT_EQ_FMT(3u, a.queries, "%u");
    ASSERT_EQ_FMT(1u, a.blocked, "%u");
    a = firc_dnsstat_totals_arpa(s, T0 + 1 + 24 * 3600);
    ASSERT_EQ_FMT(0u, a.queries, "%u");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: a name copied per key, or never released when its last key goes. */
TEST a_name_is_held_once_for_many_clients(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(3);
    firc_ip_t c1 = v4(192, 168, 1, 1), c2 = v4(192, 168, 1, 2), c3 = v4(192, 168, 1, 3), c4 = v4(192, 168, 1, 4);
    firc_dnsstat_note(s, "shared.example", &c1, NONE, false, T0 + 1);
    firc_dnsstat_note(s, "shared.example", &c2, NONE, false, T0 + 2);
    firc_dnsstat_note(s, "shared.example", &c3, NONE, false, T0 + 3);
    ASSERT_EQ_FMT((size_t)1, firc_dnsstat_names(s), "%zu");
    ASSERT_EQ_FMT((size_t)3, firc_dnsstat_keys(s), "%zu");
    rows_t rs = read_rows(s, T0 + 4);
    ASSERT_EQ_FMT((size_t)3, rs.n, "%zu");
    ASSERT_EQ_FMT(rs.r[0].slot, rs.r[1].slot, "%u");
    ASSERT_EQ_FMT(rs.r[0].slot, rs.r[2].slot, "%u");
    ASSERT_LT((size_t)rs.r[0].slot, firc_dnsstat_name_slots(s));
    firc_dnsstat_note(s, "x1.example", &c4, NONE, false, T0 + 5);
    ASSERT_EQ_FMTm("still held by two keys", (size_t)2, firc_dnsstat_names(s), "%zu");
    firc_dnsstat_note(s, "x2.example", &c4, NONE, false, T0 + 6);
    firc_dnsstat_note(s, "x3.example", &c4, NONE, false, T0 + 7);
    rs = read_rows(s, T0 + 8);
    ASSERT_EQ_FMT((size_t)3, rs.n, "%zu");
    ASSERT(find(&rs, "x1.example", &c4) != NULL);
    ASSERT(find(&rs, "x2.example", &c4) != NULL);
    ASSERT(find(&rs, "x3.example", &c4) != NULL);
    ASSERT_EQ_FMTm("the shared name went with its last key", (size_t)3, firc_dnsstat_names(s), "%zu");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: a 16-bit key counter wrapping, or the 32-bit totals clipped to it. */
TEST counters_saturate(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(4);
    firc_ip_t c = v4(192, 168, 1, 2);
    for (unsigned i = 0; i < 70000; i++) { firc_dnsstat_note(s, "busy.example", &c, G1, true, T0 + 10); }
    rows_t rs = read_rows(s, T0 + 11);
    ASSERT_EQ_FMT((size_t)1, rs.n, "%zu");
    ASSERT_EQ_FMT(65535u, rs.r[0].c.queries, "%u");
    ASSERT_EQ_FMT(65535u, rs.r[0].c.blocked, "%u");
    firc_dnsstat_count_t t = firc_dnsstat_totals(s, T0 + 11);
    ASSERT_EQ_FMT(70000u, t.queries, "%u");
    ASSERT_EQ_FMT(70000u, t.blocked, "%u");
    firc_dnsstat_note(s, "busy.example", &c, G1, false, T0 + H);
    rs = read_rows(s, T0 + H);
    ASSERT_EQ_FMTm("a new hour adds past one bucket's ceiling", 65536u, rs.r[0].c.queries, "%u");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: the first owner or blocked flag kept, or the last time not moved. */
TEST the_last_owner_and_blocked_follow_the_latest_query(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(4);
    firc_ip_t c = v4(192, 168, 1, 2);
    firc_dnsstat_note(s, "a.example", &c, G1, true, T0);
    firc_dnsstat_note(s, "a.example", &c, G2, false, T0 + 5);
    rows_t rs = read_rows(s, T0 + 6);
    ASSERT_EQ_FMT((size_t)1, rs.n, "%zu");
    ASSERT_MEM_EQ(G2.b, rs.r[0].owner.b, 4);
    ASSERT_FALSE(rs.r[0].last_blocked);
    ASSERT_EQ_FMT((long long)(T0 + 5), (long long)rs.r[0].last, "%lld");
    firc_dnsstat_note(s, "a.example", &c, NONE, true, T0 + 9);
    rs = read_rows(s, T0 + 10);
    ASSERT_MEM_EQ(NONE.b, rs.r[0].owner.b, 4);
    ASSERT(rs.r[0].last_blocked);
    ASSERT_EQ_FMT((long long)(T0 + 9), (long long)rs.r[0].last, "%lld");
    firc_dnsstat_free(s);
    PASS();
}

static bool find_name(void *ud, uint32_t name_slot, const char *name, const firc_ip_t *client,
                      firc_dnsstat_count_t c, int64_t last_mono, firc_id_t owner, bool last_blocked) {
    (void)name_slot, (void)client, (void)c, (void)last_mono, (void)owner, (void)last_blocked;
    const char **want = ud;
    if (strcmp(*want, name) == 0) {
        *want = NULL;
        return false;
    }
    return true;
}

static bool present(const firc_dnsstat_t *s, const char *name, int64_t now) {
    const char *want = name;
    firc_dnsstat_each(s, now, find_name, &want);
    return want == NULL;
}

/* Catches: the bound not kept, names leaked past the keys, or a probe run growing with churn. */
TEST two_hundred_thousand_notes_keep_the_bound(void) {
    enum { MAX = FIRC_DNSSTAT_KEYS, N = 200000 };
    firc_dnsstat_t *s = firc_dnsstat_new(MAX);
    ASSERT(s != NULL);
    char name[64];
    alarm(30);
    for (uint32_t i = 0; i < N; i++) {
        firc_ip_t c = nth(i % 7);
        snprintf(name, sizeof(name), "n%u.example", (unsigned)i);
        firc_dnsstat_note(s, name, &c, NONE, false, T0 + (int64_t)(i / 100));
    }
    alarm(0);
    ASSERT_EQ_FMT((size_t)MAX, firc_dnsstat_keys(s), "%zu");
    ASSERT_EQ_FMT((size_t)MAX, firc_dnsstat_names(s), "%zu");
    int64_t now = T0 + N / 100;
    snprintf(name, sizeof(name), "n%u.example", (unsigned)(N - 1));
    ASSERTm("the last note is held", present(s, name, now));
    ASSERTm("the first note went", !present(s, "n0.example", now));
    ASSERTm("an early note went", !present(s, "n150000.example", now));
    firc_dnsstat_count_t t = firc_dnsstat_totals(s, now);
    ASSERT_EQ_FMT((unsigned)N, t.queries, "%u");
    size_t probe = firc_dnsstat_probe_max_for_test(s);
    printf("longest probe run: %zu\n", probe);
    ASSERT(probe > 0);
    ASSERT_LT(probe, (size_t)64);
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: a sweep that keeps empty keys, keeps their names, or leaves stale totals in the eviction order. */
TEST the_sweep_drops_keys_with_nothing_left_and_frees_their_names(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(2);
    firc_ip_t c = v4(192, 168, 1, 2);
    note_n(s, "old.example", &c, 1, T0);
    note_n(s, "new.example", &c, 1, T0 + 12 * H);
    firc_dnsstat_sweep(s, T0 + 24 * H + 1);
    ASSERT_EQ_FMT((size_t)1, firc_dnsstat_keys(s), "%zu");
    ASSERT_EQ_FMT((size_t)1, firc_dnsstat_names(s), "%zu");
    rows_t rs = read_rows(s, T0 + 24 * H + 1);
    ASSERT_EQ_FMT((size_t)1, rs.n, "%zu");
    ASSERT_STR_EQ("new.example", rs.r[0].name);
    note_n(s, "old.example", &c, 1, T0 + 24 * H + 2);
    ASSERT_EQ_FMT((size_t)2, firc_dnsstat_names(s), "%zu");
    firc_dnsstat_free(s);

    s = firc_dnsstat_new(2);
    note_n(s, "a.example", &c, 5, T0);
    note_n(s, "a.example", &c, 1, T0 + 12 * H);
    note_n(s, "b.example", &c, 3, T0 + 13 * H);
    firc_dnsstat_sweep(s, T0 + 24 * H + 1);
    note_n(s, "c.example", &c, 1, T0 + 24 * H + 2);
    rs = read_rows(s, T0 + 24 * H + 3);
    ASSERT_EQ_FMT((size_t)2, rs.n, "%zu");
    ASSERTm("a has 1 left in the window, b has 3", find(&rs, "a.example", &c) == NULL);
    const row_t *b = find(&rs, "b.example", &c);
    ASSERT(b != NULL);
    ASSERT_EQ_FMT(3u, b->c.queries, "%u");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: domains counting keys instead of names, or names whose queries left the window. */
TEST domains_counts_names_with_queries_in_the_window(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(16);
    firc_ip_t c1 = v4(192, 168, 1, 2), c2 = v4(192, 168, 1, 3);
    firc_dnsstat_note(s, "a.example", &c1, NONE, false, T0);
    firc_dnsstat_note(s, "a.example", &c2, NONE, false, T0);
    firc_dnsstat_note(s, "b.example", &c1, NONE, false, T0 + 12 * H);
    ASSERT_EQ_FMT((size_t)2, firc_dnsstat_domains(s, T0 + 12 * H), "%zu");
    ASSERT_EQ_FMT((size_t)1, firc_dnsstat_domains(s, T0 + 24 * H + 1), "%zu");
    ASSERT_EQ_FMTm("a is held until the sweep", (size_t)2, firc_dnsstat_names(s), "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_dnsstat_domains(NULL, T0), "%zu");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: a window reaching before boot reading buckets at a negative hour. */
TEST a_window_from_boot_counts_its_first_day(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(16);
    firc_ip_t c = v4(192, 168, 1, 2);
    firc_dnsstat_note(s, "a.example", &c, NONE, true, 100);
    int64_t at[] = {200, 23 * H, 24 * H + 1};
    unsigned want[] = {1, 1, 0};
    for (size_t i = 0; i < 3; i++) {
        rows_t rs = read_rows(s, at[i]);
        unsigned got = rs.n == 1 ? rs.r[0].c.queries : 0;
        ASSERT_EQ_FMT(want[i], got, "%u");
        firc_dnsstat_count_t t = firc_dnsstat_totals(s, at[i]);
        ASSERT_EQ_FMT(want[i], t.queries, "%u");
        ASSERT_EQ_FMT(want[i], t.blocked, "%u");
        ASSERT_EQ_FMT((size_t)want[i], firc_dnsstat_domains(s, at[i]), "%zu");
    }
    firc_dnsstat_sweep(s, 200);
    ASSERT_EQ_FMT((size_t)1, firc_dnsstat_keys(s), "%zu");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: a new key bound to the name slot its eviction just freed. */
TEST a_full_store_reuses_the_name_of_the_key_it_evicts(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(1);
    firc_ip_t c1 = v4(192, 168, 1, 1), c2 = v4(192, 168, 1, 2);
    firc_dnsstat_note(s, "a", &c1, NONE, false, T0);
    firc_dnsstat_note(s, "a", &c2, NONE, false, T0 + 1);
    ASSERT_EQ_FMT((size_t)1, firc_dnsstat_names(s), "%zu");
    rows_t rs = read_rows(s, T0 + 2);
    ASSERT_EQ_FMT((size_t)1, rs.n, "%zu");
    ASSERT_STR_EQ("a", rs.r[0].name);
    ASSERT(find(&rs, "a", &c2) != NULL);
    ASSERT_EQ_FMT(1u, rs.r[0].c.queries, "%u");
    firc_dnsstat_note(s, "a", &c2, NONE, false, T0 + 3);
    rs = read_rows(s, T0 + 4);
    ASSERT_EQ_FMTm("the key is found again", 2u, rs.r[0].c.queries, "%u");
    firc_dnsstat_free(s);
    PASS();
}

enum { CH_NAMES = 400, CH_CLIENTS = 5, CH_MAX = 256 };

typedef struct churn {
    unsigned seen[CH_NAMES][CH_CLIENTS];
    unsigned count[CH_NAMES][CH_CLIENTS];
    bool bad;
} churn_t;

static bool churn_visit(void *ud, uint32_t name_slot, const char *name, const firc_ip_t *client,
                        firc_dnsstat_count_t c, int64_t last_mono, firc_id_t owner, bool last_blocked) {
    (void)name_slot, (void)last_mono, (void)owner, (void)last_blocked;
    churn_t *ch = ud;
    unsigned n = 0;
    if (sscanf(name, "n%u", &n) != 1 || n >= CH_NAMES || client->b[3] >= CH_CLIENTS) {
        ch->bad = true;
        return false;
    }
    ch->seen[n][client->b[3]]++;
    ch->count[n][client->b[3]] = c.queries;
    return true;
}

/* Catches: an index delete that strands or misplaces a neighbour, so a held key is lost or duplicated. */
TEST churn_keeps_every_count_and_name_against_a_model(void) {
    static unsigned model[CH_NAMES][CH_CLIENTS];
    static churn_t ch;
    memset(model, 0, sizeof(model));
    firc_dnsstat_t *s = firc_dnsstat_new(CH_MAX);
    uint32_t x = 12345;
    char name[32];
    for (unsigned i = 0; i < 3500; i++) {
        x = x * 1103515245u + 12345u;
        unsigned r = (x >> 8) % CH_NAMES;
        unsigned n = r * ((x >> 20) % CH_NAMES) / CH_NAMES;
        unsigned c = (x >> 4) % CH_CLIENTS;
        snprintf(name, sizeof(name), "n%u", n);
        firc_ip_t ip = v4(192, 168, 1, (uint8_t)c);
        firc_dnsstat_note(s, name, &ip, NONE, false, T0 + i);
        model[n][c]++;
        memset(&ch, 0, sizeof(ch));
        firc_dnsstat_each(s, T0 + i, churn_visit, &ch);
        ASSERT_FALSE(ch.bad);
        size_t keys = 0, names = 0;
        for (unsigned a = 0; a < CH_NAMES; a++) {
            bool held = false;
            for (unsigned b = 0; b < CH_CLIENTS; b++) {
                if (ch.seen[a][b] > 1) { FAILm("a key is held twice"); }
                if (ch.seen[a][b] == 0) {
                    model[a][b] = 0;
                    continue;
                }
                if (ch.count[a][b] != model[a][b]) { FAILm("a held key lost its count"); }
                held = true;
                keys++;
            }
            names += held;
        }
        if (ch.seen[n][c] != 1) { FAILm("the key just noted is missing"); }
        ASSERT_EQ_FMT(keys, firc_dnsstat_keys(s), "%zu");
        ASSERT_EQ_FMT(names, firc_dnsstat_names(s), "%zu");
    }
    ASSERT_EQ_FMT((size_t)CH_MAX, firc_dnsstat_keys(s), "%zu");
    firc_dnsstat_free(s);
    PASS();
}

#define DAY0 ((int64_t)1008 * H)

static unsigned queries_at(const firc_dnsstat_t *s, int64_t now) {
    rows_t rs = read_rows(s, now);
    return rs.n == 1 ? rs.r[0].c.queries : 0;
}

/* Catches: the bucket index wrapping one short, so the last hour of a day is skipped or written past the end. */
TEST a_key_in_the_last_bucket_is_read_and_rolled(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(4);
    firc_ip_t c = v4(192, 168, 1, 2);
    note_n(s, "a.example", &c, 2, DAY0);
    note_n(s, "a.example", &c, 1, DAY0 + 23 * H);
    ASSERT_EQ_FMT(3u, queries_at(s, DAY0 + 23 * H), "%u");
    note_n(s, "a.example", &c, 1, DAY0 + 24 * H);
    ASSERT_EQ_FMTm("hour 0 left, hours 23 and 24 stay", 2u, queries_at(s, DAY0 + 24 * H), "%u");
    firc_dnsstat_count_t t = firc_dnsstat_totals(s, DAY0 + 24 * H);
    ASSERT_EQ_FMT(2u, t.queries, "%u");
    firc_dnsstat_free(s);
    PASS();
}

/* Catches: a roll across the end of the day clearing the wrong hours. */
TEST a_roll_across_the_wrap_keeps_the_hours_in_the_window(void) {
    firc_dnsstat_t *s = firc_dnsstat_new(4);
    firc_ip_t c = v4(192, 168, 1, 2);
    note_n(s, "a.example", &c, 5, DAY0);
    note_n(s, "a.example", &c, 1, DAY0 + 2 * H);
    note_n(s, "a.example", &c, 3, DAY0 + 20 * H);
    note_n(s, "a.example", &c, 2, DAY0 + 23 * H);
    note_n(s, "a.example", &c, 4, DAY0 + 25 * H);
    struct { int64_t hour; unsigned want; } at[] = {{25, 10}, {43, 9}, {44, 6}, {48, 4}, {49, 0}};
    for (size_t i = 0; i < sizeof(at) / sizeof(at[0]); i++) {
        int64_t now = DAY0 + at[i].hour * H;
        ASSERT_EQ_FMT(at[i].want, queries_at(s, now), "%u");
        ASSERT_EQ_FMT(at[i].want, firc_dnsstat_totals(s, now).queries, "%u");
    }
    note_n(s, "a.example", &c, 1, DAY0 + 30 * H);
    firc_dnsstat_sweep(s, DAY0 + 44 * H);
    ASSERT_EQ_FMTm("hours 23, 25 and 30 after a sweep", 7u, queries_at(s, DAY0 + 44 * H), "%u");
    firc_dnsstat_free(s);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_query_counts_once_for_its_name_and_client);
    RUN_TEST(blocked_queries_are_counted_apart);
    RUN_TEST(a_query_stays_in_the_window_for_24_h);
    RUN_TEST(a_full_store_evicts_the_key_with_fewest_queries);
    RUN_TEST(ties_evict_the_key_asked_longest_ago);
    RUN_TEST(totals_survive_eviction);
    RUN_TEST(arpa_totals_survive_eviction);
    RUN_TEST(a_name_is_held_once_for_many_clients);
    RUN_TEST(counters_saturate);
    RUN_TEST(the_last_owner_and_blocked_follow_the_latest_query);
    RUN_TEST(two_hundred_thousand_notes_keep_the_bound);
    RUN_TEST(the_sweep_drops_keys_with_nothing_left_and_frees_their_names);
    RUN_TEST(domains_counts_names_with_queries_in_the_window);
    RUN_TEST(a_window_from_boot_counts_its_first_day);
    RUN_TEST(a_full_store_reuses_the_name_of_the_key_it_evicts);
    RUN_TEST(churn_keeps_every_count_and_name_against_a_model);
    RUN_TEST(a_key_in_the_last_bucket_is_read_and_rolled);
    RUN_TEST(a_roll_across_the_wrap_keeps_the_hours_in_the_window);
    GREATEST_MAIN_END();
}
