#include "greatest.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "firc/anscache.h"
#include "firc/dnswire.h"

typedef struct {
    uint8_t b[8192];
    size_t n;
} wire_t;

static const uint8_t NAME_A[] = {1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
static const uint8_t NAME_B[] = {1, 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
static const uint8_t NAME_AB[] = {2, 'a', 'b', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
static const uint8_t NAME_UPPER[] = {1, 'A', 7, 'E', 'x', 'A', 'm', 'p', 'l', 'e', 3, 'C', 'O', 'M', 0};

static void put16(wire_t *w, uint16_t v) {
    w->b[w->n++] = (uint8_t)(v >> 8);
    w->b[w->n++] = (uint8_t)v;
}

static void put32(wire_t *w, uint32_t v) {
    put16(w, (uint16_t)(v >> 16));
    put16(w, (uint16_t)v);
}

static void bump(wire_t *w, size_t at) {
    uint16_t v = (uint16_t)((unsigned)w->b[at] << 8 | w->b[at + 1]);
    v++;
    w->b[at] = (uint8_t)(v >> 8);
    w->b[at + 1] = (uint8_t)v;
}

static void begin(wire_t *w, uint16_t id, uint16_t flags, const uint8_t *name, size_t name_len) {
    w->n = 0;
    put16(w, id);
    put16(w, flags);
    put16(w, 1);
    put16(w, 0);
    put16(w, 0);
    put16(w, 0);
    memcpy(w->b + w->n, name, name_len);
    w->n += name_len;
    put16(w, FIRC_DNS_TYPE_A);
    put16(w, FIRC_DNS_CLASS_IN);
}

static void add_a(wire_t *w, uint32_t ttl, uint8_t last) {
    put16(w, 0xc00c);
    put16(w, FIRC_DNS_TYPE_A);
    put16(w, FIRC_DNS_CLASS_IN);
    put32(w, ttl);
    put16(w, 4);
    w->b[w->n++] = 10;
    w->b[w->n++] = 1;
    w->b[w->n++] = 2;
    w->b[w->n++] = last;
    bump(w, 6);
}

static void add_soa(wire_t *w, uint32_t ttl, uint32_t minimum) {
    put16(w, 0xc00c);
    put16(w, FIRC_DNS_TYPE_SOA);
    put16(w, FIRC_DNS_CLASS_IN);
    put32(w, ttl);
    put16(w, 22);
    w->b[w->n++] = 0;
    w->b[w->n++] = 0;
    put32(w, 1);
    put32(w, 7200);
    put32(w, 900);
    put32(w, 1209600);
    put32(w, minimum);
    bump(w, 8);
}

static void add_opt(wire_t *w, bool dnssec_ok, uint16_t cookie_len) {
    w->b[w->n++] = 0;
    put16(w, FIRC_DNS_TYPE_OPT);
    put16(w, 1232);
    put32(w, dnssec_ok ? 0x8000u : 0u);
    put16(w, cookie_len != 0 ? (uint16_t)(4u + cookie_len) : 0);
    if (cookie_len != 0) {
        put16(w, 10);
        put16(w, cookie_len);
        memset(w->b + w->n, 0x5a, cookie_len);
        w->n += cookie_len;
    }
    bump(w, 10);
}

static firc_dns_msg_t *parse(const wire_t *w) {
    firc_dns_msg_t *m = NULL;
    return firc_dns_msg_parse(w->b, w->n, &m) == FIRC_OK ? m : NULL;
}

static firc_id_t group(uint8_t n) {
    firc_id_t id = {{0, 0, 0, n}};
    return id;
}

static bool key_from(const wire_t *q, firc_id_t g, uint64_t gen, firc_anscache_key_t *k) {
    memset(k, 0, sizeof(*k));
    firc_dns_msg_t *m = parse(q);
    if (m == NULL) { return false; }
    bool ok = firc_anscache_key_of(m, g, gen, k);
    firc_dns_msg_free(m);
    return ok;
}

static firc_anscache_key_t key_for(const uint8_t *name, size_t len) {
    wire_t q;
    begin(&q, 0x1234, FIRC_DNS_FLAG_RD, name, len);
    firc_anscache_key_t k;
    (void)key_from(&q, group(7), 1, &k);
    return k;
}

static uint32_t lifetime_of(const wire_t *w) {
    firc_dns_msg_t *m = parse(w);
    if (m == NULL) { return 0xffffffffu; }
    uint32_t t = firc_anscache_lifetime(m);
    firc_dns_msg_free(m);
    return t;
}

static bool hit_of(firc_anscache_t *c, const firc_anscache_key_t *k, const uint8_t *name, size_t len,
                   uint64_t now, firc_anscache_hit_t *out) {
    wire_t q;
    begin(&q, 0x4321, FIRC_DNS_FLAG_RD, name, len);
    return firc_anscache_get(c, k, q.b, q.n, now, out);
}

static bool hits(firc_anscache_t *c, const firc_anscache_key_t *k, uint64_t now) {
    firc_anscache_hit_t h;
    bool ok = hit_of(c, k, NAME_A, sizeof(NAME_A), now, &h);
    if (ok) { free(h.wire); }
    return ok;
}

static void answer_a(wire_t *w, uint32_t ttl, uint8_t last) {
    begin(w, 0x1111, 0x8180, NAME_A, sizeof(NAME_A));
    add_a(w, ttl, last);
}

/* Catches: the first or the largest answer TTL taken for the entry's life instead of the smallest. */
TEST a_positive_answer_lives_as_long_as_its_shortest_ttl(void) {
    wire_t w;
    begin(&w, 1, 0x8180, NAME_A, sizeof(NAME_A));
    add_a(&w, 300, 1);
    add_a(&w, 120, 2);
    add_a(&w, 900, 3);
    ASSERT_EQ_FMT(120u, lifetime_of(&w), "%u");
    PASS();
}

/* Catches: no ceiling on a long TTL, or the ceiling applied as a floor. */
TEST a_lifetime_is_at_most_a_day(void) {
    const uint32_t ttl[] = {200000u, 86401u, 86400u, 86399u};
    const uint32_t want[] = {86400u, 86400u, 86400u, 86399u};
    for (size_t i = 0; i < 4; i++) {
        wire_t w;
        answer_a(&w, ttl[i], 1);
        ASSERT_EQ_FMT(want[i], lifetime_of(&w), "%u");
    }
    PASS();
}

/* Catches: the SOA's MINIMUM ignored, its own TTL ignored (RFC 2308), or no 60 s ceiling. */
TEST a_negative_answer_lives_by_its_soa_capped_at_a_minute(void) {
    const struct { uint16_t rcode; uint32_t soa_ttl, minimum, want; } cases[] = {
        {3, 3600, 30, 30}, {3, 3600, 900, 60}, {3, 10, 30, 10}, {0, 3600, 45, 45}, {3, 3600, 60, 60},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        wire_t w;
        begin(&w, 1, (uint16_t)(0x8180u | cases[i].rcode), NAME_A, sizeof(NAME_A));
        add_soa(&w, cases[i].soa_ttl, cases[i].minimum);
        ASSERT_EQ_FMT(cases[i].want, lifetime_of(&w), "%u");
    }
    PASS();
}

/* Catches: a negative answer with no SOA cached for some default time. */
TEST a_negative_answer_without_an_soa_is_not_cached(void) {
    wire_t w;
    begin(&w, 1, 0x8183, NAME_A, sizeof(NAME_A));
    ASSERT_EQ_FMT(0u, lifetime_of(&w), "%u");
    begin(&w, 1, 0x8180, NAME_A, sizeof(NAME_A));
    ASSERT_EQ_FMT(0u, lifetime_of(&w), "%u");
    PASS();
}

/* Catches: a truncated, TTL-less or failed answer cached. */
TEST truncated_ttl_less_and_failed_answers_are_not_cached(void) {
    const struct { uint16_t flags; uint32_t ttl; } cases[] = {
        {0x8380, 300}, {0x8180, 0}, {0x8182, 300}, {0x8181, 300}, {0x8185, 300}, {0x8184, 300},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        wire_t w;
        begin(&w, 1, cases[i].flags, NAME_A, sizeof(NAME_A));
        add_a(&w, cases[i].ttl, 1);
        ASSERT_EQ_FMT(0u, lifetime_of(&w), "%u");
    }
    PASS();
}

/* Catches: the name compared with its case, so a 0x20 forwarder never hits. */
TEST a_name_in_another_case_is_the_same_key(void) {
    wire_t lower, upper;
    begin(&lower, 1, 0x0100, NAME_A, sizeof(NAME_A));
    begin(&upper, 2, 0x0100, NAME_UPPER, sizeof(NAME_UPPER));
    firc_anscache_key_t k1, k2;
    ASSERT(key_from(&lower, group(7), 1, &k1));
    ASSERT(key_from(&upper, group(7), 1, &k2));
    ASSERT_MEM_EQ(&k1, &k2, sizeof(k1));
    ASSERT_MEM_EQ(NAME_A, k2.name, sizeof(NAME_A));
    PASS();
}

/* Catches: EDNS, DO or CD left out of the key, so an answer goes to a client that asked differently. */
TEST the_key_records_edns_do_and_cd(void) {
    wire_t q;
    firc_anscache_key_t k;
    begin(&q, 1, 0x0100, NAME_A, sizeof(NAME_A));
    ASSERT(key_from(&q, group(7), 1, &k));
    ASSERT_EQ(0u, k.variant);
    add_opt(&q, false, 0);
    ASSERT(key_from(&q, group(7), 1, &k));
    ASSERT_EQ(FIRC_ANSCACHE_EDNS, k.variant);
    begin(&q, 1, 0x0100, NAME_A, sizeof(NAME_A));
    add_opt(&q, true, 0);
    ASSERT(key_from(&q, group(7), 1, &k));
    ASSERT_EQ(FIRC_ANSCACHE_EDNS | FIRC_ANSCACHE_DO, k.variant);
    begin(&q, 1, 0x0110, NAME_A, sizeof(NAME_A));
    ASSERT(key_from(&q, group(7), 1, &k));
    ASSERT_EQ(FIRC_ANSCACHE_CD, k.variant);
    PASS();
}

/* Catches: a query with no question, or two, given a key. */
TEST only_a_single_question_has_a_key(void) {
    wire_t q;
    firc_anscache_key_t k;
    q.n = 0;
    put16(&q, 1);
    put16(&q, 0x0100);
    put16(&q, 0);
    put16(&q, 0);
    put16(&q, 0);
    put16(&q, 0);
    ASSERT_FALSE(key_from(&q, group(7), 1, &k));
    begin(&q, 1, 0x0100, NAME_A, sizeof(NAME_A));
    memcpy(q.b + q.n, NAME_B, sizeof(NAME_B));
    q.n += sizeof(NAME_B);
    put16(&q, FIRC_DNS_TYPE_A);
    put16(&q, FIRC_DNS_CLASS_IN);
    bump(&q, 4);
    ASSERT_FALSE(key_from(&q, group(7), 1, &k));
    PASS();
}

/* Catches: a hit carrying the first asker's id, RD bit or name case, or any other byte changed. */
TEST a_hit_carries_the_askers_id_rd_and_case(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    ASSERT(c != NULL);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 300, 9);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    wire_t q;
    begin(&q, 0xbeef, 0x0000, NAME_UPPER, sizeof(NAME_UPPER));
    firc_anscache_hit_t hit;
    ASSERT(firc_anscache_get(c, &k, q.b, q.n, 1000, &hit));
    ASSERT_EQ_FMT(a.n, hit.len, "%zu");
    ASSERT_EQ(0xbe, hit.wire[0]);
    ASSERT_EQ(0xef, hit.wire[1]);
    ASSERT_EQ(0x80, hit.wire[2]);
    ASSERT_EQ(0x80, hit.wire[3]);
    ASSERT_MEM_EQ(a.b + 4, hit.wire + 4, 8);
    ASSERT_MEM_EQ(NAME_UPPER, hit.wire + 12, sizeof(NAME_UPPER));
    size_t rest = 12 + sizeof(NAME_UPPER);
    ASSERT_MEM_EQ(a.b + rest, hit.wire + rest, a.n - rest);
    free(hit.wire);
    firc_anscache_free(c);
    PASS();
}

/* Catches: TTLs handed out as stored, rounded up, taken below zero, or an OPT's flags touched. */
TEST a_hit_has_its_ttls_lowered_by_the_age(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 300, 1);
    add_a(&a, 200, 2);
    add_soa(&a, 30, 30);
    add_opt(&a, true, 0);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 200, 1000));
    firc_anscache_hit_t hit;
    ASSERT(hit_of(c, &k, NAME_A, sizeof(NAME_A), 1000 + 50999, &hit));
    firc_dns_msg_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(hit.wire, hit.len, &m));
    ASSERT_EQ_FMT(250u, m->answers[0].ttl, "%u");
    ASSERT_EQ_FMT(150u, m->answers[1].ttl, "%u");
    ASSERT_EQ_FMT(0u, m->authority[0].ttl, "%u");
    ASSERT_EQ_FMT(0x8000u, m->additional[0].ttl, "%u");
    firc_dns_msg_free(m);
    free(hit.wire);
    firc_anscache_free(c);
    PASS();
}

/* Catches: an entry served at or past its lifetime, or left behind once it lapsed. */
TEST an_entry_lapses_at_its_lifetime(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 60, 1);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 60, 1000));
    ASSERT(hits(c, &k, 60999));
    ASSERT_FALSE(hits(c, &k, 61000));
    ASSERT_EQ_FMT((size_t)0, firc_anscache_count(c), "%zu");
    firc_anscache_free(c);
    PASS();
}

/* Catches: group, generation, type, class, variant or name missing from the key. */
TEST every_field_of_the_key_separates_entries(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 300, 1);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    firc_anscache_key_t other[5];
    for (size_t i = 0; i < 5; i++) { other[i] = k; }
    other[0].group_id = group(8);
    other[1].gen = 2;
    other[2].qtype = FIRC_DNS_TYPE_AAAA;
    other[3].qclass = 3;
    other[4].variant = FIRC_ANSCACHE_EDNS;
    for (size_t i = 0; i < 5; i++) { ASSERT_FALSEm("one field changed", hits(c, &other[i], 1000)); }
    firc_anscache_key_t kb = key_for(NAME_B, sizeof(NAME_B));
    firc_anscache_hit_t h;
    ASSERT_FALSE(hit_of(c, &kb, NAME_B, sizeof(NAME_B), 1000, &h));
    ASSERT(hits(c, &k, 1000));
    firc_anscache_free(c);
    PASS();
}

/* Catches: a second put for one key adding an entry beside the first, or keeping the old answer. */
TEST a_put_replaces_its_keys_entry(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 300, 1);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    answer_a(&a, 300, 2);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)1, firc_anscache_count(c), "%zu");
    firc_anscache_hit_t h;
    ASSERT(hit_of(c, &k, NAME_A, sizeof(NAME_A), 1000, &h));
    ASSERT_EQ(2, h.wire[h.len - 1]);
    free(h.wire);
    firc_anscache_free(c);
    PASS();
}

/* Catches: eviction by insertion order instead of use, or the count bound not held. */
TEST the_count_bound_evicts_the_least_recently_used(void) {
    firc_anscache_t *c = firc_anscache_new(3, 1u << 20);
    firc_anscache_key_t k[4];
    wire_t a;
    answer_a(&a, 300, 1);
    for (uint8_t i = 0; i < 4; i++) {
        k[i] = key_for(NAME_A, sizeof(NAME_A));
        k[i].group_id = group((uint8_t)(i + 1));
    }
    for (size_t i = 0; i < 3; i++) { ASSERT(firc_anscache_put(c, &k[i], a.b, a.n, 300, 1000)); }
    ASSERT(hits(c, &k[0], 1000));
    ASSERT(firc_anscache_put(c, &k[3], a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)3, firc_anscache_count(c), "%zu");
    ASSERT_FALSEm("the least recently used went", hits(c, &k[1], 1000));
    ASSERT(hits(c, &k[0], 1000));
    ASSERT(hits(c, &k[2], 1000));
    ASSERT(hits(c, &k[3], 1000));
    firc_anscache_free(c);
    PASS();
}

/* Catches: the byte bound not counted, not held, or evicting the newest instead of the oldest. */
TEST the_byte_bound_evicts_the_least_recently_used(void) {
    wire_t a;
    answer_a(&a, 300, 1);
    firc_anscache_key_t k[3];
    for (uint8_t i = 0; i < 3; i++) {
        k[i] = key_for(NAME_A, sizeof(NAME_A));
        k[i].group_id = group((uint8_t)(i + 1));
    }
    firc_anscache_t *probe = firc_anscache_new(16, 1u << 20);
    ASSERT(firc_anscache_put(probe, &k[0], a.b, a.n, 300, 1000));
    size_t one = firc_anscache_bytes(probe);
    firc_anscache_free(probe);
    size_t bound = 2 * one + one / 2;
    firc_anscache_t *c = firc_anscache_new(16, bound);
    ASSERT(firc_anscache_put(c, &k[0], a.b, a.n, 300, 1000));
    ASSERT(firc_anscache_put(c, &k[1], a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)2, firc_anscache_count(c), "%zu");
    ASSERT(firc_anscache_put(c, &k[2], a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)2, firc_anscache_count(c), "%zu");
    ASSERT(firc_anscache_bytes(c) <= bound);
    ASSERT_FALSE(hits(c, &k[0], 1000));
    ASSERT(hits(c, &k[1], 1000));
    ASSERT(hits(c, &k[2], 1000));
    firc_anscache_free(c);
    PASS();
}

/* Catches: the accounting leaving out wire bytes or the per-TTL offset. */
TEST the_accounted_bytes_grow_by_a_records_wire_and_offset(void) {
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 300, 1);
    firc_anscache_t *one = firc_anscache_new(16, 1u << 20);
    ASSERT(firc_anscache_put(one, &k, a.b, a.n, 300, 1000));
    ASSERT(firc_anscache_bytes(one) >= a.n + sizeof(NAME_A) + 2);
    add_a(&a, 300, 2);
    firc_anscache_t *two = firc_anscache_new(16, 1u << 20);
    ASSERT(firc_anscache_put(two, &k, a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)18, firc_anscache_bytes(two) - firc_anscache_bytes(one), "%zu");
    firc_anscache_free(one);
    firc_anscache_free(two);
    PASS();
}

/* Catches: bytes after the last record stored and served with the answer. */
TEST bytes_after_the_last_record_are_not_cached(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 300, 1);
    a.b[a.n++] = 0x77;
    ASSERT_FALSE(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)0, firc_anscache_count(c), "%zu");
    firc_anscache_free(c);
    PASS();
}

/* Catches: a TTL with the top bit set read as a huge lifetime instead of zero (RFC 2181). */
TEST a_ttl_above_2_31_minus_1_is_not_cached(void) {
    wire_t w;
    answer_a(&w, 0x80000000u, 1);
    ASSERT_EQ_FMT(0u, lifetime_of(&w), "%u");
    answer_a(&w, 0x7fffffffu, 1);
    ASSERT_EQ_FMT(86400u, lifetime_of(&w), "%u");
    begin(&w, 1, 0x8183, NAME_A, sizeof(NAME_A));
    add_soa(&w, 0x80000000u, 30);
    ASSERT_EQ_FMT(0u, lifetime_of(&w), "%u");
    PASS();
}

/* Catches: an answer over 4096 bytes cached, or one of exactly 4096 refused. */
TEST an_answer_over_4096_bytes_is_not_cached(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_AB, sizeof(NAME_AB));
    wire_t a;
    begin(&a, 1, 0x8180, NAME_AB, sizeof(NAME_AB));
    for (int i = 0; i < 254; i++) { add_a(&a, 300, (uint8_t)i); }
    ASSERT_EQ_FMT((size_t)4096, a.n, "%zu");
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    add_a(&a, 300, 255);
    ASSERT_EQ_FMT((size_t)4112, a.n, "%zu");
    firc_anscache_drop_group(c, group(7));
    ASSERT_FALSE(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)0, firc_anscache_count(c), "%zu");
    firc_anscache_free(c);
    PASS();
}

/* Catches: an answer to another question stored under the key and later served for it. */
TEST an_answer_to_another_question_is_not_stored(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    begin(&a, 1, 0x8180, NAME_B, sizeof(NAME_B));
    add_a(&a, 300, 1);
    ASSERT_FALSE(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)0, firc_anscache_count(c), "%zu");
    firc_anscache_free(c);
    PASS();
}

/* Catches: an answer to another type or class stored under the key and later served for it. */
TEST an_answer_of_another_type_or_class_is_not_stored(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    size_t at = FIRC_DNS_HEADER_LEN + sizeof(NAME_A);
    wire_t a;
    answer_a(&a, 300, 1);
    a.b[at + 1] = FIRC_DNS_TYPE_AAAA;
    ASSERT_FALSE(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    answer_a(&a, 300, 1);
    a.b[at + 3] = 3;
    ASSERT_FALSE(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    ASSERT_EQ_FMT((size_t)0, firc_anscache_count(c), "%zu");
    answer_a(&a, 300, 1);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    firc_anscache_free(c);
    PASS();
}

/* Catches: another client's DNS cookie handed out from the cache with the answer. */
TEST the_options_of_an_answers_opt_are_not_kept(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 300, 1);
    add_opt(&a, false, 16);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 300, 1000));
    firc_anscache_hit_t h;
    ASSERT(hit_of(c, &k, NAME_A, sizeof(NAME_A), 1000, &h));
    ASSERT_EQ_FMT(a.n - 20, h.len, "%zu");
    firc_dns_msg_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(h.wire, h.len, &m));
    ASSERT_EQ_FMT((size_t)1, m->n_additional, "%zu");
    ASSERT_EQ(FIRC_DNS_TYPE_OPT, m->additional[0].rtype);
    ASSERT_EQ_FMT((size_t)0, m->additional[0].rdata_len, "%zu");
    firc_dns_msg_free(m);
    free(h.wire);
    wire_t b;
    begin(&b, 1, 0x8180, NAME_A, sizeof(NAME_A));
    add_opt(&b, false, 16);
    add_soa(&b, 300, 300);
    b.b[8] = 0;
    b.b[9] = 0;
    b.b[10] = 0;
    b.b[11] = 2;
    ASSERT_FALSEm("an OPT with options that is not last", firc_anscache_put(c, &k, b.b, b.n, 300, 1000));
    firc_anscache_free(c);
    PASS();
}

/* Catches: dropping a group leaving its entries, or taking another group's. */
TEST dropping_a_group_drops_only_its_entries(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k7 = key_for(NAME_A, sizeof(NAME_A));
    firc_anscache_key_t k8 = k7;
    k8.group_id = group(8);
    wire_t a;
    answer_a(&a, 300, 1);
    ASSERT(firc_anscache_put(c, &k7, a.b, a.n, 300, 1000));
    ASSERT(firc_anscache_put(c, &k8, a.b, a.n, 300, 1000));
    firc_anscache_drop_group(c, group(7));
    ASSERT_FALSE(hits(c, &k7, 1000));
    ASSERT(hits(c, &k8, 1000));
    ASSERT_EQ_FMT((size_t)1, firc_anscache_count(c), "%zu");
    firc_anscache_free(c);
    PASS();
}

/* Catches: a refresh asked before the last tenth, for a TTL under 10 s, twice at once, or never again after one ends. */
TEST a_refresh_is_asked_once_in_the_last_tenth(void) {
    firc_anscache_t *c = firc_anscache_new(64, 1u << 20);
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 100, 1);
    ASSERT(firc_anscache_put(c, &k, a.b, a.n, 100, 1000));
    firc_anscache_hit_t h;
    ASSERT(hit_of(c, &k, NAME_A, sizeof(NAME_A), 1000 + 90000, &h));
    free(h.wire);
    ASSERT_FALSEm("exactly a tenth left", h.prefetch);
    ASSERT(hit_of(c, &k, NAME_A, sizeof(NAME_A), 1000 + 90001, &h));
    free(h.wire);
    ASSERT(h.prefetch);
    ASSERT(hit_of(c, &k, NAME_A, sizeof(NAME_A), 1000 + 90002, &h));
    free(h.wire);
    ASSERT_FALSEm("one in flight", h.prefetch);
    firc_anscache_prefetch_done(c, &k);
    ASSERT(hit_of(c, &k, NAME_A, sizeof(NAME_A), 1000 + 90003, &h));
    free(h.wire);
    ASSERT(h.prefetch);

    firc_anscache_key_t k9 = k;
    k9.group_id = group(9);
    answer_a(&a, 9, 1);
    ASSERT(firc_anscache_put(c, &k9, a.b, a.n, 9, 1000));
    ASSERT(hit_of(c, &k9, NAME_A, sizeof(NAME_A), 1000 + 8999, &h));
    free(h.wire);
    ASSERT_FALSEm("9 s is under the floor", h.prefetch);

    firc_anscache_key_t k10 = k;
    k10.group_id = group(10);
    answer_a(&a, 10, 1);
    ASSERT(firc_anscache_put(c, &k10, a.b, a.n, 10, 1000));
    ASSERT(hit_of(c, &k10, NAME_A, sizeof(NAME_A), 1000 + 9001, &h));
    free(h.wire);
    ASSERT(h.prefetch);
    firc_anscache_free(c);
    PASS();
}

/* Catches: a NULL cache (out of memory, or turned off) crashing a caller or answering a hit. */
TEST a_null_cache_is_inert(void) {
    ASSERT_EQ(NULL, firc_anscache_new(0, 1u << 20));
    ASSERT_EQ(NULL, firc_anscache_new(16, 0));
    firc_anscache_key_t k = key_for(NAME_A, sizeof(NAME_A));
    wire_t a;
    answer_a(&a, 300, 1);
    ASSERT_FALSE(firc_anscache_put(NULL, &k, a.b, a.n, 300, 1000));
    ASSERT_FALSE(hits(NULL, &k, 1000));
    firc_anscache_prefetch_done(NULL, &k);
    firc_anscache_drop_group(NULL, group(7));
    ASSERT_EQ_FMT((size_t)0, firc_anscache_count(NULL), "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_anscache_bytes(NULL), "%zu");
    firc_anscache_free(NULL);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_positive_answer_lives_as_long_as_its_shortest_ttl);
    RUN_TEST(a_lifetime_is_at_most_a_day);
    RUN_TEST(a_negative_answer_lives_by_its_soa_capped_at_a_minute);
    RUN_TEST(a_negative_answer_without_an_soa_is_not_cached);
    RUN_TEST(truncated_ttl_less_and_failed_answers_are_not_cached);
    RUN_TEST(a_name_in_another_case_is_the_same_key);
    RUN_TEST(the_key_records_edns_do_and_cd);
    RUN_TEST(only_a_single_question_has_a_key);
    RUN_TEST(a_hit_carries_the_askers_id_rd_and_case);
    RUN_TEST(a_hit_has_its_ttls_lowered_by_the_age);
    RUN_TEST(an_entry_lapses_at_its_lifetime);
    RUN_TEST(every_field_of_the_key_separates_entries);
    RUN_TEST(a_put_replaces_its_keys_entry);
    RUN_TEST(the_count_bound_evicts_the_least_recently_used);
    RUN_TEST(the_byte_bound_evicts_the_least_recently_used);
    RUN_TEST(the_accounted_bytes_grow_by_a_records_wire_and_offset);
    RUN_TEST(bytes_after_the_last_record_are_not_cached);
    RUN_TEST(a_ttl_above_2_31_minus_1_is_not_cached);
    RUN_TEST(an_answer_over_4096_bytes_is_not_cached);
    RUN_TEST(an_answer_to_another_question_is_not_stored);
    RUN_TEST(an_answer_of_another_type_or_class_is_not_stored);
    RUN_TEST(the_options_of_an_answers_opt_are_not_kept);
    RUN_TEST(dropping_a_group_drops_only_its_entries);
    RUN_TEST(a_refresh_is_asked_once_in_the_last_tenth);
    RUN_TEST(a_null_cache_is_inert);
    GREATEST_MAIN_END();
}
