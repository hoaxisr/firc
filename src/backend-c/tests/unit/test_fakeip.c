#include "greatest.h"

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include "firc/fakeip.h"

/* Formats into the caller's buffer, so two formatted values never share one static buffer. */
static const char *s4(const firc_ip_t *a, char buf[16]) {
    snprintf(buf, 16, "%u.%u.%u.%u", a->b[0], a->b[1], a->b[2], a->b[3]);
    return buf;
}

static const char *s6(const firc_ip_t *a, char buf[40]) {
    snprintf(buf, 40, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             a->b[0], a->b[1], a->b[2], a->b[3], a->b[4], a->b[5], a->b[6], a->b[7], a->b[8],
             a->b[9], a->b[10], a->b[11], a->b[12], a->b[13], a->b[14], a->b[15]);
    return buf;
}

static bool names(const firc_fakeip_t *f, const firc_ip_t *addr, const char *want) {
    const char *n = firc_fakeip_name_of(f, addr);
    return n != NULL && strcmp(n, want) == 0;
}

#define T0 INT64_C(1700000000)
#define DAY INT64_C(86400)
#define CLAMP INT64_C(300)
#define QUAR INT64_C(3600)
#define MANY 4096

/* 198.18.0.0/15 in /24 chunks and fd37:9a5c:be10::/48 in /64 chunks, the last of each reserved. */
static firc_fakeip_cfg_t base_cfg(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.base.b[2] = 0x9a;
    c.v6.base.b[3] = 0x5c;
    c.v6.base.b[4] = 0xbe;
    c.v6.base.b[5] = 0x10;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = MANY;
    c.idle_secs = DAY;
    c.clamp_secs = CLAMP;
    return c;
}

/* Catches: chunks not starting at the pool base, a missing skip rule, or allocation from the wrong end. */
TEST first_issued_addresses_are_the_first_usable_of_the_first_chunks(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    firc_ip_t v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0001", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: fresh addresses on every call instead of the name's existing mapping, in either family. */
TEST the_same_name_keeps_its_addresses_across_calls(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t a4 = {{0}, 0}, a6 = {{0}, 0}, b4 = {{0}, 0}, b6 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "example.com", "g1", T0, &a4, &a6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "example.com", "g1", T0, &b4, &b6));
    ASSERT_MEM_EQ(&a4, &b4, sizeof(a4));
    ASSERT_MEM_EQ(&a6, &b6, sizeof(a6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: not advancing within a chunk, or keying the mapping on the group instead of the name. */
TEST distinct_names_in_one_group_get_consecutive_addresses(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0001", s6(&v6, b6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.2", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0002", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: groups sharing a chunk, or the chunk cursor advancing by other than one chunk. */
TEST each_group_draws_from_its_own_chunk(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0001", s6(&v6, b6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.1.1", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0001:0000:0000:0000:0001", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a family allocated lazily on first request, so v4 and v6 can come from different groups. */
TEST both_families_are_issued_together_even_when_one_is_asked_for(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    for (int i = 0; i < 5; i++) {
        char n[64];
        snprintf(n, sizeof(n), "noise%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, n, "g2", T0, NULL, NULL));
    }
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, NULL, &v6));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0001", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a pool geometry that cannot be served accepted, or a check that ignores the family. */
TEST new_rejects_geometry_it_cannot_serve(void) {
    static const struct {
        const char *what;
        uint8_t v4_pool, v4_chunk, v6_pool, v6_chunk;
        uint8_t v4_b1, v4_b3, v6_b7;
    } bad[] = {
        {"v4 chunk bigger than pool", 24, 16, 48, 64, 18, 0, 0},
        {"v4 chunk equal to pool", 24, 24, 48, 64, 18, 0, 0},
        {"v4 pool prefix 0", 0, 24, 48, 64, 18, 0, 0},
        {"v4 chunk of one address", 15, 32, 48, 64, 18, 0, 0},
        {"v4 chunk of two addresses", 15, 31, 48, 64, 18, 0, 0},
        {"v6 chunk bigger than pool", 15, 24, 64, 48, 18, 0, 0},
        {"v6 chunk equal to pool", 15, 24, 64, 64, 18, 0, 0},
        {"v6 pool prefix 0", 15, 24, 0, 64, 18, 0, 0},
        {"v6 chunk of one address", 15, 24, 48, 128, 18, 0, 0},
        {"v6 index wider than 32 bits", 15, 24, 16, 64, 18, 0, 0},
        {"v6 index exactly 32 bits", 15, 24, 32, 64, 18, 0, 0},
        {"v4 host bits above the last octet", 15, 24, 48, 64, 19, 0, 0},
        {"v4 host bits in the last octet", 24, 25, 48, 64, 18, 127, 0},
        {"v6 host bits below the prefix", 15, 24, 48, 64, 18, 0, 1},
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_fakeip_cfg_t c = base_cfg();
        c.v4.pool_cidr = bad[i].v4_pool;
        c.v4.chunk_cidr = bad[i].v4_chunk;
        c.v6.pool_cidr = bad[i].v6_pool;
        c.v6.chunk_cidr = bad[i].v6_chunk;
        c.v4.base.b[1] = bad[i].v4_b1;
        c.v4.base.b[3] = bad[i].v4_b3;
        c.v6.base.b[7] = bad[i].v6_b7;
        if (bad[i].v6_pool == 32) {
            c.v6.base.b[4] = 0;
            c.v6.base.b[5] = 0;
        }
        firc_fakeip_t *f = (firc_fakeip_t *)(uintptr_t)0xDEAD;
        ASSERT_EQ_FMTm(bad[i].what, FIRC_ERR_INVAL, firc_fakeip_new(&c, &f), "%d");
        ASSERT_EQm(bad[i].what, NULL, f);
    }

    firc_fakeip_cfg_t c = base_cfg();
    c.v6.base.len = 4;
    firc_fakeip_t *f = (firc_fakeip_t *)(uintptr_t)0xDEAD;
    ASSERT_EQ_FMTm("v6 base with a v4 length", FIRC_ERR_INVAL, firc_fakeip_new(&c, &f), "%d");
    ASSERT_EQm("v6 base with a v4 length", NULL, f);

    c = base_cfg();
    c.v4.base.len = 16;
    f = (firc_fakeip_t *)(uintptr_t)0xDEAD;
    ASSERT_EQ_FMTm("v4 base with a v6 length", FIRC_ERR_INVAL, firc_fakeip_new(&c, &f), "%d");
    ASSERT_EQm("v4 base with a v6 length", NULL, f);
    PASS();
}

/* Catches: an idle window or clamp of zero or less stored unchecked. */
TEST new_rejects_windows_that_would_disable_the_protections(void) {
    static const struct {
        const char *what;
        int64_t idle, clamp;
    } bad[] = {
        {"idle zero", 0, CLAMP},   {"idle negative", -1, CLAMP},
        {"clamp zero", DAY, 0},    {"clamp negative", DAY, -1},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_fakeip_cfg_t c = base_cfg();
        c.idle_secs = bad[i].idle;
        c.clamp_secs = bad[i].clamp;
        firc_fakeip_t *f = (firc_fakeip_t *)(uintptr_t)0xDEAD;
        ASSERT_EQ_FMTm(bad[i].what, FIRC_ERR_INVAL, firc_fakeip_new(&c, &f), "%d");
        ASSERT_EQm(bad[i].what, NULL, f);
    }
    PASS();
}

/* Catches: NULL arguments dereferenced before they are checked. */
TEST null_arguments_are_refused_rather_than_dereferenced(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4, v6;
    memset(&v4, 0xA5, sizeof v4);
    memset(&v6, 0x5A, sizeof v6);
    firc_ip_t v4_before = v4, v6_before = v6;

    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_get(f, NULL, "g1", T0, &v4, &v6));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_get(f, "a.example.com", NULL, T0, &v4, &v6));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_get(NULL, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_MEM_EQm("an argument refusal writes nothing", &v4_before, &v4, sizeof v4);
    ASSERT_MEM_EQm("an argument refusal writes nothing", &v6_before, &v6, sizeof v6);
    firc_fakeip_t *spare = (firc_fakeip_t *)(uintptr_t)0xDEAD;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_new(NULL, &spare));
    ASSERT_EQ(NULL, spare);
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_new(&c, NULL));

    firc_fakeip_reclaim(NULL, T0);
    firc_fakeip_drop_group(NULL, "g1", T0);
    firc_fakeip_drop_group(f, NULL, T0);
    firc_fakeip_free(NULL);

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a name hashed or compared without folding case. */
TEST names_differing_only_in_case_are_one_name(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t l4 = {{0}, 0}, l6 = {{0}, 0}, m4 = {{0}, 0}, m6 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "example.com", "g1", T0, &l4, &l6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "ExAmPlE.CoM", "g1", T0, &m4, &m6));
    ASSERT_MEM_EQ(&l4, &m4, sizeof(l4));
    ASSERT_MEM_EQ(&l6, &m6, sizeof(l6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a bucket walk returning the first entry without comparing names (this pair collides). */
TEST names_that_share_a_hash_bucket_get_their_own_addresses(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "h209.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "h300.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.2", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0002", s6(&v6, b6));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "h209.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQm("the first name in the bucket is still there", "198.18.0.1",
                   s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the move branch kept, so one group's ask takes the name's only mapping away from the other. */
TEST one_name_holds_one_mapping_per_group(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4 = {{0}, 0}, a6 = {{0}, 0}, b4 = {{0}, 0}, b6 = {{0}, 0};
    char s[16], t[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a4, &a6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0, &b4, &b6));
    ASSERT_STR_EQ("198.18.0.1", s4(&a4, s));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0001", s6(&a6, t));
    ASSERT_STR_EQm("the second group's chunk", "198.18.1.1", s4(&b4, s));
    ASSERT_STR_EQ("fd37:9a5c:be10:0001:0000:0000:0000:0001", s6(&b6, t));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a4, NULL));
    ASSERT_STR_EQm("asked again by the first group, its own address", "198.18.0.1", s4(&a4, s));
    ASSERTm("the first group's mapping is live", names(f, &a4, "a.example.com"));
    ASSERTm("and so is the second's", names(f, &b4, "a.example.com"));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: a known name's mapping in a second group served without counting against max_names. */
TEST a_name_in_a_second_group_costs_a_second_mapping(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.max_names = 1;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4 = {{0}, 0};
    char s[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "a.example.com", "g2", T0, &v4, NULL));
    ASSERT_STR_EQm("the blackhole, never the first group's address", "198.19.255.1", s4(&v4, s));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: one group's ask keeping the name's other mapping alive, or the sweep taking both. */
TEST an_idle_mapping_is_reclaimed_while_the_other_groups_stays(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4 = {{0}, 0}, b4 = {{0}, 0}, again = {{0}, 0};
    char s[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0, &b4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0 + DAY - 10, &b4, NULL));
    firc_fakeip_reclaim(f, T0 + DAY);
    ASSERT_EQm("g1's mapping, idle a day, is released", NULL, firc_fakeip_name_of(f, &a4));
    ASSERTm("g2's, asked since, stays", names(f, &b4, "a.example.com"));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0 + DAY + 1, &again, NULL));
    ASSERT_STR_EQm("asked again in g1, it gets its parked address back", "198.18.0.1", s4(&again, s));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: a parked address of one group handed to the same name's mapping in another group. */
TEST a_name_parked_in_one_group_gets_nothing_of_it_in_another(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4 = {{0}, 0}, b4 = {{0}, 0};
    char s[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a4, NULL));
    firc_fakeip_reclaim(f, T0 + DAY);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0 + DAY + 1, &b4, NULL));
    ASSERT_STR_EQm("g2's own chunk, not g1's parked address", "198.18.1.1", s4(&b4, s));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: set_reals or needs_commit finding the name's mapping in the wrong group. */
TEST each_groups_mapping_of_one_name_keeps_its_own_real_and_commit(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4 = {{0}, 0}, b4 = {{0}, 0}, got = {{0}, 0};
    const firc_ip_t x = {{93, 184, 216, 34}, 4};
    const firc_ip_t y = {{1, 2, 3, 4}, 4};
    const firc_ip_t never = {{198, 18, 20, 186}, 4};
    const char *gid = NULL;
    char s[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0, &b4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", &x, 1));
    ASSERTm("g1's pair waits", firc_fakeip_needs_commit(f, &a4));
    ASSERT_FALSEm("g2's pair has no real yet", firc_fakeip_needs_commit(f, &b4));
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(snap));
    firc_fakeip_snapshot_free(snap);
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g2", &y, 1));
    ASSERTm("g2's new pair waits", firc_fakeip_needs_commit(f, &b4));
    ASSERT_FALSEm("g1's committed pair does not", firc_fakeip_needs_commit(f, &a4));
    ASSERT(firc_fakeip_pair_of(f, &a4, &gid, &got));
    ASSERT_STR_EQ("g1", gid);
    ASSERT_STR_EQ("93.184.216.34", s4(&got, s));
    ASSERT(firc_fakeip_pair_of(f, &b4, &gid, &got));
    ASSERT_STR_EQ("g2", gid);
    ASSERT_STR_EQ("1.2.3.4", s4(&got, s));
    ASSERT_EQ(FIRC_ERR_NOENT, firc_fakeip_set_reals(f, "a.example.com", "g3", &x, 1));
    ASSERT_FALSEm("an address the pool never issued waits for nothing", firc_fakeip_needs_commit(f, &never));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: a parked address handed to a different name before its window is out. */
TEST a_parked_address_is_not_offered_to_a_different_name(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0, &v4, &v6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0 + 1, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.2", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0002", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the quarantine window taken from idle_secs instead of the clamp, or off by one second. */
TEST the_quarantine_window_is_derived_from_the_clamp(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));

    firc_fakeip_reclaim(f, T0 + DAY);

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0 + DAY + QUAR - 1, &v4, &v6));
    ASSERT_STR_EQm("one second early the address is still parked", "198.18.0.2", s4(&v4, b4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g1", T0 + DAY + QUAR, &v4, &v6));
    ASSERT_STR_EQm("at the instant it expires it comes back", "198.18.0.1", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0001", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the window losing its 12x clamp multiplier or its one-hour floor. */
TEST the_quarantine_window_takes_the_larger_of_the_multiple_and_the_floor(void) {
    static const struct {
        const char *what;
        int64_t clamp, window;
    } rows[] = {
        {"the multiple wins", 600, 7200},
        {"the floor wins", 60, 3600},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        firc_fakeip_cfg_t c = base_cfg();
        c.clamp_secs = rows[i].clamp;
        firc_fakeip_t *f = NULL;
        ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

        firc_ip_t v4 = {{0}, 0};
        char b4[16];
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
        firc_fakeip_reclaim(f, T0 + DAY);
        ASSERT_EQ(FIRC_OK,
                  firc_fakeip_get(f, "b.example.com", "g1", T0 + DAY + rows[i].window - 1, &v4,
                                  NULL));
        ASSERT_STR_EQm(rows[i].what, "198.18.0.2", s4(&v4, b4));
        ASSERT_EQ(FIRC_OK,
                  firc_fakeip_get(f, "c.example.com", "g1", T0 + DAY + rows[i].window, &v4, NULL));
        ASSERT_STR_EQm(rows[i].what, "198.18.0.1", s4(&v4, b4));
        firc_fakeip_free(f);
    }
    PASS();
}

/* Catches: a name returning after a sweep handed fresh addresses instead of its own. */
TEST a_name_that_returns_after_a_sweep_gets_its_own_addresses_back(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    firc_fakeip_reclaim(f, T0 + DAY + 1);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0 + DAY + 1, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0001", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the sweep using the quarantine window or a fixed length instead of idle_secs. */
TEST the_sweep_runs_on_the_configured_idle_window(void) {
    static const int64_t IDLE = 5000;

    {
        firc_fakeip_cfg_t c = base_cfg();
        c.idle_secs = IDLE;
        c.max_names = 1;
        firc_fakeip_t *f = NULL;
        ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

        firc_ip_t v4 = {{0}, 0};
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
        firc_fakeip_reclaim(f, T0 + IDLE - 1);
        ASSERT_EQ(FIRC_ERR_LIMIT,
                  firc_fakeip_get(f, "b.example.com", "g1", T0 + IDLE - 1, &v4, NULL));
        firc_fakeip_free(f);
    }

    {
        firc_fakeip_cfg_t c = base_cfg();
        c.idle_secs = IDLE;
        c.max_names = 1;
        firc_fakeip_t *f = NULL;
        ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

        firc_ip_t v4 = {{0}, 0};
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
        firc_fakeip_reclaim(f, T0 + IDLE + 1);
        ASSERT_EQ(FIRC_OK,
                  firc_fakeip_get(f, "b.example.com", "g1", T0 + IDLE + 1, &v4, NULL));
        firc_fakeip_free(f);
    }
    PASS();
}

/* Catches: a group's later chunk left on the free list, so another group is handed it too. */
TEST a_groups_second_chunk_is_not_handed_to_another_group(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v4.pool_cidr = 22;
    c.v4.chunk_cidr = 26;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    char name[64];
    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    for (int i = 0; i < 63; i++) {
        snprintf(name, sizeof(name), "f%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", T0, &v4, NULL));
    }
    ASSERT_STR_EQ("198.18.0.63", s4(&v4, b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "f63.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQm("the chunk base is a usable address", "198.18.0.64", s4(&v4, b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "other.example.com", "g2", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.0.128", s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: allocation past the end of a pool instead of the blackhole addresses and an error. */
TEST a_group_with_no_chunk_left_gets_the_blackhole_addresses(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v4.pool_cidr = 22;
    c.v6.pool_cidr = 62;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", T0, &v4, &v6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g3", T0, &v4, &v6));

    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "d.example.com", "g4", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.3.1", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0003:0000:0000:0000:0001", s6(&v6, b6));

    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "e.example.com", "g5", T0, &v4, &v6));
    ASSERT_STR_EQm("the blackhole is one shared address, not a chunk", "198.18.3.1",
                   s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0003:0000:0000:0000:0001", s6(&v6, b6));

    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "d2.example.com", "g4", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.3.1", s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a refusal path that leaves the output addresses unwritten. */
TEST every_refusal_writes_both_blackhole_addresses(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.max_names = 1;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));

    firc_ip_t r4, r6;
    memset(&r4, 0x5a, sizeof(r4));
    memset(&r6, 0x5a, sizeof(r6));
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "b.example.com", "g1", T0, &r4, &r6));
    ASSERT_STR_EQ("198.19.255.1", s4(&r4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:ffff:0000:0000:0000:0001", s6(&r6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a table with no cap, known names refused at the cap, or reclaim not freeing capacity. */
TEST at_capacity_new_names_are_refused_but_known_ones_still_work(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.max_names = 2;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0, &v4, NULL));
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "c.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQ("198.19.255.1", s4(&v4, b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQm("a known name is unaffected by the cap", "198.18.0.1", s4(&v4, b4));

    firc_fakeip_reclaim(f, T0 + DAY + 1);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g1", T0 + DAY + 1, &v4, NULL));
    ASSERT_STR_EQm("reclaim returns capacity, not just addresses", "198.18.0.3", s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a mapping recording the head of the group list instead of the group that issued it. */
TEST a_mapping_records_the_group_that_issued_it(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "seed1.example.com", "g1", T0, &v4, &v6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "seed2.example.com", "g2", T0, &v4, &v6));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.2", s4(&v4, b4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQm("second query returns the same", "198.18.0.2", s4(&v4, b4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQm("and the third", "198.18.0.2", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0002", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a vacated address parked against the head of the group list instead of its owner. */
TEST a_vacated_address_returns_to_the_group_whose_chunk_it_came_from(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "seed.example.com", "g2", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.1.1", s4(&v4, b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "seed.example.com", "g2", T0 + DAY - 1, &v4, &v6));
    firc_fakeip_reclaim(f, T0 + DAY);

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g1", T0 + DAY + QUAR, &v4, &v6));
    ASSERT_STR_EQm("the vacated v4 address came back to g1", "198.18.0.1", s4(&v4, b4));
    ASSERT_STR_EQm("and the v6 one", "fd37:9a5c:be10:0000:0000:0000:0000:0001", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a deleted group's chunk reused before its quarantine ends, or never returned. */
TEST a_deleted_groups_chunk_comes_back_only_after_its_quarantine(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16], b6[40];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));

    firc_fakeip_drop_group(f, "g1", T0);

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", T0 + 1, &v4, &v6));
    ASSERT_STR_EQ("198.18.1.1", s4(&v4, b4));
    ASSERT_STR_EQ("fd37:9a5c:be10:0001:0000:0000:0000:0001", s6(&v6, b6));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g3", T0 + QUAR, &v4, &v6));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_STR_EQm("the v6 chunk came back too", "fd37:9a5c:be10:0000:0000:0000:0000:0001",
                   s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a deleted group returning only the chunk it was filling. */
TEST deleting_a_group_returns_every_chunk_it_held(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v4.pool_cidr = 22;
    c.v4.chunk_cidr = 26;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    char name[64];
    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    for (int i = 0; i < 64; i++) {
        snprintf(name, sizeof(name), "o%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", T0, &v4, NULL));
    }
    ASSERT_STR_EQm("the 64th name is in the group's second chunk", "198.18.0.64", s4(&v4, b4));

    firc_fakeip_drop_group(f, "g1", T0);

    for (int i = 0; i < 63; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g2", T0 + QUAR, &v4, NULL));
        if (i == 0) { ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4)); }
    }
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "last.example.com", "g2", T0 + QUAR, &v4, NULL));
    ASSERT_STR_EQm("the group's other chunk came back too", "198.18.0.64", s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a deleted group's mappings kept, still counting toward the cap. */
TEST deleting_a_group_returns_the_capacity_its_names_held(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.max_names = 1;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "b.example.com", "g2", T0, &v4, NULL));

    firc_fakeip_drop_group(f, "g1", T0);

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", T0, &v4, NULL));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the v4 last-octet skip rule applied to v6 addresses. */
TEST v6_skips_only_the_anycast_address_not_the_v4_reserved_octets(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v6.pool_cidr = 112;
    c.v6.chunk_cidr = 120;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    char name[64];
    firc_ip_t v6 = {{0}, 0};
    char b6[40];
    for (int i = 0; i < 255; i++) {
        snprintf(name, sizeof(name), "v%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", T0, NULL, &v6));
    }
    ASSERT_STR_EQm("an address ending in ff is perfectly good in v6",
                   "fd37:9a5c:be10:0000:0000:0000:0000:00ff", s6(&v6, b6));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a name kept with a v4 address when its v6 half was refused. */
TEST a_refused_issue_hands_back_the_half_that_succeeded(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v6.pool_cidr = 62;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    char b4[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", T0, &v4, &v6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g3", T0, &v4, &v6));

    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "x.example.com", "g4", T0, &v4, &v6));
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "x.example.com", "g4", T0, &v4, &v6));

    firc_fakeip_drop_group(f, "g1", T0);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "x.example.com", "g4", T0 + QUAR, &v4, &v6));
    ASSERT_STR_EQm("the v4 address the failed attempts handed back", "198.18.3.1",
                   s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

typedef struct {
    size_t n;
    char qname[8][64];
    char group[8][16];
    char fake[8][40];
    char real[8][40];
    bool has_real[8];
} walk_log_t;

static void log_entry(void *ud, const char *qname, const char *group_id, const firc_ip_t *fake,
                      const firc_ip_t *real) {
    walk_log_t *w = ud;
    if (w->n >= 8) { return; }
    snprintf(w->qname[w->n], sizeof(w->qname[0]), "%s", qname);
    snprintf(w->group[w->n], sizeof(w->group[0]), "%s", group_id);
    if (fake->len == 4) {
        s4(fake, w->fake[w->n]);
    } else {
        s6(fake, w->fake[w->n]);
    }
    w->has_real[w->n] = (real != NULL);
    if (real != NULL) {
        if (real->len == 4) {
            s4(real, w->real[w->n]);
        } else {
            s6(real, w->real[w->n]);
        }
    }
    w->n++;
}

static int find_fake(const walk_log_t *w, const char *fake) {
    for (size_t i = 0; i < w->n; i++) {
        if (strcmp(w->fake[i], fake) == 0) { return (int)i; }
    }
    return -1;
}

/* Catches: a real address recorded under the wrong family or name, or an unresolved fake skipped. */
TEST the_real_address_a_fake_one_stands_for_is_recorded_per_family(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));

    firc_ip_t real = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "a.example.com", "g1", &real));

    walk_log_t w = {0};
    firc_fakeip_walk(f, log_entry, &w);
    ASSERT_EQ_FMTm("one entry per name per family", (size_t)2, w.n, "%zu");

    int i4 = find_fake(&w, "198.18.0.1");
    ASSERT(i4 >= 0);
    ASSERT_STR_EQ("a.example.com", w.qname[i4]);
    ASSERT_STR_EQ("g1", w.group[i4]);
    ASSERTm("the v4 real address is known", w.has_real[i4]);
    ASSERT_STR_EQ("93.184.216.34", w.real[i4]);

    int i6 = find_fake(&w, "fd37:9a5c:be10:0000:0000:0000:0000:0001");
    ASSERT(i6 >= 0);
    ASSERT_FALSEm("the v6 real address was never set and must not be invented",
                  w.has_real[i6]);

    firc_ip_t real6 = {{0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0, 1, 0x02, 0x48, 0x18, 0x93, 0x25,
                        0xc8, 0x19, 0x46},
                       16};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "a.example.com", "g1", &real6));

    walk_log_t w2 = {0};
    firc_fakeip_walk(f, log_entry, &w2);
    int j6 = find_fake(&w2, "fd37:9a5c:be10:0000:0000:0000:0000:0001");
    ASSERT(j6 >= 0);
    ASSERTm("the v6 real address is now known", w2.has_real[j6]);
    ASSERT_STR_EQ("2606:2800:0220:0001:0248:1893:25c8:1946", w2.real[j6]);

    int j4 = find_fake(&w2, "198.18.0.1");
    ASSERT(j4 >= 0);
    ASSERT_STR_EQm("and the v4 one is untouched", "93.184.216.34", w2.real[j4]);

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a second real address ignored, or kept beside the first. */
TEST setting_the_real_address_again_replaces_it(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));

    firc_ip_t first = {{93, 184, 216, 34}, 4};
    firc_ip_t second = {{1, 2, 3, 4}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "a.example.com", "g1", &first));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "a.example.com", "g1", &second));

    walk_log_t w = {0};
    firc_fakeip_walk(f, log_entry, &w);
    ASSERT_EQ_FMTm("still one entry per family", (size_t)2, w.n, "%zu");
    int i4 = find_fake(&w, "198.18.0.1");
    ASSERT(i4 >= 0);
    ASSERT_STR_EQ("1.2.3.4", w.real[i4]);

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the real address replaced on every rotation, or never, instead of when it leaves the answer. */
TEST a_real_address_still_in_the_answer_is_kept_and_a_vanished_one_replaced(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));

    const firc_ip_t a = {{93, 184, 216, 34}, 4};
    const firc_ip_t b = {{1, 2, 3, 4}, 4};
    const firc_ip_t cc = {{5, 6, 7, 8}, 4};
    const firc_ip_t x6 = {{0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16};
    const firc_ip_t y6 = {{0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, 16};

    firc_ip_t first[] = {a, x6};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", first, 2));

    firc_ip_t rotated[] = {b, a};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", rotated, 2));
    walk_log_t w = {0};
    firc_fakeip_walk(f, log_entry, &w);
    int i4 = find_fake(&w, "198.18.0.1");
    ASSERT(i4 >= 0);
    ASSERT_STR_EQm("still present, so kept", "93.184.216.34", w.real[i4]);

    firc_ip_t gone[] = {cc, b};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", gone, 2));
    walk_log_t w2 = {0};
    firc_fakeip_walk(f, log_entry, &w2);
    i4 = find_fake(&w2, "198.18.0.1");
    ASSERT(i4 >= 0);
    ASSERT_STR_EQm("vanished, so replaced by the first offered", "5.6.7.8", w2.real[i4]);
    int i6 = find_fake(&w2, "fd37:9a5c:be10:0000:0000:0000:0000:0001");
    ASSERT(i6 >= 0);
    ASSERT_STR_EQm("a v4-only answer leaves the v6 address alone",
                   "2606:0000:0000:0000:0000:0000:0000:0001", w2.real[i6]);

    firc_ip_t only6[] = {y6};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", only6, 1));
    walk_log_t w3 = {0};
    firc_fakeip_walk(f, log_entry, &w3);
    i6 = find_fake(&w3, "fd37:9a5c:be10:0000:0000:0000:0000:0001");
    ASSERT_STR_EQ("2606:0000:0000:0000:0000:0000:0000:0002", w3.real[i6]);
    i4 = find_fake(&w3, "198.18.0.1");
    ASSERT_STR_EQ("5.6.7.8", w3.real[i4]);

    firc_fakeip_free(f);
    PASS();
}

/* Catches: pairs committed regardless of when they changed, never committed, or a rotation that waits. */
TEST a_pair_needs_a_commit_until_a_snapshot_taken_after_it_completes(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    const firc_ip_t nobody = {{198, 18, 0, 99}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_FALSEm("no real address yet: nothing to write, nothing to wait for",
                  firc_fakeip_needs_commit(f, &v4));

    const firc_ip_t a = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", &a, 1));
    ASSERT(firc_fakeip_needs_commit(f, &v4));
    ASSERT_FALSEm("the v6 half has no real address (a v4-only name)",
                  firc_fakeip_needs_commit(f, &v6));

    firc_fakeip_snapshot_t *s1 = firc_fakeip_snapshot_take(f);
    ASSERT(s1 != NULL);
    ASSERTm("taken, not yet written", firc_fakeip_needs_commit(f, &v4));

    const firc_ip_t b = {{1, 2, 3, 4}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", &b, 1));
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s1));
    ASSERTm("the pass that completed carried the OLD pair", 
            firc_fakeip_needs_commit(f, &v4));

    firc_fakeip_snapshot_t *s2 = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s2));
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &v4));

    firc_ip_t rotated[] = {a, b};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", rotated, 2));
    ASSERT_FALSEm("the stored address is still in the answer; no new pair",
                  firc_fakeip_needs_commit(f, &v4));

    ASSERT_FALSEm("an address no name holds has no pair", firc_fakeip_needs_commit(f, &nobody));

    firc_fakeip_snapshot_free(s1);
    firc_fakeip_snapshot_free(s2);
    firc_fakeip_free(f);
    PASS();
}

typedef struct {
    char groups[32][32];
    char fakes[32][48];
    bool had_real[32];
    bool empty[32];
    unsigned fams[32];
    size_t n;
} snapseen_t;

static void snap_record(void *ud, const char *group_id, unsigned family, const firc_ip_t *fake,
                        const firc_ip_t *real) {
    snapseen_t *v = ud;
    if (v->n >= 32) { return; }
    snprintf(v->groups[v->n], sizeof(v->groups[0]), "%s", group_id);
    if (family == FIRC_FAM_V4) {
        char b[16];
        snprintf(v->fakes[v->n], sizeof(v->fakes[0]), "%s", s4(fake, b));
    } else {
        char b[40];
        snprintf(v->fakes[v->n], sizeof(v->fakes[0]), "%s", s6(fake, b));
    }
    v->fams[v->n] = family;
    v->had_real[v->n] = (real != NULL);
    v->empty[v->n] = (fake->len == 0);
    v->n++;
}

/* Catches: a global dirty flag instead of per pair, a commit mark that moves back, a bad bump, or one group's pair of a name read as another's. */
TEST the_generation_is_per_pair_and_the_mark_is_monotonic(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4 = {{0}, 0}, b4 = {{0}, 0}, other = {{0}, 0};
    const firc_ip_t x = {{93, 184, 216, 34}, 4};
    const firc_ip_t y = {{1, 2, 3, 4}, 4};

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "a.example.com", "g1", &x));
    ASSERTm("set_real bumps on a first address", firc_fakeip_needs_commit(f, &a4));
    firc_fakeip_snapshot_t *s1 = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s1));
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &a4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "a.example.com", "g1", &x));
    ASSERT_FALSEm("the same address again is not a change", firc_fakeip_needs_commit(f, &a4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "a.example.com", "g1", &y));
    ASSERTm("a different one is", firc_fakeip_needs_commit(f, &a4));
    firc_fakeip_snapshot_t *s1b = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s1b));
    firc_fakeip_snapshot_free(s1b);

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0, &b4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "b.example.com", "g1", &y, 1));
    ASSERT(firc_fakeip_needs_commit(f, &b4));
    ASSERT_FALSEm("an unrelated name's change is not this name's", firc_fakeip_needs_commit(f, &a4));

    firc_fakeip_snapshot_t *s2 = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s2));
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s1));
    ASSERT_FALSEm("the mark never moves backwards", firc_fakeip_needs_commit(f, &b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0, &other, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g2", &x, 1));
    ASSERTm("the name's pair in another group is its own pair, even with the same real address",
            firc_fakeip_needs_commit(f, &other));
    ASSERT_FALSEm("and the first group's pair stays committed", firc_fakeip_needs_commit(f, &a4));

    firc_ip_t bad = {{1, 2, 3, 4, 5}, 5};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_set_reals(f, "a.example.com", "g2", &bad, 1));
    ASSERT_EQ(FIRC_ERR_NOENT, firc_fakeip_set_reals(f, "nobody.example.com", "g1", &x, 1));

    firc_fakeip_snapshot_free(s1);
    firc_fakeip_snapshot_free(s2);
    firc_fakeip_free(f);
    PASS();
}

/* Catches: a reclaimed pair dropped from the snapshot while the name's other group still holds a mapping. */
TEST a_reclaimed_pair_stays_in_the_snapshot_beside_the_other_groups_mapping(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4 = {{0}, 0};
    const firc_ip_t x = {{93, 184, 216, 34}, 4};
    const firc_ip_t x6 = {{0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16};
    firc_ip_t both[] = {x, x6};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", both, 2));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0 + DAY - 1, &v4, NULL));
    firc_fakeip_reclaim(f, T0 + DAY);

    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    ASSERT(s != NULL);
    snapseen_t seen = {{{0}}, {{0}}, {false}, {false}, {0}, 0};
    firc_fakeip_snapshot_walk(s, snap_record, &seen);
    int old_i = -1, new_i = -1, old6_i = -1;
    for (size_t i = 0; i < seen.n; i++) {
        if (strcmp(seen.fakes[i], "198.18.0.1") == 0) { old_i = (int)i; }
        if (strcmp(seen.fakes[i], "198.18.1.1") == 0) { new_i = (int)i; }
        if (strcmp(seen.fakes[i], "fd37:9a5c:be10:0000:0000:0000:0000:0001") == 0) { old6_i = (int)i; }
    }
    ASSERTm("the parked pair is in the snapshot", old_i >= 0);
    ASSERT_STR_EQm("under the group whose chunk it belongs to", "g1", seen.groups[old_i]);
    ASSERTm("with its real address, or there is no rule to write", seen.had_real[old_i]);
    ASSERTm("the v6 half of the parked pair as well", old6_i >= 0);
    ASSERT_EQ_FMTm("in its own family's slot, or the DNAT builder drops it", (unsigned)FIRC_FAM_V6,
                   seen.fams[old6_i], "%u");
    ASSERT(seen.had_real[old6_i]);
    ASSERTm("the new mapping is there too", new_i >= 0);
    ASSERT_STR_EQ("g2", seen.groups[new_i]);
    ASSERT_FALSEm("nothing resolved for it yet", seen.had_real[new_i]);
    for (size_t i = 0; i < seen.n; i++) {
        ASSERT_FALSEm("a parked pair has one family; its other slot is not reported", seen.empty[i]);
    }
    firc_fakeip_snapshot_free(s);

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g1", T0 + DAY + QUAR, &v4, NULL));
    firc_fakeip_snapshot_t *s2 = firc_fakeip_snapshot_take(f);
    snapseen_t seen2 = {{{0}}, {{0}}, {false}, {false}, {0}, 0};
    firc_fakeip_snapshot_walk(s2, snap_record, &seen2);
    int n_old = 0, old_again = -1;
    for (size_t i = 0; i < seen2.n; i++) {
        if (strcmp(seen2.fakes[i], "198.18.0.1") == 0) { n_old++; old_again = (int)i; }
    }
    ASSERT_EQ_FMTm("once, as c.example.com's, not twice", 1, n_old, "%d");
    ASSERT_FALSEm("and without the parked real address: c.example.com has resolved nothing",
                  seen2.had_real[old_again]);
    firc_fakeip_snapshot_free(s2);
    firc_fakeip_free(f);
    PASS();
}

/* Catches: a parked address past its window kept in the snapshot, or the sweep not moving the generation. */
TEST an_expired_parked_address_leaves_at_the_sweep(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4 = {{0}, 0};
    const firc_ip_t x = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", &x, 1));
    firc_fakeip_reclaim(f, T0 + DAY);

    uint64_t gen = firc_fakeip_gen(f);
    firc_fakeip_reclaim(f, T0 + DAY + 1);
    ASSERT_EQ_FMTm("inside the window nothing leaves", (unsigned long long)gen,
                   (unsigned long long)firc_fakeip_gen(f), "%llu");
    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    snapseen_t seen = {{{0}}, {{0}}, {false}, {false}, {0}, 0};
    firc_fakeip_snapshot_walk(s, snap_record, &seen);
    firc_fakeip_snapshot_free(s);
    bool parked_present = false;
    for (size_t i = 0; i < seen.n; i++) { parked_present |= strcmp(seen.fakes[i], "198.18.0.1") == 0; }
    ASSERT(parked_present);

    firc_fakeip_reclaim(f, T0 + DAY + QUAR);
    ASSERTm("a rule went: the generation moved", firc_fakeip_gen(f) > gen);
    firc_fakeip_snapshot_t *s2 = firc_fakeip_snapshot_take(f);
    snapseen_t seen2 = {{{0}}, {{0}}, {false}, {false}, {0}, 0};
    firc_fakeip_snapshot_walk(s2, snap_record, &seen2);
    firc_fakeip_snapshot_free(s2);
    for (size_t i = 0; i < seen2.n; i++) {
        ASSERT_FALSEm("the expired parked pair is gone from the snapshot",
                      strcmp(seen2.fakes[i], "198.18.0.1") == 0);
    }
    firc_fakeip_free(f);
    PASS();
}

/* Catches: an address freed by the sweep never issued again, leaking one per name. */
TEST an_address_whose_window_ran_out_under_the_sweep_is_issued_again(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t first = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &first, NULL));
    firc_fakeip_reclaim(f, T0 + DAY);
    firc_fakeip_reclaim(f, T0 + DAY + QUAR);
    firc_ip_t fresh = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0 + DAY + QUAR + 1, &fresh, NULL));
    ASSERT_MEM_EQm("the freed address is the next one g1 issues", first.b, fresh.b, 4);
    firc_fakeip_free(f);
    PASS();
}

/* Catches: a freed address's bit not cleared when taken, so two names get one address. */
TEST two_freed_addresses_of_one_chunk_are_both_issued_again(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a = {{0}, 0}, b = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0, &b, NULL));
    firc_fakeip_reclaim(f, T0 + DAY);
    firc_fakeip_reclaim(f, T0 + DAY + QUAR);
    firc_ip_t p = {{0}, 0}, q = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "p.example.com", "g1", T0 + DAY + QUAR + 1, &p, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "q.example.com", "g1", T0 + DAY + QUAR + 1, &q, NULL));
    ASSERTm("two different addresses", memcmp(p.b, q.b, 4) != 0);
    ASSERTm("both from the freed pair", (memcmp(p.b, a.b, 4) == 0 || memcmp(p.b, b.b, 4) == 0) &&
                                        (memcmp(q.b, a.b, 4) == 0 || memcmp(q.b, b.b, 4) == 0));
    firc_fakeip_free(f);
    PASS();
}

static void count_v4_chunks(void *ud, const char *group_id, unsigned family, const firc_ip_t *base,
                            uint8_t prefix) {
    (void)group_id; (void)base; (void)prefix;
    if (family == FIRC_FAM_V4) { (*(size_t *)ud)++; }
}

/* Catches: a chunk returned to the pool while it still holds a name or a parked address. */
TEST a_chunk_with_names_or_parked_addresses_is_not_given_back(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    char name[32];
    firc_ip_t a = {{0}, 0};
    for (int i = 0; i < 300; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", T0, &a, NULL));
    }
    size_t chunks = 0;
    firc_fakeip_walk_chunks(f, "g1", count_v4_chunks, &chunks);
    ASSERT_EQ_FMT((size_t)2, chunks, "%zu");
    firc_fakeip_reclaim(f, T0 + 10);
    chunks = 0;
    firc_fakeip_walk_chunks(f, "g1", count_v4_chunks, &chunks);
    ASSERT_EQ_FMTm("chunks with names stay", (size_t)2, chunks, "%zu");
    for (int i = 254; i < 300; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", T0 + DAY - 10, &a, NULL));
    }
    firc_fakeip_reclaim(f, T0 + DAY);
    chunks = 0;
    firc_fakeip_walk_chunks(f, "g1", count_v4_chunks, &chunks);
    ASSERT_EQ_FMTm("a chunk of parked addresses inside the window stays", (size_t)2, chunks, "%zu");
    firc_ip_t other = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "x.example.com", "g3", T0 + DAY + 10, &other, NULL));
    ASSERTm("and nobody else lands in it", other.b[2] != 0 && other.b[2] != 1);
    firc_fakeip_reclaim(f, T0 + DAY + QUAR);
    chunks = 0;
    firc_fakeip_walk_chunks(f, "g1", count_v4_chunks, &chunks);
    ASSERT_EQ_FMTm("the emptied first chunk went back", (size_t)1, chunks, "%zu");
    firc_ip_t still = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "n299.example.com", "g1", T0 + DAY + QUAR + 1, &still, NULL));
    ASSERTm("the kept chunk is the one with the names", still.b[2] == 1);
    firc_fakeip_free(f);
    PASS();
}

/* Catches: an overlap missed for a prefix inside or around the pool, or one claimed for a neighbour. */
TEST the_pool_knows_when_a_prefix_overlaps_it(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t inside = {{198, 18, 5, 0}, 4}, around = {{198, 16, 0, 0}, 4}, lan = {{192, 168, 0, 0}, 4};
    firc_ip_t edge = {{198, 20, 0, 0}, 4};
    ASSERT(firc_fakeip_overlaps(f, &inside, 24));
    ASSERTm("a prefix that contains the pool overlaps it", firc_fakeip_overlaps(f, &around, 14));
    ASSERT_FALSE(firc_fakeip_overlaps(f, &lan, 24));
    ASSERT_FALSEm("the next /15 up does not", firc_fakeip_overlaps(f, &edge, 15));
    firc_ip_t in6 = {{0xfd, 0x37, 0x9a, 0x5c, 0xbe, 0x10, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, 16};
    firc_ip_t other6 = {{0xfd, 0x37, 0x9a, 0x5c, 0xbe, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 16};
    ASSERT(firc_fakeip_overlaps(f, &in6, 64));
    ASSERT_FALSE(firc_fakeip_overlaps(f, &other6, 48));
    ASSERT_FALSEm("a bad length is no overlap", firc_fakeip_overlaps(f, &inside, 33));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: a real address recorded for a name with no mapping, or without folding case. */
TEST the_real_address_of_an_unknown_name_is_refused_and_case_is_folded(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t real = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_ERR_NOENT, firc_fakeip_set_real(f, "nobody.example.com", "g1", &real));

    firc_ip_t v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "A.ExAmPlE.CoM", "g1", &real));

    walk_log_t w = {0};
    firc_fakeip_walk(f, log_entry, &w);
    int i4 = find_fake(&w, "198.18.0.1");
    ASSERT(i4 >= 0);
    ASSERTm("the differently-cased name is the same name", w.has_real[i4]);

    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_set_real(f, NULL, "g1", &real));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_set_real(f, "a.example.com", "g1", NULL));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_set_real(NULL, "a.example.com", "g1", &real));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_set_real(f, "a.example.com", NULL, &real));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a reserved address returned without being removed from the parked list. */
TEST taking_a_reserved_address_consumes_the_reservation(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0, &v4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0 + QUAR, &v4, NULL));
    ASSERT_STR_EQm("the address a still holds must not be reissued", "198.18.0.2",
                   s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the sweep parking an address against any group but the mapping's owner. */
TEST the_sweep_parks_an_address_against_its_own_group(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "seed.example.com", "g2", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.1.1", s4(&v4, b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "seed.example.com", "g2", T0 + DAY, &v4, NULL));
    firc_fakeip_reclaim(f, T0 + DAY + 1);

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g2", T0 + DAY + 1 + QUAR, &v4, NULL));
    ASSERT_STR_EQm("g2 must not be handed an address out of g1's chunk", "198.18.1.2",
                   s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the idle clock not stamped when a mapping is created, or not refreshed on a lookup. */
TEST the_idle_clock_is_stamped_on_both_the_store_and_the_lookup(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.max_names = 1;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    firc_fakeip_reclaim(f, T0 + 1);
    ASSERT_EQ_FMTm("a fresh mapping must not be swept", FIRC_ERR_LIMIT,
                   firc_fakeip_get(f, "b.example.com", "g1", T0 + 1, &v4, NULL), "%d");

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0 + DAY, &v4, NULL));
    firc_fakeip_reclaim(f, T0 + DAY + 1);
    ASSERT_EQ_FMTm("a lookup marks the name as in use", FIRC_ERR_LIMIT,
                   firc_fakeip_get(f, "b.example.com", "g1", T0 + DAY + 1, &v4, NULL), "%d");

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a name comparison that stops at the first differing byte and folds only the rest. */
TEST names_that_differ_in_content_are_not_folded_together(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "x0.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "X2130.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQm("a different domain, whatever its case", "198.18.0.2", s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: an offset added to the last byte only, masked to 8 bits, or the .255/.0 skips missed. */
TEST a_chunk_wider_than_an_octet_skips_both_reserved_octets(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v4.pool_cidr = 22;
    c.v4.chunk_cidr = 23;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    char name[64];
    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    for (int i = 0; i < 254; i++) {
        snprintf(name, sizeof(name), "w%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", T0, &v4, NULL));
    }
    ASSERT_STR_EQm("the 254th usable address of the chunk", "198.18.0.254", s4(&v4, b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "w254.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQm("both .255 and the next .0 are skipped", "198.18.1.1", s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a max_names of zero taken literally, so the table is full before the first name. */
TEST a_zero_name_cap_selects_the_default_rather_than_refusing_everything(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.max_names = 0;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the chunk prefix returned instead of the pool's, or a missing family answered as 0.0.0.0/0. */
TEST the_pool_can_name_the_prefixes_its_addresses_come_from(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v4.pool_cidr = 22;
    c.v4.chunk_cidr = 26;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t base = {{0}, 0};
    uint8_t prefix = 0;
    char b4[16], b6[40];

    ASSERT(firc_fakeip_pool_prefix(f, FIRC_FAM_V4, &base, &prefix));
    ASSERT_STR_EQ("198.18.0.0", s4(&base, b4));
    ASSERT_EQ_FMTm("the pool prefix, not the chunk prefix", 22u, (unsigned)prefix, "%u");

    ASSERT(firc_fakeip_pool_prefix(f, FIRC_FAM_V6, &base, &prefix));
    ASSERT_STR_EQ("fd37:9a5c:be10:0000:0000:0000:0000:0000", s6(&base, b6));
    ASSERT_EQ_FMT(48u, (unsigned)prefix, "%u");

    ASSERT_FALSEm("a family the pool does not have", firc_fakeip_pool_prefix(f, 2, &base, &prefix));
    ASSERT_FALSE(firc_fakeip_pool_prefix(NULL, FIRC_FAM_V4, &base, &prefix));
    ASSERT_FALSE(firc_fakeip_pool_prefix(f, FIRC_FAM_V4, NULL, &prefix));
    ASSERT_FALSE(firc_fakeip_pool_prefix(f, FIRC_FAM_V4, &base, NULL));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a parked list kept newest-first, so an expired address waits behind a live one. */
TEST parked_addresses_come_back_oldest_first(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0};
    char b4[16];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.0.1", s4(&v4, b4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0, &v4, NULL));
    ASSERT_STR_EQ("198.18.0.2", s4(&v4, b4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0 + 100, &v4, NULL));
    firc_fakeip_reclaim(f, T0 + DAY);
    firc_fakeip_reclaim(f, T0 + DAY + 100);

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g1", T0 + DAY + QUAR, &v4, NULL));
    ASSERT_STR_EQm("the address whose window ran out first", "198.18.0.1", s4(&v4, b4));

    firc_fakeip_free(f);
    PASS();
}

/* Catches: a deleted group's parked addresses left in the by-name index (use after free). */
TEST deleting_a_group_unlinks_the_addresses_it_parked_by_name(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t a4, a6, b4, b6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "h209.example.com", "g1", T0, &a4, &a6));
    firc_fakeip_reclaim(f, T0 + DAY);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "h209.example.com", "g2", T0 + DAY, &b4, &b6));
    ASSERT(memcmp(&a4, &b4, sizeof a4) != 0);
    ASSERT(memcmp(&a6, &b6, sizeof a6) != 0);

    firc_fakeip_drop_group(f, "g1", T0 + DAY);

    firc_ip_t c4, c6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "h209.example.com", "g2", T0 + DAY, &c4, &c6));
    ASSERT_MEM_EQ(&b4, &c4, sizeof b4);
    ASSERT_MEM_EQ(&b6, &c6, sizeof b6);

    firc_ip_t d4, d6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "h300.example.com", "g2", T0 + DAY, &d4, &d6));
    ASSERT(memcmp(&d4, &c4, sizeof d4) != 0);
    ASSERT(memcmp(&d6, &c6, sizeof d6) != 0);

    firc_fakeip_free(f);
    PASS();
}

#define CHUNKS_MAX 16
typedef struct { char seen[CHUNKS_MAX][64]; size_t n; } chunk_collect_t;

static void collect_chunk(void *ud, const char *group_id, unsigned family,
                          const firc_ip_t *base, uint8_t prefix) {
    chunk_collect_t *c = (chunk_collect_t *)ud;
    if (c->n >= CHUNKS_MAX) { return; }
    char addr[40];
    if (family == FIRC_FAM_V4) {
        char b[16];
        snprintf(c->seen[c->n], sizeof(c->seen[0]), "%s %s/%u", group_id, s4(base, b), prefix);
    } else {
        snprintf(c->seen[c->n], sizeof(c->seen[0]), "%s %s/%u", group_id, s6(base, addr), prefix);
    }
    c->n++;
}

static bool collected(const chunk_collect_t *c, const char *want) {
    for (size_t i = 0; i < c->n; i++) {
        if (strcmp(c->seen[i], want) == 0) { return true; }
    }
    return false;
}

TEST walking_chunks_reports_every_chunk_a_group_holds(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v4.pool_cidr = 22;
    c.v4.chunk_cidr = 26;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    char name[64];
    firc_ip_t v4 = {{0}, 0};
    for (int i = 0; i < 64; i++) {
        snprintf(name, sizeof(name), "f%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", T0, &v4, NULL));
    }
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "other.example.com", "g2", T0, &v4, NULL));

    chunk_collect_t got = {{{0}}, 0};
    firc_fakeip_walk_chunks(f, "g1", collect_chunk, &got);
    ASSERT_EQ_FMTm("two v4 chunks and one v6 chunk", 3u, (unsigned)got.n, "%u");
    ASSERT(collected(&got, "g1 198.18.0.0/26"));
    ASSERT(collected(&got, "g1 198.18.0.64/26"));
    ASSERT(collected(&got, "g1 fd37:9a5c:be10:0000:0000:0000:0000:0000/64"));
    ASSERTm("g2's chunk must not appear under g1",
            !collected(&got, "g2 198.18.0.128/26"));

    chunk_collect_t two = {{{0}}, 0};
    firc_fakeip_walk_chunks(f, "g2", collect_chunk, &two);
    ASSERT_EQ_FMTm("one chunk in each family", 2u, (unsigned)two.n, "%u");
    ASSERT(collected(&two, "g2 198.18.0.128/26"));
    ASSERT(collected(&two, "g2 fd37:9a5c:be10:0001:0000:0000:0000:0000/64"));

    chunk_collect_t all = {{{0}}, 0};
    firc_fakeip_walk_chunks(f, NULL, collect_chunk, &all);
    ASSERT_EQ_FMTm("every chunk of both groups and nothing else", 5u, (unsigned)all.n, "%u");

    chunk_collect_t none = {{{0}}, 0};
    firc_fakeip_walk_chunks(f, "g3", collect_chunk, &none);
    ASSERT_EQ_FMT(0u, (unsigned)none.n, "%u");

    firc_fakeip_free(f);
    PASS();
}

/* Catches: the exported geometry and window checkers wrong on branches only outside callers reach. */
TEST the_exported_checkers_hold_their_own_boundaries(void) {
    firc_ip_t v4 = {{198, 18, 0, 0}, 4};
    firc_ip_t v6 = {{0xfd, 0x37, 0x9a, 0x5c, 0xbe, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 16};

    ASSERT_EQ(FIRC_OK, firc_fakeip_check_geometry(&v4, 15, 24, 4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_check_geometry(&v6, 48, 64, 16));

    ASSERT_EQm("no caller in this tree passes a width that is not 4 or 16, which is "
               "exactly why nothing else would notice it being accepted",
               FIRC_ERR_INVAL, firc_fakeip_check_geometry(NULL, 8, 16, 6));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_geometry(NULL, 8, 16, 0));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_geometry(&v4, 15, 24, 6));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_geometry(&v4, 15, 24, 0));

    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_geometry(&v4, 15, 24, 16));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_geometry(&v6, 48, 64, 4));

    ASSERT_EQm("a generated prefix is checked for everything except alignment", FIRC_OK,
               firc_fakeip_check_geometry(NULL, 48, 64, 16));
    ASSERT_EQm("a chunk no wider than the pool has nothing to slice", FIRC_ERR_INVAL,
               firc_fakeip_check_geometry(NULL, 48, 40, 16));
    ASSERT_EQm("2^48 chunks still cannot be counted", FIRC_ERR_INVAL,
               firc_fakeip_check_geometry(NULL, 16, 64, 16));

    firc_ip_t off = v4;
    off.b[3] = 1;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_geometry(&off, 15, 24, 4));

    ASSERT_EQ(FIRC_OK, firc_fakeip_check_windows(DAY, CLAMP));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_windows(0, CLAMP));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_windows(DAY, 0));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_windows(-1, CLAMP));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_check_windows(DAY, -1));
    ASSERT_EQm("a year exactly is the documented limit and must load",
               FIRC_OK, firc_fakeip_check_windows(FIRC_FAKEIP_MAX_WINDOW_SECS,
                                                  FIRC_FAKEIP_MAX_WINDOW_SECS));
    ASSERT_EQ(FIRC_ERR_INVAL,
              firc_fakeip_check_windows(FIRC_FAKEIP_MAX_WINDOW_SECS + 1, CLAMP));
    ASSERT_EQ(FIRC_ERR_INVAL,
              firc_fakeip_check_windows(DAY, FIRC_FAKEIP_MAX_WINDOW_SECS + 1));
    PASS();
}

static size_t snap_find(const snapseen_t *v, const char *group, const char *fake) {
    for (size_t i = 0; i < v->n; i++) {
        if (strcmp(v->groups[i], group) == 0 && strcmp(v->fakes[i], fake) == 0) { return i + 1; }
    }
    return 0;
}

/* Catches: a snapshot that borrows the pool's memory, misses mappings, or crosses family slots. */
TEST a_snapshot_outlives_the_mappings_it_describes(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    firc_ip_t real = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_real(f, "a.example.com", "g1", &real));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", T0, &v4, &v6));

    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    ASSERT(s != NULL);

    firc_fakeip_drop_group(f, "g1", T0);
    firc_fakeip_drop_group(f, "g2", T0);
    firc_fakeip_free(f);

    snapseen_t seen = {{{0}}, {{0}}, {false}, {false}, {0}, 0};
    firc_fakeip_snapshot_walk(s, snap_record, &seen);

    ASSERT_EQ_FMTm("two mappings, two families each", (size_t)4, seen.n, "%zu");
    size_t i = snap_find(&seen, "g1", "198.18.0.1");
    ASSERT(i != 0);
    ASSERT_EQ_FMTm("g1's v4 mapping had a real address", true, seen.had_real[i - 1], "%d");
    ASSERT_EQ_FMT(FIRC_FAM_V4, seen.fams[i - 1], "%u");

    i = snap_find(&seen, "g1", "fd37:9a5c:be10:0000:0000:0000:0000:0001");
    ASSERT(i != 0);
    ASSERT_EQ_FMTm("no real v6 address was ever set", false, seen.had_real[i - 1], "%d");

    ASSERTm("the second group's own chunk, not the first's",
            snap_find(&seen, "g2", "198.18.1.1") != 0);

    firc_fakeip_snapshot_free(s);
    PASS();
}

/* Catches: a snapshot without the chunks and pool prefixes its mappings come from. */
TEST a_snapshot_carries_chunks_and_prefixes(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.v4.pool_cidr = 22;
    c.v4.chunk_cidr = 26;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));

    char name[64];
    firc_ip_t v4 = {{0}, 0};
    for (int i = 0; i < 64; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", T0, &v4, NULL));
    }

    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    ASSERT(s != NULL);
    firc_fakeip_free(f);

    chunk_collect_t got = {{{0}}, 0};
    firc_fakeip_snapshot_walk_chunks(s, "g1", collect_chunk, &got);
    ASSERT_EQ_FMTm("two v4 chunks and one v6 chunk", 3u, (unsigned)got.n, "%u");
    ASSERT(collected(&got, "g1 198.18.0.0/26"));
    ASSERT(collected(&got, "g1 198.18.0.64/26"));

    chunk_collect_t none = {{{0}}, 0};
    firc_fakeip_snapshot_walk_chunks(s, "g2", collect_chunk, &none);
    ASSERT_EQ_FMT(0u, (unsigned)none.n, "%u");

    firc_ip_t base = {{0}, 0};
    uint8_t prefix = 0;
    ASSERT(firc_fakeip_snapshot_pool_prefix(s, FIRC_FAM_V4, &base, &prefix));
    ASSERT_EQ_FMTm("the pool prefix, not a chunk's", 22, (int)prefix, "%d");
    char b[16];
    ASSERT_STR_EQ("198.18.0.0", s4(&base, b));
    ASSERT(firc_fakeip_snapshot_pool_prefix(s, FIRC_FAM_V6, &base, &prefix));
    ASSERT_EQ_FMT(48, (int)prefix, "%d");
    ASSERT_FALSE(firc_fakeip_snapshot_pool_prefix(s, 7, &base, &prefix));

    firc_fakeip_snapshot_free(s);
    PASS();
}

/* Catches: an empty pool snapshotting to NULL, which reads as a failure. */
TEST an_empty_pool_still_snapshots(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    ASSERT(s != NULL);

    snapseen_t seen = {{{0}}, {{0}}, {false}, {false}, {0}, 0};
    firc_fakeip_snapshot_walk(s, snap_record, &seen);
    ASSERT_EQ_FMT((size_t)0, seen.n, "%zu");

    firc_ip_t base = {{0}, 0};
    uint8_t prefix = 0;
    ASSERTm("the prefixes are known even with nothing mapped",
            firc_fakeip_snapshot_pool_prefix(s, FIRC_FAM_V4, &base, &prefix));
    ASSERT_EQ_FMT(15, (int)prefix, "%d");

    firc_fakeip_snapshot_free(s);
    firc_fakeip_free(f);

    ASSERT_EQ(NULL, firc_fakeip_snapshot_take(NULL));
    firc_fakeip_snapshot_free(NULL);
    PASS();
}

/* Catches: uncommit marking unresolved pairs or another group's, or not advancing the generation. */
TEST uncommitting_a_group_makes_its_resolved_pairs_wait_again(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4 = {{0}, 0}, a6 = {{0}, 0}, b4 = {{0}, 0}, c4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a4, &a6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", T0, &b4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "c.example.com", "g1", T0, &c4, NULL));
    const firc_ip_t ra = {{93, 184, 216, 34}, 4}, rb = {{1, 2, 3, 4}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", &ra, 1));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "b.example.com", "g2", &rb, 1));
    firc_fakeip_snapshot_t *s1 = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s1));
    firc_fakeip_snapshot_free(s1);
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &a4));
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &b4));

    uint64_t g0 = firc_fakeip_gen(f);
    ASSERT_EQ_FMT((size_t)1, firc_fakeip_uncommit_group(f, "g1"), "%zu");
    ASSERT_EQ_FMTm("the generation advances once", (unsigned long long)g0 + 1,
                   (unsigned long long)firc_fakeip_gen(f), "%llu");
    ASSERTm("g1's resolved pair waits again", firc_fakeip_needs_commit(f, &a4));
    ASSERT_FALSEm("its unresolved v6 has nothing to wait for",
                  firc_fakeip_needs_commit(f, &a6));
    ASSERT_FALSEm("nor has a name with no real address", firc_fakeip_needs_commit(f, &c4));
    ASSERT_FALSEm("another group's pair is untouched", firc_fakeip_needs_commit(f, &b4));

    firc_fakeip_snapshot_t *s2 = firc_fakeip_snapshot_take(f);
    ASSERT_EQ_FMT((unsigned long long)g0 + 1, (unsigned long long)firc_fakeip_snapshot_gen(s2), "%llu");
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s2));
    firc_fakeip_snapshot_free(s2);
    ASSERT_FALSEm("the pass after it releases it", firc_fakeip_needs_commit(f, &a4));

    ASSERT_EQ_FMT((size_t)0, firc_fakeip_uncommit_group(f, "nobody"), "%zu");
    ASSERT_EQ_FMTm("nothing marked, nothing advanced", (unsigned long long)g0 + 1,
                   (unsigned long long)firc_fakeip_gen(f), "%llu");
    firc_fakeip_free(f);
    PASS();
}

/* Catches: uncommit of a group with nothing resolved marking pairs or advancing the generation. */
TEST uncommitting_a_group_with_nothing_resolved_marks_nothing(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4 = {{0}, 0}, a6 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g3", T0, &a4, &a6));
    uint64_t g0 = firc_fakeip_gen(f);
    ASSERT_EQ_FMT((size_t)0, firc_fakeip_uncommit_group(f, "g3"), "%zu");
    ASSERT_EQ_FMTm("the generation stays", (unsigned long long)g0, (unsigned long long)firc_fakeip_gen(f),
                   "%llu");
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &a4));
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &a6));

    const firc_ip_t ra = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g3", &ra, 1));
    firc_fakeip_snapshot_t *s1 = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s1));
    firc_fakeip_snapshot_free(s1);
    ASSERT_EQ_FMTm("control: resolved, the same group is marked", (size_t)1,
                   firc_fakeip_uncommit_group(f, "g3"), "%zu");
    firc_fakeip_free(f);
    PASS();
}

static const char *or_none(const char *s) { return s != NULL ? s : "(none)"; }

static firc_ip_t v4_of(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {{0}, 4};
    ip.b[0] = a;
    ip.b[1] = b;
    ip.b[2] = c;
    ip.b[3] = d;
    return ip;
}

TEST an_issued_address_names_its_domain_in_both_families(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4, a6, b4, b6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "Shop.Example.COM", "g1", T0, &a4, &a6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "cdn.example.net", "g2", T0, &b4, &b6));

    ASSERT_STR_EQ("shop.example.com", or_none(firc_fakeip_name_of(f, &a4)));
    ASSERT_STR_EQ("shop.example.com", or_none(firc_fakeip_name_of(f, &a6)));
    ASSERT_STR_EQ("cdn.example.net", or_none(firc_fakeip_name_of(f, &b4)));
    ASSERT_STR_EQ("cdn.example.net", or_none(firc_fakeip_name_of(f, &b6)));

    firc_ip_t never = a4;
    never.b[3] = 200;
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &never));
    firc_ip_t outside = v4_of(8, 8, 8, 8);
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &outside));
    firc_ip_t bad = a4;
    bad.len = 0;
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &bad));
    ASSERT_EQ(NULL, firc_fakeip_name_of(NULL, &a4));
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, NULL));
    firc_fakeip_free(f);
    PASS();
}

TEST the_blackhole_names_nothing(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.max_names = 1;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4, a6, h4, h6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &a4, &a6));
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f, "b.example.com", "g1", T0, &h4, &h6));
    char buf[16];
    ASSERT_STR_EQ("198.19.255.1", s4(&h4, buf));
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &h4));
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &h6));
    firc_fakeip_free(f);
    PASS();
}

TEST a_released_address_names_nothing_until_issued_again(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4, a6, m4, m6, n4, n6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "idle.example.com", "g1", T0, &a4, &a6));
    firc_fakeip_reclaim(f, T0 + DAY);
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &a4));
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &a6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "idle.example.com", "g1", T0 + DAY, &n4, &n6));
    ASSERT_MEM_EQm("control: the name takes its parked address back", &a4, &n4, sizeof(a4));
    ASSERT_STR_EQ("idle.example.com", or_none(firc_fakeip_name_of(f, &n4)));

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "idle.example.com", "g2", T0 + DAY, &m4, &m6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "idle.example.com", "g2", T0 + 2 * DAY - 1, &m4, &m6));
    firc_fakeip_reclaim(f, T0 + 2 * DAY);
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &a4));
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &a6));
    ASSERT_STR_EQ("idle.example.com", or_none(firc_fakeip_name_of(f, &m4)));
    ASSERT_STR_EQ("idle.example.com", or_none(firc_fakeip_name_of(f, &m6)));

    firc_fakeip_drop_group(f, "g2", T0 + 2 * DAY);
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &m4));
    ASSERT_EQ(NULL, firc_fakeip_name_of(f, &m6));
    firc_fakeip_free(f);
    PASS();
}

#define CHURN_NAMES 300
#define CHURN_EVER 8192

typedef struct {
    firc_ip_t fake[2 * CHURN_NAMES];
    char name[2 * CHURN_NAMES][32];
    size_t n;
} live_t;

static void live_collect(void *ud, const char *qname, const char *group_id, const firc_ip_t *fake,
                         const firc_ip_t *real) {
    (void)group_id;
    (void)real;
    live_t *l = ud;
    if (l->n == 2 * CHURN_NAMES) { return; }
    l->fake[l->n] = *fake;
    snprintf(l->name[l->n], sizeof(l->name[0]), "%s", qname);
    l->n++;
}

TEST the_reverse_index_agrees_with_a_walk_through_churn(void) {
    firc_fakeip_cfg_t c = base_cfg();
    c.max_names = CHURN_NAMES;
    c.idle_secs = 50;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    static firc_ip_t ever[CHURN_EVER];
    static live_t live;
    size_t n_ever = 0;
    uint32_t rng = 12345;
    int64_t now = T0;
    for (int step = 0; step < 6000; step++) {
        rng = rng * 1103515245u + 12345u;
        uint32_t r = rng >> 8;
        now += 1;
        char qname[32];
        snprintf(qname, sizeof(qname), "n%u.example.com", r % (CHURN_NAMES * 2));
        const char *gid = (r & 0x10000u) ? "g1" : ((r & 0x20000u) ? "g2" : "g3");
        firc_ip_t a4, a6;
        if (firc_fakeip_get(f, qname, gid, now, &a4, &a6) == FIRC_OK) {
            bool known = false;
            for (size_t e = 0; e < n_ever && !known; e++) { known = memcmp(&ever[e], &a4, sizeof(a4)) == 0; }
            if (!known && n_ever + 2 <= CHURN_EVER) {
                ever[n_ever++] = a4;
                ever[n_ever++] = a6;
            }
        }
        if (step % 97 == 0) { firc_fakeip_reclaim(f, now); }
        if (step % 1499 == 0) { firc_fakeip_drop_group(f, "g3", now); }
        if (step % 200 != 0) { continue; }
        live.n = 0;
        firc_fakeip_walk(f, live_collect, &live);
        for (size_t i = 0; i < live.n; i++) {
            const char *got = firc_fakeip_name_of(f, &live.fake[i]);
            ASSERT_STR_EQ(live.name[i], or_none(got));
        }
        for (size_t e = 0; e < n_ever; e++) {
            bool mapped = false;
            for (size_t i = 0; i < live.n && !mapped; i++) {
                mapped = ever[e].len == live.fake[i].len && memcmp(ever[e].b, live.fake[i].b, ever[e].len) == 0;
            }
            if (!mapped) { ASSERT_EQ(NULL, firc_fakeip_name_of(f, &ever[e])); }
        }
    }
    ASSERTm("control: the churn released and reissued addresses", n_ever > 2 * CHURN_NAMES);
    firc_fakeip_free(f);
    PASS();
}

typedef struct {
    size_t n;
    char group[4][16];
    char fake[4][16];
    char real[4][40];
} cross_log_t;

static void cross_entry(void *ud, const char *group_id, const firc_ip_t *fake4, const firc_ip_t *real6) {
    cross_log_t *w = ud;
    if (w->n >= 4) { return; }
    snprintf(w->group[w->n], sizeof(w->group[0]), "%s", group_id);
    s4(fake4, w->fake[w->n]);
    s6(real6, w->real[w->n]);
    w->n++;
}

static const firc_ip_t R6A = {{0x26, 0x06, [15] = 1}, 16};
static const firc_ip_t R4A = {{9, 8, 7, 6}, 4};

/* Catches: the cross walk missing a v4 fake whose only real is a v6, or changing the plain walk. */
TEST a_v6_real_pairs_with_the_v4_fake_when_no_v4_real(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4, v6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", &R6A, 1));
    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    ASSERT(s != NULL);
    cross_log_t w = {0};
    firc_fakeip_snapshot_cross_walk(s, cross_entry, &w);
    ASSERT_EQ_FMT((size_t)1, w.n, "%zu");
    ASSERT_STR_EQ("g1", w.group[0]);
    ASSERT_STR_EQ("198.18.0.1", w.fake[0]);
    ASSERT_STR_EQ("2606:0000:0000:0000:0000:0000:0000:0001", w.real[0]);
    firc_fakeip_snapshot_free(s);

    walk_log_t p = {0};
    firc_fakeip_walk(f, log_entry, &p);
    int i4 = find_fake(&p, "198.18.0.1");
    ASSERT(i4 >= 0);
    ASSERT_FALSEm("the plain walk still shows no v4 real", p.has_real[i4]);
    firc_fakeip_free(f);
    PASS();
}

static bool real_behind(const firc_fakeip_t *f, const firc_ip_t *fake, firc_ip_t *real) {
    const char *group_id = NULL;
    return firc_fakeip_pair_of(f, fake, &group_id, real);
}

/* Catches: a v6 real chosen over an existing v4 real for a v4 fake. */
TEST a_v4_real_beats_the_v6_one_for_the_v4_fake(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4, v6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    firc_ip_t both[] = {R6A, R4A};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", both, 2));
    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    cross_log_t w = {0};
    firc_fakeip_snapshot_cross_walk(s, cross_entry, &w);
    ASSERT_EQ_FMT((size_t)0, w.n, "%zu");
    firc_fakeip_snapshot_free(s);
    firc_ip_t got = {{0}, 0};
    ASSERT(real_behind(f, &v4, &got));
    ASSERT_EQ(4, got.len);
    ASSERT_MEM_EQ(R4A.b, got.b, 4);
    firc_fakeip_free(f);
    PASS();
}

/* Catches: pair_of answering true for an address no mapping holds, or for a mapping with no real. */
TEST pair_of_an_unknown_fake_is_false(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4, v6, got = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    const firc_ip_t nobody = {{198, 18, 0, 99}, 4};
    ASSERT_FALSE(real_behind(f, &nobody, &got));
    ASSERT_FALSEm("a mapping with no real at all", real_behind(f, &v4, &got));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: needs_commit reading only the v4 pair, so an answer holding a v6-backed v4 fake is released early. */
TEST a_v6_real_for_the_v4_fake_needs_a_commit(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4, v6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &v4));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", &R6A, 1));
    ASSERT(firc_fakeip_needs_commit(f, &v4));
    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s));
    firc_fakeip_snapshot_free(s);
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &v4));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: clear_real leaving the family's real, bumping nothing, touching the other family or an unknown mapping. */
TEST a_cleared_v4_real_lets_the_v6_pair(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4, v6, got = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    firc_ip_t both[] = {R6A, R4A};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", both, 2));
    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f);
    firc_fakeip_mark_committed(f, firc_fakeip_snapshot_gen(s));
    firc_fakeip_snapshot_free(s);
    ASSERT_FALSE(firc_fakeip_needs_commit(f, &v4));

    uint64_t g0 = firc_fakeip_gen(f);
    firc_fakeip_clear_real(f, "nobody.example.com", "g1", 4);
    firc_fakeip_clear_real(f, "a.example.com", "g9", 4);
    ASSERT_EQ_FMTm("an unknown mapping is a no-op", (unsigned long long)g0,
                   (unsigned long long)firc_fakeip_gen(f), "%llu");
    firc_fakeip_clear_real(f, "a.example.com", "g1", 4);
    ASSERT(firc_fakeip_gen(f) > g0);
    ASSERT(firc_fakeip_needs_commit(f, &v4));
    ASSERT(real_behind(f, &v4, &got));
    ASSERT_EQ(16, got.len);
    ASSERT_MEM_EQ(R6A.b, got.b, 16);
    s = firc_fakeip_snapshot_take(f);
    cross_log_t w = {0};
    firc_fakeip_snapshot_cross_walk(s, cross_entry, &w);
    ASSERT_EQ_FMT((size_t)1, w.n, "%zu");
    firc_fakeip_snapshot_free(s);

    firc_fakeip_clear_real(f, "a.example.com", "g1", 16);
    ASSERT_FALSE(real_behind(f, &v4, &got));
    firc_fakeip_free(f);
    PASS();
}

/* Catches: a parked pair missed, a pair without a real answered, the wrong group, a v6 address taken, or a dropped group's pair kept. */
TEST pair_of_finds_parked_mappings(void) {
    firc_fakeip_cfg_t c = base_cfg();
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t v4 = {{0}, 0}, v6 = {{0}, 0}, b4 = {{0}, 0};
    const firc_ip_t real4 = {{93, 184, 216, 34}, 4};
    const firc_ip_t real6 = {{0x26, 0x06, 0x28, 0, 2, 0x20, 0, 1, 2, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46}, 16};
    const firc_ip_t both[] = {real4, real6};
    const char *gid = NULL;
    firc_ip_t got = {{0}, 0};
    char b[16];

    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", T0, &v4, &v6));
    ASSERT_FALSEm("no real address yet", firc_fakeip_pair_of(f, &v4, &gid, &got));
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", "g1", both, 2));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g1", T0, &b4, NULL));

    ASSERT(firc_fakeip_pair_of(f, &v4, &gid, &got));
    ASSERT_STR_EQ("g1", gid);
    ASSERT_STR_EQ("93.184.216.34", s4(&got, b));
    ASSERT_FALSEm("a v6 fake is not asked about", firc_fakeip_pair_of(f, &v6, &gid, &got));
    ASSERT_FALSEm("b.example.com has no real address", firc_fakeip_pair_of(f, &b4, &gid, &got));

    firc_ip_t other = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", T0, &other, NULL));
    ASSERT_STR_EQ("198.18.1.1", s4(&other, b));
    ASSERT_FALSEm("the second group's mapping has no real yet", firc_fakeip_pair_of(f, &other, &gid, &got));
    firc_fakeip_reclaim(f, T0 + DAY);
    gid = NULL;
    memset(&got, 0, sizeof(got));
    ASSERTm("the parked pair is found", firc_fakeip_pair_of(f, &v4, &gid, &got));
    ASSERT_STR_EQ("g1", gid);
    ASSERT_STR_EQ("93.184.216.34", s4(&got, b));
    ASSERT_FALSEm("a parked address that never had a real", firc_fakeip_pair_of(f, &b4, &gid, &got));

    const firc_ip_t elsewhere = {{198, 18, 0, 200}, 4};
    ASSERT_FALSE(firc_fakeip_pair_of(f, &elsewhere, &gid, &got));
    firc_fakeip_drop_group(f, "g1", T0);
    ASSERT_FALSEm("a dropped group's parked pair is gone", firc_fakeip_pair_of(f, &v4, &gid, &got));
    firc_fakeip_free(f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(first_issued_addresses_are_the_first_usable_of_the_first_chunks);
    RUN_TEST(the_same_name_keeps_its_addresses_across_calls);
    RUN_TEST(distinct_names_in_one_group_get_consecutive_addresses);
    RUN_TEST(each_group_draws_from_its_own_chunk);
    RUN_TEST(both_families_are_issued_together_even_when_one_is_asked_for);
    RUN_TEST(new_rejects_geometry_it_cannot_serve);
    RUN_TEST(new_rejects_windows_that_would_disable_the_protections);
    RUN_TEST(null_arguments_are_refused_rather_than_dereferenced);
    RUN_TEST(names_differing_only_in_case_are_one_name);
    RUN_TEST(names_that_share_a_hash_bucket_get_their_own_addresses);
    RUN_TEST(deleting_a_group_unlinks_the_addresses_it_parked_by_name);
    RUN_TEST(walking_chunks_reports_every_chunk_a_group_holds);
    RUN_TEST(the_exported_checkers_hold_their_own_boundaries);
    RUN_TEST(a_snapshot_outlives_the_mappings_it_describes);
    RUN_TEST(a_snapshot_carries_chunks_and_prefixes);
    RUN_TEST(an_empty_pool_still_snapshots);
    RUN_TEST(one_name_holds_one_mapping_per_group);
    RUN_TEST(a_name_in_a_second_group_costs_a_second_mapping);
    RUN_TEST(an_idle_mapping_is_reclaimed_while_the_other_groups_stays);
    RUN_TEST(a_name_parked_in_one_group_gets_nothing_of_it_in_another);
    RUN_TEST(each_groups_mapping_of_one_name_keeps_its_own_real_and_commit);
    RUN_TEST(a_parked_address_is_not_offered_to_a_different_name);
    RUN_TEST(the_quarantine_window_is_derived_from_the_clamp);
    RUN_TEST(the_quarantine_window_takes_the_larger_of_the_multiple_and_the_floor);
    RUN_TEST(a_name_that_returns_after_a_sweep_gets_its_own_addresses_back);
    RUN_TEST(the_sweep_runs_on_the_configured_idle_window);
    RUN_TEST(a_groups_second_chunk_is_not_handed_to_another_group);
    RUN_TEST(a_group_with_no_chunk_left_gets_the_blackhole_addresses);
    RUN_TEST(every_refusal_writes_both_blackhole_addresses);
    RUN_TEST(at_capacity_new_names_are_refused_but_known_ones_still_work);
    RUN_TEST(a_mapping_records_the_group_that_issued_it);
    RUN_TEST(a_vacated_address_returns_to_the_group_whose_chunk_it_came_from);
    RUN_TEST(a_deleted_groups_chunk_comes_back_only_after_its_quarantine);
    RUN_TEST(deleting_a_group_returns_every_chunk_it_held);
    RUN_TEST(deleting_a_group_returns_the_capacity_its_names_held);
    RUN_TEST(v6_skips_only_the_anycast_address_not_the_v4_reserved_octets);
    RUN_TEST(a_refused_issue_hands_back_the_half_that_succeeded);
    RUN_TEST(the_real_address_a_fake_one_stands_for_is_recorded_per_family);
    RUN_TEST(setting_the_real_address_again_replaces_it);
    RUN_TEST(a_real_address_still_in_the_answer_is_kept_and_a_vanished_one_replaced);
    RUN_TEST(a_pair_needs_a_commit_until_a_snapshot_taken_after_it_completes);
    RUN_TEST(the_generation_is_per_pair_and_the_mark_is_monotonic);
    RUN_TEST(a_reclaimed_pair_stays_in_the_snapshot_beside_the_other_groups_mapping);
    RUN_TEST(an_expired_parked_address_leaves_at_the_sweep);
    RUN_TEST(an_address_whose_window_ran_out_under_the_sweep_is_issued_again);
    RUN_TEST(the_pool_knows_when_a_prefix_overlaps_it);
    RUN_TEST(two_freed_addresses_of_one_chunk_are_both_issued_again);
    RUN_TEST(a_chunk_with_names_or_parked_addresses_is_not_given_back);
    RUN_TEST(the_real_address_of_an_unknown_name_is_refused_and_case_is_folded);
    RUN_TEST(taking_a_reserved_address_consumes_the_reservation);
    RUN_TEST(the_sweep_parks_an_address_against_its_own_group);
    RUN_TEST(the_idle_clock_is_stamped_on_both_the_store_and_the_lookup);
    RUN_TEST(names_that_differ_in_content_are_not_folded_together);
    RUN_TEST(a_chunk_wider_than_an_octet_skips_both_reserved_octets);
    RUN_TEST(a_zero_name_cap_selects_the_default_rather_than_refusing_everything);
    RUN_TEST(the_pool_can_name_the_prefixes_its_addresses_come_from);
    RUN_TEST(parked_addresses_come_back_oldest_first);
    RUN_TEST(uncommitting_a_group_makes_its_resolved_pairs_wait_again);
    RUN_TEST(uncommitting_a_group_with_nothing_resolved_marks_nothing);
    RUN_TEST(an_issued_address_names_its_domain_in_both_families);
    RUN_TEST(the_blackhole_names_nothing);
    RUN_TEST(a_released_address_names_nothing_until_issued_again);
    RUN_TEST(the_reverse_index_agrees_with_a_walk_through_churn);
    RUN_TEST(pair_of_finds_parked_mappings);
    RUN_TEST(a_v6_real_pairs_with_the_v4_fake_when_no_v4_real);
    RUN_TEST(a_v4_real_beats_the_v6_one_for_the_v4_fake);
    RUN_TEST(pair_of_an_unknown_fake_is_false);
    RUN_TEST(a_v6_real_for_the_v4_fake_needs_a_commit);
    RUN_TEST(a_cleared_v4_real_lets_the_v6_pair);
    GREATEST_MAIN_END();
}
