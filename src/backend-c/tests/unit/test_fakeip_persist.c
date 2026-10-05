#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "firc/fakeip.h"

static firc_fakeip_cfg_t geometry(size_t max_names) {
    firc_fakeip_cfg_t c;
    memset(&c, 0, sizeof(c));
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.base.b[2] = 0x9a;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = max_names;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    return c;
}

static firc_fakeip_t *fresh(size_t max_names) {
    firc_fakeip_cfg_t c = geometry(max_names);
    firc_fakeip_t *f = NULL;
    if (firc_fakeip_new(&c, &f) != FIRC_OK) { abort(); }
    return f;
}

/* Saves `f` to a temp file and loads it into a fresh pool, as a clean or unclean stop. */
static firc_fakeip_t *reloaded_as(const firc_fakeip_t *f, bool clean, int64_t now, size_t *restored, firc_err_t *err) {
    FILE *tmp = tmpfile();
    if (tmp == NULL) { abort(); }
    if (firc_fakeip_save(f, tmp, clean) != FIRC_OK) { abort(); }
    rewind(tmp);
    firc_fakeip_t *g = fresh(1024);
    *err = firc_fakeip_load(g, tmp, now, restored);
    fclose(tmp);
    return g;
}

static firc_fakeip_t *reloaded(const firc_fakeip_t *f, int64_t now, size_t *restored, firc_err_t *err) {
    return reloaded_as(f, true, now, restored, err);
}

typedef struct {
    char name[8][128];
    char group[8][32];
    firc_ip_t fake[8];
    firc_ip_t real[8];
    bool has_real[8];
    size_t n;
} seen_t;

static void collect(void *ud, const char *qname, const char *group_id, const firc_ip_t *fake,
                    const firc_ip_t *real) {
    seen_t *s = ud;
    if (s->n == 8) { return; }
    snprintf(s->name[s->n], sizeof(s->name[0]), "%s", qname);
    snprintf(s->group[s->n], sizeof(s->group[0]), "%s", group_id);
    s->fake[s->n] = *fake;
    s->has_real[s->n] = real != NULL;
    if (real != NULL) { s->real[s->n] = *real; }
    s->n++;
}

static bool same_ip(const firc_ip_t *a, const firc_ip_t *b) {
    return a->len == b->len && memcmp(a->b, b->b, a->len) == 0;
}

/* Catches: a restored name losing an address, its group or its real address, or read as committed. */
TEST a_restored_name_keeps_its_addresses_group_and_reals(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4, a6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "shop.example.com", "g1", 1000, &a4, &a6));
    const firc_ip_t real4 = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "shop.example.com", &real4, 1));
    firc_fakeip_mark_committed(f, firc_fakeip_gen(f));

    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");

    seen_t seen = {0};
    firc_fakeip_walk(g, collect, &seen);
    ASSERT_EQ_FMTm("one name, two families", (size_t)2, seen.n, "%zu");
    for (size_t i = 0; i < seen.n; i++) {
        ASSERT_STR_EQ("shop.example.com", seen.name[i]);
        ASSERT_STR_EQ("g1", seen.group[i]);
        if (seen.fake[i].len == 4) {
            ASSERTm("the same v4 fake address", same_ip(&seen.fake[i], &a4));
            ASSERTm("with its real address behind it", seen.has_real[i] && same_ip(&seen.real[i], &real4));
        } else {
            ASSERTm("the same v6 fake address", same_ip(&seen.fake[i], &a6));
            ASSERT_FALSEm("no v6 real was known", seen.has_real[i]);
        }
    }
    ASSERTm("a restored pair needs a commit: the kernel has no rule for it",
            firc_fakeip_needs_commit(g, "shop.example.com", FIRC_FAM_V4));
    ASSERT_FALSEm("a family with no real address has no pair to commit",
                  firc_fakeip_needs_commit(g, "shop.example.com", FIRC_FAM_V6));

    firc_ip_t b4, b6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "shop.example.com", "g1", 2001, &b4, &b6));
    ASSERTm("asked again after the restart, the same address", same_ip(&a4, &b4) && same_ip(&a6, &b6));
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a new name after a restart given a restored address or one freed inside the window. */
TEST new_names_after_a_restart_avoid_restored_and_recently_freed_addresses(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t kept[5], freed;
    char name[32];
    for (int i = 0; i < 5; i++) {
        snprintf(name, sizeof(name), "k%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1000, &kept[i], NULL));
    }
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "gone.example.com", "g1", 1000, &freed, NULL));
    for (int i = 0; i < 5; i++) {
        snprintf(name, sizeof(name), "k%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 90000, &kept[i], NULL));
    }
    firc_fakeip_reclaim(f, 90000);

    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 90001, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMT((size_t)5, restored, "%zu");

    for (int i = 0; i < 20; i++) {
        firc_ip_t fresh4;
        snprintf(name, sizeof(name), "new%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 90002, &fresh4, NULL));
        for (int k = 0; k < 5; k++) { ASSERT_FALSEm("a restored address is taken", same_ip(&fresh4, &kept[k])); }
        ASSERT_FALSEm("the freed address is parked for the window", same_ip(&fresh4, &freed));
    }
    bool reused = false;
    for (int i = 0; i < 300 && !reused; i++) {
        firc_ip_t fresh4;
        snprintf(name, sizeof(name), "later%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 90002 + 3601, &fresh4, NULL));
        reused = same_ip(&fresh4, &freed);
    }
    ASSERTm("after the window the freed address is issued again", reused);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a file written under another pool geometry loaded instead of refused. */
TEST a_file_from_another_geometry_is_refused(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    FILE *tmp = tmpfile();
    ASSERT(tmp != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(f, tmp, true));
    rewind(tmp);
    firc_fakeip_cfg_t c = geometry(64);
    c.v4.chunk_cidr = 26;
    firc_fakeip_t *other = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &other));
    size_t restored = 7;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_load(other, tmp, 2000, &restored));
    ASSERT_EQ_FMT((size_t)0, restored, "%zu");
    seen_t seen = {0};
    firc_fakeip_walk(other, collect, &seen);
    ASSERT_EQ_FMT((size_t)0, seen.n, "%zu");
    fclose(tmp);
    firc_fakeip_free(f);
    firc_fakeip_free(other);
    PASS();
}

/* Catches: one unparseable line failing the whole load. */
TEST a_broken_line_is_skipped_not_fatal(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    FILE *tmp = tmpfile();
    ASSERT(tmp != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(f, tmp, true));
    fprintf(tmp, "map broken.example.com g1 not-an-address - - - 5\n");
    fprintf(tmp, "garbage\n");
    rewind(tmp);
    firc_fakeip_t *g = fresh(64);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(g, tmp, 2000, &restored));
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    fclose(tmp);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: last-seen reset at load, restarting every name's idle clock. */
TEST last_seen_survives_so_the_idle_sweep_is_not_reset(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "old.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "fresh.example.com", "g1", 80000, &a4, NULL));
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 80001, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    firc_fakeip_reclaim(g, 1000 + 86400 + 1);
    seen_t seen = {0};
    firc_fakeip_walk(g, collect, &seen);
    ASSERT_EQ_FMTm("the old name went, the fresh one stayed", (size_t)2, seen.n, "%zu");
    ASSERT_STR_EQ("fresh.example.com", seen.name[0]);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

static void count_chunks(void *ud, const char *group_id, unsigned family, const firc_ip_t *base,
                         uint8_t prefix) {
    (void)group_id; (void)base; (void)prefix;
    if (family == FIRC_FAM_V4) { (*(size_t *)ud)++; }
}

/* Catches: a group's chunks restored under the wrong group or not at all. */
TEST each_groups_chunks_are_restored(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4, b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", 1000, &b4, NULL));
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded_as(f, false, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    firc_ip_t c4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "c.example.com", "g2", 2001, &c4, NULL));
    ASSERTm("a new name of g2 is not in g1's chunk", memcmp(c4.b, a4.b, 3) != 0);
    ASSERTm("nor in g2's restored chunk, which is parked to its end for the window",
            memcmp(c4.b, b4.b, 3) != 0);
    size_t chunks = 0;
    firc_fakeip_walk_chunks(g, "g2", count_chunks, &chunks);
    ASSERT_EQ_FMTm("g2 holds its restored chunk and the fresh one", (size_t)2, chunks, "%zu");
    firc_ip_t d4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "d.example.com", "g2", 2000 + 3601, &d4, NULL));
    ASSERTm("after the window the restored chunk's free addresses are issued again", memcmp(d4.b, b4.b, 3) == 0);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a group's earlier full chunk handed to another group while its names still live in it. */
TEST a_groups_older_full_chunk_stays_its_own(void) {
    firc_fakeip_t *f = fresh(2048);
    firc_ip_t first, a4;
    char name[32];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "n0.example.com", "g1", 1000, &first, NULL));
    for (int i = 1; i < 300; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1000, &a4, NULL));
    }
    ASSERTm("the group is on its second chunk", a4.b[2] != first.b[2]);
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMT((size_t)300, restored, "%zu");
    size_t chunks = 0;
    firc_fakeip_walk_chunks(g, "g1", count_chunks, &chunks);
    ASSERT_EQ_FMTm("both chunks are g1's again", (size_t)2, chunks, "%zu");
    firc_ip_t other;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "x.example.com", "g2", 2000 + 3601, &other, NULL));
    ASSERTm("another group never lands in g1's full chunk", other.b[2] != first.b[2]);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a chunk no group holds at load lost for good instead of parked and returned. */
TEST a_chunk_nobody_holds_any_more_comes_back_after_the_window(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t gone4, kept4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &gone4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", 1000, &kept4, NULL));
    firc_fakeip_drop_group(f, "g1", 1000);
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    firc_ip_t soon, later;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "c.example.com", "g3", 2001, &soon, NULL));
    ASSERTm("inside the window the freed chunk is not reused", soon.b[2] != gone4.b[2]);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "d.example.com", "g4", 2000 + 3601, &later, NULL));
    ASSERTm("after the window it is", later.b[2] == gone4.b[2]);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

static const char HEADER[] = "firc-pool 1\nv4 198.18.0.0/15 chunk 24\nv6 fd37:9a00::/48 chunk 64\n";

static firc_fakeip_t *loaded_from_text(const char *text, size_t max_names, size_t *restored) {
    FILE *tmp = tmpfile();
    if (tmp == NULL) { abort(); }
    fputs(HEADER, tmp);
    fputs(text, tmp);
    rewind(tmp);
    firc_fakeip_t *g = fresh(max_names);
    if (firc_fakeip_load(g, tmp, 2000, restored) != FIRC_OK) { abort(); }
    fclose(tmp);
    return g;
}

/* Catches: the current chunk taken to be the highest-indexed one instead of the one the mark names. */
TEST the_mark_names_the_current_chunk_whatever_its_index(void) {
    firc_fakeip_t *f = fresh(4096);
    firc_ip_t a4;
    char name[32];
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "other.example.com", "g2", 1000, &a4, NULL));
    int n = 0;
    firc_ip_t last;
    do {
        snprintf(name, sizeof(name), "n%d.example.com", n++);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1000, &last, NULL));
    } while (last.b[2] != 2 || n < 300);
    firc_fakeip_drop_group(f, "g2", 1000);
    firc_ip_t victims[5];
    for (int i = 0; i < 5; i++) {
        snprintf(name, sizeof(name), "v%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1000, &victims[i], NULL));
        ASSERT_EQ(2, victims[i].b[2]);
    }
    int64_t later = 1000 + 3601;
    firc_ip_t grown;
    do {
        snprintf(name, sizeof(name), "g%d.example.com", n++);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", later, &grown, NULL));
    } while (grown.b[2] != 0);
    for (int i = 0; i < n; i++) {
        snprintf(name, sizeof(name), i < 300 ? "n%d.example.com" : "g%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 90000, &a4, NULL));
    }
    firc_fakeip_reclaim(f, 90000);

    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 90001, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    for (int i = 0; i < 40; i++) {
        firc_ip_t fresh4;
        snprintf(name, sizeof(name), "new%d.example.com", i);
        ASSERT_EQ_FMT((int)FIRC_OK, (int)firc_fakeip_get(g, name, "g1", 90002, &fresh4, NULL), "%d");
        for (int k = 0; k < 5; k++) { ASSERT_FALSEm("a victim's address is parked for the window", same_ip(&fresh4, &victims[k])); }
    }
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: addresses above the saved mark handed out within the window after a crash. */
TEST addresses_issued_after_the_last_save_are_not_reissued_after_a_crash(void) {
    firc_fakeip_t *f = fresh(4096);
    firc_ip_t a4, a6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "saved.example.com", "g1", 1000, &a4, &a6));
    FILE *tmp = tmpfile();
    ASSERT(tmp != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(f, tmp, false));
    firc_ip_t after4[3], after6[3];
    char name[32];
    for (int i = 0; i < 3; i++) {
        snprintf(name, sizeof(name), "unsaved%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1001, &after4[i], &after6[i]));
    }
    rewind(tmp);
    firc_fakeip_t *g = fresh(4096);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(g, tmp, 2000, &restored));
    fclose(tmp);
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    for (int i = 0; i < 300; i++) {
        firc_ip_t n4, n6;
        snprintf(name, sizeof(name), "new%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 2001, &n4, &n6));
        for (int k = 0; k < 3; k++) {
            ASSERT_FALSEm("a v4 address a client may hold is not reissued inside the window", same_ip(&n4, &after4[k]));
            ASSERT_FALSEm("nor a v6 one", same_ip(&n6, &after6[k]));
        }
    }
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a broken line in the middle dropping the lines after it. */
TEST a_broken_line_in_the_middle_costs_only_itself(void) {
    size_t restored = 0;
    firc_fakeip_t *g = loaded_from_text(
        "map a.example.com g1 198.18.0.1 - fd37:9a00::1 - 5\n"
        "garbage\n"
        "map broken.example.com g1 nope - - - 5\n"
        "map b.example.com g1 198.18.0.2 - fd37:9a00::2 - 5\n", 64, &restored);
    ASSERT_EQ_FMT((size_t)2, restored, "%zu");
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a blackhole, duplicate, over-cap or squatting line accepted at load. */
TEST refused_lines_and_the_cap(void) {
    size_t restored = 0;
    firc_fakeip_t *g = loaded_from_text(
        "map bh.example.com g1 198.19.255.1 - fd37:9a00:0:ffff::1 - 5\n"
        "map a.example.com g1 198.18.0.1 - fd37:9a00::1 - 5\n"
        "map A.EXAMPLE.COM g1 198.18.0.2 - fd37:9a00::2 - 5\n"
        "map c.example.com g2 198.18.0.3 - fd37:9a00::3 - 5\n", 64, &restored);
    ASSERT_EQ_FMTm("the blackhole line, the duplicate and the squatter are refused", (size_t)1, restored, "%zu");
    seen_t seen = {0};
    firc_fakeip_walk(g, collect, &seen);
    ASSERT_EQ_FMT((size_t)2, seen.n, "%zu");
    ASSERT_STR_EQ("g1", seen.group[0]);
    firc_fakeip_free(g);
    g = loaded_from_text(
        "map a.example.com g1 198.18.0.1 - fd37:9a00::1 - 5\n"
        "map b.example.com g1 198.18.0.2 - fd37:9a00::2 - 5\n"
        "map c.example.com g1 198.18.0.3 - fd37:9a00::3 - 5\n", 2, &restored);
    ASSERT_EQ_FMTm("max_names caps the load", (size_t)2, restored, "%zu");
    firc_fakeip_free(g);
    PASS();
}

/* Catches: restored names walked under the wrong group. */
TEST each_name_comes_back_under_its_own_group(void) {
    size_t restored = 0;
    firc_fakeip_t *g = loaded_from_text(
        "map a.example.com g1 198.18.0.1 - fd37:9a00::1 - 5\n"
        "map b.example.com g2 198.18.1.1 - fd37:9a00:0:1::1 - 5\n", 64, &restored);
    ASSERT_EQ_FMT((size_t)2, restored, "%zu");
    seen_t seen = {0};
    firc_fakeip_walk(g, collect, &seen);
    for (size_t i = 0; i < seen.n; i++) {
        ASSERT_STR_EQ(strcmp(seen.name[i], "a.example.com") == 0 ? "g1" : "g2", seen.group[i]);
    }
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a save writing over the file in place instead of renaming a new one over it. */
TEST the_file_is_replaced_not_overwritten(void) {
    if (geteuid() == 0) { SKIPm("root can write a read-only file"); }
    char dir[] = "/tmp/firc-pool-dir-XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char path[128];
    snprintf(path, sizeof(path), "%s/pool.state", dir);
    FILE *old = fopen(path, "w");
    ASSERT(old != NULL);
    fputs("stale\n", old);
    fclose(old);
    ASSERT_EQ(0, chmod(path, 0444));
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_save_file(f, path, true));
    firc_fakeip_t *g = fresh(64);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load_file(g, path, 2000, &restored));
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    struct stat st;
    ASSERT_EQ(0, stat(path, &st));
    ASSERT_EQ_FMTm("every name the LAN resolved: the owner's eyes only", 0600u, (unsigned)(st.st_mode & 0777), "%o");
    unlink(path);
    rmdir(dir);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* The chunk hook as the daemon has it: save at once when the pool takes a chunk. */
static void save_on_chunk(void *ud, const firc_fakeip_t *f) {
    FILE *file = ud;
    rewind(file);
    if (ftruncate(fileno(file), 0) != 0) { abort(); }
    if (firc_fakeip_save(f, file, false) != FIRC_OK) { abort(); }
}

/* Catches: a chunk taken after the last save not saved, so a crash reissues its addresses. */
TEST a_fresh_chunk_after_a_restart_is_saved_at_once(void) {
    FILE *file = tmpfile();
    ASSERT(file != NULL);
    firc_fakeip_t *one = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(one, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(one, file, false));
    firc_fakeip_free(one);

    rewind(file);
    firc_fakeip_t *two = fresh(64);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(two, file, 2000, &restored));
    int taken = 0;
    firc_fakeip_set_on_chunk(two, save_on_chunk, file);
    firc_ip_t b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(two, "b.example.com", "g1", 2001, &b4, NULL));
    ASSERTm("a fresh chunk, not the parked one", b4.b[2] != a4.b[2]);
    (void)taken;
    rewind(file);
    char line[256];
    bool named = false;
    while (fgets(line, sizeof(line), file) != NULL) { if (strstr(line, "b.example.com") != NULL) { named = true; } }
    ASSERTm("the save the take triggered holds the name that took it", named);
    firc_fakeip_free(two);

    rewind(file);
    firc_fakeip_t *three = fresh(64);
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(three, file, 3000, &restored));
    firc_ip_t c4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(three, "c.example.com", "g1", 3001, &c4, NULL));
    ASSERT_FALSEm("the address b's client still holds is not c's", same_ip(&c4, &b4));
    ASSERTm("b's chunk is known and parked: c is in yet another chunk", c4.b[2] != b4.b[2] && c4.b[2] != a4.b[2]);
    fclose(file);
    firc_fakeip_free(three);
    PASS();
}

/* Catches: a chunk a deleted group gave back before the stop handed to the next group at load. */
TEST a_chunk_returned_before_the_stop_is_parked_after_it(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4, gone4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", 1000, &gone4, NULL));
    firc_fakeip_drop_group(f, "g2", 1000);
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 1010, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    firc_ip_t c4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "c.example.com", "g3", 1011, &c4, NULL));
    ASSERTm("inside the window the returned chunk is not handed out", c4.b[2] != gone4.b[2]);
    firc_ip_t d4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "d.example.com", "g4", 1000 + 3601 + 10, &d4, NULL));
    ASSERTm("after it, it is", d4.b[2] == gone4.b[2]);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a chunk whose names and parks are gone held for ever instead of returned. */
TEST an_emptied_chunk_goes_back_to_the_pool(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded_as(f, false, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    firc_ip_t b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g1", 2001, &b4, NULL));
    size_t chunks = 0;
    firc_fakeip_walk_chunks(g, "g1", count_chunks, &chunks);
    ASSERT_EQ_FMT((size_t)2, chunks, "%zu");
    int64_t t = 2000 + 86400 + 1;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "a.example.com", "g1", t, &a4, NULL));
    firc_fakeip_reclaim(g, t);
    firc_fakeip_reclaim(g, t + 3601);
    chunks = 0;
    firc_fakeip_walk_chunks(g, "g1", count_chunks, &chunks);
    ASSERT_EQ_FMTm("the emptied chunk went back; the one with a name stayed", (size_t)1, chunks, "%zu");
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a clean restart burning a fresh chunk per group, or losing what was parked. */
TEST a_clean_stop_costs_no_fresh_chunk(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4, gone4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "gone.example.com", "g1", 1000, &gone4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 90000, &a4, NULL));
    firc_fakeip_reclaim(f, 90000);
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 90001, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    firc_ip_t b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g1", 90002, &b4, NULL));
    ASSERTm("the next name is in the same chunk", b4.b[2] == a4.b[2]);
    ASSERT_FALSEm("but not at the freed address, which is parked", same_ip(&b4, &gone4));
    size_t chunks = 0;
    firc_fakeip_walk_chunks(g, "g1", count_chunks, &chunks);
    ASSERT_EQ_FMT((size_t)1, chunks, "%zu");
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a clean file reloaded as exact after a crash in the run that loaded it. */
TEST a_clean_file_stops_being_exact_once_loaded(void) {
    firc_fakeip_t *one = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(one, "old.example.com", "g1", 1000, &a4, NULL));
    FILE *file = tmpfile();
    ASSERT(file != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(one, file, true));
    firc_fakeip_free(one);

    rewind(file);
    firc_fakeip_t *two = fresh(64);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(two, file, 2000, &restored));
    ASSERTm("a loaded clean file is dirty: the daemon has something to write at once", firc_fakeip_dirty_since_save(two));
    rewind(file);
    ASSERT_EQ(0, ftruncate(fileno(file), 0));
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(two, file, false));
    firc_ip_t victim;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(two, "victim.example.com", "g1", 2001, &victim, NULL));
    firc_fakeip_free(two);

    rewind(file);
    firc_fakeip_t *three = fresh(64);
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(three, file, 3000, &restored));
    firc_ip_t attacker;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(three, "attacker.example.com", "g1", 3001, &attacker, NULL));
    ASSERT_FALSEm("the victim's address, still held by its client, is not reissued", same_ip(&attacker, &victim));
    fclose(file);
    firc_fakeip_free(three);
    PASS();
}

typedef struct {
    char fakes[16][48];
    char reals[16][48];
    bool has_real[16];
    size_t n;
} snapseen_t;

static void snap_record(void *ud, const char *group_id, unsigned family, const firc_ip_t *fake,
                        const firc_ip_t *real) {
    (void)group_id; (void)family;
    snapseen_t *s = ud;
    if (s->n == 16) { return; }
    if (fake->len == 4) { snprintf(s->fakes[s->n], 48, "%u.%u.%u.%u", fake->b[0], fake->b[1], fake->b[2], fake->b[3]); }
    else { snprintf(s->fakes[s->n], 48, "v6"); }
    s->has_real[s->n] = real != NULL;
    if (real != NULL && real->len == 4) { snprintf(s->reals[s->n], 48, "%u.%u.%u.%u", real->b[0], real->b[1], real->b[2], real->b[3]); }
    s->n++;
}

/* Catches: a parked pair lost across a clean restart, or given a fresh window. */
TEST parked_pairs_survive_a_clean_stop(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t old4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &old4, NULL));
    const firc_ip_t real = {{93, 184, 216, 34}, 4};
    ASSERT_EQ(FIRC_OK, firc_fakeip_set_reals(f, "a.example.com", &real, 1));
    firc_ip_t new4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g2", 1000, &new4, NULL));
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);

    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(g);
    snapseen_t seen = {{{0}}, {{0}}, {false}, 0};
    firc_fakeip_snapshot_walk(s, snap_record, &seen);
    firc_fakeip_snapshot_free(s);
    bool parked_rule = false;
    for (size_t i = 0; i < seen.n; i++) {
        if (strcmp(seen.fakes[i], "198.18.0.1") == 0 && seen.has_real[i] && strcmp(seen.reals[i], "93.184.216.34") == 0) { parked_rule = true; }
    }
    ASSERTm("the parked pair is in the snapshot with its real address: its DNAT rule comes back", parked_rule);

    firc_ip_t b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g1", 2001, &b4, NULL));
    ASSERT_FALSEm("inside its window the parked address goes to nobody else", same_ip(&b4, &old4));
    firc_ip_t c4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "c.example.com", "g1", 1000 + 3601, &c4, NULL));
    ASSERTm("past the window it had -- counted from when it was parked, not from the load -- it is issued", same_ip(&c4, &old4));
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: an address free at a clean stop held back after it, burning a chunk per restart. */
TEST a_clean_restart_issues_free_addresses_at_once(void) {
    firc_fakeip_t *f = fresh(4096);
    firc_ip_t a4;
    char name[32];
    for (int i = 0; i < 250; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1000, &a4, NULL));
    }
    for (int i = 0; i < 20; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 90000, &a4, NULL));
    }
    firc_fakeip_reclaim(f, 90000);
    firc_fakeip_reclaim(f, 90000 + 3601);
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 90000 + 3602, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMT((size_t)20, restored, "%zu");
    for (int i = 0; i < 200; i++) {
        snprintf(name, sizeof(name), "new%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 90000 + 3603, &a4, NULL));
        ASSERT_EQ_FMTm("in the chunk the group already has", 0, a4.b[2], "%d");
    }
    size_t chunks = 0;
    firc_fakeip_walk_chunks(g, "g1", count_chunks, &chunks);
    ASSERT_EQ_FMT((size_t)1, chunks, "%zu");
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a chunk returned before a clean stop not retaken once its window ends. */
TEST a_returned_chunk_is_retaken_after_a_clean_restart(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4, gone4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", 1000, &gone4, NULL));
    firc_fakeip_drop_group(f, "g2", 1000);
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 1000 + 3700, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    firc_ip_t c4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "c.example.com", "g3", 1000 + 3701, &c4, NULL));
    ASSERT_EQ_FMTm("the returned chunk, not a fresh one", 1, c4.b[2], "%d");
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a file without its end line taken as exact. */
TEST a_truncated_file_is_not_taken_as_exact(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    FILE *tmp = tmpfile();
    ASSERT(tmp != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(f, tmp, true));
    long len = ftell(tmp);
    ASSERT(len > 8);
    ASSERT_EQ(0, ftruncate(fileno(tmp), len - 4));
    rewind(tmp);
    firc_fakeip_t *g = fresh(64);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(g, tmp, 2000, &restored));
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    firc_ip_t b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g1", 2001, &b4, NULL));
    ASSERTm("not exact: the chunk is parked to its end and a fresh one taken", b4.b[2] != a4.b[2]);
    fclose(tmp);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: an unclean file's park expiries trusted instead of a full window from the load. */
TEST an_unclean_files_parks_wait_a_full_window_from_the_load(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t y4, a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "y.example.com", "g1", 1000, &y4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 90000, &a4, NULL));
    firc_fakeip_reclaim(f, 90000);
    FILE *tmp = tmpfile();
    ASSERT(tmp != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(f, tmp, false));
    firc_fakeip_reclaim(f, 93601);
    firc_ip_t z4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "z.example.com", "g1", 93602, &z4, NULL));
    ASSERTm("z got y's old address, legitimately", same_ip(&z4, &y4));
    firc_fakeip_free(f);

    rewind(tmp);
    firc_fakeip_t *g = fresh(64);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(g, tmp, 93603, &restored));
    firc_fakeip_reclaim(g, 93604);
    for (int i = 0; i < 20; i++) {
        firc_ip_t w4;
        char name[32];
        snprintf(name, sizeof(name), "w%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 93605, &w4, NULL));
        ASSERT_FALSEm("z's client still holds it: not reissued for a window from the load", same_ip(&w4, &z4));
    }
    fclose(tmp);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a frontier derived for a group with no current chunk, below addresses already issued. */
TEST a_group_without_a_current_chunk_is_restored_without_a_frontier(void) {
    firc_fakeip_t *f = fresh(4096);
    firc_ip_t a4;
    char name[32];
    for (int i = 0; i < 254; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1000, &a4, NULL));
    }
    firc_ip_t one;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "one.example.com", "g1", 1000, &one, NULL));
    ASSERT_EQ(1, one.b[2]);
    for (int i = 0; i < 10; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 90000, &a4, NULL));
    }
    firc_fakeip_reclaim(f, 90000);
    firc_fakeip_reclaim(f, 90000 + 3601);
    size_t chunks = 0;
    firc_fakeip_walk_chunks(f, "g1", count_chunks, &chunks);
    ASSERT_EQ_FMTm("chunk 1 went back", (size_t)1, chunks, "%zu");
    firc_ip_t victim;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "victim.example.com", "g1", 90000 + 3602, &victim, NULL));
    ASSERT_EQ_FMTm("victim came from chunk 0's free set", 0, victim.b[2], "%d");
    ASSERTm("just above the highest live name -- where a derived frontier would start", victim.b[3] == 11);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "victim.example.com", "g2", 90000 + 3603, &a4, NULL));
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 90000 + 3610, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    for (int i = 0; i < 10; i++) {
        firc_ip_t w4;
        snprintf(name, sizeof(name), "w%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 90000 + 3611, &w4, NULL));
        ASSERT_FALSEm("the parked victim address is not handed out from a derived frontier", same_ip(&w4, &victim));
    }
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a distrusted pool not parking its current chunk to the end, as after a crash. */
TEST a_pool_can_be_told_to_distrust_its_exact_file(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    firc_fakeip_distrust(g, 2000);
    firc_ip_t b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g1", 2001, &b4, NULL));
    ASSERTm("a fresh chunk, as after a crash", b4.b[2] != a4.b[2]);
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

typedef struct { firc_ip_t addr[512]; size_t n; size_t dups; } addrs_t;
static void collect_v4(void *ud, const char *qname, const char *group_id, const firc_ip_t *fake,
                       const firc_ip_t *real) {
    (void)qname; (void)group_id; (void)real;
    addrs_t *a = ud;
    if (fake->len != 4) { return; }
    for (size_t i = 0; i < a->n; i++) { if (same_ip(&a->addr[i], fake)) { a->dups++; } }
    if (a->n < 512) { a->addr[a->n++] = *fake; }
}

/* Catches: distrust leaving parked addresses in the free set, so each is issued twice. */
TEST a_distrusted_pool_never_walks_an_address_twice(void) {
    firc_fakeip_t *f = fresh(1024);
    firc_ip_t a4;
    static firc_ip_t old[300];
    size_t n_old = 0;
    char name[32];
    for (int i = 0; i < 300; i++) {
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1000, &a4, NULL));
        if (i >= 5 && i < 260) { old[n_old++] = a4; }
    }
    for (int i = 0; i < 300; i++) {
        if (i >= 5 && i < 260) { continue; }
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 90000, &a4, NULL));
    }
    firc_fakeip_reclaim(f, 90000);
    firc_fakeip_reclaim(f, 93601);
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 93602, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    firc_fakeip_distrust(g, 93602);
    for (int i = 0; i < 30; i++) {
        snprintf(name, sizeof(name), "p%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 93603, &a4, NULL));
        for (size_t k = 0; k < n_old; k++) { ASSERT_FALSEm("a parked address is not issued", same_ip(&a4, &old[k])); }
    }
    firc_fakeip_reclaim(g, 93602 + 3601);
    for (int i = 0; i < 300; i++) {
        snprintf(name, sizeof(name), "q%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 93602 + 3602, &a4, NULL));
    }
    static addrs_t seen;
    memset(&seen, 0, sizeof(seen));
    firc_fakeip_walk(g, collect_v4, &seen);
    ASSERT_EQ_FMT((size_t)375, seen.n, "%zu");
    ASSERT_EQ_FMTm("no address is held by two live names", (size_t)0, seen.dups, "%zu");
    size_t back = 0;
    for (size_t k = 0; k < n_old; k++) {
        for (size_t i = 0; i < seen.n; i++) { if (same_ip(&old[k], &seen.addr[i])) { back++; break; } }
    }
    ASSERT_EQ_FMTm("every address parked by the distrust is issued again after the window", n_old, back, "%zu");
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a save whose rename failed clearing the dirty flag. */
TEST a_save_that_fails_after_writing_leaves_the_pool_dirty(void) {
    char dir[] = "/tmp/firc-pool-dir-XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char target[600], inner[700];
    snprintf(target, sizeof(target), "%s/pool.state", dir);
    snprintf(inner, sizeof(inner), "%s/keep", target);
    ASSERT_EQ(0, mkdir(target, 0700));
    FILE *k = fopen(inner, "w");
    ASSERT(k != NULL);
    fclose(k);
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT(firc_fakeip_save_file(f, target, false) != FIRC_OK);
    ASSERTm("nothing reached the disk, so the pool still wants saving", firc_fakeip_dirty_since_save(f));
    unlink(inner);
    rmdir(target);
    char tmp[700];
    snprintf(tmp, sizeof(tmp), "%s.tmp", target);
    unlink(tmp);
    rmdir(dir);
    firc_fakeip_free(f);
    PASS();
}

/* Catches: an unclean file's returned chunks retaken before a full window from the load. */
TEST an_unclean_files_returned_chunks_wait_a_full_window_from_the_load(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4, gone4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", 1000, &gone4, NULL));
    firc_fakeip_drop_group(f, "g2", 1000);
    FILE *tmp = tmpfile();
    ASSERT(tmp != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(f, tmp, false));
    rewind(tmp);
    firc_fakeip_t *g = fresh(64);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(g, tmp, 4700, &restored));
    fclose(tmp);
    firc_ip_t c4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "c.example.com", "g3", 4701, &c4, NULL));
    ASSERT_EQ_FMTm("a fresh chunk, not the returned one", 2, c4.b[2], "%d");
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "d.example.com", "g4", 4700 + 3601, &c4, NULL));
    ASSERT_EQ_FMTm("after a window from the load the returned chunk is taken", 1, c4.b[2], "%d");
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: an exact file's returned chunk held for years after a clock jump. */
TEST an_exact_files_returned_chunk_is_retaken_no_later_than_a_window_after_the_load(void) {
    size_t restored = 0;
    firc_fakeip_t *g = loaded_from_text(
        "map a.example.com g1 198.18.0.1 - fd37:9a00::1 - 5\n"
        "qchunk v4 198.18.1.0 1700000000\n"
        "cursor v4 2\n"
        "clean 1\n"
        "end\n", 64, &restored);
    firc_ip_t c4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "c.example.com", "g3", 2001, &c4, NULL));
    ASSERT_EQ_FMTm("inside the window: a fresh chunk", 2, c4.b[2], "%d");
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "d.example.com", "g4", 2000 + 3601, &c4, NULL));
    ASSERT_EQ_FMTm("a window after the load: the returned chunk", 1, c4.b[2], "%d");
    firc_fakeip_free(g);
    PASS();
}

/* Catches: an exact file's park held for years after a clock jump. */
TEST an_exact_files_park_is_released_no_later_than_a_window_after_the_load(void) {
    size_t restored = 0;
    firc_fakeip_t *g = loaded_from_text(
        "map a.example.com g1 198.18.0.1 - fd37:9a00::1 - 5\n"
        "park g1 v4 198.18.0.3 - 1700000000 -\n"
        "clean 1\n"
        "end\n", 64, &restored);
    firc_fakeip_reclaim(g, 2000 + 3601);
    firc_ip_t b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g1", 2000 + 3602, &b4, NULL));
    ASSERT_EQ_FMTm("the released address comes before the frontier", 3, b4.b[3], "%d");
    firc_fakeip_free(g);
    PASS();
}

/* Catches: distrust leaving the v6 mark in place, or not marking the pool dirty. */
TEST a_distrusted_pool_moves_its_v6_mark_and_wants_saving(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4, a6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, &a6));
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    FILE *tmp = tmpfile();
    ASSERT(tmp != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(g, tmp, false));
    fclose(tmp);
    ASSERT_FALSE(firc_fakeip_dirty_since_save(g));
    firc_fakeip_distrust(g, 2000);
    ASSERTm("distrust changed what the file should say", firc_fakeip_dirty_since_save(g));
    firc_ip_t b4, b6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g1", 2001, &b4, &b6));
    ASSERT_EQ_FMTm("v6: 2^32 past the old mark", 1, b6.b[11], "%d");
    ASSERT_EQ_FMTm("...and the mark itself was after a", 2, b6.b[15], "%d");
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a frontier left below a restored mapping in its own chunk. */
TEST a_mark_below_a_live_mapping_is_raised_past_it(void) {
    static const char *texts[4] = {
        "map live.example.com g1 198.18.0.5 - fd37:9a00::5 - 5\n"
        "mark g1 v4 198.18.0.0 3\n"
        "mark g1 v6 fd37:9a00:: 3\n"
        "clean 1\nend\n",
        "mark g1 v4 198.18.0.0 3\n"
        "mark g1 v6 fd37:9a00:: 3\n"
        "map live.example.com g1 198.18.0.5 - fd37:9a00::5 - 5\n"
        "clean 1\nend\n",
        "map live.example.com g1 198.18.1.5 - fd37:9a00:0:1::5 - 5\n"
        "mark g1 v4 198.18.1.0 3\n"
        "mark g1 v6 fd37:9a00:0:1:: 3\n"
        "clean 1\nend\n",
        "mark g1 v4 198.18.1.0 3\n"
        "mark g1 v6 fd37:9a00:0:1:: 3\n"
        "map live.example.com g1 198.18.1.5 - fd37:9a00:0:1::5 - 5\n"
        "clean 1\nend\n",
    };
    for (int t = 0; t < 4; t++) {
        size_t restored = 0;
        firc_fakeip_t *g = loaded_from_text(texts[t], 64, &restored);
        ASSERT_EQ_FMT((size_t)1, restored, "%zu");
        for (int i = 0; i < 6; i++) {
            firc_ip_t n4, n6;
            char name[32];
            snprintf(name, sizeof(name), "n%d.example.com", i);
            ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 2001, &n4, &n6));
            ASSERT_FALSEm("the live v4 address is not walked over", n4.len == 4 && n4.b[3] == 5);
            ASSERT_FALSEm("nor the live v6 one", n6.b[15] == 5 && n6.b[14] == 0 && n6.b[8] == 0);
        }
        firc_fakeip_free(g);
    }
    PASS();
}

/* Catches: a file with a refused line taken as exact, freeing addresses clients may hold. */
TEST a_file_with_a_refused_line_is_not_exact(void) {
    size_t restored = 0;
    firc_fakeip_t *g = loaded_from_text(
        "map a.example.com g1 198.18.0.3 - fd37:9a00::3 - 5\n"
        "map c.example.com g2 198.18.0.2 - fd37:9a00::2 - 5\n"
        "clean 1\nend\n", 64, &restored);
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    for (int i = 0; i < 5; i++) {
        firc_ip_t n4;
        char name[32];
        snprintf(name, sizeof(name), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 2001, &n4, NULL));
        ASSERTm("the refused line's address is parked, not free", n4.b[2] != 0 || n4.b[3] != 2);
    }
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a file missing an unrecordable name still written as exact. */
TEST a_name_the_writer_cannot_record_makes_the_file_not_exact(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t t4, a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "odd\tname.example.com", "g1", 1000, &t4, NULL));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    size_t restored = 0;
    firc_err_t err = FIRC_ERR_IO;
    firc_fakeip_t *g = reloaded(f, 2000, &restored, &err);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    firc_ip_t c4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "c.example.com", "g1", 2001, &c4, NULL));
    ASSERT_EQ_FMTm("not exact: chunk 0 is parked to its end, c gets a fresh chunk", 1, c4.b[2], "%d");
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a line over 511 bytes split at the buffer edge, its tail read as a line of its own. */
TEST an_overlong_line_is_refused_whole_not_split_into_two(void) {
    char text[2048];
    char pad[600];
    memset(pad, 'a', sizeof(pad));
    int n = snprintf(text, sizeof(text), "map %.*sqchunk v4 198.18.7.0 5000\n", 511 - 4, pad);
    snprintf(text + n, sizeof(text) - (size_t)n,
             "map a.example.com g1 198.18.0.1 - fd37:9a00::1 - 5\nclean 1\nend\n");
    size_t restored = 0;
    firc_fakeip_t *g = loaded_from_text(text, 64, &restored);
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    firc_ip_t b4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g2", 2001, &b4, NULL));
    ASSERT_EQ_FMTm("no tail was read as a qchunk line: the cursor did not move", 1, b4.b[2], "%d");
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a v4 chunk wider than /16 kept as the current chunk after a crash. */
TEST a_v4_chunk_wider_than_a_16_is_still_abandoned_after_a_crash(void) {
    firc_fakeip_cfg_t c = geometry(64);
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 0;
    c.v4.pool_cidr = 8;
    c.v4.chunk_cidr = 15;
    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &f));
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "saved.example.com", "g1", 1000, &a4, NULL));
    FILE *tmp = tmpfile();
    ASSERT(tmp != NULL);
    ASSERT_EQ(FIRC_OK, firc_fakeip_save(f, tmp, false));
    firc_ip_t after[3];
    char name[32];
    for (int i = 0; i < 3; i++) {
        snprintf(name, sizeof(name), "post%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, name, "g1", 1001, &after[i], NULL));
    }
    rewind(tmp);
    firc_fakeip_t *g = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &g));
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load(g, tmp, 2000, &restored));
    fclose(tmp);
    for (int i = 0; i < 30; i++) {
        firc_ip_t n4;
        snprintf(name, sizeof(name), "new%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 2001, &n4, NULL));
        for (int k = 0; k < 3; k++) { ASSERT_FALSEm("an address issued after the save is not reissued", same_ip(&n4, &after[k])); }
    }
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

/* Catches: a frontier left below a parked address in the mark's chunk. */
TEST a_park_above_the_mark_is_not_walked_over(void) {
    size_t restored = 0;
    firc_fakeip_t *g = loaded_from_text(
        "map a.example.com g1 198.18.0.5 - fd37:9a00::5 - 5\n"
        "mark g1 v4 198.18.0.0 6\n"
        "mark g1 v6 fd37:9a00:: 6\n"
        "park g1 v4 198.18.0.40 - 1700000000 held.example.com\n"
        "clean 1\nend\n", 128, &restored);
    for (int i = 0; i < 60; i++) {
        firc_ip_t n4;
        char name[32];
        snprintf(name, sizeof(name), "x%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, name, "g1", 2001, &n4, NULL));
        ASSERT_FALSEm("the parked address is not handed out", n4.b[2] == 0 && n4.b[3] == 40);
    }
    firc_fakeip_free(g);
    PASS();
}

/* Catches: refused park, qchunk, cursor or unknown lines not making the file inexact. */
TEST a_refused_park_or_qchunk_line_makes_the_file_not_exact(void) {
    static const char *texts[4] = {
        "map a.example.com g1 198.18.0.3 - fd37:9a00::3 - 5\n"
        "park g1 v4 198.19.255.7 - 5000 -\n"
        "clean 1\nend\n",
        "map a.example.com g1 198.18.0.3 - fd37:9a00::3 - 5\n"
        "qchunk v4 198.18.1.0 5000\n"
        "qchunk v4 198.18.1.0 5000\n"
        "clean 1\nend\n",
        "map a.example.com g1 198.18.0.3 - fd37:9a00::3 - 5\n"
        "cursor v4 nope\n"
        "clean 1\nend\n",
        "map a.example.com g1 198.18.0.3 - fd37:9a00::3 - 5\n"
        "garbage\n"
        "clean 1\nend\n",
    };
    for (int t = 0; t < 4; t++) {
        size_t restored = 0;
        firc_fakeip_t *g = loaded_from_text(texts[t], 64, &restored);
        firc_ip_t b4;
        ASSERT_EQ(FIRC_OK, firc_fakeip_get(g, "b.example.com", "g1", 2001, &b4, NULL));
        ASSERT_FALSEm("not exact: nothing from chunk 0's gaps", b4.b[2] == 0);
        firc_fakeip_free(g);
    }
    PASS();
}

/* Catches: the file save and load not round-tripping, or a missing file not reported as NOENT. */
TEST the_file_round_trip_and_a_missing_file(void) {
    char path[] = "/tmp/firc-pool-XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    close(fd);
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000, &a4, NULL));
    ASSERT(firc_fakeip_dirty_since_save(f));
    ASSERT_EQ(FIRC_OK, firc_fakeip_save_file(f, path, true));
    ASSERT_FALSE(firc_fakeip_dirty_since_save(f));
    firc_fakeip_t *g = fresh(64);
    size_t restored = 0;
    ASSERT_EQ(FIRC_OK, firc_fakeip_load_file(g, path, 2000, &restored));
    ASSERT_EQ_FMT((size_t)1, restored, "%zu");
    unlink(path);
    ASSERT_EQ(FIRC_ERR_NOENT, firc_fakeip_load_file(g, path, 2000, &restored));
    firc_fakeip_free(f);
    firc_fakeip_free(g);
    PASS();
}

static const char *or_none(const char *s) { return s != NULL ? s : "(none)"; }

TEST a_restored_pool_names_the_same_addresses(void) {
    firc_fakeip_t *f = fresh(64);
    firc_ip_t a4, a6, b4, b6, p4, p6;
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "parked.example.com", "g1", 1000, &p4, &p6));
    firc_fakeip_reclaim(f, 1000 + 86400);
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "a.example.com", "g1", 1000 + 86400, &a4, &a6));
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f, "b.example.com", "g2", 1000 + 86400, &b4, &b6));
    for (int clean = 0; clean < 2; clean++) {
        size_t restored = 0;
        firc_err_t err = FIRC_ERR_IO;
        firc_fakeip_t *g = reloaded_as(f, clean != 0, 1000 + 86400, &restored, &err);
        ASSERT_EQ(FIRC_OK, err);
        ASSERT_EQ_FMT((size_t)2, restored, "%zu");
        ASSERT_STR_EQ("a.example.com", or_none(firc_fakeip_name_of(g, &a4)));
        ASSERT_STR_EQ("a.example.com", or_none(firc_fakeip_name_of(g, &a6)));
        ASSERT_STR_EQ("b.example.com", or_none(firc_fakeip_name_of(g, &b4)));
        ASSERT_STR_EQ("b.example.com", or_none(firc_fakeip_name_of(g, &b6)));
        ASSERT_EQ(NULL, firc_fakeip_name_of(g, &p4));
        ASSERT_EQ(NULL, firc_fakeip_name_of(g, &p6));
        firc_fakeip_free(g);
    }
    firc_fakeip_free(f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_restored_name_keeps_its_addresses_group_and_reals);
    RUN_TEST(new_names_after_a_restart_avoid_restored_and_recently_freed_addresses);
    RUN_TEST(a_file_from_another_geometry_is_refused);
    RUN_TEST(a_broken_line_is_skipped_not_fatal);
    RUN_TEST(last_seen_survives_so_the_idle_sweep_is_not_reset);
    RUN_TEST(each_groups_chunks_are_restored);
    RUN_TEST(a_groups_older_full_chunk_stays_its_own);
    RUN_TEST(a_chunk_nobody_holds_any_more_comes_back_after_the_window);
    RUN_TEST(the_file_round_trip_and_a_missing_file);
    RUN_TEST(the_mark_names_the_current_chunk_whatever_its_index);
    RUN_TEST(addresses_issued_after_the_last_save_are_not_reissued_after_a_crash);
    RUN_TEST(a_broken_line_in_the_middle_costs_only_itself);
    RUN_TEST(refused_lines_and_the_cap);
    RUN_TEST(each_name_comes_back_under_its_own_group);
    RUN_TEST(the_file_is_replaced_not_overwritten);
    RUN_TEST(a_fresh_chunk_after_a_restart_is_saved_at_once);
    RUN_TEST(a_chunk_returned_before_the_stop_is_parked_after_it);
    RUN_TEST(an_emptied_chunk_goes_back_to_the_pool);
    RUN_TEST(a_clean_stop_costs_no_fresh_chunk);
    RUN_TEST(a_clean_file_stops_being_exact_once_loaded);
    RUN_TEST(parked_pairs_survive_a_clean_stop);
    RUN_TEST(a_clean_restart_issues_free_addresses_at_once);
    RUN_TEST(a_returned_chunk_is_retaken_after_a_clean_restart);
    RUN_TEST(a_truncated_file_is_not_taken_as_exact);
    RUN_TEST(an_unclean_files_parks_wait_a_full_window_from_the_load);
    RUN_TEST(a_group_without_a_current_chunk_is_restored_without_a_frontier);
    RUN_TEST(a_pool_can_be_told_to_distrust_its_exact_file);
    RUN_TEST(a_distrusted_pool_never_walks_an_address_twice);
    RUN_TEST(a_save_that_fails_after_writing_leaves_the_pool_dirty);
    RUN_TEST(an_unclean_files_returned_chunks_wait_a_full_window_from_the_load);
    RUN_TEST(an_exact_files_returned_chunk_is_retaken_no_later_than_a_window_after_the_load);
    RUN_TEST(an_exact_files_park_is_released_no_later_than_a_window_after_the_load);
    RUN_TEST(a_distrusted_pool_moves_its_v6_mark_and_wants_saving);
    RUN_TEST(a_mark_below_a_live_mapping_is_raised_past_it);
    RUN_TEST(a_file_with_a_refused_line_is_not_exact);
    RUN_TEST(a_name_the_writer_cannot_record_makes_the_file_not_exact);
    RUN_TEST(an_overlong_line_is_refused_whole_not_split_into_two);
    RUN_TEST(a_v4_chunk_wider_than_a_16_is_still_abandoned_after_a_crash);
    RUN_TEST(a_park_above_the_mark_is_not_walked_over);
    RUN_TEST(a_refused_park_or_qchunk_line_makes_the_file_not_exact);
    RUN_TEST(a_restored_pool_names_the_same_addresses);
    GREATEST_MAIN_END();
}
