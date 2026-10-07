#include "greatest.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fake_conntrack.h"
#include "fake_rtnl.h"
#include "firc/mark.h"
#include "firc/models.h"
#include "firc/stable_fields.h"

typedef struct {
    fake_rtnl_t *kernel;
    firc_rtnl_t *rtnl;
    fake_ct_t *ctk;
    firc_ct_t *ct;
    firc_group_t *g;
    firc_config_t cfg;
    char dir[64];
    char path[128];
} fx_t;

static bool up(fx_t *f, const char *group_id, bool enabled) {
    memset(f, 0, sizeof(*f));
    f->kernel = fake_rtnl_start(&f->rtnl);
    f->ctk = fake_ct_start(&f->ct);
    if (f->kernel == NULL || f->ctk == NULL) { return false; }
    if (group_id != NULL) {
        f->g = firc_group_new();
        if (f->g == NULL || firc_id_parse(group_id, &f->g->id) != FIRC_OK) { return false; }
        f->g->enable = enabled;
        f->cfg.groups = &f->g;
        f->cfg.n_groups = 1;
    }
    snprintf(f->dir, sizeof(f->dir), "/tmp/firc-stable-XXXXXX");
    if (mkdtemp(f->dir) == NULL) { return false; }
    snprintf(f->path, sizeof(f->path), "%s/fields.state", f->dir);
    return true;
}

static void down(fx_t *f) {
    if (f->g != NULL) { firc_group_free(f->g); }
    firc_ct_close(f->ct);
    fake_ct_stop(f->ctk);
    firc_rtnl_close(f->rtnl);
    fake_rtnl_stop(f->kernel);
    char tmp[136];
    snprintf(tmp, sizeof(tmp), "%s.tmp", f->path);
    unlink(tmp);
    unlink(f->path);
    rmdir(f->dir);
}

static uint32_t alloc(fx_t *f, const char *owner) {
    uint32_t field = 0;
    if (firc_rtnl_alloc_mark_field_for(f->rtnl, owner, &field) != FIRC_OK) { return 0; }
    return field;
}

static bool write_text(const char *path, const char *text) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) { return false; }
    fputs(text, fp);
    return fclose(fp) == 0;
}

static uint32_t field_in_file(const char *path, const char *owner, size_t *n_out) {
    firc_fields_entry_t *v = NULL;
    size_t n = 0;
    uint32_t got = 0;
    if (firc_fields_file_load(path, &v, &n) == FIRC_OK) {
        for (size_t i = 0; i < n; i++) {
            if (strcmp(v[i].owner, owner) == 0) { got = v[i].field; }
        }
    }
    if (n_out != NULL) { *n_out = n; }
    free(v);
    return got;
}

/* Catches: a dead field handed on with its owner's flows alive, or a live owner's flows flushed. */
TEST a_gone_owner_s_flows_are_flushed_and_its_field_is_free(void) {
    fx_t f;
    ASSERT(up(&f, "0000000a", true));
    const uint8_t s1[4] = {192, 168, 1, 10}, d1[4] = {10, 1, 2, 3};
    const uint8_t s2[4] = {192, 168, 1, 11}, d2[4] = {10, 1, 2, 4};
    const uint8_t s6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10};
    const uint8_t d6[16] = {0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11};
    fake_ct_add(f.ctk, AF_INET, s1, d1, d1, 0x40020000u);
    fake_ct_add(f.ctk, AF_INET, s2, d2, d2, 0x40010000u);
    fake_ct_add(f.ctk, AF_INET6, s6, d6, d6, 0x40020000u);
    firc_fields_entry_t map[2] = {{"0000000a", 1}, {"0000000b", 2}};
    size_t n = 2;

    firc_stable_fields_adoption_t r = firc_stable_fields_adopt(f.rtnl, f.ct, &f.cfg, true, map, &n);
    ASSERT_EQ_FMT((size_t)1, r.kept, "%zu");
    ASSERT_EQ_FMT((size_t)1, r.freed, "%zu");
    ASSERT_EQ_FMT((size_t)0, r.reserved, "%zu");
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_STR_EQ("0000000a", map[0].owner);
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.ctk), "%zu");
    ASSERT(fake_ct_deleted(f.ctk, d1, 4));
    ASSERT(fake_ct_deleted(f.ctk, d6, 16));
    ASSERT_FALSE(fake_ct_deleted(f.ctk, d2, 4));
    uint32_t value = 0, mask = 0;
    ASSERT(fake_ct_dump_filtered_on_mark(f.ctk, &value, &mask));
    ASSERT_EQ_FMT(0x40020000u, value, "%#x");
    ASSERT_EQ_FMT(0x40ff0000u, mask, "%#x");
    ASSERT_EQ_FMT(1u, alloc(&f, "0000000a"), "%u");
    ASSERT_EQ_FMT(2u, alloc(&f, "0000000c"), "%u");
    down(&f);
    PASS();
}

/* Catches: a disabled group treated as gone, its flows flushed and its field given away. */
TEST a_disabled_group_s_entry_is_seeded_not_flushed(void) {
    fx_t f;
    ASSERT(up(&f, "0000000a", false));
    const uint8_t s1[4] = {192, 168, 1, 10}, d1[4] = {10, 1, 2, 3};
    fake_ct_add(f.ctk, AF_INET, s1, d1, d1, 0x40040000u);
    firc_fields_entry_t map[1] = {{"0000000a", 4}};
    size_t n = 1;

    firc_stable_fields_adoption_t r = firc_stable_fields_adopt(f.rtnl, f.ct, &f.cfg, true, map, &n);
    ASSERT_EQ_FMT((size_t)1, r.kept, "%zu");
    ASSERT_EQ_FMT((size_t)0, r.freed, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.ctk), "%zu");
    ASSERT_EQ_FMT(4u, alloc(&f, "0000000a"), "%u");
    ASSERT_EQ_FMT(1u, alloc(&f, "0000000c"), "%u");
    down(&f);
    PASS();
}

/* Catches: a dead entry kept when conntrack is absent, pinning its field for ever. */
TEST without_conntrack_a_dead_entry_is_still_dropped(void) {
    fx_t f;
    ASSERT(up(&f, NULL, true));
    firc_fields_entry_t map[1] = {{"0000000b", 2}};
    size_t n = 1;

    firc_stable_fields_adoption_t r = firc_stable_fields_adopt(f.rtnl, NULL, &f.cfg, true, map, &n);
    ASSERT_EQ_FMT((size_t)1, r.freed, "%zu");
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    ASSERT_EQ_FMT(1u, alloc(&f, "0000000c"), "%u");
    ASSERT_EQ_FMT(2u, alloc(&f, "0000000d"), "%u");
    down(&f);
    PASS();
}

/* Catches: a dead field freed although its flows could not be flushed, so a new group inherits them. */
TEST a_gone_owner_whose_flush_fails_keeps_its_field_reserved(void) {
    fx_t f;
    ASSERT(up(&f, "0000000a", true));
    fake_ct_fail_next_dump(f.ctk, EPERM);
    firc_fields_entry_t map[2] = {{"0000000a", 1}, {"0000000b", 2}};
    size_t n = 2;

    firc_stable_fields_adoption_t r = firc_stable_fields_adopt(f.rtnl, f.ct, &f.cfg, true, map, &n);
    ASSERT_EQ_FMT((size_t)1, r.kept, "%zu");
    ASSERT_EQ_FMT((size_t)0, r.freed, "%zu");
    ASSERT_EQ_FMT((size_t)1, r.reserved, "%zu");
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    ASSERT_EQ_FMT(3u, alloc(&f, "0000000c"), "%u");
    down(&f);
    PASS();
}

/* Catches: a seed the allocator refused counted as kept, so the sweep vouches for a field the group lost. */
TEST a_refused_seed_is_not_kept(void) {
    fx_t f;
    ASSERT(up(&f, "0000000a", true));
    ASSERT_EQ(FIRC_OK, firc_rtnl_seed_mark_field(f.rtnl, "0000000f", 1));
    firc_fields_entry_t *map = calloc(1, sizeof(*map));
    ASSERT(map != NULL);
    snprintf(map[0].owner, sizeof(map[0].owner), "0000000a");
    map[0].field = 1;
    size_t n = 1;

    firc_stable_fields_adoption_t r = firc_stable_fields_adopt(f.rtnl, f.ct, &f.cfg, true, map, &n);
    ASSERT_EQ_FMT((size_t)0, r.kept, "%zu");
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    firc_stable_fields_t sf = {.loaded = true, .v = map, .n = n};
    ASSERT_FALSE(firc_stable_fields_kept(&sf, "0000000a", firc_mark_group_value(1)));
    firc_stable_fields_release(&sf);
    down(&f);
    PASS();
}

/* Catches: a start with no groups file flushing and freeing every group's field for good. */
TEST without_a_groups_file_nothing_is_flushed_and_every_entry_stays(void) {
    fx_t f;
    ASSERT(up(&f, NULL, true));
    const uint8_t s1[4] = {192, 168, 1, 10}, d1[4] = {10, 1, 2, 3};
    fake_ct_add(f.ctk, AF_INET, s1, d1, d1, 0x40020000u);
    firc_fields_entry_t map[1] = {{"0000000b", 2}};
    size_t n = 1;

    firc_stable_fields_adoption_t r = firc_stable_fields_adopt(f.rtnl, f.ct, &f.cfg, false, map, &n);
    ASSERT_EQ_FMT((size_t)0, r.freed, "%zu");
    ASSERT_EQ_FMT((size_t)1, r.reserved, "%zu");
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_EQ_FMT((size_t)1, fake_ct_remaining(f.ctk), "%zu");
    ASSERT_EQ_FMT((size_t)0, fake_ct_deletes(f.ctk), "%zu");
    ASSERT_EQ_FMT(1u, alloc(&f, "0000000c"), "%u");
    ASSERT_EQ_FMT(3u, alloc(&f, "0000000d"), "%u");
    down(&f);
    PASS();
}

/* Catches: the map not saved once after adoption (dead entries stay on disk) or not saved at a later change. */
TEST a_loaded_map_is_saved_without_its_dead_and_again_at_every_change(void) {
    fx_t f;
    ASSERT(up(&f, "0000000a", true));
    ASSERT(write_text(f.path, "firc-fields\nfield 0000000a 1\nfield 0000000b 2\nend\n"));
    firc_stable_fields_t sf;

    ASSERT(firc_stable_fields_start(&sf, f.path, f.rtnl, f.ct, &f.cfg, true));
    ASSERT(sf.loaded);
    size_t n = 0;
    ASSERT_EQ_FMT(1u, field_in_file(f.path, "0000000a", &n), "%u");
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT(firc_stable_fields_kept(&sf, "0000000a", firc_mark_group_value(1)));
    ASSERT_FALSE(firc_stable_fields_kept(&sf, "0000000a", firc_mark_group_value(2)));
    ASSERT_FALSE(firc_stable_fields_kept(&sf, "0000000b", firc_mark_group_value(2)));

    ASSERT_EQ_FMT(2u, alloc(&f, "0000000c"), "%u");
    ASSERT_EQ_FMT(2u, field_in_file(f.path, "0000000c", &n), "%u");
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    firc_stable_fields_release(&sf);
    ASSERT(sf.loaded);
    down(&f);
    PASS();
}

/* Catches: a malformed map kept on disk, or the on-change save left out when the start had no map. */
TEST a_malformed_map_is_removed_and_changes_are_still_saved(void) {
    fx_t f;
    ASSERT(up(&f, "0000000a", true));
    ASSERT(write_text(f.path, "firc-fields\nfield 0000000a 1\n"));
    firc_stable_fields_t sf;

    ASSERT_FALSE(firc_stable_fields_start(&sf, f.path, f.rtnl, f.ct, &f.cfg, true));
    ASSERT_FALSE(sf.loaded);
    ASSERT(access(f.path, F_OK) != 0);
    ASSERT_EQ_FMT(1u, alloc(&f, "0000000a"), "%u");
    ASSERT_EQ_FMT(1u, field_in_file(f.path, "0000000a", NULL), "%u");
    firc_stable_fields_release(&sf);
    down(&f);
    PASS();
}

/* Catches: a map that could not be read (not malformed) deleted, so a passing fault loses it for good. */
TEST a_map_that_cannot_be_read_is_left_in_place(void) {
    fx_t f;
    ASSERT(up(&f, "0000000a", true));
    ASSERT_EQ(0, symlink(f.path, f.path));
    firc_stable_fields_t sf;

    ASSERT_FALSE(firc_stable_fields_start(&sf, f.path, f.rtnl, f.ct, &f.cfg, true));
    struct stat st;
    ASSERT_EQ(0, lstat(f.path, &st));
    ASSERT(S_ISLNK(st.st_mode));
    firc_rtnl_watch_mark_fields(f.rtnl, NULL, NULL);
    firc_stable_fields_release(&sf);
    down(&f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_gone_owner_s_flows_are_flushed_and_its_field_is_free);
    RUN_TEST(a_disabled_group_s_entry_is_seeded_not_flushed);
    RUN_TEST(without_conntrack_a_dead_entry_is_still_dropped);
    RUN_TEST(a_gone_owner_whose_flush_fails_keeps_its_field_reserved);
    RUN_TEST(a_refused_seed_is_not_kept);
    RUN_TEST(without_a_groups_file_nothing_is_flushed_and_every_entry_stays);
    RUN_TEST(a_loaded_map_is_saved_without_its_dead_and_again_at_every_change);
    RUN_TEST(a_malformed_map_is_removed_and_changes_are_still_saved);
    RUN_TEST(a_map_that_cannot_be_read_is_left_in_place);
    GREATEST_MAIN_END();
}
