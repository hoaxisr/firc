#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "firc/fields_file.h"

typedef struct {
    char dir[64];
    char path[128];
    char tmp[136];
} fx_t;

static bool up(fx_t *f) {
    snprintf(f->dir, sizeof(f->dir), "/tmp/firc-fields-XXXXXX");
    if (mkdtemp(f->dir) == NULL) { return false; }
    snprintf(f->path, sizeof(f->path), "%s/fields.state", f->dir);
    snprintf(f->tmp, sizeof(f->tmp), "%s.tmp", f->path);
    return true;
}

static void down(fx_t *f) {
    unlink(f->path);
    unlink(f->tmp);
    rmdir(f->tmp);
    rmdir(f->dir);
}

static bool write_text(const char *path, const char *text) {
    FILE *fp = fopen(path, "w");
    if (fp == NULL) { return false; }
    fputs(text, fp);
    return fclose(fp) == 0;
}

static size_t read_text(const char *path, char *buf, size_t cap) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) { return 0; }
    size_t n = fread(buf, 1, cap - 1, fp);
    buf[n] = '\0';
    fclose(fp);
    return n;
}

/* Catches: an entry lost, reordered or renumbered between save and load. */
TEST a_saved_map_loads_back_identically(void) {
    fx_t f;
    ASSERT(up(&f));
    const firc_rtnl_field_t v[2] = {{"aaaaaaaa", 5}, {"bbbbbbbb", 1}};
    ASSERT_EQ(FIRC_OK, firc_fields_file_save(f.path, v, 2));
    firc_fields_entry_t *out = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_fields_file_load(f.path, &out, &n));
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    ASSERT_STR_EQ("aaaaaaaa", out[0].owner);
    ASSERT_EQ_FMT(5u, out[0].field, "%u");
    ASSERT_STR_EQ("bbbbbbbb", out[1].owner);
    ASSERT_EQ_FMT(1u, out[1].field, "%u");
    free(out);
    down(&f);
    PASS();
}

/* Catches: a format drift that the writer and the loader of one build share, the line separator included. */
TEST the_bytes_are_the_documented_format(void) {
    fx_t f;
    ASSERT(up(&f));
    const firc_rtnl_field_t v[2] = {{"aaaaaaaa", 5}, {"bbbbbbbb", 12}};
    ASSERT_EQ(FIRC_OK, firc_fields_file_save(f.path, v, 2));
    char buf[256] = {0};
    read_text(f.path, buf, sizeof(buf));
    ASSERT_STR_EQ("firc-fields\nfield aaaaaaaa 5\nfield bbbbbbbb 12\nend\n", buf);
    struct stat st;
    ASSERT_EQ(0, stat(f.path, &st));
    ASSERT_EQ_FMT(0600u, (unsigned)(st.st_mode & 0777), "%o");
    down(&f);
    PASS();
}

/* Catches: a write in place (a reader of the old file sees it change), a .tmp left behind, or a stale map outliving a failed save. */
TEST the_file_is_replaced_not_overwritten(void) {
    fx_t f;
    ASSERT(up(&f));
    const firc_rtnl_field_t one[1] = {{"aaaaaaaa", 5}};
    const firc_rtnl_field_t two[1] = {{"bbbbbbbb", 7}};
    ASSERT_EQ(FIRC_OK, firc_fields_file_save(f.path, one, 1));
    ASSERT(access(f.tmp, F_OK) != 0);
    FILE *reader = fopen(f.path, "r");
    ASSERT(reader != NULL);
    struct stat before, after;
    ASSERT_EQ(0, fstat(fileno(reader), &before));
    ASSERT_EQ(FIRC_OK, firc_fields_file_save(f.path, two, 1));
    ASSERT(access(f.tmp, F_OK) != 0);
    ASSERT_EQ(0, stat(f.path, &after));
    ASSERT(before.st_ino != after.st_ino);
    char old[128] = {0};
    size_t got = fread(old, 1, sizeof(old) - 1, reader);
    fclose(reader);
    ASSERT_EQ_FMT(strlen("firc-fields\nfield aaaaaaaa 5\nend\n"), got, "%zu");
    ASSERT_STR_EQ("firc-fields\nfield aaaaaaaa 5\nend\n", old);
    firc_fields_entry_t *out = NULL;
    size_t n = 0;
    ASSERT_EQ(FIRC_OK, firc_fields_file_load(f.path, &out, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_STR_EQ("bbbbbbbb", out[0].owner);
    ASSERT_EQ_FMT(7u, out[0].field, "%u");
    free(out);

    ASSERT_EQ(0, mkdir(f.tmp, 0700));
    ASSERT(firc_fields_file_save(f.path, one, 1) != FIRC_OK);
    ASSERT(access(f.path, F_OK) != 0);
    down(&f);
    PASS();
}

/* Catches: a partial or malformed map accepted, or a file without end read as whole. */
TEST anything_the_writer_could_not_have_produced_refuses_the_whole_file(void) {
    fx_t f;
    ASSERT(up(&f));
    const char *bad[] = {
        "firc-fields\nfield aaaaaaaa 5\nfield zz 3\nend\n",
        "firc-fields\nfield aaaaaaaa 5\nfield aaaaaaaa 6\nend\n",
        "firc-fields\nfield aaaaaaaa 5\nfield bbbbbbbb 5\nend\n",
        "firc-fields\nfield aaaaaaaa 0\nend\n",
        "firc-fields\nfield aaaaaaaa 256\nend\n",
        "firc-fields\nfield aaaaaaaa 5\n",
        "firc-fields 1\nend\n",
        "firc-fieldz\nend\n",
        "\nend\n",
        "firc-fields\nfield aaaaaaaaa 5\nend\n",
        "firc-fields\nfield AAAAAAAA 5\nend\n",
        "firc-fields\nfield aaaaaaaa 5x\nend\n",
        "firc-fields\nend\nfield aaaaaaaa 5\n",
        "firc-fields\nfield aaaaaaaa 5\nend",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ASSERT(write_text(f.path, bad[i]));
        firc_fields_entry_t *out = (firc_fields_entry_t *)&f;
        size_t n = 99;
        ASSERT_EQ_FMTm(bad[i], (int)FIRC_ERR_INVAL, (int)firc_fields_file_load(f.path, &out, &n), "%d");
        ASSERT_EQ_FMT((size_t)0, n, "%zu");
        ASSERT(out == NULL);
    }
    ASSERT(write_text(f.path, "firc-fields\nend\n"));
    firc_fields_entry_t *out = NULL;
    size_t n = 99;
    ASSERT_EQ(FIRC_OK, firc_fields_file_load(f.path, &out, &n));
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    free(out);
    unlink(f.path);
    ASSERT_EQ(FIRC_ERR_NOENT, firc_fields_file_load(f.path, &out, &n));
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    down(&f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_saved_map_loads_back_identically);
    RUN_TEST(the_bytes_are_the_documented_format);
    RUN_TEST(the_file_is_replaced_not_overwritten);
    RUN_TEST(anything_the_writer_could_not_have_produced_refuses_the_whole_file);
    GREATEST_MAIN_END();
}
