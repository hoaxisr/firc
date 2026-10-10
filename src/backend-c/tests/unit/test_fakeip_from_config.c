#include "greatest.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "firc/fakeip_from_config.h"
#include "firc/yamlio.h"

static char g_ula[192];

static void ula_path(const char *name) {
    const char *dir = getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
    snprintf(g_ula, sizeof(g_ula), "%s/%s", dir, name);
    unlink(g_ula);
}

/* Catches: the default config translated wrongly into the pool's numeric form. */
TEST the_shipped_defaults_build_a_working_pool(void) {
    ula_path("fromcfg_defaults");
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));

    firc_fakeip_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    ASSERT_EQ(FIRC_OK, firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc));

    ASSERT_EQ_FMT(4, (int)pc.v4.base.len, "%d");
    ASSERT_EQ_FMT(198, (int)pc.v4.base.b[0], "%d");
    ASSERT_EQ_FMT(18, (int)pc.v4.base.b[1], "%d");
    ASSERT_EQ_FMT(15, (int)pc.v4.pool_cidr, "%d");
    ASSERT_EQ_FMT(24, (int)pc.v4.chunk_cidr, "%d");

    ASSERT_EQ_FMT(16, (int)pc.v6.base.len, "%d");
    ASSERT_EQ_FMTm("RFC 4193 locally-assigned", 0xfd, (int)pc.v6.base.b[0], "%02x");
    ASSERT_EQ_FMT(48, (int)pc.v6.pool_cidr, "%d");
    ASSERT_EQ_FMT(64, (int)pc.v6.chunk_cidr, "%d");

    ASSERT_EQ_FMT((int64_t)300, pc.clamp_secs, "%" PRId64);
    ASSERT_EQ_FMT((int64_t)3600, pc.idle_secs, "%" PRId64);
    ASSERT_EQ_FMT((size_t)65536, pc.max_names, "%zu");

    firc_fakeip_t *f = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&pc, &f));
    firc_fakeip_free(f);

    unlink(g_ula);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a pinned v6 pool ignored, or a ULA prefix file generated anyway. */
TEST a_pinned_v6_pool_is_used_and_nothing_is_generated(void) {
    ula_path("fromcfg_pinned");
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&cfg,
                                               "configVersion: 0.1.0\napp:\n  addressPool:\n"
                                               "    v6:\n      pool: fd12:3456:789a::/48\n",
                                               strlen("configVersion: 0.1.0\napp:\n  addressPool:\n"
                                                      "    v6:\n      pool: fd12:3456:789a::/48\n")));

    firc_fakeip_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    ASSERT_EQ(FIRC_OK, firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc));

    ASSERT_EQ_FMT(0xfd, (int)pc.v6.base.b[0], "%02x");
    ASSERT_EQ_FMT(0x12, (int)pc.v6.base.b[1], "%02x");
    ASSERT_EQ_FMT(0x34, (int)pc.v6.base.b[2], "%02x");
    ASSERT_EQ_FMT(0x56, (int)pc.v6.base.b[3], "%02x");
    ASSERT_EQ_FMT(48, (int)pc.v6.pool_cidr, "%d");

    ASSERT_EQm("pinning must not generate a prefix file", -1, access(g_ula, F_OK));
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: an operator's v4 or non-ULA v6 pool not carried through exactly. */
TEST an_explicit_v4_pool_is_carried_through(void) {
    ula_path("fromcfg_v4");
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc = "configVersion: 0.1.0\napp:\n  addressPool:\n"
                      "    v4:\n      pool: 100.64.0.0/10\n      chunk: 26\n"
                      "    ttlClamp: 90s\n    maxNames: 1234\n";
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&cfg, doc, strlen(doc)));

    firc_fakeip_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    ASSERT_EQ(FIRC_OK, firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc));

    ASSERT_EQ_FMT(100, (int)pc.v4.base.b[0], "%d");
    ASSERT_EQ_FMT(64, (int)pc.v4.base.b[1], "%d");
    ASSERT_EQ_FMT(10, (int)pc.v4.pool_cidr, "%d");
    ASSERT_EQ_FMT(26, (int)pc.v4.chunk_cidr, "%d");
    ASSERT_EQ_FMT((int64_t)90, pc.clamp_secs, "%" PRId64);
    ASSERT_EQ_FMT((int64_t)3600, pc.idle_secs, "%" PRId64);
    ASSERT_EQ_FMT((size_t)1234, pc.max_names, "%zu");

    unlink(g_ula);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a malformed pool from an in-memory config giving a half-filled structure. */
TEST a_pool_that_does_not_parse_is_refused(void) {
    ula_path("fromcfg_bad");
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    free(cfg.app.fakeip.v4.pool);
    cfg.app.fakeip.v4.pool = strdup("not-an-address");

    firc_fakeip_cfg_t pc;
    memset(&pc, 0xA5, sizeof(pc));
    firc_fakeip_cfg_t before = pc;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc));
    ASSERT_MEM_EQm("a refusal must not half-fill the output", &before, &pc, sizeof(pc));

    free(cfg.app.fakeip.v4.pool);
    cfg.app.fakeip.v4.pool = strdup("fd00:1234::/48");
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc));

    free(cfg.app.fakeip.v4.pool);
    cfg.app.fakeip.v4.pool = strdup("198.18.0.0/15");
    free(cfg.app.fakeip.v6.pool);
    cfg.app.fakeip.v6.pool = strdup("198.18.0.0/15");
    ASSERT_EQ(FIRC_ERR_INVAL, firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc));

    firc_config_clear(&cfg);
    PASS();
}

/* Catches: sub-second clamps truncated silently, or a clamp whose window passes the ceiling accepted. */
TEST windows_that_do_not_convert_cleanly_are_refused(void) {
    static const struct {
        const char *why;
        int64_t clamp_ns;
    } bad[] = {
        {"a clamp below a second truncates to zero", FIRC_DURATION_MS * 999},
        {"and one that is not a whole number of seconds is rounded", FIRC_DURATION_MS * 1500},
        {"a negative clamp", -FIRC_DURATION_SEC * 5},
        {"a clamp past the pool's one-year ceiling", FIRC_DURATION_SEC * 366 * 24 * 3600},
        {"a clamp past half a year derives a window past the ceiling",
         FIRC_DURATION_SEC * 183 * 24 * 3600},
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ula_path("fromcfg_window");
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        cfg.app.fakeip.ttl_clamp = bad[i].clamp_ns;
        firc_fakeip_cfg_t pc;
        memset(&pc, 0, sizeof(pc));
        firc_err_t got = firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc);
        firc_config_clear(&cfg);
        unlink(g_ula);
        if (got != FIRC_ERR_INVAL) { FAILm(bad[i].why); }
    }

    ula_path("fromcfg_window_ok");
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    cfg.app.fakeip.ttl_clamp = FIRC_DURATION_SEC;
    firc_fakeip_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    ASSERT_EQ(FIRC_OK, firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc));
    ASSERT_EQ_FMT((int64_t)1, pc.clamp_secs, "%" PRId64);
    ASSERT_EQ_FMT((int64_t)3600, pc.idle_secs, "%" PRId64);
    firc_config_clear(&cfg);
    unlink(g_ula);
    PASS();
}

/* Catches: the window not derived from the clamp, the one-hour floor missing, or the factor not two. */
TEST the_idle_window_is_twice_the_clamp_never_under_an_hour(void) {
    ASSERT_EQ((long long)3600, (long long)firc_fakeip_idle_for_clamp(1));
    ASSERT_EQ((long long)3600, (long long)firc_fakeip_idle_for_clamp(300));
    ASSERT_EQ((long long)3600, (long long)firc_fakeip_idle_for_clamp(1800));
    ASSERT_EQ((long long)3602, (long long)firc_fakeip_idle_for_clamp(1801));
    ASSERT_EQ((long long)172800, (long long)firc_fakeip_idle_for_clamp(86400));
    PASS();
}

/* Catches: an idleWindow left in an old file still read, or refused, instead of ignored. */
TEST an_idle_window_in_an_old_file_is_ignored(void) {
    ula_path("fromcfg_old_idle");
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc = "configVersion: 0.1.0\napp:\n  addressPool:\n    ttlClamp: 90s\n    idleWindow: 12h\n";
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&cfg, doc, strlen(doc)));
    firc_fakeip_cfg_t pc;
    memset(&pc, 0, sizeof(pc));
    ASSERT_EQ(FIRC_OK, firc_fakeip_cfg_from_app(&cfg.app, g_ula, &pc));
    ASSERT_EQ_FMT((int64_t)3600, pc.idle_secs, "%" PRId64);
    unlink(g_ula);
    firc_config_clear(&cfg);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_shipped_defaults_build_a_working_pool);
    RUN_TEST(a_pinned_v6_pool_is_used_and_nothing_is_generated);
    RUN_TEST(an_explicit_v4_pool_is_carried_through);
    RUN_TEST(a_pool_that_does_not_parse_is_refused);
    RUN_TEST(windows_that_do_not_convert_cleanly_are_refused);
    RUN_TEST(the_idle_window_is_twice_the_clamp_never_under_an_hour);
    RUN_TEST(an_idle_window_in_an_old_file_is_ignored);
    GREATEST_MAIN_END();
}
