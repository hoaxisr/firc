#include "greatest.h"

#include <stdatomic.h>
#include <string.h>
#include <time.h>

#include "firc/cfedge.h"
#include "firc/fakeip.h"

typedef struct {
    bool ok[FIRC_CFPROBE_TRIES];
    double s[FIRC_CFPROBE_TRIES];
    int calls;
    uint32_t mark[FIRC_CFPROBE_TRIES];
    firc_ip_t addr[FIRC_CFPROBE_TRIES];
    void *ud[FIRC_CFPROBE_TRIES];
} script_t;

static script_t g_s[FIRC_CFPROBE_MAX];
static _Atomic int g_entered;
static int g_want;

static bool scripted(void *ud, const char *host, const firc_ip_t *addr, uint32_t mark, double *secs)
{
    int i = host[1] - '0';
    if (i < 0 || i >= FIRC_CFPROBE_MAX || strcmp(host + 2, ".example") != 0) {
        return false;
    }
    script_t *s = &g_s[i];
    int k = s->calls++;
    if (k >= FIRC_CFPROBE_TRIES) {
        return false;
    }
    s->mark[k] = mark;
    s->addr[k] = *addr;
    s->ud[k] = ud;
    *secs = s->s[k];
    return s->ok[k];
}

static bool together(void *ud, const char *host, const firc_ip_t *addr, uint32_t mark, double *secs)
{
    (void)ud;
    (void)host;
    (void)addr;
    (void)mark;
    atomic_fetch_add(&g_entered, 1);
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        if (atomic_load(&g_entered) >= g_want) {
            *secs = 0.1;
            return true;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - t0.tv_sec >= 2) {
            return false;
        }
        struct timespec nap = {0, 1000000L};
        nanosleep(&nap, NULL);
    }
}

static firc_fakeip_cf_cand_t cand(int i, uint8_t d)
{
    firc_fakeip_cf_cand_t c;
    memset(&c, 0, sizeof c);
    c.addr.len = 4;
    c.addr.b[0] = 104;
    c.addr.b[1] = 16;
    c.addr.b[3] = d;
    snprintf(c.name, sizeof c.name, "h%d.example", i);
    return c;
}

static void script(int i, bool a, double sa, bool b, double sb, bool c, double sc)
{
    memset(&g_s[i], 0, sizeof g_s[i]);
    g_s[i].ok[0] = a;
    g_s[i].s[0] = sa;
    g_s[i].ok[1] = b;
    g_s[i].s[1] = sb;
    g_s[i].ok[2] = c;
    g_s[i].s[2] = sc;
}

TEST two_of_three_successes_pass_with_their_median(void)
{
    script(0, true, 0.10, false, 9.0, true, 0.30);
    script(1, true, 0.50, true, 0.10, true, 0.30);
    firc_fakeip_cf_cand_t c[2] = {cand(0, 1), cand(1, 2)};
    firc_cfprobe_t out[2];
    memset(out, 0, sizeof out);
    firc_cfprobe_run(scripted, NULL, c, 2, 0, out);
    ASSERT(out[0].ok);
    ASSERT_IN_RANGE(0.20, out[0].median_s, 1e-9);
    ASSERT_EQ(1, out[0].addr.b[3]);
    ASSERT_EQ(4, out[0].addr.len);
    ASSERT(out[1].ok);
    ASSERT_IN_RANGE(0.30, out[1].median_s, 1e-9);
    ASSERT_EQ(2, out[1].addr.b[3]);
    PASS();
}

TEST one_of_three_fails_the_candidate(void)
{
    script(0, true, 0.10, false, 0.0, false, 0.0);
    script(1, false, 0.0, false, 0.0, false, 0.0);
    script(2, false, 0.0, true, 0.20, true, 0.40);
    firc_fakeip_cf_cand_t c[3] = {cand(0, 1), cand(1, 2), cand(2, 3)};
    firc_cfprobe_t out[3];
    memset(out, 0, sizeof out);
    firc_cfprobe_run(scripted, NULL, c, 3, 0, out);
    ASSERT_FALSE(out[0].ok);
    ASSERT_EQ(1, out[0].addr.b[3]);
    ASSERT_FALSE(out[1].ok);
    ASSERT(out[2].ok);
    ASSERT_IN_RANGE(0.30, out[2].median_s, 1e-9);
    ASSERT_EQ(3, g_s[0].calls);
    PASS();
}

TEST the_mark_and_host_reach_the_probe(void)
{
    script(0, true, 0.1, true, 0.1, true, 0.1);
    script(1, true, 0.1, true, 0.1, true, 0.1);
    firc_fakeip_cf_cand_t c[2] = {cand(0, 7), cand(1, 8)};
    firc_cfprobe_t out[2];
    int token = 0;
    firc_cfprobe_run(scripted, &token, c, 2, 0x40050000u, out);
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ(FIRC_CFPROBE_TRIES, g_s[i].calls);
        for (int k = 0; k < FIRC_CFPROBE_TRIES; k++) {
            ASSERT_EQ_FMT(0x40050000u, g_s[i].mark[k], "%x");
            ASSERT_EQ(7 + i, g_s[i].addr[k].b[3]);
            ASSERT_EQ(&token, g_s[i].ud[k]);
        }
    }
    PASS();
}

TEST candidates_are_checked_at_once(void)
{
    atomic_store(&g_entered, 0);
    g_want = 4;
    firc_fakeip_cf_cand_t c[4] = {cand(0, 1), cand(1, 2), cand(2, 3), cand(3, 4)};
    firc_cfprobe_t out[4];
    memset(out, 0, sizeof out);
    firc_cfprobe_run(together, NULL, c, 4, 0, out);
    for (int i = 0; i < 4; i++) {
        ASSERT(out[i].ok);
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(two_of_three_successes_pass_with_their_median);
    RUN_TEST(one_of_three_fails_the_candidate);
    RUN_TEST(the_mark_and_host_reach_the_probe);
    RUN_TEST(candidates_are_checked_at_once);
    GREATEST_MAIN_END();
}
