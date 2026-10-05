#include "greatest.h"

#include <string.h>
#include <sys/socket.h>

#include "firc/pool_reject.h"

#define MAX_PLAN 8
typedef struct {
    int family[MAX_PLAN];
    uint32_t table[MAX_PLAN];
    uint32_t metric[MAX_PLAN];
    char cidr[MAX_PLAN][64];
    size_t n;
} plan_t;

static void collect(void *ud, int family, uint32_t table, uint32_t metric, const firc_ip_t *base,
                    uint8_t prefix) {
    plan_t *p = ud;
    if (p->n >= MAX_PLAN) { return; }
    p->family[p->n] = family;
    p->table[p->n] = table;
    p->metric[p->n] = metric;
    if (base->len == 4) {
        snprintf(p->cidr[p->n], sizeof(p->cidr[0]), "%u.%u.%u.%u/%u", base->b[0], base->b[1],
                 base->b[2], base->b[3], prefix);
    } else {
        snprintf(p->cidr[p->n], sizeof(p->cidr[0]), "%02x%02x:%02x%02x::/%u", base->b[0],
                 base->b[1], base->b[2], base->b[3], prefix);
    }
    p->n++;
}

static firc_fakeip_t *make_pool(void) {
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
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = 16;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *f = NULL;
    return firc_fakeip_new(&c, &f) == FIRC_OK ? f : NULL;
}

/* Catches: a reject route planned for one family only. */
TEST both_pool_prefixes_are_protected(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);

    plan_t p;
    memset(&p, 0, sizeof(p));
    firc_pool_reject_plan(pool, 51999, FIRC_POOL_REJECT_METRIC_GROUP, collect, &p);

    ASSERT_EQ_FMTm("one route per family, neither skipped", (size_t)2, p.n, "%zu");

    ASSERT_EQ_FMT(AF_INET, p.family[0], "%d");
    ASSERT_STR_EQm("the POOL prefix, not a chunk's", "198.18.0.0/15", p.cidr[0]);
    ASSERT_EQ_FMT(AF_INET6, p.family[1], "%d");
    ASSERT_STR_EQ("fd37:9a5c::/48", p.cidr[1]);

    for (size_t i = 0; i < p.n; i++) {
        ASSERT_EQ_FMTm("the table asked for", 51999u, p.table[i], "%u");
        ASSERT_EQ_FMT(FIRC_POOL_REJECT_METRIC_GROUP, p.metric[i], "%u");
    }
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the group's table and main given the same metric. */
TEST the_two_tables_get_different_metrics(void) {
    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);

    plan_t g, m;
    memset(&g, 0, sizeof(g));
    memset(&m, 0, sizeof(m));
    firc_pool_reject_plan(pool, 1001, FIRC_POOL_REJECT_METRIC_GROUP, collect, &g);
    firc_pool_reject_plan(pool, 254, FIRC_POOL_REJECT_METRIC_MAIN, collect, &m);

    ASSERT_EQ_FMT((size_t)2, g.n, "%zu");
    ASSERT_EQ_FMT((size_t)2, m.n, "%zu");
    ASSERTm("main must be the easier one to override", m.metric[0] > g.metric[0]);
    ASSERT_EQ_FMT(5u, g.metric[0], "%u");
    ASSERT_EQ_FMT(4096u, m.metric[0], "%u");
    ASSERT_EQ_FMT(254u, m.table[0], "%u");
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the reject routes planned from the default pool instead of the configured one. */
TEST the_plan_follows_the_configured_pool(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4;
    c.v4.base.b[0] = 100;
    c.v4.base.b[1] = 64;
    c.v4.pool_cidr = 10;
    c.v4.chunk_cidr = 26;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x12;
    c.v6.base.b[2] = 0x34;
    c.v6.base.b[3] = 0x56;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = 16;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));

    plan_t p;
    memset(&p, 0, sizeof(p));
    firc_pool_reject_plan(pool, 254, FIRC_POOL_REJECT_METRIC_MAIN, collect, &p);
    ASSERT_EQ_FMT((size_t)2, p.n, "%zu");
    ASSERT_STR_EQ("100.64.0.0/10", p.cidr[0]);
    ASSERT_STR_EQ("fd12:3456::/48", p.cidr[1]);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: a plan without a pool, or with a NULL callback, faulting or planning something. */
TEST nothing_to_protect_plans_nothing(void) {
    plan_t p;
    memset(&p, 0, sizeof(p));
    firc_pool_reject_plan(NULL, 254, 4096, collect, &p);
    ASSERT_EQ_FMT((size_t)0, p.n, "%zu");

    firc_fakeip_t *pool = make_pool();
    ASSERT(pool != NULL);
    firc_pool_reject_plan(pool, 254, 4096, NULL, &p);
    ASSERT_EQ_FMT((size_t)0, p.n, "%zu");

    ASSERT_EQ(FIRC_ERR_INVAL, firc_pool_reject_install(NULL, pool, 254, 4096));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_pool_reject_remove(NULL, pool, 254, 4096));
    firc_fakeip_free(pool);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(both_pool_prefixes_are_protected);
    RUN_TEST(the_two_tables_get_different_metrics);
    RUN_TEST(the_plan_follows_the_configured_pool);
    RUN_TEST(nothing_to_protect_plans_nothing);
    GREATEST_MAIN_END();
}
