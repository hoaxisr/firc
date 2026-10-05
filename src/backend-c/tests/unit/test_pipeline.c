#include "greatest.h"

#include <unistd.h>

#include "firc/log.h"

#include <stdlib.h>
#include <string.h>

#include "firc/dnspipeline.h"
#include "firc/events.h"
#include "firc/fakeip.h"
#include "firc/models.h"
#include "firc/recall.h"
#include "firc/rulesnap.h"

static firc_config_t make_cfg(void) {
    firc_config_t c;
    firc_config_init_defaults(&c);
    return c;
}

static void add_group(firc_config_t *cfg, uint8_t id, const char *name, const char *type,
                      const char *rule) {
    firc_group_t *g = firc_group_new();
    g->id = (firc_id_t){{id, 0, 0, 0}};
    firc_strset(&g->name, name);
    g->enable = true;
    firc_rule_t *r = firc_rule_new();
    r->id = (firc_id_t){{id, 1, 0, 0}};
    firc_strset(&r->type, type);
    firc_strset(&r->rule, rule);
    r->enable = true;
    firc_group_add_rule(g, r);
    firc_config_add_group(cfg, g);
}

static size_t put_name(uint8_t *buf, size_t p, const char *const *labels, size_t n) {
    for (size_t i = 0; i < n; i++) {
        size_t l = strlen(labels[i]);
        buf[p++] = (uint8_t)l;
        memcpy(buf + p, labels[i], l);
        p += l;
    }
    buf[p++] = 0;
    return p;
}

static size_t build_response(uint8_t *buf, const char *const *q, size_t nq,
                             const char *const *target, size_t ntarget) {
    size_t p = 0;
    buf[p++] = 0x12; buf[p++] = 0x34;
    buf[p++] = 0x81; buf[p++] = 0x80;
    buf[p++] = 0x00; buf[p++] = 0x01;
    buf[p++] = 0x00; buf[p++] = (uint8_t)(ntarget ? 2 : 1);
    buf[p++] = 0x00; buf[p++] = 0x00;
    buf[p++] = 0x00; buf[p++] = 0x00;
    p = put_name(buf, p, q, nq);
    buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_A;
    buf[p++] = 0x00; buf[p++] = 0x01;

    if (ntarget) {
        p = put_name(buf, p, q, nq);
        buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_CNAME;
        buf[p++] = 0x00; buf[p++] = 0x01;
        buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 60;
        size_t at = p;
        buf[p++] = 0; buf[p++] = 0;
        size_t start = p;
        p = put_name(buf, p, target, ntarget);
        buf[at] = (uint8_t)((p - start) >> 8);
        buf[at + 1] = (uint8_t)(p - start);
    }

    const char *const *owner = ntarget ? target : q;
    size_t nowner = ntarget ? ntarget : nq;
    p = put_name(buf, p, owner, nowner);
    buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_A;
    buf[p++] = 0x00; buf[p++] = 0x01;
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 60;
    buf[p++] = 0; buf[p++] = 4;
    buf[p++] = 93; buf[p++] = 184; buf[p++] = 216; buf[p++] = 34;
    return p;
}

#define MAX_SEEN 16
typedef struct {
    char group[MAX_SEEN][64];
    char name[MAX_SEEN][128];
    char real[MAX_SEEN][48];
    bool has_real[MAX_SEEN];
    unsigned family[MAX_SEEN];
    size_t n;
} seen_t;

static void record(void *ud, const char *qname, const char *group_id, const firc_ip_t *fake,
                   const firc_ip_t *real) {
    seen_t *s = ud;
    (void)fake;
    if (s->n >= MAX_SEEN) { return; }
    snprintf(s->group[s->n], sizeof(s->group[0]), "%s", group_id);
    snprintf(s->name[s->n], sizeof(s->name[0]), "%s", qname);
    s->family[s->n] = real != NULL && real->len == 16 ? 6 : 4;
    s->has_real[s->n] = real != NULL;
    if (real != NULL && real->len == 4) {
        snprintf(s->real[s->n], sizeof(s->real[0]), "%u.%u.%u.%u", real->b[0], real->b[1], real->b[2], real->b[3]);
    } else {
        s->real[s->n][0] = '\0';
    }
    s->n++;
}

static void seen_from(firc_fakeip_t *pool, seen_t *s) {
    memset(s, 0, sizeof(*s));
    firc_fakeip_walk(pool, record, s);
}

static bool saw_real(const seen_t *s, const char *real) {
    for (size_t i = 0; i < s->n; i++) {
        if (strcmp(s->real[i], real) == 0) { return true; }
    }
    return false;
}

/* Mappings under a group, by the group's id string */
static size_t count_for(const seen_t *s, const char *group_id) {
    size_t n = 0;
    for (size_t i = 0; i < s->n; i++) {
        if (strcmp(s->group[i], group_id) == 0) { n++; }
    }
    return n;
}

static firc_fakeip_cfg_t pool_cfg(size_t max_names) {
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
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = max_names;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    return c;
}

typedef struct {
    firc_config_t cfg;
    firc_fakeip_t *pool;
    firc_dns_pipeline_t *p;
    seen_t seen;
} rw_fixture_t;

/* The pipeline over `cfg` (taken over), with a pool of `max_names` */
static void rw_up_cfg(rw_fixture_t *f, firc_config_t cfg, size_t max_names) {
    f->cfg = cfg;
    firc_fakeip_cfg_t c = pool_cfg(max_names);
    if (firc_fakeip_new(&c, &f->pool) != FIRC_OK) { abort(); }
    memset(&f->seen, 0, sizeof(f->seen));
    f->p = firc_dns_pipeline_create();
    firc_dns_pipeline_set_snapshot(f->p, firc_ruleset_snapshot_build(&f->cfg));
    firc_dns_pipeline_set_pool(f->p, f->pool, 300);
}

static void rw_up(rw_fixture_t *f, size_t max_names) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "g", FIRC_RULE_NAMESPACE, "example.com");
    rw_up_cfg(f, cfg, max_names);
}

static void rw_down(rw_fixture_t *f) {
    firc_dns_pipeline_destroy(f->p);
    firc_fakeip_free(f->pool);
    firc_config_clear(&f->cfg);
}

/* shop.example.com CNAME cdn.example.net, cdn.example.net A 93.184.216.34 */
static firc_dns_msg_t *chain_answer(void) {
    uint8_t buf[512];
    static const char *q[] = {"shop", "example", "com"};
    static const char *t[] = {"cdn", "example", "net"};
    size_t len = build_response(buf, q, 3, t, 3);
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(buf, len, &msg) != FIRC_OK) { abort(); }
    return msg;
}

/* Catches: the pool called once per matching group, or the later group winning the name. */
TEST only_the_first_matching_group_owns_the_name(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 2, "first", FIRC_RULE_NAMESPACE, "example.com");
    add_group(&cfg, 1, "second", FIRC_RULE_WILDCARD, "*.example.*");
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);
    char first[FIRC_ID_STR_LEN], second[FIRC_ID_STR_LEN];
    firc_id_format(f.cfg.groups[0]->id, first);
    firc_id_format(f.cfg.groups[1]->id, second);

    uint8_t buf[512];
    static const char *org[] = {"www", "example", "org"};
    size_t len = build_response(buf, org, 3, NULL, 0);
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    seen_t seen;
    seen_from(f.pool, &seen);
    ASSERT_EQ_FMTm("the second group matches on its own, or this proves nothing", (size_t)2,
                   count_for(&seen, second), "%zu");
    firc_dns_msg_free(msg);

    static const char *q[] = {"www", "example", "com"};
    len = build_response(buf, q, 3, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));

    seen_from(f.pool, &seen);
    ASSERT_EQ_FMTm("one name, one mapping per family, not one per matching group", (size_t)4, seen.n, "%zu");
    ASSERT_EQ_FMTm("owned by the earlier group in config order, not the lower id", (size_t)2,
                   count_for(&seen, first), "%zu");
    ASSERT_EQ_FMTm("the second group holds only its own name", (size_t)2, count_for(&seen, second), "%zu");

    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

TEST a_rule_on_the_chains_target_does_not_capture_the_query(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "cdnrule", FIRC_RULE_NAMESPACE, "cdn.example.net");
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);

    firc_dns_msg_t *msg = chain_answer();
    ASSERT_EQ_FMTm("the fixture must carry the chain", (size_t)2, msg->n_answers, "%zu");
    uint64_t gen = firc_fakeip_gen(f.pool);
    ASSERT_EQ_FMTm("the client asked about shop.example.com, which matches nothing",
                   (int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL), "%d");
    ASSERT_EQ_FMTm("and nothing was issued", (unsigned long long)gen, (unsigned long long)firc_fakeip_gen(f.pool), "%llu");
    ASSERT_EQ_FMT((size_t)2, msg->n_answers, "%zu");

    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: a matched answer not rewritten, issued to the CNAME target, or not held for its rule. */
TEST a_matched_name_gets_an_address_of_its_own_and_waits_for_its_rule(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_msg_t *msg = chain_answer();
    bool changed = false;
    firc_dns_verdict_t v = firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, &changed);
    ASSERT_EQ_FMT((int)FIRC_DNS_HOLD, (int)v, "%d");
    ASSERTm("a chunk and a pair are new to the kernel", changed);

    ASSERT_EQ_FMTm("the chain collapsed to one record", (size_t)1, msg->n_answers, "%zu");
    ASSERT_EQ(FIRC_DNS_TYPE_A, msg->answers[0].rtype);
    char owner[256];
    firc_dns_name_to_string(msg->answers[0].name, msg->answers[0].name_len, owner, sizeof(owner), NULL);
    ASSERT_STR_EQ("shop.example.com.", owner);
    static const uint8_t first_issued[4] = {198, 18, 0, 1};
    ASSERT_MEM_EQm("the first address the pool issues", first_issued, msg->answers[0].rdata, 4);
    ASSERT_EQ_FMTm("the record's own TTL (60), under the clamp", 60u, msg->answers[0].ttl, "%u");

    char gid[FIRC_ID_STR_LEN];
    firc_id_format(f.cfg.groups[0]->id, gid);
    firc_ip_t fake4 = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_fakeip_get(f.pool, "shop.example.com", gid, 1000, &fake4, NULL));
    ASSERT_MEM_EQm("the same address the client got: issued to THIS name in THIS group",
                   first_issued, fake4.b, 4);
    ASSERT(firc_fakeip_needs_commit(f.pool, "shop.example.com", FIRC_FAM_V4));

    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: an answer held although a pass carrying its pair has already completed. */
TEST a_repeat_answer_for_a_committed_pair_is_not_held(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_msg_t *msg = chain_answer();
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    firc_dns_msg_free(msg);

    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f.pool);
    firc_fakeip_mark_committed(f.pool, firc_fakeip_snapshot_gen(s));
    firc_fakeip_snapshot_free(s);

    msg = chain_answer();
    bool changed = true;
    ASSERT_EQ((int)FIRC_DNS_REWRITTEN, (int)firc_dns_pipeline_handle_message(f.p, msg, 1010, NULL, &changed));
    ASSERT_FALSEm("nothing new for the kernel", changed);
    static const uint8_t same[4] = {198, 18, 0, 1};
    ASSERT_MEM_EQm("the same address, every time", same, msg->answers[0].rdata, 4);
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

TEST an_unmatched_name_passes_untouched(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    uint8_t buf[512];
    static const char *q[] = {"other", "example", "org"};
    static const char *t[] = {"cdn", "example", "net"};
    size_t len = build_response(buf, q, 3, t, 3);
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    bool changed = true;
    ASSERT_EQ((int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, &changed));
    ASSERT_FALSE(changed);
    ASSERT_EQ_FMT((size_t)2, msg->n_answers, "%zu");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* An unmatched answer: one A record for other.example.org with TTL `ttl`. */
static firc_dns_msg_t *unmatched_answer(uint32_t ttl) {
    uint8_t buf[512];
    static const char *q[] = {"other", "example", "org"};
    size_t len = build_response(buf, q, 3, NULL, 0);
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(buf, len, &msg) != FIRC_OK) { abort(); }
    msg->answers[0].ttl = ttl;
    return msg;
}

TEST an_unmatched_answer_is_clamped_to_unmatched_ttl(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_pipeline_set_unmatched_ttl(f.p, 60);
    firc_dns_msg_t *msg = unmatched_answer(3600);
    ASSERT_EQ((int)FIRC_DNS_RETIMED,
             (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMT(60u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: an answer already at or below unmatchedTtl repacked, or its TTL raised to the ceiling. */
TEST an_unmatched_answer_already_short_is_passed_not_rewritten(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_pipeline_set_unmatched_ttl(f.p, 60);
    firc_dns_msg_t *msg = unmatched_answer(30);
    ASSERT_EQm("nothing was lowered: no re-pack", (int)FIRC_DNS_PASS,
              (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMTm("not raised to the ceiling either", 30u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

TEST unmatched_ttl_zero_leaves_the_answer_untouched(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_pipeline_set_unmatched_ttl(f.p, 0);
    firc_dns_msg_t *msg = unmatched_answer(3600);
    ASSERT_EQ((int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMT(3600u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: the NOT_COVERED path skipping the unmatchedTtl clamp on any of its records. */
TEST a_not_covered_client_gets_the_unmatched_ttl(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "g", FIRC_RULE_NAMESPACE, "example.com");
    firc_group_t *g = cfg.groups[0];
    g->devices.allow = calloc(1, sizeof(char *));
    g->devices.allow[0] = strdup("192.168.1.0/24");
    g->devices.n_allow = 1;
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);
    firc_dns_pipeline_set_unmatched_ttl(f.p, 60);

    firc_ip_t stranger = {{10, 0, 0, 7}, 4};
    firc_dns_msg_t *msg = chain_answer();
    msg->answers[0].ttl = 3600;
    msg->answers[1].ttl = 3600;
    ASSERT_EQ((int)FIRC_DNS_RETIMED,
             (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, NULL));
    for (size_t i = 0; i < msg->n_answers; i++) {
        ASSERT_EQ_FMTm("clamped like an unmatched name, not left at the upstream TTL", 60u,
                       msg->answers[i].ttl, "%u");
    }
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: unmatchedTtl applied to a fake answer instead of the pool's own clamp. */
TEST a_fake_answer_keeps_its_own_clamp_regardless_of_unmatched_ttl(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_pipeline_set_unmatched_ttl(f.p, 60);
    firc_dns_msg_t *msg = chain_answer();
    msg->answers[1].ttl = 3600;
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMTm("the pool's clamp, not unmatchedTtl", 300u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: unmatchedTtl applied to an MX or TXT answer. */
TEST a_non_address_unmatched_question_is_untouched_by_unmatched_ttl(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_pipeline_set_unmatched_ttl(f.p, 60);
    firc_dns_msg_t *msg = unmatched_answer(3600);
    msg->questions[0].qtype = 16;
    ASSERT_EQ((int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMT(3600u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: unmatchedTtl cached instead of read on every message. */
TEST changing_unmatched_ttl_takes_effect_on_the_next_answer(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_pipeline_set_unmatched_ttl(f.p, 60);
    firc_dns_msg_t *msg = unmatched_answer(3600);
    ASSERT_EQ((int)FIRC_DNS_RETIMED,
             (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMT(60u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);

    firc_dns_pipeline_set_unmatched_ttl(f.p, 30);
    msg = unmatched_answer(3600);
    ASSERT_EQ((int)FIRC_DNS_RETIMED,
             (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMTm("the new value, not the one the pipeline started with", 30u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Adds a group whose list has no body hash yet, so the snapshot built from it is provisional. */
static void add_unfetched_list_group(firc_config_t *cfg) {
    firc_group_t *g = firc_group_new();
    g->id = (firc_id_t){{9, 0, 0, 0}};
    firc_strset(&g->name, "list1");
    firc_strset(&g->iface, "nwg0");
    g->enable = true;
    g->list = firc_group_list_new();
    firc_strset(&g->list->url, "https://example.invalid/l.txt");
    firc_config_add_group(cfg, g);
}

TEST an_unmatched_answer_is_clamped_while_the_snapshot_is_provisional(void) {
    firc_config_t cfg = make_cfg();
    add_unfetched_list_group(&cfg);

    firc_fakeip_cfg_t c = pool_cfg(64);
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_dns_pipeline_t *p = firc_dns_pipeline_create();
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERTm("the fixture must actually be provisional, or this proves nothing", snap->provisional);
    firc_dns_pipeline_set_snapshot(p, snap);
    firc_dns_pipeline_set_pool(p, pool, 30);

    uint8_t buf[512];
    static const char *q[] = {"other", "example", "com"};
    size_t len = build_response(buf, q, 3, NULL, 0);
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    msg->answers[0].ttl = 3600;
    ASSERT_EQ((int)FIRC_DNS_RETIMED,
             (int)firc_dns_pipeline_handle_message(p, msg, 1000, NULL, NULL));
    for (size_t i = 0; i < msg->n_answers; i++) {
        ASSERT_EQ_FMTm("clamped to the pool's clamp, not the upstream TTL", 30u, msg->answers[i].ttl,
                       "%u");
    }

    len = build_response(buf, q, 3, NULL, 0);
    firc_dns_msg_t *msg_short = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg_short));
    for (size_t i = 0; i < msg_short->n_answers; i++) { msg_short->answers[i].ttl = 20; }
    ASSERT_EQm("nothing was lowered: no re-pack", (int)FIRC_DNS_PASS,
               (int)firc_dns_pipeline_handle_message(p, msg_short, 1000, NULL, NULL));
    for (size_t i = 0; i < msg_short->n_answers; i++) {
        ASSERT_EQ_FMTm("and the TTL is not raised to the clamp either", 20u,
                       msg_short->answers[i].ttl, "%u");
    }
    firc_dns_msg_free(msg_short);

    firc_dns_msg_free(msg);
    firc_dns_pipeline_destroy(p);
    firc_fakeip_free(pool);
    firc_config_clear(&cfg);

    firc_config_t cfg2 = make_cfg();
    firc_fakeip_t *pool2 = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool2));
    firc_dns_pipeline_t *p2 = firc_dns_pipeline_create();
    firc_ruleset_snapshot_t *snap2 = firc_ruleset_snapshot_build(&cfg2);
    ASSERT_FALSE(snap2->provisional);
    firc_dns_pipeline_set_snapshot(p2, snap2);
    firc_dns_pipeline_set_pool(p2, pool2, 30);

    len = build_response(buf, q, 3, NULL, 0);
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    msg->answers[0].ttl = 3600;
    ASSERT_EQ((int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(p2, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMTm("untouched outside the provisional window", 3600u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    firc_dns_pipeline_destroy(p2);
    firc_fakeip_free(pool2);
    firc_config_clear(&cfg2);
    PASS();
}

TEST a_provisional_clamp_is_further_lowered_by_unmatched_ttl(void) {
    firc_config_t cfg = make_cfg();
    add_unfetched_list_group(&cfg);

    firc_fakeip_cfg_t c = pool_cfg(64);
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_dns_pipeline_t *p = firc_dns_pipeline_create();
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERTm("the fixture must actually be provisional, or this proves nothing", snap->provisional);
    firc_dns_pipeline_set_snapshot(p, snap);
    firc_dns_pipeline_set_pool(p, pool, 300);
    firc_dns_pipeline_set_unmatched_ttl(p, 60);

    firc_dns_msg_t *msg = unmatched_answer(3600);
    ASSERT_EQ((int)FIRC_DNS_RETIMED,
             (int)firc_dns_pipeline_handle_message(p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMTm("the lower of the pool's clamp and unmatchedTtl", 60u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    firc_dns_pipeline_destroy(p);
    firc_fakeip_free(pool);
    firc_config_clear(&cfg);
    PASS();
}

TEST a_provisional_clamp_is_unchanged_when_unmatched_ttl_is_off(void) {
    firc_config_t cfg = make_cfg();
    add_unfetched_list_group(&cfg);

    firc_fakeip_cfg_t c = pool_cfg(64);
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_dns_pipeline_t *p = firc_dns_pipeline_create();
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERTm("the fixture must actually be provisional, or this proves nothing", snap->provisional);
    firc_dns_pipeline_set_snapshot(p, snap);
    firc_dns_pipeline_set_pool(p, pool, 300);
    firc_dns_pipeline_set_unmatched_ttl(p, 0);

    firc_dns_msg_t *msg = unmatched_answer(3600);
    ASSERT_EQ((int)FIRC_DNS_RETIMED,
             (int)firc_dns_pipeline_handle_message(p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMTm("the pool's own clamp, unmatchedTtl off", 300u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    firc_dns_pipeline_destroy(p);
    firc_fakeip_free(pool);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: the provisional flag checked before the owner lookup, passing a matched name real. */
TEST a_matched_answer_is_not_touched_by_the_provisional_flag(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "g", FIRC_RULE_NAMESPACE, "example.com");
    add_unfetched_list_group(&cfg);

    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    ASSERTm("the fixture must actually be provisional, or this proves nothing", snap->provisional);

    firc_fakeip_cfg_t c = pool_cfg(64);
    firc_fakeip_t *pool = NULL;
    ASSERT_EQ(FIRC_OK, firc_fakeip_new(&c, &pool));
    firc_dns_pipeline_t *p = firc_dns_pipeline_create();
    firc_dns_pipeline_set_snapshot(p, snap);
    firc_dns_pipeline_set_pool(p, pool, 300);

    firc_dns_msg_t *msg = chain_answer();
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMTm("the chain still collapses to one record", (size_t)1, msg->n_answers, "%zu");
    static const uint8_t first_issued[4] = {198, 18, 0, 1};
    ASSERT_MEM_EQm("the group still mints its own fake address, as without the flag",
                   first_issued, msg->answers[0].rdata, 4);

    firc_dns_msg_free(msg);
    firc_dns_pipeline_destroy(p);
    firc_fakeip_free(pool);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a rewritten answer keeping a TTL above the clamp. */
TEST a_ttl_above_the_clamp_is_clamped(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_msg_t *msg = chain_answer();
    msg->answers[1].ttl = 86400;
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMT(300u, msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: an exhausted pool answering the real address, or holding the blackhole answer. */
TEST pool_exhaustion_answers_the_blackhole_without_waiting(void) {
    rw_fixture_t f;
    rw_up(&f, 1);
    firc_dns_msg_t *msg = chain_answer();
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    firc_dns_msg_free(msg);

    uint8_t buf[512];
    static const char *q[] = {"second", "example", "com"};
    static const char *t[] = {"cdn", "example", "net"};
    size_t len = build_response(buf, q, 3, t, 3);
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    bool changed = true;
    ASSERT_EQ((int)FIRC_DNS_REWRITTEN, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, &changed));
    ASSERT_FALSE(changed);
    char gid[FIRC_ID_STR_LEN];
    firc_id_format(f.cfg.groups[0]->id, gid);
    firc_ip_t blackhole = {{0}, 0};
    ASSERT_EQ(FIRC_ERR_LIMIT, firc_fakeip_get(f.pool, "third.example.com", gid, 1000, &blackhole, NULL));
    ASSERT_EQ_FMT((size_t)1, msg->n_answers, "%zu");
    ASSERT_MEM_EQ(blackhole.b, msg->answers[0].rdata, 4);
    static const uint8_t real[4] = {93, 184, 216, 34};
    ASSERT(memcmp(real, msg->answers[0].rdata, 4) != 0);
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

TEST a_v4_only_name_gets_nodata_for_aaaa(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    uint8_t buf[512];
    static const char *q[] = {"shop", "example", "com"};
    static const char *t[] = {"cdn", "example", "net"};
    size_t len = build_response(buf, q, 3, t, 3);
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    free(msg->answers[1].rdata);
    msg->n_answers = 1;
    msg->questions[0].qtype = FIRC_DNS_TYPE_AAAA;
    bool changed = false;
    ASSERT_EQ((int)FIRC_DNS_REWRITTEN, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, &changed));
    ASSERTm("the name was issued its addresses; the chunk is new to the kernel", changed);
    ASSERT_EQ_FMTm("NODATA", (size_t)0, msg->n_answers, "%zu");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: a TXT or MX answer for a matched name minting a fake address. */
TEST a_non_address_question_is_left_alone(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_msg_t *msg = chain_answer();
    msg->questions[0].qtype = 16;
    uint64_t gen = firc_fakeip_gen(f.pool);
    bool changed = true;
    ASSERT_EQ((int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, &changed));
    ASSERT_FALSE(changed);
    ASSERT_EQ_FMTm("nothing minted", (unsigned long long)gen, (unsigned long long)firc_fakeip_gen(f.pool), "%llu");
    ASSERT_EQ_FMT((size_t)2, msg->n_answers, "%zu");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: an HTTPS answer for a matched name passed with its address hints, or minting an address. */
TEST an_https_question_for_a_matched_name_is_emptied(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_msg_t *msg = chain_answer();
    msg->questions[0].qtype = 65;
    msg->answers[1].rtype = 65;
    uint64_t gen = firc_fakeip_gen(f.pool);
    ASSERT_EQ((int)FIRC_DNS_REWRITTEN, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMT((size_t)0, msg->n_answers, "%zu");
    ASSERT_EQ_FMT((unsigned long long)gen, (unsigned long long)firc_fakeip_gen(f.pool), "%llu");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: a fake v6 address issued by a daemon without ip6tables, instead of NODATA. */
TEST no_fake_v6_where_v6_cannot_be_routed(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_pipeline_set_v6_routable(f.p, false);
    firc_dns_msg_t *msg = chain_answer();
    msg->answers = realloc(msg->answers, 3 * sizeof(*msg->answers));
    msg->answers[2] = msg->answers[1];
    msg->answers[2].rtype = FIRC_DNS_TYPE_AAAA;
    msg->answers[2].rdata = malloc(16);
    memset(msg->answers[2].rdata, 0x26, 16);
    msg->answers[2].rdata_len = 16;
    msg->n_answers = 3;
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMT((size_t)1, msg->n_answers, "%zu");
    ASSERT_EQ(FIRC_DNS_TYPE_A, msg->answers[0].rtype);
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

static bool kids_policy(const char *policy, const firc_ip_t *client, void *ud) {
    (*(int *)ud)++;
    return strcmp(policy, "Kids") == 0 && client->len == 4 && client->b[3] == 42;
}

/* The listed device at 192.168.1.10, which also holds fd00::10. */
static size_t listed_device(const firc_ip_t *client, firc_ip_t *out, size_t cap, firc_mac_t *mac, void *ud) {
    (void)ud;
    (void)mac;
    static const firc_ip_t v6 = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}, 16};
    static const firc_ip_t v4 = {{192, 168, 1, 10}, 4};
    if (cap < 1 || client->len != 16 || memcmp(client->b, v6.b, 16) != 0) { return 0; }
    out[0] = v4;
    return 1;
}

/* Catches: a client outside the selector rewritten, or one inside it passed the real answer. */
TEST a_group_applies_only_to_the_devices_it_names(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "kids", FIRC_RULE_NAMESPACE, "example.com");
    firc_group_t *g = cfg.groups[0];
    g->devices.allow = calloc(2, sizeof(char *));
    g->devices.allow[0] = strdup("192.168.1.0/24");
    g->devices.allow[1] = strdup("policy:Kids");
    g->devices.n_allow = 2;
    g->devices.deny = calloc(1, sizeof(char *));
    g->devices.deny[0] = strdup("192.168.1.5");
    g->devices.n_deny = 1;
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);
    int asked = 0;
    firc_dns_pipeline_set_policy_resolver(f.p, kids_policy, listed_device, &asked);

    firc_ip_t listed = {{192, 168, 1, 10}, 4}, denied = {{192, 168, 1, 5}, 4};
    firc_ip_t stranger = {{10, 0, 0, 7}, 4}, kid = {{10, 0, 0, 42}, 4};

    firc_dns_msg_t *msg = chain_answer();
    uint64_t gen = firc_fakeip_gen(f.pool);
    bool changed = true;
    ASSERT_EQ_FMTm("a stranger gets the real answer", (int)FIRC_DNS_PASS,
                   (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, &changed), "%d");
    ASSERT_FALSE(changed);
    ASSERT_EQ_FMTm("and nothing was issued for it", (unsigned long long)gen, (unsigned long long)firc_fakeip_gen(f.pool), "%llu");
    ASSERT_EQ_FMT((size_t)2, msg->n_answers, "%zu");
    firc_dns_msg_free(msg);

    msg = chain_answer();
    ASSERT_EQ_FMTm("a denied device too, whatever the allow list says", (int)FIRC_DNS_PASS,
                   (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &denied, NULL), "%d");
    firc_dns_msg_free(msg);

    msg = chain_answer();
    ASSERT_EQ_FMTm("a listed device is rewritten", (int)FIRC_DNS_HOLD,
                   (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &listed, NULL), "%d");
    ASSERT_EQ_FMT((size_t)1, msg->n_answers, "%zu");
    firc_dns_msg_free(msg);
    firc_fakeip_mark_committed(f.pool, firc_fakeip_gen(f.pool));

    msg = chain_answer();
    ASSERT_EQ_FMTm("a device the policy resolver puts in the policy is rewritten", (int)FIRC_DNS_REWRITTEN,
                   (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &kid, NULL), "%d");
    ASSERTm("the resolver was asked", asked > 0);
    firc_dns_msg_free(msg);

    msg = chain_answer();
    firc_ip_t listed6 = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10}, 16};
    ASSERT_EQ_FMTm("the listed device asking over v6 is the listed device", (int)FIRC_DNS_REWRITTEN,
                   (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &listed6, NULL), "%d");
    firc_dns_msg_free(msg);

    msg = chain_answer();
    ASSERT_EQ_FMTm("an unknown client is admitted, as before selectors", (int)FIRC_DNS_REWRITTEN,
                   (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL), "%d");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: an AAAA question on a v4-only daemon dropped instead of answered NODATA. */
TEST an_aaaa_question_where_v6_cannot_be_routed_is_nodata_not_dropped(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_pipeline_set_v6_routable(f.p, false);
    firc_dns_msg_t *msg = chain_answer();
    msg->questions[0].qtype = FIRC_DNS_TYPE_AAAA;
    msg->answers[1].rtype = FIRC_DNS_TYPE_AAAA;
    free(msg->answers[1].rdata);
    msg->answers[1].rdata = malloc(16);
    memset(msg->answers[1].rdata, 0x26, 16);
    msg->answers[1].rdata_len = 16;
    bool changed = false;
    ASSERT_EQ((int)FIRC_DNS_REWRITTEN, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, &changed));
    ASSERT_EQ_FMTm("NODATA", (size_t)0, msg->n_answers, "%zu");
    ASSERTm("the name was issued its addresses: the kernel has a chunk to learn", changed);
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

typedef struct {
    bool seen4;
    uint8_t real4[4];
} recorded_t;

static void record_real(void *ud, const char *group_id, unsigned family, const firc_ip_t *fake,
                        const firc_ip_t *real) {
    (void)group_id;
    (void)fake;
    recorded_t *r = ud;
    if (family == FIRC_FAM_V4 && real != NULL) {
        r->seen4 = true;
        memcpy(r->real4, real->b, 4);
    }
}

/* Catches: a stranger's address recorded instead of the chain's, or a changed address not committed. */
TEST the_chains_real_address_is_recorded_and_a_change_asks_for_a_commit(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_dns_msg_t *msg = chain_answer();
    msg->answers = realloc(msg->answers, 3 * sizeof(*msg->answers));
    memset(&msg->answers[2], 0, sizeof(msg->answers[2]));
    static const uint8_t junk[] = {4, 'j', 'u', 'n', 'k', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'n', 'e', 't', 0};
    memcpy(msg->answers[2].name, junk, sizeof(junk));
    msg->answers[2].name_len = sizeof(junk);
    msg->answers[2].rtype = FIRC_DNS_TYPE_A;
    msg->answers[2].rclass = 1;
    msg->answers[2].ttl = 5;
    msg->answers[2].rdata = malloc(4);
    memcpy(msg->answers[2].rdata, (uint8_t[]){203, 0, 113, 9}, 4);
    msg->answers[2].rdata_len = 4;
    msg->n_answers = 3;
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMTm("the stranger's TTL (5) is not the answer's; the chain's record (60) is", 60u,
                   msg->answers[0].ttl, "%u");
    firc_dns_msg_free(msg);

    firc_fakeip_snapshot_t *s0 = firc_fakeip_snapshot_take(f.pool);
    recorded_t rec = {0};
    firc_fakeip_snapshot_walk(s0, record_real, &rec);
    firc_fakeip_snapshot_free(s0);
    static const uint8_t chain_real[4] = {93, 184, 216, 34};
    ASSERT(rec.seen4);
    ASSERT_MEM_EQ(chain_real, rec.real4, 4);

    firc_fakeip_snapshot_t *s = firc_fakeip_snapshot_take(f.pool);
    firc_fakeip_mark_committed(f.pool, firc_fakeip_snapshot_gen(s));
    firc_fakeip_snapshot_free(s);

    msg = chain_answer();
    msg->answers[1].rdata[3] = 35;
    bool changed = false;
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1010, NULL, &changed));
    ASSERTm("a changed pair is something for the kernel", changed);
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

TEST a_rule_on_the_queried_name_fires_through_a_chain(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "shoprule", FIRC_RULE_DOMAIN, "shop.example.com");
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);

    firc_dns_msg_t *msg = chain_answer();
    ASSERT_EQ((int)FIRC_DNS_HOLD, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    seen_t seen;
    seen_from(f.pool, &seen);
    char gid[FIRC_ID_STR_LEN];
    firc_id_format(f.cfg.groups[0]->id, gid);
    ASSERT_EQ_FMTm("the queried name matches, so it is issued an address under that group",
                   (size_t)2, count_for(&seen, gid), "%zu");
    ASSERTm("behind it, the address at the END of the chain", saw_real(&seen, "93.184.216.34"));
    ASSERT_STR_EQm("keyed by the queried name", "shop.example.com", seen.name[0]);
    ASSERT_EQ_FMTm("the answer collapsed to the one issued record", (size_t)1, msg->n_answers, "%zu");
    ASSERTm("carrying a pool address, not the real one",
            msg->answers[0].rdata_len == 4 && msg->answers[0].rdata[0] == 198 && (msg->answers[0].rdata[1] & 0xfe) == 18);

    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: NXDOMAIN logged as a warning on every response, flooding the syslog ring. */
TEST an_unresolved_name_is_not_logged_as_a_problem(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    uint8_t buf[512];
    static const char *q[] = {"nx", "example", "com"};
    size_t len = build_response(buf, q, 3, NULL, 0);
    buf[3] = 0x83;
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));

    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    char out[1024];
    ssize_t n = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);
    if (n < 0) { n = 0; }
    out[n] = '\0';
    ASSERT_EQ_FMTm("nothing is said about an ordinary answer at the shipped level", (size_t)0,
                   (size_t)n, "%zu");

    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Runs `rcodes` through the pipeline; returns the lines logged at INFO and above, copied into `out`. */
static size_t rcodes_through(rw_fixture_t *f, const uint8_t *rcodes, size_t n, char *out,
                             size_t cap) {
    static const char *q[] = {"www", "example", "com"};
    int fds[2];
    if (pipe(fds) != 0) { return (size_t)-1; }
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    for (size_t i = 0; i < n; i++) {
        uint8_t buf[512];
        size_t len = build_response(buf, q, 3, NULL, 0);
        buf[3] = (uint8_t)(0x80u | rcodes[i]);
        firc_dns_msg_t *msg = NULL;
        if (firc_dns_msg_parse(buf, len, &msg) != FIRC_OK) { continue; }
        (void)firc_dns_pipeline_handle_message(f->p, msg, 1000, NULL, NULL);
        firc_dns_msg_free(msg);
    }
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    ssize_t got = read(fds[0], out, cap - 1);
    close(fds[0]);
    if (got < 0) { got = 0; }
    out[got] = '\0';
    size_t lines = 0;
    for (const char *c = out; *c != '\0'; c++) {
        if (*c == '\n') { lines++; }
    }
    return lines;
}

/* Catches: a failure run keyed on the current rcode, so mixed failures log a line per response. */
TEST an_upstream_that_fails_intermittently_is_not_an_outage(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    char out[8192];

    uint8_t sparse[400];
    for (size_t i = 0; i < sizeof(sparse); i++) { sparse[i] = (i % 10 == 3) ? 2 : 0; }
    size_t lines = rcodes_through(&f, sparse, sizeof(sparse), out, sizeof(out));
    ASSERT(lines != (size_t)-1);
    ASSERT_EQ_FMTm("nothing is said about a resolver having a bad minute", (size_t)0, lines, "%zu");

    rw_down(&f);
    PASS();
}

TEST an_upstream_alternating_failures_is_one_outage(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    char out[8192];

    uint8_t alt[60];
    for (size_t i = 0; i < 52; i++) { alt[i] = (i % 2) ? 5 : 2; }
    for (size_t i = 52; i < sizeof(alt); i++) { alt[i] = 0; }
    size_t lines = rcodes_through(&f, alt, sizeof(alt), out, sizeof(out));
    ASSERT(lines != (size_t)-1);
    ASSERT_EQ_FMTm("one line in, one line out", (size_t)2, lines, "%zu");
    ASSERTm("the count is of the whole run, whichever rcode each response was",
            strstr(out, "52 failed") != NULL);

    rw_down(&f);
    PASS();
}

/* Catches: one good answer ending a failure run, so a flaky upstream logs a start and end per answer. */
TEST one_good_answer_in_a_dead_minute_is_not_a_recovery(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    char out[8192];

    uint8_t spotty[96];
    for (size_t i = 0; i < sizeof(spotty); i++) { spotty[i] = (i % 8 == 7) ? 0 : 2; }
    size_t lines = rcodes_through(&f, spotty, sizeof(spotty), out, sizeof(out));
    ASSERT(lines != (size_t)-1);
    ASSERT_EQ_FMTm("one outage, still going", (size_t)1, lines, "%zu");
    ASSERTm("and it is the start", strstr(out, "names it refuses are not routed") != NULL);

    rw_down(&f);
    PASS();
}

/* Catches: an upstream that SERVFAILs everything logged on every response, or never. */
TEST an_upstream_answering_servfail_to_everything_is_said_once(void) {
    rw_fixture_t f;
    rw_up(&f, 64);

    char out[4096];
    uint8_t run[48];
    for (size_t i = 0; i < 40; i++) { run[i] = 2; }
    for (size_t i = 40; i < sizeof(run); i++) { run[i] = 0; }
    size_t lines = rcodes_through(&f, run, sizeof(run), out, sizeof(out));
    ASSERT(lines != (size_t)-1);
    ASSERT_EQ_FMTm("one line when it starts, one when it ends -- not forty", (size_t)2, lines,
                   "%zu");
    ASSERTm("the start names the rcode", strstr(out, "rcode=2") != NULL);
    ASSERTm("the end carries the count", strstr(out, "40 failed") != NULL);

    uint8_t again[10];
    for (size_t i = 0; i < sizeof(again); i++) { again[i] = 2; }
    lines = rcodes_through(&f, again, sizeof(again), out, sizeof(out));
    ASSERT(lines != (size_t)-1);
    ASSERTm("the next outage is said, not swallowed by the last one",
            strstr(out, "names it refuses are not routed") != NULL);
    ASSERT_EQ_FMTm("one line, and not a stale count from the run that ended", (size_t)1, lines,
                   "%zu");
    ASSERTm("counted from zero", strstr(out, "for 8 responses") != NULL);

    rw_down(&f);
    PASS();
}

/* Catches: a run of NXDOMAIN logged at the shipped level. */
TEST a_run_of_nxdomain_is_still_not_a_problem(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    static const char *q[] = {"nx", "example", "com"};
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    for (int i = 0; i < 40; i++) {
        uint8_t buf[512];
        size_t len = build_response(buf, q, 3, NULL, 0);
        buf[3] = 0x83;
        firc_dns_msg_t *msg = NULL;
        ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
        (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL);
        firc_dns_msg_free(msg);
    }
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    char out[1024];
    ssize_t got = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);
    if (got < 0) { got = 0; }
    ASSERT_EQ_FMTm("nothing is said about a name that does not exist", (size_t)0, (size_t)got,
                   "%zu");
    rw_down(&f);
    PASS();
}

TEST a_failed_response_is_ignored(void) {
    rw_fixture_t f;
    rw_up(&f, 64);
    uint8_t buf[512];
    static const char *q[] = {"www", "example", "com"};
    size_t len = build_response(buf, q, 3, NULL, 0);
    buf[3] = 0x83;
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    uint64_t gen = firc_fakeip_gen(f.pool);
    ASSERT_EQ((int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL));
    ASSERT_EQ_FMT((unsigned long long)gen, (unsigned long long)firc_fakeip_gen(f.pool), "%llu");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: a CNAME the question does not reach extending the chain, letting an injected address in. */
TEST an_unreachable_cname_does_not_extend_the_chain(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "vpn", FIRC_RULE_DOMAIN, "shop.example.com");
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);
    firc_ruleset_snapshot_free(snap);
    firc_dns_pipeline_t *p = f.p;

    uint8_t buf[512];
    size_t pp = 0;
    buf[pp++] = 0x12; buf[pp++] = 0x34;
    buf[pp++] = 0x81; buf[pp++] = 0x80;
    buf[pp++] = 0x00; buf[pp++] = 0x01;
    buf[pp++] = 0x00; buf[pp++] = 0x03;
    buf[pp++] = 0x00; buf[pp++] = 0x00;
    buf[pp++] = 0x00; buf[pp++] = 0x00;
    static const char *q[] = {"shop", "example", "com"};
    pp = put_name(buf, pp, q, 3);
    buf[pp++] = 0x00; buf[pp++] = FIRC_DNS_TYPE_A;
    buf[pp++] = 0x00; buf[pp++] = 0x01;

    static const char *evil[] = {"evil", "invalid"};
    static const char *att[] = {"attacker", "net"};
    pp = put_name(buf, pp, evil, 2);
    buf[pp++] = 0x00; buf[pp++] = FIRC_DNS_TYPE_CNAME;
    buf[pp++] = 0x00; buf[pp++] = 0x01;
    buf[pp++] = 0; buf[pp++] = 0; buf[pp++] = 0; buf[pp++] = 60;
    size_t at = pp;
    buf[pp++] = 0; buf[pp++] = 0;
    size_t start = pp;
    pp = put_name(buf, pp, att, 2);
    buf[at] = (uint8_t)((pp - start) >> 8);
    buf[at + 1] = (uint8_t)(pp - start);

    pp = put_name(buf, pp, att, 2);
    buf[pp++] = 0x00; buf[pp++] = FIRC_DNS_TYPE_A;
    buf[pp++] = 0x00; buf[pp++] = 0x01;
    buf[pp++] = 0; buf[pp++] = 0; buf[pp++] = 0; buf[pp++] = 60;
    buf[pp++] = 0; buf[pp++] = 4;
    buf[pp++] = 203; buf[pp++] = 0; buf[pp++] = 113; buf[pp++] = 9;

    pp = put_name(buf, pp, q, 3);
    buf[pp++] = 0x00; buf[pp++] = FIRC_DNS_TYPE_A;
    buf[pp++] = 0x00; buf[pp++] = 0x01;
    buf[pp++] = 0; buf[pp++] = 0; buf[pp++] = 0; buf[pp++] = 60;
    buf[pp++] = 0; buf[pp++] = 4;
    buf[pp++] = 93; buf[pp++] = 184; buf[pp++] = 216; buf[pp++] = 34;

    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, pp, &msg));
    ASSERT_EQ_FMTm("the name is matched and rewritten", (int)FIRC_DNS_HOLD,
                   (int)firc_dns_pipeline_handle_message(p, msg, 1000, NULL, NULL), "%d");

    seen_t seen;
    seen_from(f.pool, &seen);
    ASSERT(saw_real(&seen, "93.184.216.34"));
    ASSERT_FALSEm("a CNAME the question does not reach is not part of its chain",
                  saw_real(&seen, "203.0.113.9"));

    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: the pool keyed by the name's spelling, so case variants get two fake addresses. */
TEST the_pool_is_keyed_by_the_folded_name(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "g", FIRC_RULE_DOMAIN, "www.example.com");
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);
    firc_ruleset_snapshot_free(snap);
    firc_dns_pipeline_t *p = f.p;

    uint8_t buf[512];
    static const char *q[] = {"WwW", "ExAmPlE", "CoM"};
    size_t len = build_response(buf, q, 3, NULL, 0);
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    firc_dns_pipeline_handle_message(p, msg, 1000, NULL, NULL);

    seen_t seen;
    seen_from(f.pool, &seen);
    ASSERT_EQ_FMTm("the folded routing key matches the rule", (size_t)2, seen.n, "%zu");
    ASSERT_STR_EQm("and the pool is keyed on the folded name", "www.example.com", seen.name[0]);

    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

static size_t journal(firc_event_t *out, size_t cap) {
    uint64_t next = 0, dropped = 0;
    return firc_event_read(0, out, cap, &next, &dropped);
}

static size_t dns_events(firc_event_t *all, size_t n, firc_event_t *out) {
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (all[i].kind == FIRC_EVENT_DNS) { out[k++] = all[i]; }
    }
    return k;
}

/* One question, one A record, no chain: the name answered with 93.184.216.34. */
static firc_dns_msg_t *plain_answer(const char *const *labels, size_t n, uint8_t rcode) {
    uint8_t buf[1024];
    size_t len = build_response(buf, labels, n, NULL, 0);
    buf[3] = (uint8_t)(0x80 | rcode);
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(buf, len, &msg) != FIRC_OK) { abort(); }
    return msg;
}

/* Catches: an issued answer not journalled, or journalled without client, name, addresses or group. */
TEST an_issued_answer_is_journalled_with_both_addresses(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    firc_dns_msg_t *msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);

    firc_event_t all[8], ev[8];
    size_t n = dns_events(all, journal(all, 8), ev);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    const firc_event_dns_t *d = &ev[0].u.dns;
    ASSERT_MEM_EQ(client.b, d->client.b, 4);
    ASSERT_STR_EQ("shop.example.com", d->name);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_TYPE_A, (unsigned)d->qtype, "%u");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)d->decision, "%u");
    char gid[FIRC_ID_STR_LEN];
    firc_id_format(f.cfg.groups[0]->id, gid);
    ASSERT_STR_EQ(gid, d->group_id);
    ASSERT_STR_EQ("g", d->group_name);
    ASSERT_EQ_FMT(4u, (unsigned)d->fake.len, "%u");
    ASSERT_MEM_EQ(msg->answers[0].rdata, d->fake.b, 4);
    ASSERT_EQ_FMT(1u, (unsigned)d->n_reals, "%u");
    static const uint8_t real[4] = {93, 184, 216, 34};
    ASSERT_MEM_EQ(real, d->reals[0].b, 4);
    ASSERTm("the event has a time", ev[0].at == 1000);
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: the answer's source dropped on the issued or rcode path, or the wrapper passing another. */
TEST the_journal_says_where_the_answer_came_from(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t client = {{192, 168, 1, 42}, 4};

    firc_dns_msg_t *msg = chain_answer();
    (void)firc_dns_pipeline_handle_message_from(f.p, msg, 1000, &client, FIRC_DNS_RESOLVER_GROUP, NULL);
    firc_dns_msg_free(msg);
    static const char *q[] = {"ya", "ru"};
    msg = plain_answer(q, 2, 3 );
    (void)firc_dns_pipeline_handle_message_from(f.p, msg, 1001, &client, FIRC_DNS_RESOLVER_FALLBACK_TIMEOUT, NULL);
    firc_dns_msg_free(msg);
    msg = plain_answer(q, 2, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1002, &client, NULL);
    firc_dns_msg_free(msg);

    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)3, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_RESOLVER_GROUP, (unsigned)ev[0].u.dns.resolver, "%u");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_RESOLVER_FALLBACK_TIMEOUT, (unsigned)ev[1].u.dns.resolver, "%u");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_RESOLVER_UPSTREAM, (unsigned)ev[2].u.dns.resolver, "%u");
    rw_down(&f);
    PASS();
}

/* Catches: an unmatched name from a covered client not journalled. */
TEST an_unmatched_name_from_a_covered_client_is_journalled(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    static const char *q[] = {"ya", "ru"};
    firc_dns_msg_t *msg = plain_answer(q, 2, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)1, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_STR_EQ("ya.ru", ev[0].u.dns.name);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_NO_MATCH, (unsigned)ev[0].u.dns.decision, "%u");
    ASSERT_STR_EQ("", ev[0].u.dns.group_id);
    ASSERT_EQ_FMT(0u, (unsigned)ev[0].u.dns.fake.len, "%u");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: an NXDOMAIN not journalled, or journalled without its rcode. */
TEST a_failed_answer_is_journalled_with_its_rcode(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    static const char *q[] = {"nx", "example", "com"};
    firc_dns_msg_t *msg = plain_answer(q, 3, 3);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)1, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_STR_EQ("nx.example.com", ev[0].u.dns.name);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_PASSED, (unsigned)ev[0].u.dns.decision, "%u");
    ASSERT_EQ_FMT(3u, (unsigned)ev[0].u.dns.rcode, "%u");
    ASSERT_STR_EQm("the name matched a group, and the event says which", "g",
                   ev[0].u.dns.group_name);
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: a failed answer tagged with the owning group although its selector excludes the client. */
TEST a_failed_answer_names_a_group_only_for_a_client_it_covers(void) {
    firc_event_reset_for_test();
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "kids", FIRC_RULE_NAMESPACE, "example.com");
    add_group(&cfg, 2, "all", FIRC_RULE_NAMESPACE, "other.net");
    cfg.groups[0]->devices.allow = calloc(1, sizeof(char *));
    cfg.groups[0]->devices.allow[0] = strdup("192.168.1.0/24");
    cfg.groups[0]->devices.n_allow = 1;
    cfg.groups[1]->devices.allow = calloc(1, sizeof(char *));
    cfg.groups[1]->devices.allow[0] = strdup("10.0.0.0/8");
    cfg.groups[1]->devices.n_allow = 1;
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);

    firc_ip_t other = {{10, 0, 0, 7}, 4}, kid = {{192, 168, 1, 42}, 4};
    static const char *q[] = {"nx", "example", "com"};
    firc_dns_msg_t *msg = plain_answer(q, 3, 3);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &other, NULL);
    firc_dns_msg_free(msg);
    msg = plain_answer(q, 3, 3);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &kid, NULL);
    firc_dns_msg_free(msg);

    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)2, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_MEM_EQ(other.b, ev[0].u.dns.client.b, 4);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_PASSED, (unsigned)ev[0].u.dns.decision, "%u");
    ASSERT_STR_EQm("kids does not cover 10.0.0.7", "", ev[0].u.dns.group_id);
    ASSERT_STR_EQ("", ev[0].u.dns.group_name);
    ASSERT_MEM_EQ(kid.b, ev[1].u.dns.client.b, 4);
    ASSERT_STR_EQm("kids covers 192.168.1.42", "kids", ev[1].u.dns.group_name);
    rw_down(&f);
    PASS();
}

/* Catches: an uncovered client journalled, NOT_COVERED never produced, or coverage from the owner only. */
TEST coverage_decides_who_is_journalled(void) {
    firc_event_reset_for_test();
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "kids", FIRC_RULE_NAMESPACE, "example.com");
    add_group(&cfg, 2, "all", FIRC_RULE_NAMESPACE, "other.net");
    cfg.groups[0]->devices.allow = calloc(1, sizeof(char *));
    cfg.groups[0]->devices.allow[0] = strdup("192.168.1.0/24");
    cfg.groups[0]->devices.n_allow = 1;
    cfg.groups[1]->devices.allow = calloc(1, sizeof(char *));
    cfg.groups[1]->devices.allow[0] = strdup("10.0.0.0/8");
    cfg.groups[1]->devices.n_allow = 1;
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);

    firc_ip_t other = {{10, 0, 0, 7}, 4}, stranger = {{172, 16, 0, 1}, 4};
    firc_dns_msg_t *msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &other, NULL);
    firc_dns_msg_free(msg);
    msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, NULL);
    firc_dns_msg_free(msg);

    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMTm("only the covered client", (size_t)1, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_MEM_EQ(other.b, ev[0].u.dns.client.b, 4);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_NOT_COVERED, (unsigned)ev[0].u.dns.decision, "%u");
    ASSERT_STR_EQ("kids", ev[0].u.dns.group_name);
    rw_down(&f);
    PASS();
}

/* Catches: a refused issue journalled as ISSUED, or without the blackhole address. */
TEST a_refused_issue_is_journalled_as_refused(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 1);
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    firc_dns_msg_t *msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    firc_dns_msg_free(msg);
    uint8_t buf[512];
    static const char *q[] = {"second", "example", "com"};
    static const char *t[] = {"cdn", "example", "net"};
    size_t len = build_response(buf, q, 3, t, 3);
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)2, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_POOL_REFUSED, (unsigned)ev[1].u.dns.decision, "%u");
    ASSERT_EQ_FMT(4u, (unsigned)ev[1].u.dns.fake.len, "%u");
    ASSERT_MEM_EQ(msg->answers[0].rdata, ev[1].u.dns.fake.b, 4);
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* Catches: a crash or an event when there is no snapshot, or an unknown client journalled. */
TEST no_snapshot_and_no_client_journal_nothing(void) {
    firc_event_reset_for_test();
    firc_dns_pipeline_t *p = firc_dns_pipeline_create();
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    firc_dns_msg_t *msg = chain_answer();
    ASSERT_EQ((int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(p, msg, 1000, &client, NULL));
    firc_dns_msg_free(msg);
    firc_dns_pipeline_destroy(p);

    rw_fixture_t f;
    rw_up(&f, 64);
    msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, NULL, NULL);
    firc_dns_msg_free(msg);
    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)0, dns_events(all, journal(all, 8), ev), "%zu");
    rw_down(&f);
    PASS();
}

/* Catches: who covers everyone not recomputed with a new snapshot. */
TEST coverage_follows_the_snapshot(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t stranger = {{172, 16, 0, 1}, 4};
    static const char *q[] = {"ya", "ru"};
    firc_dns_msg_t *msg = plain_answer(q, 2, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, NULL);
    firc_dns_msg_free(msg);
    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMTm("covered while a group admits everyone", (size_t)1,
                   dns_events(all, journal(all, 8), ev), "%zu");

    firc_config_t narrow = make_cfg();
    add_group(&narrow, 1, "g", FIRC_RULE_NAMESPACE, "example.com");
    narrow.groups[0]->devices.allow = calloc(1, sizeof(char *));
    narrow.groups[0]->devices.allow[0] = strdup("192.168.1.0/24");
    narrow.groups[0]->devices.n_allow = 1;
    firc_dns_pipeline_set_snapshot(f.p, firc_ruleset_snapshot_build(&narrow));
    firc_event_reset_for_test();
    msg = plain_answer(q, 2, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, NULL);
    firc_dns_msg_free(msg);
    ASSERT_EQ_FMTm("not covered once the group is narrowed", (size_t)0,
                   dns_events(all, journal(all, 8), ev), "%zu");

    firc_dns_pipeline_set_snapshot(f.p, firc_ruleset_snapshot_build(&f.cfg));
    msg = plain_answer(q, 2, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, NULL);
    firc_dns_msg_free(msg);
    ASSERT_EQ_FMTm("and covered again when it is widened", (size_t)1,
                   dns_events(all, journal(all, 8), ev), "%zu");
    firc_config_clear(&narrow);
    rw_down(&f);
    PASS();
}

/* Adds a fetched list group routing example.com through nwg0 for 192.168.1.0/24 only. */
static void add_scoped_list_group(firc_config_t *cfg) {
    firc_group_t *g = firc_group_new();
    g->id = (firc_id_t){{9, 0, 0, 0}};
    firc_strset(&g->name, "kids-list");
    firc_strset(&g->iface, "nwg0");
    g->enable = true;
    g->list = firc_group_list_new();
    firc_strset(&g->list->url, "https://example.invalid/l.txt");
    g->list->has_body_hash = true;
    firc_sub_rules_push(&g->list->rules, "example.com", FIRC_RULE_NAMESPACE, true, (firc_id_t){{9, 1, 0, 0}});
    g->devices.allow = calloc(1, sizeof(char *));
    g->devices.allow[0] = strdup("192.168.1.0/24");
    g->devices.n_allow = 1;
    firc_config_add_group(cfg, g);
}

TEST a_list_group_applies_only_to_the_devices_it_names(void) {
    firc_event_reset_for_test();
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 2, "all", FIRC_RULE_NAMESPACE, "other.net");
    add_scoped_list_group(&cfg);
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);

    firc_ip_t kid = {{192, 168, 1, 42}, 4}, other = {{10, 0, 0, 7}, 4};
    firc_dns_msg_t *msg = chain_answer();
    uint64_t gen = firc_fakeip_gen(f.pool);
    bool changed = true;
    ASSERT_EQ_FMTm("a device outside the selector gets the real answer", (int)FIRC_DNS_PASS,
                   (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &other, &changed), "%d");
    ASSERT_FALSE(changed);
    ASSERT_EQ_FMTm("and nothing was issued for it", (unsigned long long)gen,
                   (unsigned long long)firc_fakeip_gen(f.pool), "%llu");
    ASSERT_EQ_FMTm("the upstream's chain, untouched", (size_t)2, msg->n_answers, "%zu");
    firc_dns_msg_free(msg);

    msg = chain_answer();
    ASSERT_EQ_FMTm("a device inside it is issued a fake address", (int)FIRC_DNS_HOLD,
                   (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &kid, NULL), "%d");
    ASSERT_EQ_FMT((size_t)1, msg->n_answers, "%zu");
    firc_dns_msg_free(msg);

    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)2, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_MEM_EQ(other.b, ev[0].u.dns.client.b, 4);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_NOT_COVERED, (unsigned)ev[0].u.dns.decision, "%u");
    ASSERT_STR_EQ("kids-list", ev[0].u.dns.group_name);
    ASSERT_MEM_EQ(kid.b, ev[1].u.dns.client.b, 4);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)ev[1].u.dns.decision, "%u");
    ASSERT_STR_EQ("kids-list", ev[1].u.dns.group_name);
    rw_down(&f);
    PASS();
}

/* Catches: a scoped list group's snapshot entry without its selector, journalling every client. */
TEST a_scoped_list_group_does_not_cover_a_stranger(void) {
    firc_event_reset_for_test();
    firc_config_t cfg = make_cfg();
    add_scoped_list_group(&cfg);
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);

    firc_ip_t kid = {{192, 168, 1, 42}, 4}, stranger = {{172, 16, 0, 1}, 4};
    static const char *q[] = {"ya", "ru"};
    firc_dns_msg_t *msg = plain_answer(q, 2, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, NULL);
    firc_dns_msg_free(msg);
    msg = chain_answer();
    ASSERT_EQ((int)FIRC_DNS_PASS, (int)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, NULL));
    firc_dns_msg_free(msg);
    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMTm("the stranger is nobody's", (size_t)0, dns_events(all, journal(all, 8), ev), "%zu");

    msg = plain_answer(q, 2, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &kid, NULL);
    firc_dns_msg_free(msg);
    ASSERT_EQ_FMTm("the device it names is journalled", (size_t)1,
                   dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_MEM_EQ(kid.b, ev[0].u.dns.client.b, 4);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_NO_MATCH, (unsigned)ev[0].u.dns.decision, "%u");
    rw_down(&f);
    PASS();
}

/* Catches: a 253-character name cut or overrunning the journal slot. */
TEST a_longest_name_is_journalled_whole(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    static char l63[64], l57[58];
    memset(l63, 'a', 63);
    memset(l57, 'b', 57);
    const char *q[] = {l63, l63, l63, l57, "com"};
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    firc_dns_msg_t *msg = plain_answer(q, 5, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)1, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_EQ_FMT((size_t)253, strlen(ev[0].u.dns.name), "%zu");
    firc_dns_msg_free(msg);
    rw_down(&f);
    PASS();
}

/* shop.example.com answered with six A records, 93.184.216.1 to .6. */
static firc_dns_msg_t *six_answer(void) {
    uint8_t buf[1024];
    static const char *q[] = {"shop", "example", "com"};
    size_t p = 0;
    buf[p++] = 0x12; buf[p++] = 0x34;
    buf[p++] = 0x81; buf[p++] = 0x80;
    buf[p++] = 0x00; buf[p++] = 0x01;
    buf[p++] = 0x00; buf[p++] = 6;
    buf[p++] = 0x00; buf[p++] = 0x00;
    buf[p++] = 0x00; buf[p++] = 0x00;
    p = put_name(buf, p, q, 3);
    buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_A;
    buf[p++] = 0x00; buf[p++] = 0x01;
    for (uint8_t i = 1; i <= 6; i++) {
        p = put_name(buf, p, q, 3);
        buf[p++] = 0x00; buf[p++] = FIRC_DNS_TYPE_A;
        buf[p++] = 0x00; buf[p++] = 0x01;
        buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 60;
        buf[p++] = 0; buf[p++] = 4;
        buf[p++] = 93; buf[p++] = 184; buf[p++] = 216; buf[p++] = i;
    }
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(buf, p, &msg) != FIRC_OK) { abort(); }
    return msg;
}

/* Catches: the recall fed from the four-address event instead of all six answers, or not fed. */
TEST an_issued_answer_feeds_every_real_address(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    firc_dns_msg_t *msg = six_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    firc_dns_msg_free(msg);

    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMT((size_t)1, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_EQ_FMTm("the event keeps four", 4u, (unsigned)ev[0].u.dns.n_reals, "%u");

    firc_recall_t *r = firc_dns_pipeline_recall(f.p);
    ASSERT(r != NULL);
    char gid[FIRC_ID_STR_LEN];
    firc_id_format(f.cfg.groups[0]->id, gid);
    for (uint8_t i = 1; i <= 6; i++) {
        firc_ip_t real = {{93, 184, 216, i}, 4};
        char name[256], group[FIRC_ID_STR_LEN];
        ASSERTm("every real address is recalled",
                firc_recall_by_real(r, &real, name, sizeof(name), group));
        ASSERT_STR_EQ("shop.example.com", name);
        ASSERT_STR_EQ(gid, group);
    }
    ASSERT_EQ_FMT((size_t)6, firc_recall_real_count(r), "%zu");
    rw_down(&f);
    PASS();
}

/* Catches: an answer not recalled, recalled for an uncovered client, or without decision or fake. */
TEST a_covered_answer_is_recalled_and_an_uncovered_one_is_not(void) {
    firc_event_reset_for_test();
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "kids", FIRC_RULE_NAMESPACE, "example.com");
    cfg.groups[0]->devices.allow = calloc(1, sizeof(char *));
    cfg.groups[0]->devices.allow[0] = strdup("192.168.1.0/24");
    cfg.groups[0]->devices.n_allow = 1;
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);

    firc_ip_t kid = {{192, 168, 1, 42}, 4}, stranger = {{172, 16, 0, 1}, 4};
    firc_dns_msg_t *msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &kid, NULL);
    uint8_t told[4];
    memcpy(told, msg->answers[0].rdata, 4);
    firc_dns_msg_free(msg);
    msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &stranger, NULL);
    firc_dns_msg_free(msg);

    firc_recall_t *r = firc_dns_pipeline_recall(f.p);
    firc_recall_answer_t out;
    ASSERT(firc_recall_last_answer(r, &kid, "shop.example.com", FIRC_RECALL_V4, 1010, &out));
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)out.decision, "%u");
    ASSERT_EQ_FMT((long long)1000, (long long)out.at, "%lld");
    ASSERT_EQ_FMT(4u, (unsigned)out.fake.len, "%u");
    ASSERT_MEM_EQ(told, out.fake.b, 4);
    ASSERTm("the stranger is nobody the journal is for",
            !firc_recall_last_answer(r, &stranger, "shop.example.com", FIRC_RECALL_V4, 1010, &out));
    rw_down(&f);
    PASS();
}

/* Catches: a failed answer overwriting the recall of what firc last told the client. */
TEST a_servfail_after_an_issued_answer_does_not_overwrite_the_recall(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    firc_dns_msg_t *msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    uint8_t told[4];
    memcpy(told, msg->answers[0].rdata, 4);
    firc_dns_msg_free(msg);

    static const char *q[] = {"shop", "example", "com"};
    msg = plain_answer(q, 3, 2);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1010, &client, NULL);
    firc_dns_msg_free(msg);

    firc_recall_t *r = firc_dns_pipeline_recall(f.p);
    firc_recall_answer_t out;
    ASSERT(firc_recall_last_answer(r, &client, "shop.example.com", FIRC_RECALL_V4, 1010, &out));
    ASSERT_EQ_FMTm("still the issued answer, not the servfail",
                   (unsigned)FIRC_DNS_ISSUED, (unsigned)out.decision, "%u");
    ASSERT_EQ_FMT((long long)1000, (long long)out.at, "%lld");
    ASSERT_EQ_FMT(4u, (unsigned)out.fake.len, "%u");
    ASSERT_MEM_EQ(told, out.fake.b, 4);
    rw_down(&f);
    PASS();
}

/* Catches: recall keyed without the family, or an HTTPS answer overwriting an address answer. */
TEST each_address_answer_is_recalled_under_its_family_and_nothing_else_is(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    firc_dns_msg_t *msg = chain_answer();
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    uint8_t told[4];
    memcpy(told, msg->answers[0].rdata, 4);
    firc_dns_msg_free(msg);

    msg = chain_answer();
    free(msg->answers[1].rdata);
    msg->n_answers = 1;
    msg->questions[0].qtype = FIRC_DNS_TYPE_AAAA;
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1001, &client, NULL);
    ASSERT_EQ_FMTm("NODATA", (size_t)0, msg->n_answers, "%zu");
    firc_dns_msg_free(msg);

    msg = chain_answer();
    msg->questions[0].qtype = 65;
    msg->answers[1].rtype = 65;
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1002, &client, NULL);
    firc_dns_msg_free(msg);

    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMTm("all three journalled", (size_t)3, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_PASSED, (unsigned)ev[2].u.dns.decision, "%u");

    firc_recall_t *r = firc_dns_pipeline_recall(f.p);
    firc_recall_answer_t out;
    memset(&out, 0xff, sizeof(out));
    ASSERT(firc_recall_last_answer(r, &client, "shop.example.com", FIRC_RECALL_V4, 1010, &out));
    ASSERT_EQ_FMTm("the A answer, not the HTTPS one", (unsigned)FIRC_DNS_ISSUED,
                   (unsigned)out.decision, "%u");
    ASSERT_EQ_FMT((long long)1000, (long long)out.at, "%lld");
    ASSERT_EQ_FMT(4u, (unsigned)out.fake.len, "%u");
    ASSERT_MEM_EQ(told, out.fake.b, 4);
    memset(&out, 0xff, sizeof(out));
    ASSERT(firc_recall_last_answer(r, &client, "shop.example.com", FIRC_RECALL_V6, 1010, &out));
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)out.decision, "%u");
    ASSERT_EQ_FMTm("the AAAA answer", (long long)1001, (long long)out.at, "%lld");
    ASSERT_EQ_FMTm("no v6 address in it", 0u, (unsigned)out.fake.len, "%u");
    rw_down(&f);
    PASS();
}

/* Catches: every answer fed to the recall, pushing out pairs the judge can read. */
TEST an_unowned_name_and_a_non_address_question_are_not_recalled(void) {
    firc_event_reset_for_test();
    rw_fixture_t f;
    rw_up(&f, 64);
    firc_ip_t client = {{192, 168, 1, 42}, 4};
    static const char *q[] = {"ya", "ru"};
    firc_dns_msg_t *msg = plain_answer(q, 2, 0);
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    firc_dns_msg_free(msg);
    msg = chain_answer();
    msg->questions[0].qtype = 16;
    (void)firc_dns_pipeline_handle_message(f.p, msg, 1000, &client, NULL);
    firc_dns_msg_free(msg);

    firc_event_t all[8], ev[8];
    ASSERT_EQ_FMTm("both journalled", (size_t)2, dns_events(all, journal(all, 8), ev), "%zu");
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_NO_MATCH, (unsigned)ev[0].u.dns.decision, "%u");

    firc_recall_t *r = firc_dns_pipeline_recall(f.p);
    firc_recall_answer_t out;
    static const unsigned fam[2] = {FIRC_RECALL_V4, FIRC_RECALL_V6};
    for (int i = 0; i < 2; i++) {
        ASSERTm("no NO_MATCH pair", !firc_recall_last_answer(r, &client, "ya.ru", fam[i], 1001, &out));
        ASSERTm("no TXT pair",
                !firc_recall_last_answer(r, &client, "shop.example.com", fam[i], 1001, &out));
    }
    rw_down(&f);
    PASS();
}

/* Catches: a coverage predicate that is not the pipeline's own. */
TEST the_pipeline_says_who_is_covered(void) {
    firc_config_t cfg = make_cfg();
    add_group(&cfg, 1, "kids", FIRC_RULE_NAMESPACE, "example.com");
    cfg.groups[0]->devices.allow = calloc(1, sizeof(char *));
    cfg.groups[0]->devices.allow[0] = strdup("192.168.1.0/24");
    cfg.groups[0]->devices.n_allow = 1;
    rw_fixture_t f;
    rw_up_cfg(&f, cfg, 64);
    firc_ip_t kid = {{192, 168, 1, 42}, 4}, stranger = {{172, 16, 0, 1}, 4};
    ASSERT(firc_dns_pipeline_covers(f.p, &kid));
    ASSERT(!firc_dns_pipeline_covers(f.p, &stranger));
    ASSERTm("nobody is no one", !firc_dns_pipeline_covers(f.p, NULL));
    rw_down(&f);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(only_the_first_matching_group_owns_the_name);
    RUN_TEST(a_rule_on_the_chains_target_does_not_capture_the_query);
    RUN_TEST(a_matched_name_gets_an_address_of_its_own_and_waits_for_its_rule);
    RUN_TEST(a_repeat_answer_for_a_committed_pair_is_not_held);
    RUN_TEST(an_unmatched_name_passes_untouched);
    RUN_TEST(an_unmatched_answer_is_clamped_to_unmatched_ttl);
    RUN_TEST(an_unmatched_answer_already_short_is_passed_not_rewritten);
    RUN_TEST(unmatched_ttl_zero_leaves_the_answer_untouched);
    RUN_TEST(a_not_covered_client_gets_the_unmatched_ttl);
    RUN_TEST(a_fake_answer_keeps_its_own_clamp_regardless_of_unmatched_ttl);
    RUN_TEST(a_non_address_unmatched_question_is_untouched_by_unmatched_ttl);
    RUN_TEST(changing_unmatched_ttl_takes_effect_on_the_next_answer);
    RUN_TEST(an_unmatched_answer_is_clamped_while_the_snapshot_is_provisional);
    RUN_TEST(a_provisional_clamp_is_further_lowered_by_unmatched_ttl);
    RUN_TEST(a_provisional_clamp_is_unchanged_when_unmatched_ttl_is_off);
    RUN_TEST(a_matched_answer_is_not_touched_by_the_provisional_flag);
    RUN_TEST(a_ttl_above_the_clamp_is_clamped);
    RUN_TEST(pool_exhaustion_answers_the_blackhole_without_waiting);
    RUN_TEST(a_v4_only_name_gets_nodata_for_aaaa);
    RUN_TEST(a_non_address_question_is_left_alone);
    RUN_TEST(a_group_applies_only_to_the_devices_it_names);
    RUN_TEST(an_https_question_for_a_matched_name_is_emptied);
    RUN_TEST(no_fake_v6_where_v6_cannot_be_routed);
    RUN_TEST(an_aaaa_question_where_v6_cannot_be_routed_is_nodata_not_dropped);
    RUN_TEST(the_chains_real_address_is_recorded_and_a_change_asks_for_a_commit);
    RUN_TEST(a_rule_on_the_queried_name_fires_through_a_chain);
    RUN_TEST(an_upstream_that_fails_intermittently_is_not_an_outage);
    RUN_TEST(an_upstream_alternating_failures_is_one_outage);
    RUN_TEST(one_good_answer_in_a_dead_minute_is_not_a_recovery);
    RUN_TEST(an_upstream_answering_servfail_to_everything_is_said_once);
    RUN_TEST(a_run_of_nxdomain_is_still_not_a_problem);
    RUN_TEST(a_failed_response_is_ignored);
    RUN_TEST(an_unresolved_name_is_not_logged_as_a_problem);
    RUN_TEST(an_unreachable_cname_does_not_extend_the_chain);
    RUN_TEST(the_pool_is_keyed_by_the_folded_name);
    RUN_TEST(an_issued_answer_is_journalled_with_both_addresses);
    RUN_TEST(the_journal_says_where_the_answer_came_from);
    RUN_TEST(an_unmatched_name_from_a_covered_client_is_journalled);
    RUN_TEST(a_failed_answer_is_journalled_with_its_rcode);
    RUN_TEST(a_failed_answer_names_a_group_only_for_a_client_it_covers);
    RUN_TEST(coverage_decides_who_is_journalled);
    RUN_TEST(a_refused_issue_is_journalled_as_refused);
    RUN_TEST(no_snapshot_and_no_client_journal_nothing);
    RUN_TEST(coverage_follows_the_snapshot);
    RUN_TEST(a_longest_name_is_journalled_whole);
    RUN_TEST(a_list_group_applies_only_to_the_devices_it_names);
    RUN_TEST(a_scoped_list_group_does_not_cover_a_stranger);
    RUN_TEST(an_issued_answer_feeds_every_real_address);
    RUN_TEST(a_covered_answer_is_recalled_and_an_uncovered_one_is_not);
    RUN_TEST(a_servfail_after_an_issued_answer_does_not_overwrite_the_recall);
    RUN_TEST(each_address_answer_is_recalled_under_its_family_and_nothing_else_is);
    RUN_TEST(an_unowned_name_and_a_non_address_question_are_not_recalled);
    RUN_TEST(the_pipeline_says_who_is_covered);
    GREATEST_MAIN_END();
}
