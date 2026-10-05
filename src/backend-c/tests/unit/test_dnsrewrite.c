#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "firc/dnsrewrite.h"
#include "firc/dnswire.h"

static const uint8_t k_q[] = {3, 'w', 'W', 'w', 1, 'A', 7, 'e', 'X', 'a', 'm', 'p', 'l', 'e', 0};
static const uint8_t k_q_lower[] = {3, 'w', 'w', 'w', 1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0};
static const uint8_t k_cdn[] = {3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0};

static void rr_set(firc_dns_rr_t *rr, const uint8_t *name, size_t name_len, uint16_t type,
                   uint32_t ttl, const uint8_t *rdata, size_t rdata_len) {
    memset(rr, 0, sizeof(*rr));
    memcpy(rr->name, name, name_len);
    rr->name_len = name_len;
    rr->rtype = type;
    rr->rclass = 1;
    rr->ttl = ttl;
    rr->rdata = malloc(rdata_len ? rdata_len : 1);
    if (rdata_len) { memcpy(rr->rdata, rdata, rdata_len); }
    rr->rdata_len = rdata_len;
}

/* www.a.example IN A: a CNAME to cdn.example, its A and AAAA, an HTTPS, a TXT, an HTTPS hint and OPT. */
static firc_dns_msg_t *typical_answer(void) {
    firc_dns_msg_t *m = calloc(1, sizeof(*m));
    m->id = 0x1234;
    m->flags = 0x8180;
    m->questions = calloc(1, sizeof(*m->questions));
    m->n_questions = 1;
    memcpy(m->questions[0].name, k_q, sizeof(k_q));
    m->questions[0].name_len = sizeof(k_q);
    m->questions[0].qtype = FIRC_DNS_TYPE_A;
    m->questions[0].qclass = 3;

    m->answers = calloc(5, sizeof(*m->answers));
    m->n_answers = 5;
    static const uint8_t a4[4] = {93, 184, 216, 34};
    static const uint8_t a6[16] = {0x26, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t https[] = {0, 1, 0, 0, 4, 0, 4, 93, 184, 216, 34};
    static const uint8_t txt[] = {5, 'h', 'e', 'l', 'l', 'o'};
    rr_set(&m->answers[0], k_q_lower, sizeof(k_q_lower), FIRC_DNS_TYPE_CNAME, 60, k_cdn, sizeof(k_cdn));
    rr_set(&m->answers[1], k_cdn, sizeof(k_cdn), FIRC_DNS_TYPE_A, 20, a4, 4);
    rr_set(&m->answers[2], k_cdn, sizeof(k_cdn), FIRC_DNS_TYPE_AAAA, 20, a6, 16);
    rr_set(&m->answers[3], k_q_lower, sizeof(k_q_lower), 65, 60, https, sizeof(https));
    rr_set(&m->answers[4], k_cdn, sizeof(k_cdn), 16, 60, txt, sizeof(txt));

    m->authority = calloc(1, sizeof(*m->authority));
    m->n_authority = 1;
    rr_set(&m->authority[0], k_cdn, sizeof(k_cdn), 64, 60, https, sizeof(https));

    m->additional = calloc(2, sizeof(*m->additional));
    m->n_additional = 2;
    rr_set(&m->additional[0], k_cdn, sizeof(k_cdn), 65, 60, https, sizeof(https));
    static const uint8_t root[] = {0};
    rr_set(&m->additional[1], root, 1, FIRC_DNS_TYPE_OPT, 0, NULL, 0);
    m->additional[1].rclass = 1232;
    return m;
}

static size_t count_type(const firc_dns_rr_t *rrs, size_t n, uint16_t type) {
    size_t c = 0;
    for (size_t i = 0; i < n; i++) { c += rrs[i].rtype == type; }
    return c;
}

static const firc_dns_rr_t *find_type(const firc_dns_rr_t *rrs, size_t n, uint16_t type) {
    for (size_t i = 0; i < n; i++) {
        if (rrs[i].rtype == type) { return &rrs[i]; }
    }
    return NULL;
}

TEST the_chain_is_collapsed_onto_the_queried_name(void) {
    firc_dns_msg_t *m = typical_answer();
    const firc_ip_t f4 = {{198, 18, 0, 7}, 4};
    const firc_ip_t f6 = {{0xfd, 0x37, 0x9a, 0x5c, 0xbe, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}, 16};

    ASSERT_EQ(FIRC_OK, firc_dns_msg_collapse(m, &f4, &f6, 300));

    ASSERT_EQ_FMTm("no CNAME survives", (size_t)0, count_type(m->answers, m->n_answers, FIRC_DNS_TYPE_CNAME), "%zu");
    ASSERT_EQ_FMT((size_t)1, count_type(m->answers, m->n_answers, FIRC_DNS_TYPE_A), "%zu");
    ASSERT_EQ_FMT((size_t)1, count_type(m->answers, m->n_answers, FIRC_DNS_TYPE_AAAA), "%zu");

    const firc_dns_rr_t *a = find_type(m->answers, m->n_answers, FIRC_DNS_TYPE_A);
    ASSERT_EQ_FMTm("owned by the QUERIED name, not the chain's target", sizeof(k_q), a->name_len, "%zu");
    ASSERT_MEM_EQ(k_q, a->name, sizeof(k_q));
    ASSERT_EQ_FMT((size_t)4, a->rdata_len, "%zu");
    ASSERT_MEM_EQ(f4.b, a->rdata, 4);
    ASSERT_EQ_FMT(300u, a->ttl, "%u");
    ASSERT_EQ_FMTm("the question's class, whatever it is", 3u, (unsigned)a->rclass, "%u");

    const firc_dns_rr_t *aaaa = find_type(m->answers, m->n_answers, FIRC_DNS_TYPE_AAAA);
    ASSERT_MEM_EQ(k_q, aaaa->name, sizeof(k_q));
    ASSERT_EQ_FMT((size_t)16, aaaa->rdata_len, "%zu");
    ASSERT_MEM_EQ(f6.b, aaaa->rdata, 16);
    ASSERT_EQ_FMT(300u, aaaa->ttl, "%u");

    ASSERT_EQ_FMTm("a record type we do not understand is left alone", (size_t)1,
                   count_type(m->answers, m->n_answers, 16), "%zu");

    firc_dns_msg_free(m);
    PASS();
}

TEST a_family_not_offered_gets_no_record(void) {
    firc_dns_msg_t *m = typical_answer();
    const firc_ip_t f4 = {{198, 18, 0, 7}, 4};
    ASSERT_EQ(FIRC_OK, firc_dns_msg_collapse(m, &f4, NULL, 300));
    ASSERT_EQ_FMT((size_t)1, count_type(m->answers, m->n_answers, FIRC_DNS_TYPE_A), "%zu");
    ASSERT_EQ_FMTm("the upstream's AAAA went with the chain and nothing replaced it: NODATA for v6",
                   (size_t)0, count_type(m->answers, m->n_answers, FIRC_DNS_TYPE_AAAA), "%zu");
    firc_dns_msg_free(m);
    PASS();
}

TEST https_records_are_stripped_from_every_section_and_the_opt_stays(void) {
    firc_dns_msg_t *m = typical_answer();
    const firc_ip_t f4 = {{198, 18, 0, 7}, 4};
    ASSERT_EQ(FIRC_OK, firc_dns_msg_collapse(m, &f4, NULL, 300));
    ASSERT_EQ_FMT((size_t)0, count_type(m->answers, m->n_answers, 65), "%zu");
    ASSERT_EQ_FMT((size_t)0, count_type(m->additional, m->n_additional, 65), "%zu");
    ASSERT_EQ_FMTm("SVCB is the same side door under another number", (size_t)0,
                   count_type(m->authority, m->n_authority, 64), "%zu");
    ASSERT_EQ_FMT((size_t)0, m->n_authority, "%zu");
    ASSERT_EQ_FMTm("the OPT is how the client knows we speak EDNS", (size_t)1,
                   count_type(m->additional, m->n_additional, FIRC_DNS_TYPE_OPT), "%zu");
    ASSERT_EQ_FMT((size_t)1, m->n_additional, "%zu");
    firc_dns_msg_free(m);
    PASS();
}

/* Catches: a collapsed message whose counts and arrays disagree. */
TEST a_collapsed_answer_packs_and_parses_back(void) {
    firc_dns_msg_t *m = typical_answer();
    const firc_ip_t f4 = {{198, 18, 0, 7}, 4};
    const firc_ip_t f6 = {{0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}, 16};
    ASSERT_EQ(FIRC_OK, firc_dns_msg_collapse(m, &f4, &f6, 300));

    uint8_t *wire = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_pack(m, &wire, &len));
    firc_dns_msg_t *back = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(wire, len, &back));
    ASSERT_EQ_FMT((size_t)3, back->n_answers, "%zu");
    ASSERT_EQ_FMT((size_t)1, back->n_additional, "%zu");
    ASSERT_EQ_FMT(0x1234u, (unsigned)back->id, "%u");

    firc_dns_msg_free(back);
    free(wire);
    firc_dns_msg_free(m);
    PASS();
}

TEST a_message_with_no_question_is_refused(void) {
    const firc_ip_t f4 = {{198, 18, 0, 7}, 4};
    firc_dns_msg_t *m = typical_answer();
    m->n_questions = 0;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_dns_msg_collapse(m, &f4, NULL, 300));
    ASSERT_EQ_FMTm("untouched", (size_t)5, m->n_answers, "%zu");
    m->n_questions = 1;
    firc_dns_question_t *q = m->questions;
    m->questions = NULL;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_dns_msg_collapse(m, &f4, NULL, 300));
    ASSERT_EQ_FMT((size_t)5, m->n_answers, "%zu");
    m->questions = q;
    firc_dns_msg_free(m);
    PASS();
}

/* Catches: an address of the wrong length written into a slot, or no address turning into NODATA. */
TEST a_wrong_family_or_no_address_is_refused(void) {
    const firc_ip_t f4 = {{198, 18, 0, 7}, 4};
    const firc_ip_t f6 = {{0xfd, 0x37, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}, 16};
    firc_dns_msg_t *m = typical_answer();
    ASSERT_EQ(FIRC_ERR_INVAL, firc_dns_msg_collapse(m, &f6, &f4, 300));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_dns_msg_collapse(m, &f6, NULL, 300));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_dns_msg_collapse(m, NULL, &f4, 300));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_dns_msg_collapse(m, NULL, NULL, 300));
    ASSERT_EQ_FMTm("untouched", (size_t)5, m->n_answers, "%zu");
    ASSERT_EQ_FMT((size_t)2, m->n_additional, "%zu");
    firc_dns_msg_free(m);
    PASS();
}

/* Catches: an AAAA for a v4-only name not answered NODATA, or the CNAME dropped. */
TEST no_address_for_an_answer_that_had_none_is_nodata(void) {
    firc_dns_msg_t *m = typical_answer();
    for (size_t i = 1; i < 4; i++) { free(m->answers[i].rdata); }
    m->answers[1] = m->answers[4];
    m->n_answers = 2;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_collapse(m, NULL, NULL, 300));
    ASSERT_EQ_FMT((size_t)0, count_type(m->answers, m->n_answers, FIRC_DNS_TYPE_CNAME), "%zu");
    ASSERT_EQ_FMT((size_t)0, count_type(m->answers, m->n_answers, FIRC_DNS_TYPE_AAAA), "%zu");
    ASSERT_EQ_FMTm("the TXT stays", (size_t)1, m->n_answers, "%zu");
    firc_dns_msg_free(m);
    PASS();
}

SUITE(rewrite) {
    RUN_TEST(the_chain_is_collapsed_onto_the_queried_name);
    RUN_TEST(a_family_not_offered_gets_no_record);
    RUN_TEST(https_records_are_stripped_from_every_section_and_the_opt_stays);
    RUN_TEST(a_collapsed_answer_packs_and_parses_back);
    RUN_TEST(a_message_with_no_question_is_refused);
    RUN_TEST(a_wrong_family_or_no_address_is_refused);
    RUN_TEST(no_address_for_an_answer_that_had_none_is_nodata);
}

GREATEST_MAIN_DEFS();
int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(rewrite);
    GREATEST_MAIN_END();
}
