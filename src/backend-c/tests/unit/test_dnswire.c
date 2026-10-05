#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "firc/dnswire.h"

/* Builds a query for `labels` with `qtype`. */
static size_t build_query(uint8_t *buf, uint16_t id, const char *const *labels,
                          size_t n_labels, uint16_t qtype)
{
    size_t p = 0;
    buf[p++] = (uint8_t)(id >> 8);
    buf[p++] = (uint8_t)id;
    buf[p++] = 0x01;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x01;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    buf[p++] = 0x00;
    for (size_t i = 0; i < n_labels; i++) {
        size_t l = strlen(labels[i]);
        buf[p++] = (uint8_t)l;
        memcpy(buf + p, labels[i], l);
        p += l;
    }
    buf[p++] = 0;
    buf[p++] = (uint8_t)(qtype >> 8);
    buf[p++] = (uint8_t)qtype;
    buf[p++] = 0x00;
    buf[p++] = 0x01;
    return p;
}

TEST parse_simple_query(void)
{
    uint8_t buf[64];
    const char *labels[] = {"example", "com"};
    size_t len = build_query(buf, 0x1234, labels, 2, FIRC_DNS_TYPE_A);

    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    ASSERT_EQ(0x1234, msg->id);
    ASSERT_EQ(1u, (unsigned)msg->n_questions);
    ASSERT_EQ(FIRC_DNS_TYPE_A, msg->questions[0].qtype);

    char name[1024];
    ASSERT_EQ(FIRC_OK, firc_dns_name_to_string(msg->questions[0].name,
                                           msg->questions[0].name_len, name,
                                           sizeof(name), NULL));
    ASSERT_STR_EQ("example.com.", name);
    firc_dns_msg_free(msg);
    PASS();
}

TEST parse_answer_with_compression(void)
{
    uint8_t buf[] = {
        0xab, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00,
        0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03,
        'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00,
        0x04, 0x01, 0x02, 0x03, 0x04};

    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, sizeof(buf), &msg));
    ASSERT_EQ(1u, (unsigned)msg->n_answers);
    ASSERT_EQ(FIRC_DNS_TYPE_A, msg->answers[0].rtype);
    ASSERT_EQ(300u, msg->answers[0].ttl);
    ASSERT_EQ(4u, (unsigned)msg->answers[0].rdata_len);
    ASSERT_EQ(1, msg->answers[0].rdata[0]);
    ASSERT_EQ(4, msg->answers[0].rdata[3]);

    char name[1024];
    firc_dns_name_to_string(msg->answers[0].name, msg->answers[0].name_len,
                          name, sizeof(name), NULL);
    ASSERT_STR_EQ("www.example.com.", name);
    firc_dns_msg_free(msg);
    PASS();
}

TEST cname_rdata_decompressed(void)
{
    uint8_t buf[] = {
        0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x05, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00,
        0x06, 0x03, 'w', 'w', 'w', 0xc0, 0x0c};

    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, sizeof(buf), &msg));
    ASSERT_EQ(FIRC_DNS_TYPE_CNAME, msg->answers[0].rtype);
    uint8_t expect[] = {0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm',
                        'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00};
    ASSERT_EQ(sizeof(expect), msg->answers[0].rdata_len);
    ASSERT_EQ(0, memcmp(expect, msg->answers[0].rdata, sizeof(expect)));
    firc_dns_msg_free(msg);
    PASS();
}

TEST strip_aaaa(void)
{
    uint8_t buf[] = {
        0x00, 0x02, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x00, 0x01, 'a', 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00,
        0x04, 0x0a, 0x00, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00,
        0x10, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, sizeof(buf), &msg));
    ASSERT_EQ(2u, (unsigned)msg->n_answers);
    firc_dns_msg_strip_aaaa(msg);
    ASSERT_EQ(1u, (unsigned)msg->n_answers);
    ASSERT_EQ(FIRC_DNS_TYPE_A, msg->answers[0].rtype);

    uint8_t *packed = NULL;
    size_t plen = 0;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_pack(msg, &packed, &plen));
    firc_dns_msg_t *rt = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(packed, plen, &rt));
    ASSERT_EQ(1u, (unsigned)rt->n_answers);
    ASSERT_EQ(FIRC_DNS_TYPE_A, rt->answers[0].rtype);
    free(packed);
    firc_dns_msg_free(rt);
    firc_dns_msg_free(msg);
    PASS();
}

static bool reverse_of(const char *const *labels, size_t n, uint16_t qtype, firc_ip_t *out)
{
    uint8_t buf[512];
    size_t len = build_query(buf, 0x1234, labels, n, qtype);
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(buf, len, &msg) != FIRC_OK) { return false; }
    bool ok = firc_dns_ptr_query_addr(msg, out);
    firc_dns_msg_free(msg);
    return ok;
}

TEST a_v4_reverse_name_reads_as_its_address(void)
{
    firc_ip_t ip;
    const char *a[] = {"1", "0", "0", "127", "in-addr", "arpa"};
    ASSERT(reverse_of(a, 6, FIRC_DNS_TYPE_PTR, &ip));
    ASSERT_EQ(4, ip.len);
    const uint8_t want_a[4] = {127, 0, 0, 1};
    ASSERT_MEM_EQ(want_a, ip.b, 4);
    const char *b[] = {"255", "0", "19", "198", "IN-ADDR", "Arpa"};
    ASSERT(reverse_of(b, 6, FIRC_DNS_TYPE_PTR, &ip));
    const uint8_t want_b[4] = {198, 19, 0, 255};
    ASSERT_MEM_EQ(want_b, ip.b, 4);
    PASS();
}

TEST a_v6_reverse_name_of_32_nibbles_reads_as_its_address(void)
{
    const char *n[] = {"A", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                       "0", "0", "0", "0", "0", "1", "e", "b", "c", "5", "a", "9", "7", "3", "d", "f",
                       "ip6", "ARPA"};
    firc_ip_t ip;
    ASSERT(reverse_of(n, 34, FIRC_DNS_TYPE_PTR, &ip));
    ASSERT_EQ(16, ip.len);
    const uint8_t want[16] = {0xfd, 0x37, 0x9a, 0x5c, 0xbe, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a};
    ASSERT_MEM_EQ(want, ip.b, 16);
    PASS();
}

TEST only_a_full_reverse_ptr_question_reads_as_an_address(void)
{
    firc_ip_t ip;
    const char *short4[] = {"0", "0", "127", "in-addr", "arpa"};
    ASSERT_FALSE(reverse_of(short4, 5, FIRC_DNS_TYPE_PTR, &ip));
    const char *long4[] = {"1", "1", "0", "0", "127", "in-addr", "arpa"};
    ASSERT_FALSE(reverse_of(long4, 7, FIRC_DNS_TYPE_PTR, &ip));
    const char *big[] = {"256", "0", "0", "127", "in-addr", "arpa"};
    ASSERT_FALSE(reverse_of(big, 6, FIRC_DNS_TYPE_PTR, &ip));
    const char *zero[] = {"01", "0", "0", "127", "in-addr", "arpa"};
    ASSERT_FALSE(reverse_of(zero, 6, FIRC_DNS_TYPE_PTR, &ip));
    const char *alpha[] = {"1x", "0", "0", "127", "in-addr", "arpa"};
    ASSERT_FALSE(reverse_of(alpha, 6, FIRC_DNS_TYPE_PTR, &ip));
    const char *tail[] = {"1", "0", "0", "127", "in-addr", "arpa", "example"};
    ASSERT_FALSE(reverse_of(tail, 7, FIRC_DNS_TYPE_PTR, &ip));
    const char *zone[] = {"in-addr", "arpa"};
    ASSERT_FALSE(reverse_of(zone, 2, FIRC_DNS_TYPE_PTR, &ip));
    const char *v6in4[] = {"1", "0", "0", "127", "ip6", "arpa"};
    ASSERT_FALSE(reverse_of(v6in4, 6, FIRC_DNS_TYPE_PTR, &ip));
    const char *n31[] = {"1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                         "0", "0", "0", "0", "1", "e", "b", "c", "5", "a", "9", "7", "3", "d", "f",
                         "ip6", "arpa"};
    ASSERT_FALSE(reverse_of(n31, 33, FIRC_DNS_TYPE_PTR, &ip));
    const char *wide[] = {"10", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                          "0", "0", "0", "0", "0", "1", "e", "b", "c", "5", "a", "9", "7", "3", "d", "f",
                          "ip6", "arpa"};
    ASSERT_FALSE(reverse_of(wide, 34, FIRC_DNS_TYPE_PTR, &ip));
    const char *notx[] = {"g", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                          "0", "0", "0", "0", "0", "1", "e", "b", "c", "5", "a", "9", "7", "3", "d", "f",
                          "ip6", "arpa"};
    ASSERT_FALSE(reverse_of(notx, 34, FIRC_DNS_TYPE_PTR, &ip));
    const char *ok[] = {"1", "0", "0", "127", "in-addr", "arpa"};
    ASSERT_FALSE(reverse_of(ok, 6, FIRC_DNS_TYPE_A, &ip));
    ASSERTm("control: the same name as a PTR question reads", reverse_of(ok, 6, FIRC_DNS_TYPE_PTR, &ip));

    uint8_t buf[512];
    size_t len = build_query(buf, 0x1234, ok, 6, FIRC_DNS_TYPE_PTR);
    firc_dns_msg_t *msg = NULL;
    buf[len - 1] = 3;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    ASSERT_FALSE(firc_dns_ptr_query_addr(msg, &ip));
    firc_dns_msg_free(msg);
    buf[len - 1] = 1;
    buf[2] |= 0x80;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    ASSERT_FALSE(firc_dns_ptr_query_addr(msg, &ip));
    firc_dns_msg_free(msg);
    buf[2] = 0x01 | (4 << 3);
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    ASSERT_FALSE(firc_dns_ptr_query_addr(msg, &ip));
    firc_dns_msg_free(msg);
    buf[2] = 0x01;
    memcpy(buf + len, buf + 12, len - 12);
    buf[5] = 2;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len + (len - 12), &msg));
    ASSERT_FALSE(firc_dns_ptr_query_addr(msg, &ip));
    firc_dns_msg_free(msg);
    ASSERT_FALSE(firc_dns_ptr_query_addr(NULL, &ip));
    PASS();
}

static firc_dns_msg_t *ptr_answer(bool edns, const char *target, uint32_t ttl, firc_err_t *err)
{
    uint8_t buf[512];
    const char *labels[] = {"5", "0", "18", "198", "in-addr", "arpa"};
    size_t len = build_query(buf, 0x7777, labels, 6, FIRC_DNS_TYPE_PTR);
    if (edns) {
        const uint8_t opt[] = {0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0};
        memcpy(buf + len, opt, sizeof(opt));
        len += sizeof(opt);
        buf[11] = 1;
    }
    firc_dns_msg_t *q = NULL;
    if (firc_dns_msg_parse(buf, len, &q) != FIRC_OK) { abort(); }
    uint8_t *out = NULL;
    size_t out_len = 0;
    *err = firc_dns_make_ptr_response(q, target, ttl, &out, &out_len);
    firc_dns_msg_free(q);
    if (*err != FIRC_OK) { return NULL; }
    firc_dns_msg_t *r = NULL;
    if (firc_dns_msg_parse(out, out_len, &r) != FIRC_OK) { abort(); }
    free(out);
    return r;
}

TEST a_ptr_answer_names_the_target_with_the_ttl(void)
{
    firc_err_t err = FIRC_ERR_IO;
    firc_dns_msg_t *r = ptr_answer(false, "shop.example.com", 300, &err);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ(0x7777, r->id);
    ASSERT_EQ(FIRC_DNS_FLAG_QR | 0x0100 | FIRC_DNS_FLAG_RA, r->flags);
    ASSERT_EQ(1u, (unsigned)r->n_questions);
    ASSERT_EQ(FIRC_DNS_TYPE_PTR, r->questions[0].qtype);
    ASSERT_EQ(1, r->questions[0].qclass);
    ASSERT_MEM_EQ("\0015\0010\00218\003198\007in-addr\004arpa", r->questions[0].name, 24);
    ASSERT_EQ(1u, (unsigned)r->n_answers);
    ASSERT_EQ(FIRC_DNS_TYPE_PTR, r->answers[0].rtype);
    ASSERT_EQ(1, r->answers[0].rclass);
    ASSERT_EQ(300u, r->answers[0].ttl);
    ASSERT_EQ(r->questions[0].name_len, r->answers[0].name_len);
    ASSERT_MEM_EQ(r->questions[0].name, r->answers[0].name, r->answers[0].name_len);
    ASSERT_EQ(18u, (unsigned)r->answers[0].rdata_len);
    ASSERT_MEM_EQ("\004shop\007example\003com", r->answers[0].rdata, 18);
    ASSERT_EQ(0u, (unsigned)r->n_authority);
    ASSERT_EQ(0u, (unsigned)r->n_additional);
    firc_dns_msg_free(r);
    PASS();
}

TEST no_target_is_nxdomain_and_edns_is_answered_in_kind(void)
{
    firc_err_t err = FIRC_ERR_IO;
    firc_dns_msg_t *r = ptr_answer(true, NULL, 300, &err);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ(FIRC_DNS_FLAG_QR | 0x0100 | FIRC_DNS_FLAG_RA | FIRC_DNS_RCODE_NXDOMAIN, r->flags);
    ASSERT_EQ(1u, (unsigned)r->n_questions);
    ASSERT_EQ(0u, (unsigned)r->n_answers);
    ASSERT_EQ(1u, (unsigned)r->n_additional);
    ASSERT_EQ(FIRC_DNS_TYPE_OPT, r->additional[0].rtype);
    ASSERT_EQ(0u, (unsigned)r->additional[0].rdata_len);
    ASSERT_EQ(1u, (unsigned)r->additional[0].name_len);
    ASSERT_EQ(1232, r->additional[0].rclass);
    firc_dns_msg_free(r);
    PASS();
}

TEST a_ptr_query_without_rd_is_answered_without_rd(void)
{
    uint8_t buf[512];
    const char *labels[] = {"5", "0", "18", "198", "in-addr", "arpa"};
    size_t len = build_query(buf, 0x7777, labels, 6, FIRC_DNS_TYPE_PTR);
    buf[2] = 0x00;
    firc_dns_msg_t *q = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &q));
    const char *targets[] = {"shop.example.com", NULL};
    for (size_t i = 0; i < 2; i++) {
        uint8_t *out = NULL;
        size_t out_len = 0;
        ASSERT_EQ(FIRC_OK, firc_dns_make_ptr_response(q, targets[i], 300, &out, &out_len));
        firc_dns_msg_t *r = NULL;
        ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(out, out_len, &r));
        free(out);
        uint16_t want = (uint16_t)(FIRC_DNS_FLAG_QR | FIRC_DNS_FLAG_RA | (i == 1 ? FIRC_DNS_RCODE_NXDOMAIN : 0));
        ASSERT_EQ(want, r->flags);
        firc_dns_msg_free(r);
    }
    firc_dns_msg_free(q);
    PASS();
}

TEST a_target_that_is_not_a_name_is_refused(void)
{
    firc_err_t err = FIRC_OK;
    ASSERT_EQ(NULL, ptr_answer(false, "a..b", 60, &err));
    ASSERT_EQ(FIRC_ERR_INVAL, err);
    ASSERT_EQ(NULL, ptr_answer(false, "", 60, &err));
    ASSERT_EQ(FIRC_ERR_INVAL, err);
    char label[70];
    memset(label, 'a', 64);
    memcpy(label + 64, ".com", 5);
    ASSERT_EQ(NULL, ptr_answer(false, label, 60, &err));
    ASSERT_EQ(FIRC_ERR_INVAL, err);
    label[1] = '.';
    firc_dns_msg_t *r = ptr_answer(false, label, 60, &err);
    ASSERTm("control: labels of 1 and 62 octets pack", r != NULL);
    firc_dns_msg_free(r);
    PASS();
}

TEST rejects_malformed(void)
{
    firc_dns_msg_t *msg = NULL;
    uint8_t a[] = {0, 0, 0};
    ASSERT_EQ(FIRC_ERR_PROTO, firc_dns_msg_parse(a, sizeof(a), &msg));
    uint8_t c[] = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x3f, 'x'};
    ASSERT_EQ(FIRC_ERR_PROTO, firc_dns_msg_parse(c, sizeof(c), &msg));
    PASS();
}

TEST header_only_is_lenient(void)
{
    uint8_t b[] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0};
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(b, sizeof(b), &msg));
    ASSERT_EQ(0u, (unsigned)msg->n_questions);
    ASSERT_EQ(0u, (unsigned)msg->n_answers);
    firc_dns_msg_free(msg);
    PASS();
}

TEST rejects_compression_loop(void)
{
    uint8_t buf[] = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1,
                     0, 1};
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_dns_msg_parse(buf, sizeof(buf), &msg));
    PASS();
}

/* Catches: the clamp raising a TTL, or stopping after the first record. */
TEST clamp_ttl_lowers_answer_ttls_and_never_raises_them(void) {
    firc_dns_rr_t answers[5] = {0};
    static const uint32_t before[5] = {60, 300, 301, 86400, 0};
    static const uint32_t want[5] = {60, 300, 300, 300, 0};
    for (size_t i = 0; i < 5; i++) { answers[i].ttl = before[i]; }

    firc_dns_rr_t extra = {0};
    extra.ttl = 86400;

    firc_dns_msg_t msg = {0};
    msg.answers = answers;
    msg.n_answers = 5;
    msg.additional = &extra;
    msg.n_additional = 1;

    firc_dns_msg_clamp_ttl(&msg, 300);

    for (size_t i = 0; i < 5; i++) { ASSERT_EQ_FMT(want[i], answers[i].ttl, "%u"); }
    ASSERT_EQ_FMTm("sections other than the answer carry no address of ours", 86400u,
                   extra.ttl, "%u");
    PASS();
}

/* Catches: owner names packed uncompressed, or compressed to a wrong offset. */
TEST owner_names_are_compressed_on_pack(void) {
    static const uint8_t www[] = {3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    static const uint8_t cdn[] = {3, 'c', 'd', 'n', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0};
    firc_dns_msg_t *m = calloc(1, sizeof(*m));
    m->id = 1;
    m->flags = 0x8180;
    m->questions = calloc(1, sizeof(*m->questions));
    m->n_questions = 1;
    memcpy(m->questions[0].name, www, sizeof(www));
    m->questions[0].name_len = sizeof(www);
    m->questions[0].qtype = FIRC_DNS_TYPE_A;
    m->questions[0].qclass = 1;
    m->answers = calloc(4, sizeof(*m->answers));
    m->n_answers = 4;
    for (size_t i = 0; i < 3; i++) {
        const uint8_t *owner = i == 2 ? cdn : www;
        memcpy(m->answers[i].name, owner, sizeof(www));
        m->answers[i].name_len = sizeof(www);
        m->answers[i].rtype = FIRC_DNS_TYPE_A;
        m->answers[i].rclass = 1;
        m->answers[i].ttl = 300;
        m->answers[i].rdata = malloc(4);
        memset(m->answers[i].rdata, (int)i + 1, 4);
        m->answers[i].rdata_len = 4;
    }
    memcpy(m->answers[3].name, www, sizeof(www));
    m->answers[3].name_len = sizeof(www);
    m->answers[3].rtype = FIRC_DNS_TYPE_CNAME;
    m->answers[3].rclass = 1;
    m->answers[3].ttl = 300;
    m->answers[3].rdata = malloc(sizeof(cdn));
    memcpy(m->answers[3].rdata, cdn, sizeof(cdn));
    m->answers[3].rdata_len = sizeof(cdn);

    uint8_t *wire = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_pack(m, &wire, &len));
    ASSERT_EQ_FMT((size_t)12 + 21 + 2 * 16 + 20 + 29, len, "%zu");
    ASSERTm("the CNAME's rdata is the target's bytes, uncompressed (RFC 3597 territory)",
            memcmp(wire + len - sizeof(cdn), cdn, sizeof(cdn)) == 0);
    ASSERT_EQ_FMTm("first answer: pointer to the question name at offset 12", 0xc0u, (unsigned)wire[33], "%#x");
    ASSERT_EQ_FMT(12u, (unsigned)wire[34], "%u");

    firc_dns_msg_t *back = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(wire, len, &back));
    ASSERT_EQ_FMT((size_t)4, back->n_answers, "%zu");
    for (size_t i = 0; i < 3; i++) {
        const uint8_t *owner = i == 2 ? cdn : www;
        ASSERT_EQ_FMT(sizeof(www), back->answers[i].name_len, "%zu");
        ASSERT_MEM_EQ(owner, back->answers[i].name, sizeof(www));
        ASSERT_EQ((int)i + 1, back->answers[i].rdata[0]);
    }
    firc_dns_msg_free(back);
    free(wire);
    firc_dns_msg_free(m);
    PASS();
}

/* Catches: the OPT ignored, a size below 512 honoured, or the size read from the wrong field. */
TEST the_udp_payload_size_comes_from_the_opt_record_or_is_512(void) {
    firc_dns_msg_t none = {0};
    ASSERT_EQ_FMT(512u, (unsigned)firc_dns_msg_udp_payload_size(&none), "%u");

    firc_dns_rr_t opt = {0};
    opt.rtype = FIRC_DNS_TYPE_OPT;
    opt.rclass = 1232;
    firc_dns_msg_t with = {0};
    with.additional = &opt;
    with.n_additional = 1;
    ASSERT_EQ_FMT(1232u, (unsigned)firc_dns_msg_udp_payload_size(&with), "%u");

    opt.rclass = 400;
    ASSERT_EQ_FMTm("under the RFC 1035 minimum the minimum stands", 512u,
                   (unsigned)firc_dns_msg_udp_payload_size(&with), "%u");

    firc_dns_rr_t not_opt = {0};
    not_opt.rtype = FIRC_DNS_TYPE_A;
    not_opt.rclass = 4096;
    with.additional = &not_opt;
    ASSERT_EQ_FMTm("only an OPT carries a size", 512u,
                   (unsigned)firc_dns_msg_udp_payload_size(&with), "%u");
    PASS();
}

/* Catches: a truncated reply without TC, with answers left in, or without the OPT. */
TEST truncating_keeps_only_the_question_and_the_opt(void) {
    firc_dns_rr_t *answers = calloc(2, sizeof(*answers));
    answers[0].rdata = malloc(4);
    answers[0].rdata_len = 4;
    answers[1].rdata = malloc(4);
    answers[1].rdata_len = 4;
    firc_dns_rr_t *authority = calloc(1, sizeof(*authority));
    authority[0].rdata = malloc(1);
    firc_dns_rr_t *additional = calloc(2, sizeof(*additional));
    additional[0].rtype = FIRC_DNS_TYPE_A;
    additional[0].rdata = malloc(4);
    additional[1].rtype = FIRC_DNS_TYPE_OPT;
    additional[1].rclass = 1232;
    additional[1].name_len = 1;
    firc_dns_question_t *q = calloc(1, sizeof(*q));
    q->name_len = 1;
    q->qtype = FIRC_DNS_TYPE_A;
    q->qclass = 1;

    firc_dns_msg_t *msg = calloc(1, sizeof(*msg));
    msg->flags = 0x8180;
    msg->questions = q;
    msg->n_questions = 1;
    msg->answers = answers;
    msg->n_answers = 2;
    msg->authority = authority;
    msg->n_authority = 1;
    msg->additional = additional;
    msg->n_additional = 2;

    firc_dns_msg_truncate(msg);

    ASSERT(msg->flags & FIRC_DNS_FLAG_TC);
    ASSERT_EQ_FMTm("the rest of the header is not ours to change", 0x8180u | FIRC_DNS_FLAG_TC,
                   (unsigned)msg->flags, "%#x");
    ASSERT_EQ_FMT((size_t)1, msg->n_questions, "%zu");
    ASSERT_EQ_FMT((size_t)0, msg->n_answers, "%zu");
    ASSERT_EQ_FMT((size_t)0, msg->n_authority, "%zu");
    ASSERT_EQ_FMT((size_t)1, msg->n_additional, "%zu");
    ASSERT_EQ(FIRC_DNS_TYPE_OPT, msg->additional[0].rtype);
    ASSERT_EQ_FMT(1232u, (unsigned)msg->additional[0].rclass, "%u");

    uint8_t *wire = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_pack(msg, &wire, &len));
    ASSERT_EQ_FMT((size_t)12 + 1 + 4 + 11, len, "%zu");
    free(wire);

    firc_dns_msg_free(msg);
    PASS();
}

/* Catches: the routing key taken from an answer record's owner instead of the question. */
TEST the_queried_name_is_taken_from_the_question(void)
{
    uint8_t buf[512];
    const char *q[] = {"www", "example", "com"};
    size_t p = build_query(buf, 0x4242, q, 3, FIRC_DNS_TYPE_A);
    buf[2] = 0x81;
    buf[3] = 0x80;
    buf[7] = 0x02;

    static const char *owner[] = {"www", "example", "com"};
    for (size_t i = 0; i < 3; i++) {
        size_t l = strlen(owner[i]);
        buf[p++] = (uint8_t)l;
        memcpy(buf + p, owner[i], l);
        p += l;
    }
    buf[p++] = 0;
    buf[p++] = 0; buf[p++] = FIRC_DNS_TYPE_CNAME;
    buf[p++] = 0; buf[p++] = 1;
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 60;
    size_t rdlen_at = p;
    buf[p++] = 0; buf[p++] = 0;
    size_t rd_start = p;
    static const char *target[] = {"cdn", "example", "net"};
    for (size_t i = 0; i < 3; i++) {
        size_t l = strlen(target[i]);
        buf[p++] = (uint8_t)l;
        memcpy(buf + p, target[i], l);
        p += l;
    }
    buf[p++] = 0;
    buf[rdlen_at] = (uint8_t)((p - rd_start) >> 8);
    buf[rdlen_at + 1] = (uint8_t)(p - rd_start);

    for (size_t i = 0; i < 3; i++) {
        size_t l = strlen(target[i]);
        buf[p++] = (uint8_t)l;
        memcpy(buf + p, target[i], l);
        p += l;
    }
    buf[p++] = 0;
    buf[p++] = 0; buf[p++] = FIRC_DNS_TYPE_A;
    buf[p++] = 0; buf[p++] = 1;
    buf[p++] = 0; buf[p++] = 0; buf[p++] = 0; buf[p++] = 60;
    buf[p++] = 0; buf[p++] = 4;
    buf[p++] = 93; buf[p++] = 184; buf[p++] = 216; buf[p++] = 34;

    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, p, &msg));
    ASSERT_EQ_FMTm("the fixture must actually carry both records", (size_t)2, msg->n_answers,
                   "%zu");

    char name[300];
    ASSERT(firc_dns_msg_queried_name(msg, name, sizeof(name)));
    ASSERT_STR_EQm("the question, not the answer's owner", "www.example.com", name);

    char other[300];
    ASSERT_EQ(FIRC_OK, firc_dns_name_to_string(msg->answers[1].name, msg->answers[1].name_len,
                                               other, sizeof(other), NULL));
    ASSERT_STR_EQ("cdn.example.net.", other);

    firc_dns_msg_free(msg);
    PASS();
}

TEST a_message_with_no_question_has_no_queried_name(void)
{
    uint8_t buf[32];
    memset(buf, 0, sizeof(buf));
    buf[0] = 0x12; buf[1] = 0x34;
    buf[2] = 0x81; buf[3] = 0x80;

    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, 12, &msg));
    ASSERT_EQ_FMT((size_t)0, msg->n_questions, "%zu");

    char name[300];
    memset(name, 'x', sizeof(name));
    ASSERT_FALSEm("no question means no routing key, not an empty one",
                  firc_dns_msg_queried_name(msg, name, sizeof(name)));
    firc_dns_msg_free(msg);

    const char *q[] = {"averyverylongdomainlabelindeed", "example", "com"};
    uint8_t qb[128];
    size_t len = build_query(qb, 1, q, 3, FIRC_DNS_TYPE_A);
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(qb, len, &msg));
    char small[8];
    ASSERT_FALSE(firc_dns_msg_queried_name(msg, small, sizeof(small)));
    firc_dns_msg_free(msg);
    PASS();
}

TEST the_root_is_not_a_routing_key(void)
{
    uint8_t buf[32];
    size_t len = build_query(buf, 7, NULL, 0, FIRC_DNS_TYPE_A);
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));

    char name[300];
    ASSERT_FALSE(firc_dns_msg_queried_name(msg, name, sizeof(name)));
    firc_dns_msg_free(msg);
    PASS();
}

/* Catches: a routing key not folded to lower case, so mixed-case queries match nothing. */
TEST the_routing_key_is_case_folded(void)
{
    static const struct {
        const char *l1, *l2, *l3;
    } rows[] = {
        {"WWW", "EXAMPLE", "COM"},
        {"WwW", "ExAmPlE", "CoM"},
        {"www", "example", "com"},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        const char *labels[] = {rows[i].l1, rows[i].l2, rows[i].l3};
        uint8_t buf[128];
        size_t len = build_query(buf, 1, labels, 3, FIRC_DNS_TYPE_A);
        firc_dns_msg_t *msg = NULL;
        ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
        char name[300];
        ASSERT(firc_dns_msg_queried_name(msg, name, sizeof(name)));
        ASSERT_STR_EQm("however the client spelled it", "www.example.com", name);
        firc_dns_msg_free(msg);
    }

    const char *mixed[] = {"A-1_b", "Example", "COM"};
    uint8_t buf[128];
    size_t len = build_query(buf, 2, mixed, 3, FIRC_DNS_TYPE_A);
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));
    char name[300];
    ASSERT(firc_dns_msg_queried_name(msg, name, sizeof(name)));
    ASSERT_STR_EQ("a-1_b.example.com", name);
    firc_dns_msg_free(msg);
    PASS();
}

/* Catches: an off-by-one in the buffer check, writing one byte past it. */
TEST a_buffer_exactly_the_size_of_the_name_is_refused(void)
{
    const char *labels[] = {"ab", "cd"};
    uint8_t buf[64];
    size_t len = build_query(buf, 3, labels, 2, FIRC_DNS_TYPE_A);
    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, len, &msg));

    char exact[5];
    memset(exact, 'Z', sizeof(exact));
    ASSERT_FALSEm("five characters plus a NUL do not fit in five bytes",
                  firc_dns_msg_queried_name(msg, exact, sizeof(exact)));
    for (size_t i = 0; i < sizeof(exact); i++) {
        if (exact[i] != 'Z') { FAILm("a refusal wrote into the caller's buffer"); }
    }

    char just_enough[6];
    ASSERT(firc_dns_msg_queried_name(msg, just_enough, sizeof(just_enough)));
    ASSERT_STR_EQ("ab.cd", just_enough);
    firc_dns_msg_free(msg);
    PASS();
}

/* Catches: a name with an escaped dot accepted as a routing key. */
TEST a_name_needing_escapes_is_not_a_routing_key(void)
{
    uint8_t buf[128];
    size_t p = 0;
    buf[p++] = 0; buf[p++] = 4;
    buf[p++] = 0x01; buf[p++] = 0x00;
    buf[p++] = 0; buf[p++] = 1;
    buf[p++] = 0; buf[p++] = 0;
    buf[p++] = 0; buf[p++] = 0;
    buf[p++] = 0; buf[p++] = 0;
    buf[p++] = 3; buf[p++] = 'a'; buf[p++] = '.'; buf[p++] = 'b';
    const char *rest[] = {"example", "com"};
    for (size_t i = 0; i < 2; i++) {
        size_t l = strlen(rest[i]);
        buf[p++] = (uint8_t)l;
        memcpy(buf + p, rest[i], l);
        p += l;
    }
    buf[p++] = 0;
    buf[p++] = 0; buf[p++] = FIRC_DNS_TYPE_A;
    buf[p++] = 0; buf[p++] = 1;

    firc_dns_msg_t *msg = NULL;
    ASSERT_EQ(FIRC_OK, firc_dns_msg_parse(buf, p, &msg));
    char name[300];
    ASSERT_FALSEm("an escaped name would be matched into the wrong zone",
                  firc_dns_msg_queried_name(msg, name, sizeof(name)));
    firc_dns_msg_free(msg);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(parse_simple_query);
    RUN_TEST(parse_answer_with_compression);
    RUN_TEST(cname_rdata_decompressed);
    RUN_TEST(strip_aaaa);
    RUN_TEST(a_v4_reverse_name_reads_as_its_address);
    RUN_TEST(a_v6_reverse_name_of_32_nibbles_reads_as_its_address);
    RUN_TEST(only_a_full_reverse_ptr_question_reads_as_an_address);
    RUN_TEST(a_ptr_answer_names_the_target_with_the_ttl);
    RUN_TEST(no_target_is_nxdomain_and_edns_is_answered_in_kind);
    RUN_TEST(a_ptr_query_without_rd_is_answered_without_rd);
    RUN_TEST(a_target_that_is_not_a_name_is_refused);
    RUN_TEST(rejects_malformed);
    RUN_TEST(header_only_is_lenient);
    RUN_TEST(rejects_compression_loop);
    RUN_TEST(clamp_ttl_lowers_answer_ttls_and_never_raises_them);
    RUN_TEST(owner_names_are_compressed_on_pack);
    RUN_TEST(the_udp_payload_size_comes_from_the_opt_record_or_is_512);
    RUN_TEST(truncating_keeps_only_the_question_and_the_opt);
    RUN_TEST(the_queried_name_is_taken_from_the_question);
    RUN_TEST(a_message_with_no_question_has_no_queried_name);
    RUN_TEST(the_root_is_not_a_routing_key);
    RUN_TEST(the_routing_key_is_case_folded);
    RUN_TEST(a_buffer_exactly_the_size_of_the_name_is_refused);
    RUN_TEST(a_name_needing_escapes_is_not_a_routing_key);
    GREATEST_MAIN_END();
}
