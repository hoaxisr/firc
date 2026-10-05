#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "fake_nflog.h"
#include "firc/events.h"
#include "firc/taprules.h"
#include "firc/tapwindow.h"

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {0};
    ip.len = 4;
    ip.b[0] = a; ip.b[1] = b; ip.b[2] = c; ip.b[3] = d;
    return ip;
}

static firc_ruleset_snapshot_t *make_snap(void) {
    firc_config_t cfg;
    firc_config_init_defaults(&cfg);
    firc_group_t *g = firc_group_new();
    g->id = (firc_id_t){{1, 0, 0, 0}};
    firc_strset(&g->name, "media");
    g->enable = true;
    g->devices.allow = calloc(2, sizeof(char *));
    g->devices.allow[0] = strdup("192.168.1.0/24");
    g->devices.allow[1] = strdup("fd00:1::/64");
    g->devices.n_allow = 2;
    firc_rule_t *r = firc_rule_new();
    r->id = (firc_id_t){{1, 1, 0, 0}};
    firc_strset(&r->type, "namespace");
    firc_strset(&r->rule, "example.com");
    r->enable = true;
    firc_group_add_rule(g, r);
    firc_config_add_group(&cfg, g);
    firc_ruleset_snapshot_t *snap = firc_ruleset_snapshot_build(&cfg);
    firc_config_clear(&cfg);
    return snap;
}

static int64_t fake_now;
static int64_t clock_fn(void) { return fake_now; }

typedef struct {
    fake_nflog_t *k[2];
    firc_nflog_t *n[2];
    firc_dns_pipeline_t *p;
    firc_recall_t *recall;
    firc_tap_report_t *rep;
    firc_tap_drain_t d[2];
} rig_t;

static bool rig_up(rig_t *r) {
    memset(r, 0, sizeof(*r));
    firc_event_reset_for_test();
    fake_now = 1000;
    static const uint16_t group[2] = {FIRC_TAP_GROUP_NEW, FIRC_TAP_GROUP_HELLO};
    static const uint16_t range[2] = {FIRC_TAP_HEAD_RANGE, FIRC_TAP_COPY_RANGE};
    for (int w = 0; w < 2; w++) {
        int fd = -1;
        r->k[w] = fake_nflog_start(&fd);
        if (r->k[w] == NULL) { return false; }
        r->n[w] = firc_nflog_open_fd(fd, group[w], range[w]);
        if (r->n[w] == NULL) { return false; }
    }
    r->p = firc_dns_pipeline_create();
    firc_ruleset_snapshot_t *snap = make_snap();
    r->rep = firc_tap_report_new(16);
    if (r->p == NULL || snap == NULL || r->rep == NULL) { return false; }
    firc_dns_pipeline_set_snapshot(r->p, snap);
    r->recall = firc_dns_pipeline_recall(r->p);
    if (r->recall == NULL) { return false; }
    for (int w = 0; w < 2; w++) {
        r->d[w].ctx.snap = firc_dns_pipeline_snapshot(r->p);
        r->d[w].ctx.pipeline = r->p;
        r->d[w].ctx.recall = r->recall;
        r->d[w].report = r->rep;
        r->d[w].which = w;
        r->d[w].now = clock_fn;
    }
    return true;
}

static void rig_down(rig_t *r) {
    firc_tap_report_free(r->rep);
    firc_dns_pipeline_destroy(r->p);
    for (int w = 0; w < 2; w++) {
        firc_nflog_close(r->n[w]);
        fake_nflog_stop(r->k[w]);
    }
    firc_event_reset_for_test();
}

/* Sends one packet to socket `w` and drains one datagram; the events put, or (size_t)-1. */
static size_t push(rig_t *r, int w, const uint8_t *pkt, size_t len) {
    _Alignas(4) uint8_t dg[2400];
    size_t dg_len = fake_nflog_msg(dg, pkt, len);
    if (!fake_nflog_send(r->k[w], dg, dg_len)) { return (size_t)-1; }
    size_t events = 0;
    if (firc_tap_drain(&r->d[w], r->n[w], &events) != FIRC_OK) { return (size_t)-1; }
    return events;
}

static const uint8_t no_payload[1];

static size_t syn(rig_t *r, const firc_ip_t *src, const firc_ip_t *dst, uint16_t port) {
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, src->b, dst->b, port, no_payload, 0);
    return push(r, 0, pkt, len);
}

/* A UDP datagram's head. */
static size_t udp(rig_t *r, const firc_ip_t *src, const firc_ip_t *dst, uint16_t port) {
    uint8_t pkt[28];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x45;
    pkt[3] = 28;
    pkt[8] = 64;
    pkt[9] = 17;
    memcpy(pkt + 12, src->b, 4);
    memcpy(pkt + 16, dst->b, 4);
    pkt[20] = 0xc0;
    pkt[22] = (uint8_t)(port >> 8);
    pkt[23] = (uint8_t)port;
    pkt[25] = 8;
    return push(r, 0, pkt, sizeof(pkt));
}

/* A ClientHello naming `sni`, to 443, on the hello socket. */
static size_t hello(rig_t *r, const firc_ip_t *src, const firc_ip_t *dst, const char *sni) {
    uint8_t rec[1024], pkt[1200];
    size_t rec_len = fake_nflog_hello(rec, sni);
    size_t len = fake_nflog_packet(pkt, src->b, dst->b, 443, rec, rec_len);
    return push(r, 1, pkt, len);
}

/* An IPv6 TCP SYN: a 40-byte header and a bare 20-byte TCP header. */
static size_t syn6(rig_t *r, const firc_ip_t *src, const firc_ip_t *dst, uint16_t port) {
    uint8_t pkt[60];
    memset(pkt, 0, sizeof(pkt));
    pkt[0] = 0x60;
    pkt[5] = 20;
    pkt[6] = 6;
    pkt[7] = 64;
    memcpy(pkt + 8, src->b, 16);
    memcpy(pkt + 24, dst->b, 16);
    pkt[40] = 0xc0;
    pkt[42] = (uint8_t)(port >> 8);
    pkt[43] = (uint8_t)port;
    pkt[52] = 0x50;
    pkt[53] = 0x02;
    return push(r, 0, pkt, sizeof(pkt));
}

static size_t read_events(firc_event_t *out, size_t cap) {
    uint64_t next = 0, dropped = 0;
    return firc_event_read(0, out, cap, &next, &dropped);
}

typedef struct {
    char buf[4096];
    size_t len;
} said_t;

static void collect(const char *sentence, void *ud) {
    said_t *s = ud;
    int w = snprintf(s->buf + s->len, sizeof(s->buf) - s->len, "%s\n", sentence);
    if (w > 0 && (size_t)w < sizeof(s->buf) - s->len) { s->len += (size_t)w; }
}

static said_t *summary(const rig_t *r) {
    static said_t s;
    memset(&s, 0, sizeof(s));
    firc_tap_report_sentences(r->rep, true, collect, &s);
    return &s;
}

static bool ip_is(const firc_ip_t *ip, const firc_ip_t *want) {
    return ip->len == want->len && memcmp(ip->b, want->b, ip->len) == 0;
}

static firc_event_t ev[8];

/* Catches: a bypass event missing a field, or the wrong annotation of what firc answered. */
TEST a_new_connection_to_a_recalled_address_becomes_a_bypass_event(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t real = v4(104, 21, 0, 5), fake = v4(198, 18, 0, 7);
    firc_ip_t asked = v4(192, 168, 1, 42), silent = v4(192, 168, 1, 43);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 900);
    firc_recall_answer(r.recall, &asked, "video.example.com", FIRC_RECALL_V4, FIRC_DNS_ISSUED, &fake, 950);

    ASSERT_EQ_FMT((size_t)1, syn(&r, &asked, &real, 8443), "%zu");
    fake_now = 1003;
    ASSERT_EQ_FMT((size_t)1, udp(&r, &silent, &real, 443), "%zu");

    ASSERT_EQ_FMT((size_t)2, read_events(ev, 8), "%zu");
    const firc_event_bypass_t *b = &ev[0].u.bypass;
    ASSERT_EQ(FIRC_EVENT_BYPASS, ev[0].kind);
    ASSERT_EQ_FMT(1000LL, (long long)ev[0].at, "%lld");
    ASSERT(ip_is(&b->client, &asked));
    ASSERT(ip_is(&b->dst, &real));
    ASSERT_EQ_FMT(8443u, (unsigned)b->dst_port, "%u");
    ASSERT_EQ_FMT(6u, (unsigned)b->proto, "%u");
    ASSERT_EQ_FMT((unsigned)FIRC_BYPASS_BY_ADDR, (unsigned)b->how, "%u");
    ASSERT_STR_EQ("video.example.com", b->name);
    ASSERT_STR_EQ("01000000", b->group_id);
    ASSERT_STR_EQ("media", b->group_name);
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)b->last_decision, "%u");
    ASSERT_EQ_FMT(950LL, (long long)b->last_at, "%lld");
    ASSERT(ip_is(&b->last_fake, &fake));
    ASSERT_EQ_FMT(0u, b->repeats, "%u");

    b = &ev[1].u.bypass;
    ASSERT_EQ_FMT(1003LL, (long long)ev[1].at, "%lld");
    ASSERT(ip_is(&b->client, &silent));
    ASSERT_EQ_FMTm("UDP, from the head", 17u, (unsigned)b->proto, "%u");
    ASSERT_EQ_FMT(443u, (unsigned)b->dst_port, "%u");
    ASSERT_EQ_FMTm("never asked", (unsigned)FIRC_BYPASS_NOT_ASKED, (unsigned)b->last_decision,
                   "%u");
    ASSERT_EQ_FMT(0LL, (long long)b->last_at, "%lld");
    ASSERT_EQ_FMT(0u, (unsigned)b->last_fake.len, "%u");
    rig_down(&r);
    PASS();
}

/* Catches: the drain looking up the client's answer without the destination's family. */
TEST a_bypass_reads_the_answer_of_its_own_family(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t real4 = v4(104, 21, 0, 5), fake4 = v4(198, 18, 0, 7);
    firc_ip_t real6 = {{0x20, 0x01, 0x0d, 0xb8, [15] = 5}, 16};
    firc_ip_t c4 = v4(192, 168, 1, 42);
    firc_ip_t c6 = {{0xfd, 0x00, 0x00, 0x01, [15] = 0x42}, 16};
    firc_recall_real(r.recall, &real4, "video.example.com", "01000000", 900);
    firc_recall_real(r.recall, &real6, "video.example.com", "01000000", 900);
    const firc_ip_t *askers[2] = {&c4, &c6};
    for (int i = 0; i < 2; i++) {
        firc_recall_answer(r.recall, askers[i], "video.example.com", FIRC_RECALL_V4,
                           FIRC_DNS_ISSUED, &fake4, 950);
        firc_recall_answer(r.recall, askers[i], "video.example.com", FIRC_RECALL_V6,
                           FIRC_DNS_ISSUED, NULL, 951);
    }

    ASSERT_EQ_FMT((size_t)1, syn(&r, &c4, &real4, 443), "%zu");
    ASSERT_EQ_FMT((size_t)1, syn6(&r, &c6, &real6, 443), "%zu");
    ASSERT_EQ_FMT((size_t)2, read_events(ev, 8), "%zu");

    const firc_event_bypass_t *b = &ev[0].u.bypass;
    ASSERT(ip_is(&b->dst, &real4));
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)b->last_decision, "%u");
    ASSERT_EQ_FMT(950LL, (long long)b->last_at, "%lld");
    ASSERTm("the v4 answer's fake", ip_is(&b->last_fake, &fake4));

    b = &ev[1].u.bypass;
    ASSERT(ip_is(&b->client, &c6));
    ASSERT(ip_is(&b->dst, &real6));
    ASSERT_EQ_FMT((unsigned)FIRC_DNS_ISSUED, (unsigned)b->last_decision, "%u");
    ASSERT_EQ_FMTm("the v6 answer, not the v4 one", 951LL, (long long)b->last_at, "%lld");
    ASSERT_EQ_FMTm("issued, with no address of this family", 0u,
                   (unsigned)b->last_fake.len, "%u");
    rig_down(&r);
    PASS();
}

/* Catches: a hello to an unrecalled address not judged by its SNI. */
TEST a_hello_becomes_a_bypass_event_by_sni(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t dst = v4(104, 21, 0, 9), client = v4(192, 168, 1, 42);
    ASSERT_EQ_FMTm("the address path knows nothing", (size_t)0, syn(&r, &client, &dst, 443),
                   "%zu");
    ASSERT_EQ_FMT((size_t)1, hello(&r, &client, &dst, "video.example.com"), "%zu");

    ASSERT_EQ_FMT((size_t)1, read_events(ev, 8), "%zu");
    const firc_event_bypass_t *b = &ev[0].u.bypass;
    ASSERT_EQ(FIRC_EVENT_BYPASS, ev[0].kind);
    ASSERT_EQ_FMT((unsigned)FIRC_BYPASS_BY_SNI, (unsigned)b->how, "%u");
    ASSERT_STR_EQ("video.example.com", b->name);
    ASSERT(ip_is(&b->dst, &dst));
    ASSERT_EQ_FMT(443u, (unsigned)b->dst_port, "%u");
    ASSERT_EQ_FMT(6u, (unsigned)b->proto, "%u");
    ASSERT_STR_EQ("media", b->group_name);
    rig_down(&r);
    PASS();
}

/* Catches: one flow seen on both sockets reported twice or counted as a repeat. */
TEST the_same_flow_on_both_sockets_is_one_event(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t real = v4(104, 21, 0, 5), client = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 900);

    ASSERT_EQ_FMT((size_t)1, syn(&r, &client, &real, 443), "%zu");
    fake_now = 1001;
    ASSERT_EQ_FMTm("the hello is the same flow", (size_t)0,
                   hello(&r, &client, &real, "cdn.example.com"), "%zu");
    ASSERT_EQ_FMT((size_t)1, read_events(ev, 8), "%zu");

    fake_now = 1000 + FIRC_TAP_DEDUP_SECS;
    ASSERT_EQ_FMT((size_t)1, syn(&r, &client, &real, 443), "%zu");
    ASSERT_EQ_FMT((size_t)2, read_events(ev, 8), "%zu");
    ASSERT_STR_EQ("video.example.com", ev[1].u.bypass.name);
    ASSERT_EQ_FMTm("the hello was not a second flow", 0u, ev[1].u.bypass.repeats, "%u");

    fake_now = 1000 + FIRC_TAP_DEDUP_SECS + 5;
    ASSERT_EQ_FMT((size_t)0, syn(&r, &client, &real, 443), "%zu");
    fake_now = 1000 + 2 * FIRC_TAP_DEDUP_SECS;
    ASSERT_EQ_FMT((size_t)1, syn(&r, &client, &real, 443), "%zu");
    ASSERT_EQ_FMT((size_t)3, read_events(ev, 8), "%zu");
    ASSERT_EQ_FMT(1u, ev[2].u.bypass.repeats, "%u");
    rig_down(&r);
    PASS();
}

TEST an_uncovered_client_is_no_event(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t real = v4(104, 21, 0, 5), stranger = v4(10, 0, 0, 7), client = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 900);
    ASSERT_EQ_FMT((size_t)0, syn(&r, &stranger, &real, 443), "%zu");
    ASSERT_EQ_FMT((size_t)0, hello(&r, &stranger, &real, "video.example.com"), "%zu");
    ASSERT_EQ_FMT((size_t)0, read_events(ev, 8), "%zu");
    ASSERT_EQ_FMTm("the rig: a covered one is", (size_t)1, syn(&r, &client, &real, 443), "%zu");
    rig_down(&r);
    PASS();
}

/* Catches: an unfinished datagram not counted as lost, or what was read not reported. */
TEST a_datagram_the_reader_could_not_finish_is_lost_packets(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t real = v4(104, 21, 0, 5), client = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 900);
    uint8_t pkt[64];
    _Alignas(4) uint8_t dg[256];
    size_t len = fake_nflog_packet(pkt, client.b, real.b, 443, no_payload, 0);
    size_t dg_len = fake_nflog_msg(dg, pkt, len);
    memset(dg + dg_len, 0xff, 2);
    ASSERT(fake_nflog_send(r.k[0], dg, dg_len + 2));
    size_t events = 0;
    ASSERT_EQ(FIRC_OK, firc_tap_drain(&r.d[0], r.n[0], &events));
    ASSERT_EQ_FMTm("the packet before the tail is still an event", (size_t)1, events, "%zu");
    ASSERT_EQ_FMT((size_t)1, read_events(ev, 8), "%zu");
    ASSERTm(summary(&r)->buf, strstr(summary(&r)->buf, "packets were lost") != NULL);
    rig_down(&r);
    PASS();
}

/* Catches: a packet no parser takes left uncounted, or the capture called clean. */
TEST a_packet_the_parser_refuses_is_said_out_loud(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    uint8_t junk[40];
    memset(junk, 0, sizeof(junk));
    junk[0] = 0x70;
    ASSERT_EQ_FMT((size_t)0, push(&r, 0, junk, sizeof(junk)), "%zu");

    uint8_t v6[48];
    memset(v6, 0, sizeof(v6));
    v6[0] = 0x60;
    v6[5] = 8;
    v6[6] = 0;
    v6[7] = 64;
    ASSERT_EQ_FMT((size_t)0, push(&r, 1, v6, sizeof(v6)), "%zu");

    const char *s = summary(&r)->buf;
    ASSERTm(s, strstr(s, "2 packets could not be read as IPv4 or IPv6") != NULL);
    ASSERT_FALSEm(s, strstr(s, "No bypass") != NULL);
    rig_down(&r);
    PASS();
}

/* Catches: a packet counted toward the other socket's rate. */
TEST the_drain_counts_the_seconds_on_its_own_socket(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t dst = v4(104, 21, 0, 9), client = v4(10, 0, 0, 7);
    for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC; i++) {
        ASSERT_EQ_FMT((size_t)0, syn(&r, &client, &dst, 443), "%zu");
    }
    const char *s = summary(&r)->buf;
    ASSERTm(s, strstr(s, "at least 1 second on the new-connection capture") != NULL);
    ASSERT_FALSEm(s, strstr(s, "ClientHello capture") != NULL);

    fake_now = 1001;
    for (int i = 0; i < FIRC_TAP_LIMIT_PER_SEC; i++) {
        ASSERT_EQ_FMT((size_t)0, hello(&r, &client, &dst, "video.example.com"), "%zu");
    }
    s = summary(&r)->buf;
    ASSERTm(s, strstr(s, "at least 1 second on the ClientHello capture") != NULL);
    ASSERTm(s, strstr(s, "at least 1 second on the new-connection capture") != NULL);
    rig_down(&r);
    PASS();
}

/* Catches: an encrypted Finished on the hello socket judged as another sighting of the flow. */
TEST a_finished_on_the_hello_socket_is_not_another_flow(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t real = v4(104, 21, 0, 5), client = v4(192, 168, 1, 42);
    firc_recall_real(r.recall, &real, "video.example.com", "01000000", 900);
    ASSERT_EQ_FMT((size_t)1, syn(&r, &client, &real, 443), "%zu");

    static const uint8_t finished[] = {0x16, 0x03, 0x03, 0x00, 0x20,
                                       0x9d, 0x2b, 0xc1, 0x74, 0xe8, 0x0f};
    uint8_t pkt[128];
    size_t len = fake_nflog_packet(pkt, client.b, real.b, 443, finished, sizeof(finished));
    ASSERT_EQ_FMT((size_t)0, push(&r, 1, pkt, len), "%zu");

    fake_now = 1000 + FIRC_TAP_DEDUP_SECS;
    ASSERT_EQ_FMT((size_t)1, syn(&r, &client, &real, 443), "%zu");
    ASSERT_EQ_FMT((size_t)2, read_events(ev, 8), "%zu");
    ASSERT_EQ_FMTm("nothing folded", 0u, ev[1].u.bypass.repeats, "%u");
    const char *s = summary(&r)->buf;
    ASSERT_FALSEm(s, strstr(s, "carried no server name") != NULL);
    rig_down(&r);
    PASS();
}

/* Catches: an unreadable hello to an unrecalled address not counted. */
TEST a_hello_whose_name_cannot_be_read_is_counted(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t dst = v4(104, 21, 0, 9), client = v4(192, 168, 1, 42);
    uint8_t rec[1024], pkt[1200];
    size_t rec_len = fake_nflog_hello(rec, "video.example.com");
    size_t len = fake_nflog_packet(pkt, client.b, dst.b, 443, rec, rec_len / 2);
    ASSERT_EQ_FMT((size_t)0, push(&r, 1, pkt, len), "%zu");
    const char *s = summary(&r)->buf;
    ASSERTm(s, strstr(s, "1 packet carried no server name") != NULL);
    rig_down(&r);
    PASS();
}

/* Catches: a hello from a client no group covers read or counted. */
TEST an_uncovered_clients_hello_is_not_read(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_ip_t dst = v4(104, 21, 0, 9), stranger = v4(10, 0, 0, 7), client = v4(192, 168, 1, 42);
    uint8_t rec[1024], pkt[1200];
    size_t rec_len = fake_nflog_hello(rec, "video.example.com");
    size_t len = fake_nflog_packet(pkt, stranger.b, dst.b, 443, rec, rec_len / 2);
    ASSERT_EQ_FMT((size_t)0, push(&r, 1, pkt, len), "%zu");
    const char *s = summary(&r)->buf;
    ASSERT_FALSEm(s, strstr(s, "carried no server name") != NULL);

    len = fake_nflog_packet(pkt, client.b, dst.b, 443, rec, rec_len / 2);
    ASSERT_EQ_FMT((size_t)0, push(&r, 1, pkt, len), "%zu");
    s = summary(&r)->buf;
    ASSERTm(s, strstr(s, "1 packet carried no server name") != NULL);
    rig_down(&r);
    PASS();
}

/* Catches: an empty read counted as lost packets. */
TEST an_empty_read_is_not_a_loss(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    for (int w = 0; w < 2; w++) {
        size_t events = 7;
        ASSERT_EQ_FMTm("nothing to read says so", FIRC_ERR_AGAIN,
                       firc_tap_drain(&r.d[w], r.n[w], &events), "%d");
        ASSERT_EQ_FMT((size_t)0, events, "%zu");
    }
    ASSERT_FALSEm("no loss on an idle turn", strstr(summary(&r)->buf, "lost") != NULL);
    rig_down(&r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_new_connection_to_a_recalled_address_becomes_a_bypass_event);
    RUN_TEST(a_bypass_reads_the_answer_of_its_own_family);
    RUN_TEST(a_hello_becomes_a_bypass_event_by_sni);
    RUN_TEST(the_same_flow_on_both_sockets_is_one_event);
    RUN_TEST(an_uncovered_client_is_no_event);
    RUN_TEST(a_datagram_the_reader_could_not_finish_is_lost_packets);
    RUN_TEST(a_packet_the_parser_refuses_is_said_out_loud);
    RUN_TEST(the_drain_counts_the_seconds_on_its_own_socket);
    RUN_TEST(a_finished_on_the_hello_socket_is_not_another_flow);
    RUN_TEST(a_hello_whose_name_cannot_be_read_is_counted);
    RUN_TEST(an_uncovered_clients_hello_is_not_read);
    RUN_TEST(an_empty_read_is_not_a_loss);
    GREATEST_MAIN_END();
}
