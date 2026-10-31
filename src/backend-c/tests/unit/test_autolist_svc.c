#include "greatest.h"

#include <string.h>

#include "fake_nflog.h"
#include "firc/autolistrules.h"
#include "firc/autolistsvc.h"

static fake_nflog_t *kernels[6];
static uint16_t bound_group[6];
static uint16_t bound_range[6];
static int opened;

static firc_nflog_t *open_fake(uint16_t group, uint16_t copy_range) {
    if (opened >= 6) { return NULL; }
    int fd = -1;
    kernels[opened] = fake_nflog_start(&fd);
    if (kernels[opened] == NULL) { return NULL; }
    bound_group[opened] = group;
    bound_range[opened] = copy_range;
    opened++;
    return firc_nflog_open_fd(fd, group, copy_range);
}

static int64_t clock_now = 1000;
static int64_t fake_clock(void) { return clock_now; }

typedef struct {
    int listed;
    char host[FIRC_AUTOLIST_NAME_MAX];
    bool refuse;
    int bypassed;
    int nominated;
    firc_autolist_nomination_t nom;
} seen_t;

static bool eligible(void *ud, const firc_ip_t *client) {
    (void)client;
    return !((seen_t *)ud)->refuse;
}

static void listed(void *ud, const firc_autolist_failure_t *f) {
    seen_t *s = ud;
    s->listed++;
    memcpy(s->host, f->host, sizeof(s->host));
}

static void bypassed(void *ud, const firc_autolist_failure_t *f) {
    seen_t *s = ud;
    if (f->bypass) { s->bypassed++; }
}

static void nominated(void *ud, const firc_autolist_nomination_t *n) {
    seen_t *s = ud;
    s->nominated++;
    s->nom = *n;
}

static const uint8_t CLIENT[4] = {192, 168, 1, 10};
static const uint8_t SERVER[4] = {203, 0, 113, 7};

static firc_autolist_svc_t *start(seen_t *seen) {
    memset(seen, 0, sizeof(*seen));
    opened = 0;
    firc_autolist_deps_t deps = {
        .nflog_open = open_fake,
        .now = fake_clock,
        .eligible = eligible,
        .listed = listed,
        .bypassed = bypassed,
        .nominated = nominated,
        .ud = seen};
    firc_err_t err;
    firc_autolist_svc_t *s = firc_autolist_svc_start(&deps, &err);
    if (s != NULL) {
        firc_autolist_params_t p = {2, 60, 1};
        firc_autolist_svc_set_params(s, &p);
    }
    return s;
}

static void stop(firc_autolist_svc_t *s) {
    firc_autolist_svc_stop(s);
    for (int i = 0; i < opened; i++) { fake_nflog_stop(kernels[i]); }
    opened = 0;
}

static bool push(firc_autolist_svc_t *s, int which, const uint8_t *pkt, size_t len) {
    _Alignas(4) uint8_t dg[2400];
    size_t dg_len = fake_nflog_msg(dg, pkt, len);
    if (!fake_nflog_send(kernels[which], dg, dg_len)) { return false; }
    return firc_autolist_svc_drain(s, which) == FIRC_OK;
}

static void set_ports(uint8_t *pkt, uint16_t sport, uint16_t dport) {
    pkt[20] = (uint8_t)(sport >> 8);
    pkt[21] = (uint8_t)sport;
    pkt[22] = (uint8_t)(dport >> 8);
    pkt[23] = (uint8_t)dport;
}

static void put_ack(uint8_t *pkt, uint32_t ack) {
    pkt[28] = (uint8_t)(ack >> 24);
    pkt[29] = (uint8_t)(ack >> 16);
    pkt[30] = (uint8_t)(ack >> 8);
    pkt[31] = (uint8_t)ack;
}

static bool bare_hello(firc_autolist_svc_t *s, uint16_t client_port, const char *sni) {
    uint8_t rec[1024], pkt[1200];
    size_t rec_len = fake_nflog_hello(rec, sni);
    size_t len = fake_nflog_packet(pkt, CLIENT, SERVER, 443, rec, rec_len);
    set_ports(pkt, client_port, 443);
    pkt[27] = 7;
    put_ack(pkt, 1000);
    return push(s, 0, pkt, len);
}

static void ask(firc_autolist_svc_t *s, const char *name) {
    firc_ip_t client = {{0}, 4}, server = {{0}, 4};
    memcpy(client.b, CLIENT, 4);
    memcpy(server.b, SERVER, 4);
    firc_autolist_svc_hint(s, &client, name, &server, 1);
}

static bool hello(firc_autolist_svc_t *s, uint16_t client_port, const char *sni) {
    ask(s, sni);
    return bare_hello(s, client_port, sni);
}

static bool fin(firc_autolist_svc_t *s, uint16_t client_port, uint32_t ack) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, CLIENT, SERVER, 443, none, 0);
    set_ports(pkt, client_port, 443);
    put_ack(pkt, ack);
    pkt[33] = 0x11;
    return push(s, 3, pkt, len);
}

static bool client_close(firc_autolist_svc_t *s, int which, uint16_t client_port, uint32_t ack, uint8_t flags) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, CLIENT, SERVER, 443, none, 0);
    set_ports(pkt, client_port, 443);
    put_ack(pkt, ack);
    pkt[33] = flags;
    return push(s, which, pkt, len);
}

static bool syn(firc_autolist_svc_t *s, uint16_t client_port, uint8_t flags) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, CLIENT, SERVER, 443, none, 0);
    set_ports(pkt, client_port, 443);
    pkt[27] = 6;
    pkt[33] = flags;
    return push(s, 5, pkt, len);
}

static bool reply(firc_autolist_svc_t *s, int which, uint16_t client_port, uint8_t flags) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, SERVER, CLIENT, client_port, none, 0);
    set_ports(pkt, 443, client_port);
    pkt[33] = flags;
    return push(s, which, pkt, len);
}

TEST svc_binds_six_groups(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    ASSERT_EQ(6, opened);
    ASSERT_EQ(6, bound_group[0]);
    ASSERT_EQ(7, bound_group[1]);
    ASSERT_EQ(8, bound_group[2]);
    ASSERT_EQ(9, bound_group[3]);
    ASSERT_EQ(10, bound_group[4]);
    ASSERT_EQ(11, bound_group[5]);
    ASSERT_EQ(FIRC_TAP_COPY_RANGE, bound_range[0]);
    ASSERT_EQ(FIRC_TAP_HEAD_RANGE, bound_range[1]);
    ASSERT_EQ(FIRC_TAP_HEAD_RANGE, bound_range[2]);
    ASSERT_EQ(FIRC_TAP_HEAD_RANGE, bound_range[3]);
    ASSERT_EQ(FIRC_TAP_HEAD_RANGE, bound_range[4]);
    ASSERT_EQ(FIRC_TAP_HEAD_RANGE, bound_range[5]);
    stop(s);
    PASS();
}

TEST client_rst_is_a_close(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "freeze.example.com"));
        ASSERT(reply(s, 2, port, 0x10));
        clock_now += 11;
        ASSERT(client_close(s, 4, port, 1000 + 16384, 0x14));
    }
    ASSERT_EQ(1, seen.nominated);
    ASSERT_EQ(FIRC_AL_NOM_STALL, seen.nom.kind);
    ASSERT_STR_EQ("freeze.example.com", seen.nom.host);
    ASSERT_EQ(16384u, seen.nom.received);
    stop(s);
    PASS();
}

TEST a_reset_without_ack_is_no_close(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "freeze.example.com"));
        ASSERT(reply(s, 2, port, 0x10));
        clock_now += 11;
        ASSERT(client_close(s, 4, port, 1000 + 16384, 0x04));
    }
    ASSERT_EQ(0, seen.nominated);
    stop(s);
    PASS();
}

TEST a_fin_on_the_reset_socket_is_no_close(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "freeze.example.com"));
        ASSERT(reply(s, 2, port, 0x10));
        clock_now += 11;
        ASSERT(client_close(s, 4, port, 1000 + 16384, 0x11));
    }
    ASSERT_EQ(0, seen.nominated);
    stop(s);
    PASS();
}

TEST syns_on_the_syn_socket_nominate(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ask(s, "www.instagram.com");
        ASSERT(syn(s, port, 0x02));
        clock_now += 3;
        ASSERT(syn(s, port, 0x02));
    }
    ASSERT_EQ(1, seen.nominated);
    ASSERT_EQ(FIRC_AL_NOM_NO_CONNECT, seen.nom.kind);
    ASSERT_STR_EQ("www.instagram.com", seen.nom.host);
    ASSERT_EQ(10, seen.nom.client.b[3]);
    stop(s);
    PASS();
}

TEST a_syn_ack_on_the_syn_socket_is_nothing(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ask(s, "www.instagram.com");
        ASSERT(syn(s, port, 0x12));
        clock_now += 3;
        ASSERT(syn(s, port, 0x12));
    }
    ASSERT_EQ(0, seen.nominated);
    stop(s);
    PASS();
}

TEST a_syn_from_a_device_not_routed_is_not_watched(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    seen.refuse = true;
    for (uint16_t port = 50001; port <= 50002; port++) {
        ask(s, "www.instagram.com");
        ASSERT(syn(s, port, 0x02));
        clock_now += 3;
        ASSERT(syn(s, port, 0x02));
    }
    ASSERT_EQ(0, seen.nominated);
    stop(s);
    PASS();
}

TEST a_syn_bypass_goes_to_bypassed(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    ASSERT(syn(s, 50001, 0x02));
    clock_now += 3;
    ASSERT(syn(s, 50001, 0x02));
    ASSERT_EQ(1, seen.bypassed);
    ASSERT_EQ(0, seen.nominated);
    stop(s);
    PASS();
}

TEST ambiguous_syns_are_counted_for_the_day(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    ask(s, "one.example.com");
    ask(s, "two.example.net");
    ASSERT(syn(s, 50001, 0x02));
    clock_now += 3;
    ASSERT(syn(s, 50001, 0x02));
    ASSERT_EQ(0, seen.nominated);
    ASSERT_EQ(1u, firc_autolist_svc_ambiguous_day(s));
    ASSERT_EQ(0u, firc_autolist_svc_ambiguous_day(NULL));
    stop(s);
    PASS();
}

TEST a_client_that_never_asked_goes_to_bypassed(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(bare_hello(s, port, "doh.example.com"));
        ASSERT(reply(s, 1, port, 0x14));
    }
    ASSERT_EQ(2, seen.bypassed);
    ASSERT_EQ(0, seen.listed);
    uint64_t failures = 0, n_listed = 0;
    firc_autolist_svc_counts(s, &failures, &n_listed);
    ASSERT_EQ(0u, (unsigned)failures);
    stop(s);
    PASS();
}

TEST two_stalled_fins_nominate(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "freeze.example.com"));
        ASSERT(reply(s, 2, port, 0x10));
        clock_now += 11;
        ASSERT(fin(s, port, 1000 + 16384));
    }
    ASSERT_EQ(1, seen.nominated);
    ASSERT_STR_EQ("freeze.example.com", seen.nom.host);
    ASSERT_EQ(16384u, seen.nom.received);
    ASSERT_EQ(0, seen.listed);
    stop(s);
    PASS();
}

TEST resets_on_two_connections_list_the_host(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    ASSERT(hello(s, 50001, "blocked.example.com"));
    ASSERT(reply(s, 1, 50001, 0x14));
    ASSERT_EQ(0, seen.listed);
    ASSERT(hello(s, 50002, "blocked.example.com"));
    ASSERT(reply(s, 1, 50002, 0x14));
    ASSERT_EQ(1, seen.listed);
    ASSERT_STR_EQ("blocked.example.com", seen.host);
    uint64_t failures = 0, n_listed = 0;
    firc_autolist_svc_counts(s, &failures, &n_listed);
    ASSERT_EQ(2u, (unsigned)failures);
    ASSERT_EQ(1u, (unsigned)n_listed);
    stop(s);
    PASS();
}

TEST a_hello_sent_again_is_a_failure(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "silent.example.com"));
        ASSERT(hello(s, port, "silent.example.com"));
    }
    ASSERT_EQ(1, seen.listed);
    stop(s);
    PASS();
}

TEST a_working_reply_keeps_the_host_off(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    ASSERT(hello(s, 50001, "fine.example.com"));
    ASSERT(reply(s, 1, 50001, 0x14));
    ASSERT(hello(s, 50002, "fine.example.com"));
    ASSERT(reply(s, 2, 50002, 0x10));
    ASSERT(hello(s, 50003, "fine.example.com"));
    ASSERT(reply(s, 1, 50003, 0x14));
    ASSERT_EQ(0, seen.listed);
    stop(s);
    PASS();
}

TEST a_packet_on_the_reset_socket_without_rst_is_nothing(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "x.example.com"));
        ASSERT(reply(s, 1, port, 0x10));
    }
    ASSERT_EQ(0, seen.listed);
    stop(s);
    PASS();
}

TEST a_device_the_group_would_not_route_is_not_watched(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    seen.refuse = true;
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, "x.example.com"));
        ASSERT(reply(s, 1, port, 0x14));
    }
    ASSERT_EQ(0, seen.listed);
    stop(s);
    PASS();
}

TEST a_hello_without_sni_is_named_by_the_dns_answer(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    firc_ip_t client = {{0}, 4}, server = {{0}, 4};
    memcpy(client.b, CLIENT, 4);
    memcpy(server.b, SERVER, 4);
    firc_autolist_svc_hint(s, &client, "asked.example.com", &server, 1);
    for (uint16_t port = 50001; port <= 50002; port++) {
        ASSERT(hello(s, port, ""));
        ASSERT(reply(s, 1, port, 0x14));
    }
    ASSERT_EQ(1, seen.listed);
    ASSERT_STR_EQ("asked.example.com", seen.host);
    stop(s);
    PASS();
}

static void ask_at(firc_autolist_svc_t *s, const uint8_t *server, const char *name) {
    firc_ip_t client = {{0}, 4}, ip = {{0}, 4};
    memcpy(client.b, CLIENT, 4);
    memcpy(ip.b, server, 4);
    firc_autolist_svc_hint(s, &client, name, &ip, 1);
}

static bool syn_at(firc_autolist_svc_t *s, const uint8_t *server, uint16_t client_port) {
    static const uint8_t none[1];
    uint8_t pkt[64];
    size_t len = fake_nflog_packet(pkt, CLIENT, server, 443, none, 0);
    set_ports(pkt, client_port, 443);
    pkt[27] = 6;
    pkt[33] = 0x02;
    return push(s, 5, pkt, len);
}

static bool unanswered_at(firc_autolist_svc_t *s, const uint8_t *server, const char *name, uint16_t from) {
    for (uint16_t port = from; port < from + 3; port++) {
        ask_at(s, server, name);
        if (!syn_at(s, server, port)) { return false; }
        clock_now += 3;
        if (!syn_at(s, server, port)) { return false; }
    }
    return true;
}

static bool reset_at(firc_autolist_svc_t *s, const uint8_t *server, const char *name, uint16_t from) {
    for (uint16_t port = from; port < from + 3; port++) {
        uint8_t rec[1024], pkt[1200];
        ask_at(s, server, name);
        size_t rec_len = fake_nflog_hello(rec, name);
        size_t len = fake_nflog_packet(pkt, CLIENT, server, 443, rec, rec_len);
        set_ports(pkt, port, 443);
        pkt[27] = 7;
        put_ack(pkt, 1000);
        if (!push(s, 0, pkt, len)) { return false; }
        static const uint8_t none[1];
        uint8_t back[64];
        len = fake_nflog_packet(back, server, CLIENT, port, none, 0);
        set_ports(back, 443, port);
        back[33] = 0x14;
        if (!push(s, 1, back, len)) { return false; }
    }
    return true;
}

TEST syns_to_a_lan_host_never_nominate(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    static const uint8_t nas[4] = {192, 168, 1, 10};
    ASSERT(unanswered_at(s, nas, "nas.home.arpa", 50001));
    ASSERT_EQ(0, seen.nominated);
    ASSERT_EQ(0, seen.bypassed);
    ASSERT(unanswered_at(s, SERVER, "www.instagram.com", 50011));
    ASSERT_EQ(1, seen.nominated);
    stop(s);
    PASS();
}

TEST resets_from_a_lan_host_never_list(void) {
    seen_t seen;
    firc_autolist_svc_t *s = start(&seen);
    ASSERT(s != NULL);
    static const uint8_t printer[4] = {10, 0, 0, 5};
    ASSERT(reset_at(s, printer, "printer.lan.example", 50001));
    ASSERT_EQ(0, seen.listed);
    ASSERT_EQ(0, seen.bypassed);
    uint64_t failures = 9;
    firc_autolist_svc_counts(s, &failures, NULL);
    ASSERT_EQ(0u, (unsigned)failures);
    stop(s);
    PASS();
}

TEST syns_into_the_configured_pool_never_nominate(void) {
    seen_t seen;
    memset(&seen, 0, sizeof(seen));
    opened = 0;
    firc_autolist_deps_t deps = {.nflog_open = open_fake, .now = fake_clock, .eligible = eligible,
                                 .listed = listed, .bypassed = bypassed, .nominated = nominated, .ud = &seen};
    deps.pools[0].base.len = 4;
    deps.pools[0].base.b[0] = 203;
    deps.pools[0].prefix = 8;
    deps.n_pools = 1;
    firc_err_t err;
    firc_autolist_svc_t *s = firc_autolist_svc_start(&deps, &err);
    ASSERT(s != NULL);
    firc_autolist_params_t p = {2, 60, 1};
    firc_autolist_svc_set_params(s, &p);
    ASSERT(unanswered_at(s, SERVER, "www.instagram.com", 50001));
    ASSERT_EQ(0, seen.nominated);
    stop(s);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(svc_binds_six_groups);
    RUN_TEST(client_rst_is_a_close);
    RUN_TEST(a_reset_without_ack_is_no_close);
    RUN_TEST(a_fin_on_the_reset_socket_is_no_close);
    RUN_TEST(syns_on_the_syn_socket_nominate);
    RUN_TEST(a_syn_ack_on_the_syn_socket_is_nothing);
    RUN_TEST(a_syn_from_a_device_not_routed_is_not_watched);
    RUN_TEST(a_syn_bypass_goes_to_bypassed);
    RUN_TEST(ambiguous_syns_are_counted_for_the_day);
    RUN_TEST(a_client_that_never_asked_goes_to_bypassed);
    RUN_TEST(two_stalled_fins_nominate);
    RUN_TEST(resets_on_two_connections_list_the_host);
    RUN_TEST(a_hello_sent_again_is_a_failure);
    RUN_TEST(a_working_reply_keeps_the_host_off);
    RUN_TEST(a_packet_on_the_reset_socket_without_rst_is_nothing);
    RUN_TEST(a_device_the_group_would_not_route_is_not_watched);
    RUN_TEST(a_hello_without_sni_is_named_by_the_dns_answer);
    RUN_TEST(syns_to_a_lan_host_never_nominate);
    RUN_TEST(resets_from_a_lan_host_never_list);
    RUN_TEST(syns_into_the_configured_pool_never_nominate);
    GREATEST_MAIN_END();
}
