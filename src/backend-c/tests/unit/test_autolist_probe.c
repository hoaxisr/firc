#include "greatest.h"

#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "firc/autolistcand.h"
#include "firc/autolistcheck.h"

static const firc_sub_fetch_info_t k_none = {false, false, false, false, false, false};
static const firc_sub_fetch_info_t k_none_timed_out = {false, false, false, true, false, false};
static const firc_sub_fetch_info_t k_tcp = {true, false, false, false, false, false};
static const firc_sub_fetch_info_t k_tcp_reset = {true, false, true, false, false, false};
static const firc_sub_fetch_info_t k_tcp_timed_out = {true, false, false, true, false, false};
static const firc_sub_fetch_info_t k_tls = {true, true, false, false, false, false};
static const firc_sub_fetch_info_t k_tls_reset = {true, true, true, false, false, false};
static const firc_sub_fetch_info_t k_tls_timed_out = {true, true, false, true, false, false};
static const firc_sub_fetch_info_t k_refused = {false, false, false, false, true, false};

static firc_autolist_result_t classify(const firc_sub_fetch_info_t *info, uint32_t bytes, bool stalled, bool complete) {
    firc_autolist_result_t r;
    memset(&r, 0xAA, sizeof(r));
    firc_autolist_classify(info, bytes, stalled, complete, false, &r);
    return r;
}

static firc_autolist_result_t classify_wan(const firc_sub_fetch_info_t *info, bool wan_ok) {
    firc_autolist_result_t r;
    memset(&r, 0xAA, sizeof(r));
    firc_autolist_classify(info, 0, false, false, wan_ok, &r);
    return r;
}

TEST stall_in_window_is_freeze(void) {
    firc_autolist_result_t r = classify(&k_tls, 16384, true, false);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_FREEZE, r.why);
    ASSERT_EQ(16384, r.bytes);
    ASSERT_FALSE(r.short_body);
    PASS();
}

TEST stall_at_both_window_edges_is_freeze(void) {
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, classify(&k_tls, 8192, true, false).verdict);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, classify(&k_tls, 32768, true, false).verdict);
    PASS();
}

TEST stall_below_window_is_unknown(void) {
    firc_autolist_result_t r = classify(&k_tls, 4096, true, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_tls, 8191, true, false).verdict);
    PASS();
}

TEST a_slow_page_without_a_stall_is_not_freeze(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_tls, 16384, false, false).verdict);
    PASS();
}

TEST past_window_is_open(void) {
    firc_autolist_result_t r = classify(&k_tls, 40000, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, r.verdict);
    ASSERT_EQ(0, r.why);
    ASSERT_FALSE(r.short_body);
    ASSERT_EQ(40000, r.bytes);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, classify(&k_tls, 32769, true, false).verdict);
    PASS();
}

TEST the_capped_body_is_open(void) {
    firc_autolist_result_t r = classify(&k_tls, 65536, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, r.verdict);
    ASSERT_FALSE(r.short_body);
    PASS();
}

TEST complete_small_is_open_short(void) {
    firc_autolist_result_t r = classify(&k_tls, 3000, false, true);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, r.verdict);
    ASSERT(r.short_body);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST complete_big_is_open_not_short(void) {
    firc_autolist_result_t r = classify(&k_tls, 50000, false, true);
    ASSERT_EQ(FIRC_AUTOLIST_REACHABLE, r.verdict);
    ASSERT_FALSE(r.short_body);
    PASS();
}

TEST timeout_before_tls_is_no_answer(void) {
    firc_autolist_result_t r = classify(&k_tcp_timed_out, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_NO_ANSWER, r.why);
    PASS();
}

TEST stall_before_tls_is_not_no_answer(void) {
    firc_autolist_result_t r = classify(&k_tcp, 0, true, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST timeout_without_connect_is_unknown(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_none_timed_out, 0, false, false).verdict);
    PASS();
}

TEST timeout_after_tls_without_body_is_unknown(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_tls_timed_out, 0, false, false).verdict);
    PASS();
}

TEST reset_wins_over_timeout_before_tls(void) {
    const firc_sub_fetch_info_t both = {true, false, true, true, false, false};
    firc_autolist_result_t r = classify(&both, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_RESET, r.why);
    PASS();
}

TEST reset_before_tls_is_reset(void) {
    firc_autolist_result_t r = classify(&k_tcp_reset, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_RESET, r.why);
    PASS();
}

TEST reset_after_tls_is_unknown(void) {
    firc_autolist_result_t r = classify(&k_tls_reset, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    PASS();
}

typedef struct {
    int lfd;
    const char *reply;
} wan_srv_t;

static void *wan_serve(void *ud) {
    wan_srv_t *w = ud;
    struct pollfd pf = {.fd = w->lfd, .events = POLLIN};
    if (poll(&pf, 1, 3000) != 1) { return NULL; }
    int fd = accept(w->lfd, NULL, NULL);
    if (fd < 0) { return NULL; }
    char buf[1024];
    pf.fd = fd;
    if (poll(&pf, 1, 3000) == 1) { (void)recv(fd, buf, sizeof(buf), 0); }
    (void)send(fd, w->reply, strlen(w->reply), 0);
    pf.events = POLLIN;
    (void)poll(&pf, 1, 8000);
    close(fd);
    return NULL;
}

static int wan_listen(struct sockaddr_in *sa) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    *sa = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sl = sizeof(*sa);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)sa, sizeof(*sa)) != 0 || listen(lfd, 1) != 0 ||
        getsockname(lfd, (struct sockaddr *)sa, &sl) != 0) {
        if (lfd >= 0) { close(lfd); }
        return -1;
    }
    return lfd;
}

static bool wan_said(const char *reply, bool expects_204, double *secs, char *said, size_t cap) {
    struct sockaddr_in sa;
    int lfd = wan_listen(&sa);
    if (lfd < 0) { return false; }
    wan_srv_t w = {lfd, reply};
    pthread_t t;
    pthread_create(&t, NULL, wan_serve, &w);
    firc_autolist_check_opts_t o = {0};
    snprintf(o.wan_url, sizeof(o.wan_url), "http://127.0.0.1:%u/", (unsigned)ntohs(sa.sin_port));
    o.wan_expects_204 = expects_204;
    bool unreachable = true;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    bool ok = firc_autolist_wan_check(&o, NULL, &unreachable, said, cap);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    if (secs != NULL) { *secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9; }
    pthread_join(t, NULL);
    close(lfd);
    return ok && !unreachable;
}

static bool wan_against(const char *reply, bool expects_204, double *secs) {
    char said[128];
    return wan_said(reply, expects_204, secs, said, sizeof(said));
}

TEST wan_does_not_read_a_long_body(void) {
    double secs = 99;
    bool ok = wan_against("HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\n\r\nxxxxxxxx", false, &secs);
    ASSERT(ok);
    ASSERT(secs < 2.0);
    PASS();
}

TEST wan_stops_when_stop_is_raised(void) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t sl = sizeof(sa);
    ASSERT(lfd >= 0 && bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) == 0 && listen(lfd, 1) == 0 &&
           getsockname(lfd, (struct sockaddr *)&sa, &sl) == 0);
    firc_autolist_check_opts_t o = {0};
    snprintf(o.wan_url, sizeof(o.wan_url), "http://127.0.0.1:%u/", (unsigned)ntohs(sa.sin_port));
    _Atomic bool stop = true;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    bool ok = firc_autolist_wan_check(&o, &stop, NULL, NULL, 0);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    close(lfd);
    ASSERT_FALSE(ok);
    ASSERT(t1.tv_sec - t0.tv_sec < 2);
    PASS();
}

TEST a_wan_host_too_long_for_the_pin_is_down_not_unpinned(void) {
    firc_autolist_check_opts_t o = {0};
    size_t n = (size_t)snprintf(o.wan_url, sizeof(o.wan_url), "http://");
    memset(o.wan_url + n, 'a', 300);
    o.wan_url[n + 300] = '\0';
    ASSERT_FALSE(firc_autolist_wan_check(&o, NULL, NULL, NULL, 0));
    PASS();
}

TEST wan_204_passes_when_204_is_expected(void) {
    ASSERT(wan_against("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", true, NULL));
    PASS();
}

TEST wan_200_fails_when_204_is_expected(void) {
    ASSERT_FALSE(wan_against("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true, NULL));
    PASS();
}

TEST wan_any_status_passes_when_204_is_not_expected(void) {
    ASSERT(wan_against("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", false, NULL));
    ASSERT(wan_against("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n", false, NULL));
    PASS();
}

TEST wan_without_an_answer_is_down(void) {
    firc_autolist_check_opts_t o = {0};
    snprintf(o.wan_url, sizeof(o.wan_url), "http://127.0.0.1:1/");
    bool unreachable = true;
    ASSERT_FALSE(firc_autolist_wan_check(&o, NULL, &unreachable, NULL, 0));
    ASSERT_FALSE(unreachable);
    PASS();
}

TEST an_empty_wan_url_is_down(void) {
    firc_autolist_check_opts_t o = {0};
    ASSERT_FALSE(firc_autolist_wan_check(&o, NULL, NULL, NULL, 0));
    PASS();
}

static bool no_v6_route(void) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) { return false; }
    struct sockaddr_in6 sa = {.sin6_family = AF_INET6, .sin6_port = htons(80)};
    inet_pton(AF_INET6, "2001:db8::1", &sa.sin6_addr);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    int e = errno;
    close(fd);
    return rc != 0 && (e == ENETUNREACH || e == EHOSTUNREACH);
}

TEST wan_with_no_route_is_down_and_unreachable(void) {
    firc_autolist_check_opts_t o = {0};
    snprintf(o.wan_url, sizeof(o.wan_url), "http://[2001:db8::1]/");
    bool unreachable = false;
    if (!no_v6_route()) { SKIPm("the host can reach or lacks IPv6 for 2001:db8::1"); }
    ASSERT_FALSE(firc_autolist_wan_check(&o, NULL, &unreachable, NULL, 0));
    ASSERT(unreachable);
    PASS();
}

TEST no_connect_with_wan_ok_is_blocked(void) {
    firc_autolist_result_t r = classify_wan(&k_none_timed_out, true);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_NO_CONNECT, r.why);
    ASSERT_EQ(4, r.why);
    ASSERT_EQ(0, r.bytes);
    PASS();
}

TEST no_connect_with_wan_down_is_unknown(void) {
    firc_autolist_result_t r = classify_wan(&k_none_timed_out, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST refused_is_unknown(void) {
    firc_autolist_result_t r = classify_wan(&k_refused, true);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST no_connect_without_a_timeout_is_unknown_even_with_wan_ok(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify_wan(&k_none, true).verdict);
    PASS();
}

TEST wan_ok_does_not_change_a_connected_verdict(void) {
    firc_autolist_result_t r = classify_wan(&k_tcp_timed_out, true);
    ASSERT_EQ(FIRC_AUTOLIST_BLOCKED, r.verdict);
    ASSERT_EQ(FIRC_AL_WHY_NO_ANSWER, r.why);
    PASS();
}

TEST no_connect_is_unknown(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_none, 0, false, false).verdict);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(&k_none, 0, true, false).verdict);
    PASS();
}

TEST cert_error_is_unknown(void) {
    firc_autolist_result_t r = classify(&k_tcp, 0, false, false);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_EQ(0, r.why);
    PASS();
}

TEST no_info_is_unknown(void) {
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, classify(NULL, 50000, false, true).verdict);
    PASS();
}

TEST an_unknown_result_has_no_short_body(void) {
    firc_autolist_result_t r = classify(&k_tcp, 0, false, false);
    ASSERT_FALSE(r.short_body);
    ASSERT_EQ(0, r.bytes);
    PASS();
}

TEST wan_says_the_status_it_got(void) {
    char said[128] = "x";
    ASSERT_FALSE(wan_said("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true, NULL, said, sizeof(said)));
    ASSERT_STR_EQ("wan 127.0.0.1: 200", said);
    ASSERT(wan_said("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n", true, NULL, said, sizeof(said)));
    ASSERT_STR_EQ("wan 127.0.0.1: 204", said);
    PASS();
}

TEST wan_says_curl_s_error_without_a_status(void) {
    firc_autolist_check_opts_t o = {0};
    snprintf(o.wan_url, sizeof(o.wan_url), "http://127.0.0.1:1/");
    char said[128] = "";
    ASSERT_FALSE(firc_autolist_wan_check(&o, NULL, NULL, said, sizeof(said)));
    ASSERT_EQ(0, strncmp(said, "wan 127.0.0.1: ", 15));
    ASSERTm(said, strstr(said, "onnect") != NULL);
    PASS();
}

TEST an_empty_wan_url_says_so(void) {
    firc_autolist_check_opts_t o = {0};
    char said[128] = "";
    ASSERT_FALSE(firc_autolist_wan_check(&o, NULL, NULL, said, sizeof(said)));
    ASSERT_STR_EQ("no wan check url", said);
    PASS();
}

TEST a_long_said_is_cut_not_overrun(void) {
    char said[24];
    memset(said, 'z', sizeof(said));
    ASSERT_FALSE(wan_said("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true, NULL, said, 8));
    ASSERT_STR_EQ("wan 127", said);
    ASSERT_EQ('z', said[8]);
    PASS();
}

static bool ends_with(const char *s, const char *tail) {
    size_t n = strlen(s), m = strlen(tail);
    return n >= m && strcmp(s + n - m, tail) == 0;
}

static bool connect_stays_pending(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0 || fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != 0) {
        if (fd >= 0) { close(fd); }
        return false;
    }
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons(443)};
    inet_pton(AF_INET, "192.0.2.1", &sa.sin_addr);
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    bool pending = rc != 0 && errno == EINPROGRESS;
    if (pending) {
        struct pollfd pf = {.fd = fd, .events = POLLOUT};
        pending = poll(&pf, 1, 1100) == 0;
    }
    close(fd);
    return pending;
}

static void probe_timed_out_with(const char *reply, bool expects_204, firc_autolist_result_t *r) {
    struct sockaddr_in sa;
    int lfd = wan_listen(&sa);
    memset(r, 0, sizeof(*r));
    if (lfd < 0) { return; }
    wan_srv_t w = {lfd, reply};
    pthread_t t;
    bool served = reply != NULL && pthread_create(&t, NULL, wan_serve, &w) == 0;
    firc_autolist_check_opts_t o = {0};
    if (served) { snprintf(o.wan_url, sizeof(o.wan_url), "http://127.0.0.1:%u/", (unsigned)ntohs(sa.sin_port)); }
    o.wan_expects_204 = expects_204;
    o.timeout_s = 1;
    firc_autolist_probe_once("192.0.2.1", &o, NULL, r);
    if (served) { pthread_join(t, NULL); }
    close(lfd);
}

TEST a_probe_that_ran_the_wan_check_says_its_outcome(void) {
    if (!connect_stays_pending()) { SKIPm("the network completes or refuses connects to 192.0.2.1"); }
    firc_autolist_result_t r;
    probe_timed_out_with("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", true, &r);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERTm(r.error, ends_with(r.error, " \xc2\xb7 wan 127.0.0.1: 200"));
    PASS();
}

TEST a_probe_without_a_wan_url_says_so(void) {
    if (!connect_stays_pending()) { SKIPm("the network completes or refuses connects to 192.0.2.1"); }
    firc_autolist_result_t r;
    probe_timed_out_with(NULL, true, &r);
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERTm(r.error, ends_with(r.error, " \xc2\xb7 no wan check url"));
    PASS();
}

typedef struct {
    int fd;
    const uint8_t *addr;
} dns_srv_t;

static void *dns_serve(void *ud) {
    dns_srv_t *d = ud;
    struct pollfd pf = {.fd = d->fd, .events = POLLIN};
    if (poll(&pf, 1, 3000) != 1) { return NULL; }
    uint8_t q[512], a[600];
    struct sockaddr_in from;
    socklen_t fl = sizeof(from);
    ssize_t n = recvfrom(d->fd, q, sizeof(q), 0, (struct sockaddr *)&from, &fl);
    if (n < 12) { return NULL; }
    memcpy(a, q, (size_t)n);
    a[2] = 0x81;
    a[3] = 0x80;
    a[7] = 1;
    size_t at = (size_t)n;
    static const uint8_t rr[] = {0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4};
    memcpy(a + at, rr, sizeof(rr));
    at += sizeof(rr);
    memcpy(a + at, d->addr, 4);
    at += 4;
    (void)sendto(d->fd, a, at, 0, (struct sockaddr *)&from, fl);
    return NULL;
}

static bool probe_local(const char *host, const uint8_t *answer, const firc_autolist_net_t *pools, size_t n_pools,
                        firc_autolist_result_t *r, bool *wan_asked) {
    struct sockaddr_in wa;
    int lfd = wan_listen(&wa);
    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in da = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t dl = sizeof(da);
    if (lfd < 0 || ufd < 0 || bind(ufd, (struct sockaddr *)&da, sizeof(da)) != 0 ||
        getsockname(ufd, (struct sockaddr *)&da, &dl) != 0) {
        if (lfd >= 0) { close(lfd); }
        if (ufd >= 0) { close(ufd); }
        return false;
    }
    dns_srv_t d = {ufd, answer};
    pthread_t t;
    bool served = answer != NULL && pthread_create(&t, NULL, dns_serve, &d) == 0;
    firc_autolist_check_opts_t o = {0};
    snprintf(o.dns, sizeof(o.dns), "127.0.0.1");
    o.dns_port = ntohs(da.sin_port);
    snprintf(o.wan_url, sizeof(o.wan_url), "http://127.0.0.1:%u/", (unsigned)ntohs(wa.sin_port));
    o.timeout_s = 2;
    for (size_t i = 0; i < n_pools; i++) { o.pools[i] = pools[i]; }
    o.n_pools = n_pools;
    firc_autolist_probe_once(host, &o, NULL, r);
    if (served) { pthread_join(t, NULL); }
    struct pollfd pf = {.fd = lfd, .events = POLLIN};
    *wan_asked = poll(&pf, 1, 0) == 1;
    close(lfd);
    close(ufd);
    return true;
}

TEST a_name_resolved_to_a_lan_host_is_not_probed(void) {
    static const uint8_t nas[4] = {192, 168, 1, 10};
    firc_autolist_result_t r;
    bool wan_asked = true;
    ASSERT(probe_local("nas.home.arpa", nas, NULL, 0, &r, &wan_asked));
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_STR_EQ("resolved to 192.168.1.10, a local address: not probed", r.error);
    ASSERT_FALSE(wan_asked);
    PASS();
}

TEST local_literals_are_not_probed(void) {
    firc_autolist_result_t r;
    bool wan_asked = true;
    ASSERT(probe_local("127.0.0.1", NULL, NULL, 0, &r, &wan_asked));
    ASSERT_STR_EQ("resolved to 127.0.0.1, a local address: not probed", r.error);
    ASSERT(probe_local("100.100.0.1", NULL, NULL, 0, &r, &wan_asked));
    ASSERT_STR_EQ("resolved to 100.100.0.1, a local address: not probed", r.error);
    ASSERT_FALSE(wan_asked);
    PASS();
}

TEST an_address_in_the_configured_pool_is_not_probed(void) {
    firc_autolist_net_t pool = {{{192, 0, 2, 0}, 4}, 24};
    firc_autolist_result_t r;
    bool wan_asked = true;
    ASSERT(probe_local("192.0.2.1", NULL, &pool, 1, &r, &wan_asked));
    ASSERT_EQ(FIRC_AUTOLIST_UNKNOWN, r.verdict);
    ASSERT_STR_EQ("resolved to 192.0.2.1, a local address: not probed", r.error);
    ASSERT_FALSE(wan_asked);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(stall_in_window_is_freeze);
    RUN_TEST(stall_at_both_window_edges_is_freeze);
    RUN_TEST(stall_below_window_is_unknown);
    RUN_TEST(a_slow_page_without_a_stall_is_not_freeze);
    RUN_TEST(past_window_is_open);
    RUN_TEST(the_capped_body_is_open);
    RUN_TEST(complete_small_is_open_short);
    RUN_TEST(complete_big_is_open_not_short);
    RUN_TEST(timeout_before_tls_is_no_answer);
    RUN_TEST(stall_before_tls_is_not_no_answer);
    RUN_TEST(timeout_without_connect_is_unknown);
    RUN_TEST(timeout_after_tls_without_body_is_unknown);
    RUN_TEST(reset_wins_over_timeout_before_tls);
    RUN_TEST(reset_before_tls_is_reset);
    RUN_TEST(reset_after_tls_is_unknown);
    RUN_TEST(wan_204_passes_when_204_is_expected);
    RUN_TEST(wan_200_fails_when_204_is_expected);
    RUN_TEST(wan_any_status_passes_when_204_is_not_expected);
    RUN_TEST(wan_does_not_read_a_long_body);
    RUN_TEST(wan_stops_when_stop_is_raised);
    RUN_TEST(a_wan_host_too_long_for_the_pin_is_down_not_unpinned);
    RUN_TEST(wan_without_an_answer_is_down);
    RUN_TEST(an_empty_wan_url_is_down);
    RUN_TEST(wan_with_no_route_is_down_and_unreachable);
    RUN_TEST(no_connect_with_wan_ok_is_blocked);
    RUN_TEST(no_connect_with_wan_down_is_unknown);
    RUN_TEST(refused_is_unknown);
    RUN_TEST(no_connect_without_a_timeout_is_unknown_even_with_wan_ok);
    RUN_TEST(wan_ok_does_not_change_a_connected_verdict);
    RUN_TEST(no_connect_is_unknown);
    RUN_TEST(cert_error_is_unknown);
    RUN_TEST(no_info_is_unknown);
    RUN_TEST(an_unknown_result_has_no_short_body);
    RUN_TEST(wan_says_the_status_it_got);
    RUN_TEST(wan_says_curl_s_error_without_a_status);
    RUN_TEST(an_empty_wan_url_says_so);
    RUN_TEST(a_long_said_is_cut_not_overrun);
    RUN_TEST(a_probe_that_ran_the_wan_check_says_its_outcome);
    RUN_TEST(a_probe_without_a_wan_url_says_so);
    RUN_TEST(a_name_resolved_to_a_lan_host_is_not_probed);
    RUN_TEST(local_literals_are_not_probed);
    RUN_TEST(an_address_in_the_configured_pool_is_not_probed);
    GREATEST_MAIN_END();
}
