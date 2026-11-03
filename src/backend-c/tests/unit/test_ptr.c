#include "greatest.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "firc/loop.h"
#include "firc/ptr.h"

#define NOW 1000000

enum fake_mode {
    FAKE_ANSWER,
    FAKE_COMPRESSED,
    FAKE_NXDOMAIN,
    FAKE_EMPTY,
    FAKE_SERVFAIL,
    FAKE_REFUSED,
    FAKE_SILENT,
    FAKE_WRONG_ID,
    FAKE_WRONG_QUESTION,
    FAKE_GARBAGE
};

typedef struct fake {
    int fd;
    uint16_t port;
    int queries;
    enum fake_mode mode;
    uint8_t last[512];
    size_t last_len;
} fake_t;

typedef struct run_ctx {
    firc_ptr_t *p;
    const firc_ip_t *ip;
} run_ctx_t;

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    firc_ip_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.len = 4;
    ip.b[0] = a;
    ip.b[1] = b;
    ip.b[2] = c;
    ip.b[3] = d;
    return ip;
}

static size_t put_u16(uint8_t *buf, size_t at, uint16_t v)
{
    buf[at] = (uint8_t)((unsigned)v >> 8u);
    buf[at + 1] = (uint8_t)((unsigned)v & 0xffu);
    return at + 2;
}

static size_t put_answer(uint8_t *buf, size_t at, const uint8_t *rdata, size_t rdlen)
{
    at = put_u16(buf, at, 0xC00C);
    at = put_u16(buf, at, 12);
    at = put_u16(buf, at, 1);
    at = put_u16(buf, at, 0);
    at = put_u16(buf, at, 300);
    at = put_u16(buf, at, (uint16_t)rdlen);
    memcpy(buf + at, rdata, rdlen);
    return at + rdlen;
}

static void send_reply(int fd, const uint8_t *q, size_t qlen, const struct sockaddr_in *peer, uint16_t id, uint8_t rcode,
                       const uint8_t *rdata, size_t rdlen)
{
    uint8_t buf[600];
    memcpy(buf, q, qlen);
    put_u16(buf, 0, id);
    put_u16(buf, 2, (uint16_t)(0x8180u | (unsigned)rcode));
    put_u16(buf, 6, rdata != NULL ? 1 : 0);
    size_t len = qlen;
    if (rdata != NULL) { len = put_answer(buf, len, rdata, rdlen); }
    (void)sendto(fd, buf, len, 0, (const struct sockaddr *)peer, sizeof(*peer));
}

static void fake_cb(firc_loop_t *loop, int fd, uint32_t events, void *ud)
{
    (void)loop;
    (void)events;
    fake_t *f = ud;
    uint8_t q[512];
    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    ssize_t n = recvfrom(fd, q, sizeof(q), 0, (struct sockaddr *)&peer, &plen);
    if (n < 12) { return; }
    f->queries++;
    size_t qlen = (size_t)n;
    memcpy(f->last, q, qlen);
    f->last_len = qlen;
    uint16_t id = (uint16_t)(((unsigned)q[0] << 8u) | (unsigned)q[1]);
    static const uint8_t host[] = "\x04Host\x07" "Example\x03" "COM";
    static const uint8_t wrong[] = "\x05wrong\x07" "example";
    static const uint8_t compressed[] = {0x01, 'x', 0xC0, 0x0F};
    switch (f->mode) {
    case FAKE_ANSWER:
        send_reply(fd, q, qlen, &peer, id, 0, host, sizeof(host));
        break;
    case FAKE_COMPRESSED:
        send_reply(fd, q, qlen, &peer, id, 0, compressed, sizeof(compressed));
        break;
    case FAKE_NXDOMAIN:
        send_reply(fd, q, qlen, &peer, id, 3, NULL, 0);
        break;
    case FAKE_EMPTY:
        send_reply(fd, q, qlen, &peer, id, 0, NULL, 0);
        break;
    case FAKE_SERVFAIL:
        send_reply(fd, q, qlen, &peer, id, 2, NULL, 0);
        break;
    case FAKE_REFUSED:
        send_reply(fd, q, qlen, &peer, id, 5, NULL, 0);
        break;
    case FAKE_SILENT:
        break;
    case FAKE_GARBAGE:
        q[2] = 0x80;
        q[5] = 0;
        q[7] = 1;
        (void)sendto(fd, q, 14, 0, (const struct sockaddr *)&peer, sizeof(peer));
        break;
    case FAKE_WRONG_ID:
        send_reply(fd, q, qlen, &peer, (uint16_t)(id ^ 1u), 0, wrong, sizeof(wrong));
        send_reply(fd, q, qlen, &peer, id, 0, host, sizeof(host));
        break;
    case FAKE_WRONG_QUESTION: {
        uint8_t other[512];
        memcpy(other, q, qlen);
        other[13] = '8';
        send_reply(fd, other, qlen, &peer, id, 0, wrong, sizeof(wrong));
        send_reply(fd, q, qlen, &peer, id, 0, host, sizeof(host));
        break;
    }
    }
}

static int fake_open(fake_t *f, enum fake_mode mode)
{
    memset(f, 0, sizeof(*f));
    f->mode = mode;
    f->fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (f->fd < 0) { return -1; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(sa);
    if (bind(f->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || getsockname(f->fd, (struct sockaddr *)&sa, &len) != 0) {
        close(f->fd);
        return -1;
    }
    f->port = ntohs(sa.sin_port);
    return 0;
}

static int fake_drain(fake_t *f)
{
    int extra = 0;
    uint8_t q[512];
    while (recv(f->fd, q, sizeof(q), MSG_DONTWAIT) > 0) { extra++; }
    return extra;
}

static void settled_cb(firc_loop_t *loop, void *ud)
{
    run_ctx_t *c = ud;
    char name[256];
    if (firc_ptr_peek(c->p, c->ip, NOW, name, sizeof(name)) != FIRC_PTR_PENDING) { firc_loop_stop(loop); }
}

static void deadline_cb(firc_loop_t *loop, void *ud)
{
    (void)ud;
    firc_loop_stop(loop);
}

static void run_until_settled(firc_loop_t *loop, firc_ptr_t *p, const firc_ip_t *ip)
{
    run_ctx_t c = {p, ip};
    int tick = -1;
    int deadline = -1;
    (void)firc_loop_add_timer(loop, 5, 5, settled_cb, &c, &tick);
    (void)firc_loop_add_timer(loop, 2000, 0, deadline_cb, NULL, &deadline);
    (void)firc_loop_run(loop);
    (void)firc_loop_del_timer(loop, tick);
    (void)firc_loop_del_timer(loop, deadline);
}

typedef struct all_ctx {
    firc_ptr_t *p;
    const firc_ip_t *ips;
    size_t n;
} all_ctx_t;

static void all_settled_cb(firc_loop_t *loop, void *ud)
{
    all_ctx_t *c = ud;
    char name[256];
    for (size_t i = 0; i < c->n; i++) {
        if (firc_ptr_peek(c->p, &c->ips[i], NOW, name, sizeof(name)) == FIRC_PTR_PENDING) { return; }
    }
    firc_loop_stop(loop);
}

static void run_until_all_settled(firc_loop_t *loop, firc_ptr_t *p, const firc_ip_t *ips, size_t n)
{
    all_ctx_t c = {p, ips, n};
    int tick = -1;
    int deadline = -1;
    (void)firc_loop_add_timer(loop, 1, 1, all_settled_cb, &c, &tick);
    (void)firc_loop_add_timer(loop, 2000, 0, deadline_cb, NULL, &deadline);
    (void)firc_loop_run(loop);
    (void)firc_loop_del_timer(loop, tick);
    (void)firc_loop_del_timer(loop, deadline);
}

static firc_ptr_state_t resolve(enum fake_mode mode, uint32_t timeout_ms, const firc_ip_t *ip, char *out, size_t cap,
                                fake_t *seen)
{
    firc_loop_t *loop = NULL;
    fake_t f;
    if (firc_loop_create(&loop) != FIRC_OK || fake_open(&f, mode) != 0) { return FIRC_PTR_PENDING; }
    (void)firc_loop_add_fd(loop, f.fd, EPOLLIN, fake_cb, &f);
    firc_ptr_t *p = firc_ptr_new(loop, timeout_ms);
    firc_ptr_state_t first = firc_ptr_get(p, ip, "127.0.0.1", f.port, NOW, out, cap, NULL);
    firc_ptr_state_t got = FIRC_PTR_PENDING;
    if (first == FIRC_PTR_PENDING) {
        run_until_settled(loop, p, ip);
        got = firc_ptr_peek(p, ip, NOW, out, cap);
    }
    f.queries += fake_drain(&f);
    if (seen != NULL) { *seen = f; }
    firc_ptr_free(p);
    (void)firc_loop_del_fd(loop, f.fd);
    close(f.fd);
    firc_loop_destroy(loop);
    return got;
}

static int queries_by(enum fake_mode mode, uint32_t timeout_ms, int64_t later_ms)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_loop_t *loop = NULL;
    fake_t f;
    if (firc_loop_create(&loop) != FIRC_OK || fake_open(&f, mode) != 0) { return -1; }
    (void)firc_loop_add_fd(loop, f.fd, EPOLLIN, fake_cb, &f);
    firc_ptr_t *p = firc_ptr_new(loop, timeout_ms);
    char name[256] = "";
    int got = -1;
    if (firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), NULL) == FIRC_PTR_PENDING) {
        run_until_settled(loop, p, &ip);
        if (firc_ptr_peek(p, &ip, NOW, name, sizeof(name)) == FIRC_PTR_NONE) {
            if (firc_ptr_get(p, &ip, "127.0.0.1", f.port, later_ms, name, sizeof(name), NULL) == FIRC_PTR_PENDING) {
                run_until_settled(loop, p, &ip);
            }
            got = f.queries + fake_drain(&f);
        }
    }
    firc_ptr_free(p);
    (void)firc_loop_del_fd(loop, f.fd);
    close(f.fd);
    firc_loop_destroy(loop);
    return got;
}

/* catches: octets written in address order instead of reversed */
TEST ipv4_name_is_reversed(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[128];
    ASSERT(firc_ptr_name_for(&ip, name, sizeof(name)));
    ASSERT_STR_EQ("93.243.107.34.in-addr.arpa", name);
    PASS();
}

/* catches: nibbles taken high-first or the zone left out */
TEST ipv6_name_is_nibbles(void)
{
    firc_ip_t ip;
    memset(&ip, 0, sizeof(ip));
    ip.len = 16;
    ASSERT_EQ(1, inet_pton(AF_INET6, "2001:db8::1", ip.b));
    char name[128];
    ASSERT(firc_ptr_name_for(&ip, name, sizeof(name)));
    ASSERT_STR_EQ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", name);
    PASS();
}

/* catches: a name cut to fit a short buffer instead of refused */
TEST a_short_buffer_is_refused(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[26];
    ASSERT_FALSE(firc_ptr_name_for(&ip, name, sizeof(name)));
    PASS();
}

/* catches: the target kept in its case or with its trailing dot */
TEST an_answer_names_the_address(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_NAME, resolve(FAKE_ANSWER, 3000, &ip, name, sizeof(name), NULL));
    ASSERT_STR_EQ("host.example.com", name);
    PASS();
}

/* catches: ptr.c reading rdata bytes instead of the parser's decompressed name */
TEST compressed_target_is_decoded(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_NAME, resolve(FAKE_COMPRESSED, 3000, &ip, name, sizeof(name), NULL));
    ASSERT_STR_EQ("x.243.107.34.in-addr.arpa", name);
    PASS();
}

/* catches: an NXDOMAIN left pending or taken as a name */
TEST nxdomain_is_none(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_NONE, resolve(FAKE_NXDOMAIN, 3000, &ip, name, sizeof(name), NULL));
    PASS();
}

/* catches: an unparsable reply ignored, leaving the address pending until the timeout */
TEST a_garbled_reply_is_none(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_NONE, resolve(FAKE_GARBAGE, 60000, &ip, name, sizeof(name), NULL));
    PASS();
}

/* catches: no timeout, so a silent upstream leaves the address pending for ever */
TEST silence_ends_in_none(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[256] = "";
    fake_t seen;
    ASSERT_EQ(FIRC_PTR_NONE, resolve(FAKE_SILENT, 100, &ip, name, sizeof(name), &seen));
    ASSERT_EQ(1, seen.queries);
    PASS();
}

/* catches: a query without RD, of another type or class, or with a misbuilt name */
TEST the_query_asks_ptr_with_recursion(void)
{
    static const uint8_t want[] = {0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   2,    '9',  '3',  3,    '2',  '4',  '3',  3,    '1',  '0',
                                   '7',  2,    '3',  '4',  7,    'i',  'n',  '-',  'a',  'd',
                                   'd',  'r',  4,    'a',  'r',  'p',  'a',  0,    0x00, 0x0c,
                                   0x00, 0x01};
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[256] = "";
    fake_t seen;
    ASSERT_EQ(FIRC_PTR_NAME, resolve(FAKE_ANSWER, 3000, &ip, name, sizeof(name), &seen));
    ASSERT_EQ(2 + sizeof(want), seen.last_len);
    ASSERT_MEM_EQ(want, seen.last + 2, sizeof(want));
    PASS();
}

/* catches: a failed send left pending until the timeout instead of NONE at once */
TEST a_failed_send_is_none_at_once(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_get(p, &ip, "127.0.0.1", 0, NOW, name, sizeof(name), NULL));
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_peek(p, &ip, NOW, name, sizeof(name)));
    firc_ptr_free(p);
    firc_loop_destroy(loop);
    PASS();
}

/* catches: a reply taken without checking its id */
TEST a_reply_with_another_id_is_ignored(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_NAME, resolve(FAKE_WRONG_ID, 3000, &ip, name, sizeof(name), NULL));
    ASSERT_STR_EQ("host.example.com", name);
    PASS();
}

/* catches: a reply taken without checking its question */
TEST a_reply_for_another_question_is_ignored(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_NAME, resolve(FAKE_WRONG_QUESTION, 3000, &ip, name, sizeof(name), NULL));
    ASSERT_STR_EQ("host.example.com", name);
    PASS();
}

/* catches: no cache, or a pending address asked again */
TEST a_known_address_is_not_asked_again(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_loop_t *loop = NULL;
    fake_t f;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT_EQ(0, fake_open(&f, FAKE_ANSWER));
    ASSERT_EQ(FIRC_OK, firc_loop_add_fd(loop, f.fd, EPOLLIN, fake_cb, &f));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), NULL));
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), NULL));
    run_until_settled(loop, p, &ip);
    ASSERT_EQ(FIRC_PTR_NAME, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW + 1000, name, sizeof(name), NULL));
    ASSERT_STR_EQ("host.example.com", name);
    ASSERT_EQ(1, f.queries + fake_drain(&f));
    firc_ptr_free(p);
    (void)firc_loop_del_fd(loop, f.fd);
    close(f.fd);
    firc_loop_destroy(loop);
    PASS();
}

/* catches: a name kept past 24 h, or dropped before it */
TEST a_name_is_kept_for_a_day(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_loop_t *loop = NULL;
    fake_t f;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT_EQ(0, fake_open(&f, FAKE_ANSWER));
    ASSERT_EQ(FIRC_OK, firc_loop_add_fd(loop, f.fd, EPOLLIN, fake_cb, &f));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), NULL));
    run_until_settled(loop, p, &ip);
    ASSERT_EQ(FIRC_PTR_NAME, firc_ptr_peek(p, &ip, NOW + 86399999, name, sizeof(name)));
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_peek(p, &ip, NOW + 86400000, name, sizeof(name)));
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW + 86400000, name, sizeof(name), NULL));
    run_until_settled(loop, p, &ip);
    ASSERT_EQ(2, f.queries + fake_drain(&f));
    firc_ptr_free(p);
    (void)firc_loop_del_fd(loop, f.fd);
    close(f.fd);
    firc_loop_destroy(loop);
    PASS();
}

/* catches: a cache that grows past 1024 or reuses a slot other than the oldest */
TEST the_oldest_of_1024_is_reused(void)
{
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    for (int i = 0; i < 1025; i++) {
        firc_ip_t ip = v4(10, 0, (uint8_t)(i >> 8), (uint8_t)(i & 0xff));
        ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_get(p, &ip, "127.0.0.1", 0, NOW + i, name, sizeof(name), NULL));
    }
    firc_ip_t first = v4(10, 0, 0, 0);
    firc_ip_t second = v4(10, 0, 0, 1);
    firc_ip_t last = v4(10, 0, 4, 0);
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_peek(p, &first, NOW + 2000, name, sizeof(name)));
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_peek(p, &second, NOW + 2000, name, sizeof(name)));
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_peek(p, &last, NOW + 2000, name, sizeof(name)));
    firc_ptr_free(p);
    firc_loop_destroy(loop);
    PASS();
}

TEST the_cache_holds_1024(void)
{
    static firc_ip_t ips[1024];
    firc_loop_t *loop = NULL;
    fake_t f;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT_EQ(0, fake_open(&f, FAKE_ANSWER));
    ASSERT_EQ(FIRC_OK, firc_loop_add_fd(loop, f.fd, EPOLLIN, fake_cb, &f));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    for (size_t i = 0; i < 1024; i++) { ips[i] = v4(10, 1, (uint8_t)(i >> 8u), (uint8_t)(i & 0xffu)); }
    for (size_t at = 0; at < 1024; at += 64) {
        for (size_t i = at; i < at + 64; i++) {
            ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ips[i], "127.0.0.1", f.port, NOW, name, sizeof(name), NULL));
        }
        run_until_all_settled(loop, p, ips + at, 64);
    }
    size_t named = 0;
    for (size_t i = 0; i < 1024; i++) {
        named += firc_ptr_peek(p, &ips[i], NOW, name, sizeof(name)) == FIRC_PTR_NAME;
    }
    ASSERT_EQ(1024u, (unsigned)named);
    ASSERT_EQ(1024, f.queries + fake_drain(&f));
    firc_ptr_free(p);
    (void)firc_loop_del_fd(loop, f.fd);
    close(f.fd);
    firc_loop_destroy(loop);
    PASS();
}

TEST get_says_when_it_sent(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_ip_t other = v4(34, 107, 243, 94);
    firc_loop_t *loop = NULL;
    fake_t f;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT_EQ(0, fake_open(&f, FAKE_ANSWER));
    ASSERT_EQ(FIRC_OK, firc_loop_add_fd(loop, f.fd, EPOLLIN, fake_cb, &f));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    bool sent = false;
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), &sent));
    ASSERT(sent);
    sent = true;
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), &sent));
    ASSERT_FALSE(sent);
    run_until_settled(loop, p, &ip);
    sent = true;
    ASSERT_EQ(FIRC_PTR_NAME, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), &sent));
    ASSERT_FALSE(sent);
    sent = true;
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_get(p, &other, "not-an-address", f.port, NOW, name, sizeof(name), &sent));
    ASSERT_FALSE(sent);
    ASSERT_EQ(1, f.queries + fake_drain(&f));
    firc_ptr_free(p);
    (void)firc_loop_del_fd(loop, f.fd);
    close(f.fd);
    firc_loop_destroy(loop);
    PASS();
}

/* catches: a free that leaves its timer on the loop to fire into freed memory */
TEST free_while_pending_leaves_no_timer(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_loop_t *loop = NULL;
    fake_t f;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT_EQ(0, fake_open(&f, FAKE_SILENT));
    firc_ptr_t *p = firc_ptr_new(loop, 10);
    ASSERT(p != NULL);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), NULL));
    firc_ptr_free(p);
    ASSERT_EQ(FIRC_OK, firc_loop_add_timer(loop, 50, 0, deadline_cb, NULL, NULL));
    ASSERT_EQ(FIRC_OK, firc_loop_run(loop));
    close(f.fd);
    firc_loop_destroy(loop);
    PASS();
}

/* catches: peek sending a query or inventing a state for an unknown address */
TEST peek_never_asks(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_loop_t *loop = NULL;
    fake_t f;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT_EQ(0, fake_open(&f, FAKE_ANSWER));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_peek(p, &ip, NOW, name, sizeof(name)));
    ASSERT_EQ(0, fake_drain(&f));
    firc_ptr_free(p);
    close(f.fd);
    firc_loop_destroy(loop);
    PASS();
}

/* catches: a SERVFAIL kept as a day-long NONE, or asked again within 5 min */
TEST servfail_is_asked_again_after_5_min(void)
{
    ASSERT_EQ(1, queries_by(FAKE_SERVFAIL, 3000, NOW + 299999));
    ASSERT_EQ(2, queries_by(FAKE_SERVFAIL, 3000, NOW + 300000));
    PASS();
}

/* catches: only SERVFAIL taken as transient, other rcodes kept for a day */
TEST refused_is_asked_again_after_5_min(void)
{
    ASSERT_EQ(2, queries_by(FAKE_REFUSED, 3000, NOW + 300000));
    PASS();
}

/* catches: an NXDOMAIN asked again before 24 h */
TEST nxdomain_is_kept_for_a_day(void)
{
    ASSERT_EQ(1, queries_by(FAKE_NXDOMAIN, 3000, NOW + 300000));
    ASSERT_EQ(1, queries_by(FAKE_NXDOMAIN, 3000, NOW + 86399999));
    ASSERT_EQ(2, queries_by(FAKE_NXDOMAIN, 3000, NOW + 86400000));
    PASS();
}

/* catches: a NOERROR reply without PTR taken as transient */
TEST an_empty_answer_is_kept_for_a_day(void)
{
    ASSERT_EQ(1, queries_by(FAKE_EMPTY, 3000, NOW + 86399999));
    PASS();
}

/* catches: a timeout kept as a day-long NONE, or asked again within 5 min */
TEST a_timeout_is_asked_again_after_5_min(void)
{
    ASSERT_EQ(1, queries_by(FAKE_SILENT, 100, NOW + 299999));
    ASSERT_EQ(2, queries_by(FAKE_SILENT, 100, NOW + 300000));
    PASS();
}

/* catches: an unparsable reply kept as a day-long NONE */
TEST a_garbled_reply_is_asked_again_after_5_min(void)
{
    ASSERT_EQ(2, queries_by(FAKE_GARBAGE, 60000, NOW + 300000));
    PASS();
}

/* catches: a failed send kept as a day-long NONE */
TEST a_failed_send_is_retried_after_5_min(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_loop_t *loop = NULL;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_get(p, &ip, "127.0.0.1", 0, NOW, name, sizeof(name), NULL));
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_peek(p, &ip, NOW + 299999, name, sizeof(name)));
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_peek(p, &ip, NOW + 300000, name, sizeof(name)));
    firc_ptr_free(p);
    firc_loop_destroy(loop);
    PASS();
}

/* catches: a name cut to the caller's buffer instead of withheld */
TEST a_name_longer_than_the_buffer_is_none(void)
{
    firc_ip_t ip = v4(34, 107, 243, 93);
    firc_loop_t *loop = NULL;
    fake_t f;
    ASSERT_EQ(FIRC_OK, firc_loop_create(&loop));
    ASSERT_EQ(0, fake_open(&f, FAKE_ANSWER));
    ASSERT_EQ(FIRC_OK, firc_loop_add_fd(loop, f.fd, EPOLLIN, fake_cb, &f));
    firc_ptr_t *p = firc_ptr_new(loop, 3000);
    ASSERT(p != NULL);
    char name[256] = "";
    ASSERT_EQ(FIRC_PTR_PENDING, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, name, sizeof(name), NULL));
    run_until_settled(loop, p, &ip);
    char cut[16] = "x";
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_peek(p, &ip, NOW, cut, sizeof(cut)));
    ASSERT_STR_EQ("", cut);
    ASSERT_EQ(FIRC_PTR_NONE, firc_ptr_get(p, &ip, "127.0.0.1", f.port, NOW, cut, sizeof(cut), NULL));
    ASSERT_STR_EQ("", cut);
    char fits[17] = "";
    ASSERT_EQ(FIRC_PTR_NAME, firc_ptr_peek(p, &ip, NOW, fits, sizeof(fits)));
    ASSERT_STR_EQ("host.example.com", fits);
    firc_ptr_free(p);
    (void)firc_loop_del_fd(loop, f.fd);
    close(f.fd);
    firc_loop_destroy(loop);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(ipv4_name_is_reversed);
    RUN_TEST(ipv6_name_is_nibbles);
    RUN_TEST(a_short_buffer_is_refused);
    RUN_TEST(an_answer_names_the_address);
    RUN_TEST(compressed_target_is_decoded);
    RUN_TEST(nxdomain_is_none);
    RUN_TEST(a_garbled_reply_is_none);
    RUN_TEST(silence_ends_in_none);
    RUN_TEST(the_query_asks_ptr_with_recursion);
    RUN_TEST(a_failed_send_is_none_at_once);
    RUN_TEST(a_reply_with_another_id_is_ignored);
    RUN_TEST(a_reply_for_another_question_is_ignored);
    RUN_TEST(a_known_address_is_not_asked_again);
    RUN_TEST(a_name_is_kept_for_a_day);
    RUN_TEST(the_oldest_of_1024_is_reused);
    RUN_TEST(the_cache_holds_1024);
    RUN_TEST(get_says_when_it_sent);
    RUN_TEST(free_while_pending_leaves_no_timer);
    RUN_TEST(peek_never_asks);
    RUN_TEST(servfail_is_asked_again_after_5_min);
    RUN_TEST(refused_is_asked_again_after_5_min);
    RUN_TEST(nxdomain_is_kept_for_a_day);
    RUN_TEST(an_empty_answer_is_kept_for_a_day);
    RUN_TEST(a_timeout_is_asked_again_after_5_min);
    RUN_TEST(a_garbled_reply_is_asked_again_after_5_min);
    RUN_TEST(a_failed_send_is_retried_after_5_min);
    RUN_TEST(a_name_longer_than_the_buffer_is_none);
    GREATEST_MAIN_END();
}
