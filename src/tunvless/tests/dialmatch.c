#define _GNU_SOURCE
#include <dirent.h>
#include <sys/resource.h>
#include "unit.h"
#include "../src/proto/transport/trdial.c"

static char g_err[4096];

static void put4(struct tr_ip *ip, uint32_t a) {
    memset(ip, 0, sizeof *ip);
    ip->b[0] = (unsigned char)(a >> 24);
    ip->b[1] = (unsigned char)(a >> 16);
    ip->b[2] = (unsigned char)(a >> 8);
    ip->b[3] = (unsigned char)a;
}

static void put6(struct tr_ip *ip, const char *s) {
    memset(ip, 0, sizeof *ip);
    inet_pton(AF_INET6, s, ip->b);
    ip->v6 = 1;
}

static unsigned two_addrs(const char *host, struct tr_ip out[ADDR_MAX]) {
    if (!strcmp(host, "dual")) { put4(&out[0], 0x7f000001u); put6(&out[1], "::1"); return 2; }
    if (!strcmp(host, "::1") || !strcmp(host, "w")) {
        put4(&out[0], 0x7f000002u);
        put6(&out[1], "::1");
        return 2;
    }
    if (!strcmp(host, "w3")) {
        put4(&out[0], 0x7f000002u);
        put6(&out[1], "::ffff:127.0.0.2");
        put6(&out[2], "::1");
        return 3;
    }
    if (!strcmp(host, "w4")) {
        put4(&out[0], 0x7f000002u);
        put6(&out[1], "7f00:1::");
        put4(&out[2], 0x7f000001u);
        return 3;
    }
    if (!strcmp(host, "bh")) { put4(&out[0], 0x7f000001u); put6(&out[1], "::1"); return 2; }
    if (!strcmp(host, "quiet")) {
        put4(&out[0], 0x7f000002u);
        put6(&out[1], "2001:db8::1");
        put6(&out[2], "::1");
        return 3;
    }
    if (!strcmp(host, "order")) {
        put4(&out[0], 0x7f000003u);
        put4(&out[1], 0x7f000002u);
        put6(&out[2], "::ffff:127.0.0.4");
        put6(&out[3], "::1");
        return 4;
    }
    if (!strcmp(host, "slowx")) { put4(&out[0], 0x7f000001u); put6(&out[1], "2001:db8::1"); return 2; }
    if (!strcmp(host, "back")) { put4(&out[0], 0x7f000001u); put6(&out[1], "::1"); return 2; }
    if (!strcmp(host, "refnr")) { put4(&out[0], 0x7f000001u); put6(&out[1], "2001:db8::1"); return 2; }
    if (!strcmp(host, "refused6")) { put6(&out[0], "::1"); return 1; }
    if (!strcmp(host, "six")) { put6(&out[0], "2001:db8::1"); return 1; }
    put4(&out[0], 0x7f000002u);
    put4(&out[1], 0x7f000001u);
    return 2;
}

struct chain { struct addrinfo ai[24]; struct sockaddr_storage sa[24]; unsigned n; };

static void link4(struct chain *c, uint32_t a) {
    struct sockaddr_in *s = (struct sockaddr_in *)&c->sa[c->n];
    s->sin_family = AF_INET;
    s->sin_addr.s_addr = htonl(a);
    c->ai[c->n].ai_family = AF_INET;
    c->ai[c->n].ai_addr = (struct sockaddr *)s;
    c->ai[c->n].ai_addrlen = sizeof *s;
    if (c->n) c->ai[c->n - 1].ai_next = &c->ai[c->n];
    c->n++;
}

static void link6(struct chain *c, const char *a) {
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&c->sa[c->n];
    s->sin6_family = AF_INET6;
    inet_pton(AF_INET6, a, &s->sin6_addr);
    c->ai[c->n].ai_family = AF_INET6;
    c->ai[c->n].ai_addr = (struct sockaddr *)s;
    c->ai[c->n].ai_addrlen = sizeof *s;
    if (c->n) c->ai[c->n - 1].ai_next = &c->ai[c->n];
    c->n++;
}

static void link_unix(struct chain *c) {
    struct sockaddr *s = (struct sockaddr *)&c->sa[c->n];
    s->sa_family = AF_UNIX;
    memset(s->sa_data, 0x7f, sizeof s->sa_data);
    c->ai[c->n].ai_family = AF_UNIX;
    c->ai[c->n].ai_addr = s;
    c->ai[c->n].ai_addrlen = sizeof(struct sockaddr_storage);
    if (c->n) c->ai[c->n - 1].ai_next = &c->ai[c->n];
    c->n++;
}

static int is4(const struct tr_ip *ip, uint32_t a) {
    struct tr_ip w;
    put4(&w, a);
    return !memcmp(&w, ip, sizeof w);
}

static int is6(const struct tr_ip *ip, const char *a) {
    struct tr_ip w;
    put6(&w, a);
    return !memcmp(&w, ip, sizeof w);
}

static int listener6(uint16_t port) {
    int s = socket(AF_INET6, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_port = htons(port), .sin6_addr = IN6ADDR_LOOPBACK_INIT };
    if (s < 0) return -1;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0) { close(s); return -1; }
    return s;
}

static int peer_family(int fd) {
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0) return -1;
    return ss.ss_family;
}

static int pending(int ls) {
    struct pollfd p = { .fd = ls, .events = POLLIN };
    return poll(&p, 1, 0);
}

static int attempt_logged(const struct tr_ip *ip, uint16_t port) {
    int p[2];
    if (pipe(p) != 0) return -999;
    fflush(stderr);
    int save = dup(2);
    dup2(p[1], 2);
    int d = 0;
    int fd = attempt_start(ip, port, &d);
    fflush(stderr);
    dup2(save, 2);
    close(save);
    close(p[1]);
    ssize_t r = read(p[0], g_err, sizeof g_err - 1);
    close(p[0]);
    g_err[r > 0 ? r : 0] = 0;
    return fd;
}

static int dial_logged(const char *host, uint16_t port) {
    int p[2];
    if (pipe(p) != 0) return -999;
    fflush(stderr);
    int save = dup(2);
    dup2(p[1], 2);
    int fd = tcp_connect(host, port, 2);
    fflush(stderr);
    dup2(save, 2);
    close(save);
    close(p[1]);
    ssize_t r = read(p[0], g_err, sizeof g_err - 1);
    close(p[0]);
    g_err[r > 0 ? r : 0] = 0;
    return fd;
}

static int listener(uint16_t *port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000001u) };
    socklen_t al = sizeof a;
    if (s < 0 || bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0 ||
        getsockname(s, (struct sockaddr *)&a, &al) != 0) return -1;
    *port = ntohs(a.sin_port);
    return s;
}

static int listen_on(int fam, uint16_t *port, int backlog) {
    int s = socket(fam, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t sl;
    if (fam == AF_INET6) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(*port);
        a->sin6_addr = in6addr_loopback;
        sl = sizeof *a;
    } else {
        struct sockaddr_in *a = (struct sockaddr_in *)&ss;
        a->sin_family = AF_INET;
        a->sin_port = htons(*port);
        a->sin_addr.s_addr = htonl(0x7f000001u);
        sl = sizeof *a;
    }
    if (s < 0) return -1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (fam == AF_INET6) setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    if (bind(s, (struct sockaddr *)&ss, sl) != 0 || listen(s, backlog) != 0 ||
        getsockname(s, (struct sockaddr *)&ss, &sl) != 0) { close(s); return -1; }
    *port = ntohs(fam == AF_INET6 ? ((struct sockaddr_in6 *)&ss)->sin6_port : ((struct sockaddr_in *)&ss)->sin_port);
    return s;
}

static int listen4_at(uint32_t addr, uint16_t port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(addr) };
    if (s < 0) return -1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (bind(s, (struct sockaddr *)&a, sizeof a) != 0 || listen(s, 4) != 0) { close(s); return -1; }
    return s;
}

static int full_listener(int fam, uint16_t *port, int *filler) {
    int s = listen_on(fam, port, 0);
    if (s < 0) return -1;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    getsockname(s, (struct sockaddr *)&ss, &sl);
    *filler = socket(fam, SOCK_STREAM, 0);
    if (*filler >= 0 && connect(*filler, (struct sockaddr *)&ss, sl) == 0) return s;
    if (*filler >= 0) close(*filler);
    close(s);
    return -1;
}

static void *accept_late(void *arg) {
    struct timespec d = { .tv_sec = 0, .tv_nsec = 300000000L };
    nanosleep(&d, NULL);
    int c = accept(*(int *)arg, NULL, NULL);
    if (c >= 0) close(c);
    return NULL;
}

static int have_lo6(void) {
    uint16_t p = 0;
    int s = listen_on(AF_INET6, &p, 1);
    if (s < 0) return 0;
    close(s);
    return 1;
}

static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

static int mark_settable(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    uint32_t m = 1;
    int r = s >= 0 && setsockopt(s, SOL_SOCKET, SO_MARK, &m, sizeof m) == 0;
    if (s >= 0) close(s);
    return r;
}

static void t_reach_parallel(void) {
    /* catches: a refused or unroutable host read as reached or told as another failure, the call waiting out the deadline with nothing pending, or a leaked fd */
    uint16_t open_p = 0, shut_p = 0;
    int lo = listener(&open_p), ls = listener(&shut_p);
    close(ls);
    check("reach: six pinned", 1, transport_pin_host("six"));
    const char *hosts[3] = { "127.0.0.1", "127.0.0.1", "six" };
    uint16_t ports[3] = { open_p, shut_p, 443 };
    char ok[3] = { 7, 7, 7 };
    int err[3] = { 7, 7, 7 };
    int before = fd_count();
    int64_t t0 = now_ms();
    int rc = tr_reach(hosts, ports, 3, 3000, ok, err);
    int64_t el = now_ms() - t0;
    int after = fd_count();
    check("reach: the listening host connects", 1, ok[0]);
    check("reach: the refused host does not", 0, ok[1]);
    check("reach: the unroutable host does not", 0, ok[2]);
    check("reach: the reached host has no error", 0, err[0]);
    check("reach: the refused host told as refused", TR_ECONNREFUSED, err[1]);
    check("reach: the unroutable host told as unreachable", TR_EUNREACH, err[2]);
    check("reach: one host reached", 1, rc);
    check("reach: nothing pending, no wait for the deadline", 1, el < 1000);
    check("reach: no fd left open", before, after);
    if (lo >= 0) close(lo);
}

static void t_reach_mark_refused(void) {
    /* catches: a socket whose required mark cannot be set used for the pre-pass, so it leaves unmarked into the tunnel */
    if (mark_settable()) {
        printf("dialmatch: the mark can be set here, the refused mark is not checked\n");
        return;
    }
    uint16_t open_p = 0;
    int lo = listener(&open_p);
    const char *hosts[1] = { "127.0.0.1" };
    uint16_t ports[1] = { open_p };
    char ok[1] = { 7 };
    int err[1] = { 7 };
    transport_set_sock_mark(1, 1);
    int before = fd_count();
    int64_t t0 = now_ms();
    tr_reach(hosts, ports, 1, 3000, ok, err);
    int64_t el = now_ms() - t0;
    transport_set_sock_mark(0, 0);
    check("reach: no mark, a listening host not reached", 0, ok[0]);
    check("reach: no mark, told as a failed connect", TR_ECONNECT, err[0]);
    check("reach: no mark, at once", 1, el < 1000);
    check("reach: no mark, no fd left open", before, fd_count());
    if (lo >= 0) close(lo);
}

static void t_reach_deadline(void) {
    /* catches: a silent host waited for sequentially, past the deadline, or told as other than a timeout */
    uint16_t p = 0;
    int filler = -1;
    int ls = full_listener(AF_INET, &p, &filler);
    check("reach: a full listener on 127.0.0.1", 1, ls >= 0);
    const char *hosts[2] = { "127.0.0.1", "127.0.0.1" };
    uint16_t ports[2] = { p, p };
    char ok[2] = { 7, 7 };
    int err[2] = { 7, 7 };
    int before = fd_count();
    int64_t t0 = now_ms();
    tr_reach(hosts, ports, 1, 300, ok, err);
    int64_t el = now_ms() - t0;
    check("reach: a silent host is not reached", 0, ok[0]);
    check("reach: a silent host told as a timeout", TR_ECONNTIMEOUT, err[0]);
    check("reach: a silent host costs the deadline, no more", 1, el >= 300 && el < 600);
    ok[0] = ok[1] = 7;
    t0 = now_ms();
    tr_reach(hosts, ports, 2, 300, ok, err);
    el = now_ms() - t0;
    check("reach: two silent hosts, neither reached", 1, ok[0] == 0 && ok[1] == 0);
    check("reach: two silent hosts share one wait", 1, el >= 300 && el < 600);
    check("reach: no fd left open after the deadline", before, fd_count());
    if (ls >= 0) { close(filler); close(ls); }
}

static void t_reach_no_fd(void) {
    /* catches: a pre-pass out of descriptors failing the host instead of leaving it to the probe */
    uint16_t shut_p = 0;
    int ls = listener(&shut_p);
    close(ls);
    const char *hosts[1] = { "127.0.0.1" };
    uint16_t ports[1] = { shut_p };
    char ok[1] = { 7 };
    int err[1] = { 7 };
    struct rlimit rl, low;
    getrlimit(RLIMIT_NOFILE, &rl);
    int fd = dup(0);
    close(fd);
    low = rl;
    low.rlim_cur = (rlim_t)fd;
    setrlimit(RLIMIT_NOFILE, &low);
    tr_reach(hosts, ports, 1, 3000, ok, err);
    setrlimit(RLIMIT_NOFILE, &rl);
    check("reach: out of descriptors, the probe decides", 1, ok[0]);
}

struct late { int ls, filler; };

static void *close_late(void *arg) {
    struct late *l = arg;
    struct timespec d = { .tv_sec = 0, .tv_nsec = 300000000L };
    nanosleep(&d, NULL);
    close(l->filler);
    close(l->ls);
    return NULL;
}

static void t_reach_v4_first(void) {
    /* catches: an IPv6 winner cached while an IPv4 address of the node is still connecting, so later dials go IPv6 first, or never cached once IPv4 fails */
    uint16_t ps = 0;
    int filler = -1, l4 = -1, l6 = -1;
    for (int tries = 0; tries < 50 && l6 < 0; tries++) {
        ps = 0;
        l4 = full_listener(AF_INET, &ps, &filler);
        if (l4 < 0) break;
        l6 = listener6(ps);
        if (l6 < 0) { close(filler); close(l4); l4 = -1; }
    }
    check("reach: a full listener on 127.0.0.1 and one on ::1, one port", 1, l4 >= 0 && l6 >= 0);
    struct tr_ip rv[2];
    put4(&rv[0], 0x7f000001u);
    put6(&rv[1], "::1");
    check("reach: rv pinned", 1, pin_add("rv", rv, 2) == 2 && pin_add("rw", rv, 2) == 2 && pin_add("rx", rv, 2) == 2);
    pthread_t th;
    int th_ok = l4 >= 0 && pthread_create(&th, NULL, accept_late, &l4) == 0;
    const char *hosts[1] = { "rv" };
    uint16_t ports[1] = { ps };
    char ok[1] = { 7 };
    int err[1] = { 7 };
    tr_reach(hosts, ports, 1, 3000, ok, err);
    if (th_ok) pthread_join(th, NULL);
    const struct tr_ip *g = good_get("rv", ps);
    check("reach: IPv6 first, IPv4 later: reached", 1, ok[0]);
    check("reach: IPv6 first, IPv4 later: IPv4 remembered", 1, g && is4(g, 0x7f000001u));
    if (l4 >= 0) { close(filler); close(l4); }
    if (l6 >= 0) close(l6);
    struct late lt;
    l6 = -1;
    for (int tries = 0; tries < 50 && l6 < 0; tries++) {
        ps = 0;
        lt.ls = full_listener(AF_INET, &ps, &lt.filler);
        if (lt.ls < 0) break;
        l6 = listener6(ps);
        if (l6 < 0) { close(lt.filler); close(lt.ls); lt.ls = -1; }
    }
    check("reach: a full listener on 127.0.0.1 to close, one on ::1", 1, lt.ls >= 0 && l6 >= 0);
    th_ok = lt.ls >= 0 && pthread_create(&th, NULL, close_late, &lt) == 0;
    hosts[0] = "rw";
    ports[0] = ps;
    tr_reach(hosts, ports, 1, 3000, ok, err);
    if (th_ok) pthread_join(th, NULL);
    g = good_get("rw", ps);
    check("reach: IPv6 first, IPv4 refused later: IPv6 remembered", 1, ok[0] == 1 && g && is6(g, "::1"));
    if (l6 >= 0) close(l6);
    l6 = -1;
    for (int tries = 0; tries < 50 && l6 < 0; tries++) {
        ps = 0;
        l4 = full_listener(AF_INET, &ps, &filler);
        if (l4 < 0) break;
        l6 = listener6(ps);
        if (l6 < 0) { close(filler); close(l4); l4 = -1; }
    }
    check("reach: a full listener on 127.0.0.1 left silent, one on ::1", 1, l4 >= 0 && l6 >= 0);
    hosts[0] = "rx";
    ports[0] = ps;
    tr_reach(hosts, ports, 1, 300, ok, err);
    check("reach: IPv6 answers, IPv4 silent: reached", 1, ok[0]);
    check("reach: IPv6 answers, IPv4 silent: no family remembered", 1, !good_get("rx", ps));
    if (l4 >= 0) { close(filler); close(l4); }
    if (l6 >= 0) close(l6);
}

static void t_reach_cache_keeps_the_round(void) {
    /* catches: the winner cache keeping its first entries forever, so a round's pre-pass winner is gone before the probe dials */
    uint16_t p = 0, l = 0;
    int filler = -1;
    int dead = full_listener(AF_INET, &p, &filler);
    int live = dead >= 0 ? listen4_at(0x7f000002u, p) : -1;
    int many = listen_on(AF_INET, &l, 64);
    check("reach: a full listener, a live one on the same port, a third", 1, dead >= 0 && live >= 0 && many >= 0);
    struct tr_ip one;
    put4(&one, 0x7f000001u);
    for (int i = 0; i < GOOD_MAX; i++) {
        char h[16];
        snprintf(h, sizeof h, "o%d", i);
        good_put(h, l, one);
    }
    struct tr_ip pp[5];
    for (int i = 0; i < 4; i++) put4(&pp[i], 0x7f000001u);
    put4(&pp[4], 0x7f000002u);
    check("reach: pp pinned", 5, pin_add("pp", pp, 5));
    const char *hosts[16];
    uint16_t ports[16];
    char names[16][16];
    hosts[0] = "pp";
    ports[0] = p;
    for (int i = 1; i < 16; i++) {
        snprintf(names[i], sizeof names[i], "q%d", i);
        pin_add(names[i], &one, 1);
        hosts[i] = names[i];
        ports[i] = l;
    }
    char ok[16];
    int err[16];
    int rc = tr_reach(hosts, ports, 16, 3000, ok, err);
    check("reach: the round of sixteen all reached", 16, rc);
    pin_add("q16", &one, 1);
    const char *last[1] = { "q16" };
    tr_reach(last, &l, 1, 3000, ok, err);
    int64_t t0 = now_ms();
    int fd = tr_dial("pp", p, 2);
    int64_t el = now_ms() - t0;
    check("reach: the probe dials the pre-pass winner first", 1, fd >= 0 && el < 1000);
    if (fd >= 0) close(fd);
    close(many);
    close(live);
    close(filler);
    close(dead);
}

int main(void) {
    if (!have_lo6()) {
        printf("dialmatch: SKIPPED the IPv6 loopback checks (no ::1)\n");
        return 2;
    }
    uint16_t port = 0;
    int ls = listener(&port);
    check("a listener on 127.0.0.1", 1, ls >= 0);
    close(ls);
    char want[256];
    int fd = dial_logged("127.0.0.1", port);
    snprintf(want, sizeof want,
             "tunvless[warn]: 127.0.0.1:%u — node refused the TCP connection (nothing listens on that port)\n",
             port);
    /* catches: a closed port reported as a bare connect failure, or told untagged so fircd keeps it at info */
    check("closed port: refused", TR_ECONNREFUSED, fd);
    check_str("closed port: a warning naming the refusal", want, g_err);
    fd = dial_logged("127.0.0.1", port);
    /* catches: a dead node's every dial warned, flooding the journal while the pool keeps probing it */
    check("closed port again: refused", TR_ECONNREFUSED, fd);
    check_str("closed port again: held back", "", g_err);

    /* catches: an attempt still waiting at the deadline told as a refusal instead of silence */
    check("in flight at the deadline: timeout", TR_ECONNTIMEOUT, dial_fail(1, ECONNREFUSED));
    /* catches: a deadline with no answer at all told as some other failure */
    check("no error seen: timeout", TR_ECONNTIMEOUT, dial_fail(0, 0));
    /* catches: an unreachable host or network folded into refusal or timeout */
    check("host unreachable", TR_EUNREACH, dial_fail(0, EHOSTUNREACH));
    check("network unreachable", TR_EUNREACH, dial_fail(0, ENETUNREACH));
    /* catches: an unexpected errno mapped onto a specific cause it is not */
    check("other errno: generic", TR_ECONNECT, dial_fail(0, EACCES));
    /* catches: a connect code left without its own text, so the log falls back to a bare number */
    check("timeout has text", 1, tr_dial_strerror(TR_ECONNTIMEOUT) != NULL);
    check("unreachable has text", 1, tr_dial_strerror(TR_EUNREACH) != NULL);
    check("no node has text", 1, tr_dial_strerror(TR_ENONODE) != NULL);
    check("a TLS code is not a dial code", 1, tr_dial_strerror(TLS13_ETIMEOUT) == NULL);

    ls = listener(&port);
    check("a second listener on 127.0.0.1", 1, ls >= 0);
    g_resolve = two_addrs;
    check("two addresses pinned", 2, transport_pin_host("two"));
    fd = dial_logged("two", port);
    snprintf(want, sizeof want, "tunvless[info]: two:%u — connected after 1 of 2 addresses failed\n", port);
    /* catches: a connection made on a later address told untagged, or louder than the node it reached */
    check("connected after a failure: connected", 1, fd >= 0);
    check_str("connected after a failure: an info line", want, g_err);
    if (fd >= 0) close(fd);
    close(ls);

    struct chain c;
    struct tr_ip got[ADDR_MAX];
    memset(&c, 0, sizeof c);
    link6(&c, "2001:db8::a");
    link4(&c, 0xc0000201u);
    link6(&c, "2001:db8::b");
    link4(&c, 0xc0000202u);
    unsigned n = addrs_of(c.ai, got);
    check("mixed chain: every address", 4, n);
    check("mixed chain: IPv4 first, resolver order", 1, is4(&got[0], 0xc0000201u) && is4(&got[1], 0xc0000202u));
    check("mixed chain: IPv6 after, resolver order", 1, is6(&got[2], "2001:db8::a") && is6(&got[3], "2001:db8::b"));

    memset(&c, 0, sizeof c);
    char v6s[10][24];
    for (int i = 0; i < 10; i++) {
        snprintf(v6s[i], sizeof v6s[i], "2001:db8::%x", i + 1);
        link6(&c, v6s[i]);
    }
    for (int i = 0; i < 10; i++) link4(&c, 0xc0000201u + (uint32_t)i);
    n = addrs_of(c.ai, got);
    check("ten of each: the cap", ADDR_MAX, n);
    int order = 1;
    for (int i = 0; i < 10; i++) order &= is4(&got[i], 0xc0000201u + (uint32_t)i);
    for (int i = 0; i < 6; i++) order &= is6(&got[10 + i], v6s[i]);
    check("ten of each: every IPv4, then the first IPv6", 1, order);

    memset(&c, 0, sizeof c);
    link4(&c, 0xc0000201u);
    link_unix(&c);
    link4(&c, 0xc0000202u);
    n = addrs_of(c.ai, got);
    check("other family skipped", 2, n);
    check("other family skipped: both IPv4 kept", 1, is4(&got[0], 0xc0000201u) && is4(&got[1], 0xc0000202u));

    n = resolve("::1", got);
    check("resolve ::1: one address", 1, n);
    check("resolve ::1: the IPv6 loopback", 1, n == 1 && is6(&got[0], "::1"));
    n = resolve("127.0.0.1", got);
    check("resolve 127.0.0.1: one IPv4", 1, n == 1 && is4(&got[0], 0x7f000001u));

    int l4 = -1, l6 = -1;
    for (int tries = 0; tries < 50 && l6 < 0; tries++) {
        l4 = listener(&port);
        if (l4 < 0) break;
        l6 = listener6(port);
        if (l6 < 0) { close(l4); l4 = -1; }
    }
    check("listeners on 127.0.0.1 and ::1, one port", 1, l4 >= 0 && l6 >= 0);
    check("dual pinned", 2, transport_pin_host("dual"));
    fd = dial_logged("dual", port);
    check("dual: connected", 1, fd >= 0);
    check("dual: over IPv4", AF_INET, fd >= 0 ? peer_family(fd) : -1);
    check("dual: IPv6 not dialled", 0, pending(l6));
    if (fd >= 0) close(fd);

    check("::1 pinned", 2, transport_pin_host("::1"));
    fd = dial_logged("::1", port);
    snprintf(want, sizeof want, "tunvless[info]: [::1]:%u — connected after 1 of 2 addresses failed\n", port);
    check("v4 refused, v6 listens: connected", 1, fd >= 0);
    check("v4 refused, v6 listens: over IPv6", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    check_str("v4 refused, v6 listens: bracketed host in the info line", want, g_err);
    if (fd >= 0) close(fd);

    check("w pinned", 2, transport_pin_host("w"));
    fd = dial_logged("w", port);
    snprintf(want, sizeof want, "tunvless[info]: w:%u — connected after 1 of 2 addresses failed\n", port);
    check_str("winner cache: first dial passes the dead IPv4", want, g_err);
    if (fd >= 0) close(fd);
    fd = dial_logged("w", port);
    check("winner cache: second dial connected", 1, fd >= 0);
    check_str("winner cache: second dial starts with the IPv6 winner", "", g_err);
    if (fd >= 0) close(fd);
    check("w3 pinned", 3, transport_pin_host("w3"));
    fd = dial_logged("w3", port);
    snprintf(want, sizeof want, "tunvless[info]: w3:%u — connected after 2 of 3 addresses failed\n", port);
    check_str("winner cache: first dial passes both dead addresses", want, g_err);
    if (fd >= 0) close(fd);
    fd = dial_logged("w3", port);
    check_str("winner cache: the winner told apart by all 16 bytes", "", g_err);
    if (fd >= 0) close(fd);
    check("w4 pinned", 3, transport_pin_host("w4"));
    fd = dial_logged("w4", port);
    check("winner cache: an IPv4 winner behind a look-alike IPv6", 1, fd >= 0);
    if (fd >= 0) close(fd);
    fd = dial_logged("w4", port);
    check_str("winner cache: the winner told apart by its family", "", g_err);
    if (fd >= 0) close(fd);
    close(l4);
    close(l6);

    l6 = listener6(0);
    struct sockaddr_in6 a6;
    socklen_t a6l = sizeof a6;
    getsockname(l6, (struct sockaddr *)&a6, &a6l);
    uint16_t p6 = ntohs(a6.sin6_port);
    close(l6);
    check("refused6 pinned", 1, transport_pin_host("refused6"));
    check("IPv6 closed port: refused", TR_ECONNREFUSED, dial_logged("refused6", p6));

    uint16_t ps = 0;
    int filler = -1;
    l4 = l6 = -1;
    for (int tries = 0; tries < 50 && l6 < 0; tries++) {
        ps = 0;
        l4 = full_listener(AF_INET, &ps, &filler);
        if (l4 < 0) break;
        l6 = listener6(ps);
        if (l6 < 0) { close(filler); close(l4); l4 = -1; }
    }
    check("a full listener on 127.0.0.1 and one on ::1, one port", 1, l4 >= 0 && l6 >= 0);
    check("bh pinned", 2, transport_pin_host("bh"));
    fd = dial_logged("bh", ps);
    /* catches: IPv6 held back while a black-holed IPv4 attempt waits out the deadline */
    check("IPv4 black hole, IPv6 listens: connected", 1, fd >= 0);
    check("IPv4 black hole, IPv6 listens: over IPv6", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    check_str("IPv4 black hole, IPv6 listens: nothing failed", "", g_err);
    if (fd >= 0) close(fd);
    close(filler);
    close(l4);
    close(l6);

    l6 = listen_on(AF_INET6, &ps, 4);
    check("a listener on ::1", 1, l6 >= 0);
    check("quiet pinned", 3, transport_pin_host("quiet"));
    fd = dial_logged("quiet", ps);
    snprintf(want, sizeof want, "tunvless[info]: quiet:%u — connected after 1 of 2 addresses failed\n", ps);
    /* catches: an address refused for want of a route counted as one that failed or as one tried */
    check("unrouted IPv6 left out of the count: connected", 1, fd >= 0);
    check_str("unrouted IPv6 left out of the count", want, g_err);
    if (fd >= 0) close(fd);
    if (l6 >= 0) close(l6);

    pthread_t th;
    int th_ok;
    ps = 0;
    l4 = full_listener(AF_INET, &ps, &filler);
    check("a full listener on 127.0.0.1", 1, l4 >= 0);
    th_ok = l4 >= 0 && pthread_create(&th, NULL, accept_late, &l4) == 0;
    check("slowx pinned", 2, transport_pin_host("slowx"));
    fd = dial_logged("slowx", ps);
    if (th_ok) pthread_join(th, NULL);
    /* catches: an IPv6 address without a route tried and logged as failed while IPv4 was still connecting */
    check("IPv4 slow, IPv6 without a route: connected", 1, fd >= 0);
    check("IPv4 slow, IPv6 without a route: over IPv4", AF_INET, fd >= 0 ? peer_family(fd) : -1);
    check_str("IPv4 slow, IPv6 without a route: no failed address told", "", g_err);
    if (fd >= 0) close(fd);
    if (l4 >= 0) { close(filler); close(l4); }

    uint16_t pb = 0;
    l4 = l6 = -1;
    for (int tries = 0; tries < 50 && l6 < 0; tries++) {
        pb = 0;
        l4 = listen_on(AF_INET, &pb, 4);
        if (l4 < 0) break;
        l6 = listen_on(AF_INET6, &pb, 4);
        close(l4);
    }
    check("back pinned", 2, transport_pin_host("back"));
    fd = dial_logged("back", pb);
    check("back: the IPv6 winner", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    if (l6 >= 0) close(l6);
    int f6 = -1;
    l6 = full_listener(AF_INET6, &pb, &f6);
    l4 = listen_on(AF_INET, &pb, 4);
    check("back: a full listener on ::1 and one on 127.0.0.1, the same port", 1, l6 >= 0 && l4 >= 0);
    fd = dial_logged("back", pb);
    /* catches: IPv4 held back behind an IPv6 winner that stopped answering, so every dial times out */
    check("IPv6 winner silent: connected", 1, fd >= 0);
    check("IPv6 winner silent: over IPv4", AF_INET, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    if (l6 >= 0) { close(f6); close(l6); }
    if (l4 >= 0) close(l4);

    uint16_t pr = 0;
    l4 = listen_on(AF_INET, &pr, 1);
    check("a listener on 127.0.0.1 to close", 1, l4 >= 0);
    if (l4 >= 0) close(l4);
    check("refnr pinned", 2, transport_pin_host("refnr"));
    /* catches: an IPv6 address without a route hiding that the node's IPv4 refused */
    check("IPv4 refused, IPv6 without a route: refused", TR_ECONNREFUSED, dial_logged("refnr", pr));

    uint16_t po = 0;
    int lo3 = -1, lo4 = -1;
    l6 = -1;
    for (int tries = 0; tries < 50 && lo4 < 0; tries++) {
        po = 0;
        l6 = listen_on(AF_INET6, &po, 4);
        if (l6 < 0) break;
        lo3 = listen4_at(0x7f000003u, po);
        lo4 = lo3 >= 0 ? listen4_at(0x7f000004u, po) : -1;
        if (lo4 < 0) { if (lo3 >= 0) close(lo3); close(l6); lo3 = -1; l6 = -1; }
    }
    check("listeners on ::1, 127.0.0.3 and 127.0.0.4, one port", 1, l6 >= 0 && lo3 >= 0 && lo4 >= 0);
    if (lo3 >= 0) close(lo3);
    if (lo4 >= 0) close(lo4);
    check("order pinned", 4, transport_pin_host("order"));
    fd = dial_logged("order", po);
    check("order: the IPv6 winner", AF_INET6, fd >= 0 ? peer_family(fd) : -1);
    if (fd >= 0) close(fd);
    if (l6 >= 0) close(l6);
    int fo = -1;
    l6 = full_listener(AF_INET6, &po, &fo);
    lo3 = listen4_at(0x7f000003u, po);
    lo4 = listen4_at(0x7f000004u, po);
    check("order: a full listener on ::1, listeners on 127.0.0.3 and 127.0.0.4", 1, l6 >= 0 && lo3 >= 0 && lo4 >= 0);
    fd = dial_logged("order", po);
    struct sockaddr_in pa = { 0 };
    socklen_t pal = sizeof pa;
    if (fd >= 0) getpeername(fd, (struct sockaddr *)&pa, &pal);
    /* catches: the winner swapped into place, so a later IPv6 address jumps ahead of the first IPv4 */
    check("IPv6 winner silent: the first IPv4 next", 0x7f000003L, pa.sin_family == AF_INET ? (long)ntohl(pa.sin_addr.s_addr) : -1);
    if (fd >= 0) close(fd);
    if (l6 >= 0) { close(fo); close(l6); }
    if (lo3 >= 0) close(lo3);
    if (lo4 >= 0) close(lo4);

    check("six: pinned", 1, transport_pin_host("six"));
    check("six: counted", 1, transport_pin_count("six"));
    /* catches: a connect refused at once for want of a route told as a timeout */
    check("six: no route", TR_EUNREACH, dial_logged("six", 443));
    uint32_t a4[4];
    check("six: no IPv4 route address", 0, transport_pinned_addrs("six", a4, 4));
    check("not pinned: counted 0", 0, transport_pin_count("nobody"));
    check("two: counted", 2, transport_pin_count("two"));

    struct tr_ip lo6;
    put6(&lo6, "::1");
    transport_set_bind_dev("lo");
    fd = attempt_logged(&lo6, p6);
    char dev[IFNAMSIZ] = "";
    socklen_t dl = sizeof dev;
    if (fd < 0) {
        const char *pre = "tunvless[warn]: cannot bind a socket for the node to lo";
        check("IPv6 socket without its device is not used", 1, !strncmp(g_err, pre, strlen(pre)));
    } else if (getenv("TUNVLESS_NO_SOCKOPT_READ")) {
        printf("dialmatch: the device of a socket cannot be read here (qemu-user), not checked\n");
    } else {
        getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, &dl);
        check_str("IPv6 socket bound to the device", "lo", dev);
    }
    if (fd >= 0) close(fd);
    transport_set_bind_dev(NULL);

    transport_set_sock_mark(0x10000, 1);
    fd = attempt_logged(&lo6, p6);
    if (fd >= 0) {
        uint32_t mk = 0;
        socklen_t ml = sizeof mk;
        getsockopt(fd, SOL_SOCKET, SO_MARK, &mk, &ml);
        check("IPv6 socket carries the mark", 0x10000, mk);
        close(fd);
    } else {
        const char *pre = "tunvless[warn]: cannot set mark 0x00010000 on a socket to the node";
        check("IPv6 socket without its mark is not used", 1, !strncmp(g_err, pre, strlen(pre)));
    }
    transport_set_sock_mark(0, 0);
    t_reach_parallel();
    t_reach_mark_refused();
    t_reach_deadline();
    t_reach_no_fd();
    t_reach_v4_first();
    t_reach_cache_keeps_the_round();
    return unit_done("dialmatch");
}
