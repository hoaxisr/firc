#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "transport.h"
#include "reality.h"
#include "ech.h"
#include "unit.h"

extern long tr_nopq_ttl_s;
extern long tr_nopq_skip_s;

static char g_cur[64];
static int g_dials, g_hs, g_last_pq;
static size_t g_last_n;
static int g_all_silent;

static char g_fd_host[1024][64];
static int g_peer[4] = { -1, -1, -1, -1 };
static unsigned g_peer_at;

int tr_dial(const char *host, uint16_t port, int timeout_s) {
    (void)port; (void)timeout_s;
    g_dials++;
    snprintf(g_cur, sizeof g_cur, "%s", host);
    if (!strncmp(host, "nodial", 6)) return TR_ECONNECT;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return TR_ECONNECT;
    if (sv[0] >= 1024 || sv[1] >= 1024) { close(sv[0]); close(sv[1]); return TR_ECONNECT; }
    if (g_peer[g_peer_at] >= 0) close(g_peer[g_peer_at]);
    g_peer[g_peer_at] = sv[1];
    g_peer_at = (g_peer_at + 1) % 4;
    snprintf(g_fd_host[sv[0]], sizeof g_fd_host[0], "%s", host);
    if (strncmp(host, "mute", 4) && write(sv[1], "", 1) != 1) { close(sv[0]); return TR_ECONNECT; }
    return sv[0];
}

static int g_closes;
void tr_link_close(struct tr_link *l) {
    if (l->fd >= 0) close(l->fd);
    l->fd = -1;
    g_closes++;
}

static const void *g_st_at;
static int g_build_rc, g_st_wipes, g_other_wipes;
void sc_wipe(void *p, size_t n) {
    memset(p, 0, n);
    if (p == g_st_at && n == sizeof(struct reality_state)) g_st_wipes++;
    else if (n >= sizeof(struct ech_state)) g_other_wipes++;
}

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len) {
    (void)out_n;
    g_st_at = st;
    memset(st, 0xAB, sizeof *st);
    if (g_build_rc) return g_build_rc;
    st->pq = cfg->pq;
    g_last_pq = cfg->pq;
    *out_len = reality_fp_of(cfg->fp) == REALITY_FP_FIREFOX ? (cfg->pq ? 1890 : 600) : cfg->pq ? 1760 : 537;
    memset(out, 0x16, *out_len);
    return 0;
}

int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len) {
    (void)car;
    return reality_build_hello(cfg, st, out, out_n, out_len);
}

static int long_dropped(const char *h) {
    return !strncmp(h, "dpi", 3) || !strncmp(h, "f", 1) || !strncmp(h, "log", 3) ||
           !strncmp(h, "exp", 3) || !strncmp(h, "camo", 4);
}

int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth) {
    (void)t; (void)ch; (void)ss; (void)auth;
    g_hs++;
    g_last_n = n;
    if (fd >= 0 && fd < 1024) snprintf(g_cur, sizeof g_cur, "%s", g_fd_host[fd]);
    if (g_all_silent || !strncmp(g_cur, "dead", 4)) return TLS13_ETIMEOUT;
    if (!strncmp(g_cur, "rej", 3)) return TLS13_ECERT;
    if (long_dropped(g_cur) && n > 1400) return TLS13_ETIMEOUT;
    if (!strncmp(g_cur, "camo", 4)) return TLS13_ECERT;
    return 0;
}

const char *tls13_verify_reason(void) { return ""; }
const char *tls_cert_roots(void) { return NULL; }
int xc_b64url_decode(const char *in, unsigned char *out, size_t out_n) {
    (void)in; (void)out; (void)out_n;
    return -1;
}
int ech_b64_decode(const char *in, uint8_t *out, size_t cap) {
    (void)in; (void)out; (void)cap;
    return -1;
}
int ech_pick(const uint8_t *list, size_t n, struct ech_cfg *out) {
    (void)list; (void)n; (void)out;
    return ECH_ENOCONFIG;
}
int ech_wrap(const struct ech_cfg *cfg, const uint8_t *hello, size_t hello_n, uint8_t *out, size_t cap,
             size_t *out_n, struct ech_state *st) {
    (void)cfg; (void)hello; (void)hello_n; (void)out; (void)cap; (void)out_n; (void)st;
    return ECH_ENOCONFIG;
}

static int g_d, g_h, g_pq;
static size_t g_n;
static const char *g_fp = "chrome";

static int open_at(const char *host, uint16_t port, const char *sec) {
    struct tr_node n = { .host = host, .port = port, .type = "tcp", .security = sec,
                         .sni = "www.example.com", .fp = g_fp,
                         .pbk = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA", .sid = "0123456789abcdef" };
    struct tr_link l;
    g_dials = g_hs = 0;
    g_last_pq = -1;
    g_last_n = 0;
    int rc = tr_link_open(&l, &n, NULL, 1);
    if (rc == 0) close(l.fd);
    g_d = g_dials;
    g_h = g_hs;
    g_pq = g_last_pq;
    g_n = g_last_n;
    return rc;
}

static int open_to(const char *host, const char *sec) { return open_at(host, 443, sec); }

static int g_fa, g_fb;
static const char *g_sec2 = "reality";

static int open_two(const char *ha, const char *hb) {
    struct tr_node na = { .host = ha, .port = 443, .type = "xhttp", .security = g_sec2,
                          .sni = "www.example.com", .fp = g_fp,
                          .pbk = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA", .sid = "0123456789abcdef" };
    struct tr_node nb = na;
    nb.host = hb;
    struct tr_link a, b;
    memset(&a, 0, sizeof a);
    memset(&b, 0, sizeof b);
    g_dials = g_hs = g_closes = g_st_wipes = 0;
    int rc = tr_link_open2(&a, &na, &b, &nb, "h2", 1);
    g_fa = a.fd;
    g_fb = b.fd;
    if (rc == 0) { close(a.fd); close(b.fd); }
    g_d = g_dials;
    g_h = g_hs;
    return rc;
}

static char g_err[4096];

static int open_logged(const char *host) {
    int p[2];
    if (pipe(p) != 0) return -999;
    fflush(stderr);
    int save = dup(2);
    dup2(p[1], 2);
    int rc = open_to(host, "reality");
    fflush(stderr);
    dup2(save, 2);
    close(save);
    close(p[1]);
    ssize_t r = read(p[0], g_err, sizeof g_err - 1);
    close(p[0]);
    g_err[r > 0 ? r : 0] = 0;
    return rc;
}

int main(void) {
    unsetenv("STEER_NOPQ");
    tr_nopq_skip_s = 0;
    char h[32];

    tr_nopq_ttl_s = 0;
    check("ttl 0: the short Hello gets through", 0, open_to("exp.invalid", "reality"));
    check("ttl 0: the first open costs two connections", 2, g_d);
    check("ttl 0: a second open succeeds", 0, open_to("exp.invalid", "reality"));
    check("ttl 0: nothing remembered, two connections again", 2, g_d);
    tr_nopq_ttl_s = 3600;

    check("clean node: the handshake passes", 0, open_to("ok.invalid", "reality"));
    check("clean node: one connection", 1, g_d);
    check("clean node: the Hello offers the hybrid", 1, g_pq);

    check("dropped long Hello: the short one gets through", 0, open_to("dpi.invalid", "reality"));
    check("dropped long Hello: exactly two connections", 2, g_d);
    check("dropped long Hello: two handshakes", 2, g_h);
    check("dropped long Hello: the last Hello has no hybrid", 0, g_pq);

    check("remembered: the next open succeeds", 0, open_to("dpi.invalid", "reality"));
    check("remembered: one connection", 1, g_d);
    check("remembered: the short Hello at once", 0, g_pq);

    check("another port of the host is not remembered", 0, open_at("dpi.invalid", 8443, "reality"));
    check("another port: two connections", 2, g_d);
    check("another node keeps the hybrid", 0, open_to("ok.invalid", "tls"));
    check("another node: the Hello offers the hybrid", 1, g_pq);

    check("silent node: the timeout is the answer", TLS13_ETIMEOUT, open_to("dead.invalid", "reality"));
    check("silent node: one retry, two connections", 2, g_d);
    check("silent node again: still a timeout", TLS13_ETIMEOUT, open_to("dead.invalid", "reality"));
    check("silent node again: not remembered, two connections", 2, g_d);

    check("short Hello refused: the first reason is kept", TLS13_ETIMEOUT, open_to("camo.invalid", "reality"));
    check("short Hello refused: two connections", 2, g_d);
    check("short Hello refused: not remembered", TLS13_ETIMEOUT, open_to("camo.invalid", "reality"));
    check("short Hello refused again: two connections", 2, g_d);

    check("refused node: the refusal is the answer", TLS13_ECERT, open_to("rej.invalid", "reality"));
    check("refused node: no retry", 1, g_d);

    g_all_silent = 1;
    check("remembered node goes silent: a timeout", TLS13_ETIMEOUT, open_to("dpi.invalid", "reality"));
    check("remembered node goes silent: no second retry", 1, g_d);
    g_all_silent = 0;

    check("security none: the link opens", 0, open_to("ok.invalid", "none"));
    check("security none: one connection, no handshake", 10, g_d * 10 + g_h);
    check("security none behind the middlebox: no retry", 0, open_to("dpi2.invalid", "none"));
    check("security none behind the middlebox: one connection", 1, g_d);

    for (int i = 0; i < TR_NOPQ_MAX + 1; i++) {
        snprintf(h, sizeof h, "f%d.invalid", i);
        open_to(h, "reality");
    }
    check("table full: the newest node is remembered", 0, open_to("f256.invalid", "reality"));
    check("table full: the newest node takes one connection", 1, g_d);
    check("table full: the oldest node was replaced", 0, open_to("f0.invalid", "reality"));
    check("table full: the oldest node takes two connections", 2, g_d);
    check("table full: the second oldest is kept until then", 0, open_to("f2.invalid", "reality"));
    check("table full: the second oldest takes one connection", 1, g_d);
    check("table full: relearning replaced the next oldest", 0, open_to("f1.invalid", "reality"));
    check("table full: the next oldest takes two connections", 2, g_d);

    tr_nopq_ttl_s = 0;
    check("warning: the fallback succeeds", 0, open_logged("log.invalid"));
    check("warning: one line names the node", 1,
          strstr(g_err, "tunvless[warn]: node log.invalid:443 does not answer a long ClientHello") != NULL);
    check("warning: relearned after expiry", 0, open_logged("log.invalid"));
    check("warning: not repeated for the same node", 1, g_err[0] == '\0');
    tr_nopq_ttl_s = 3600;
    check("an expired entry is reused first", 0, open_to("dpi9.invalid", "reality"));
    check("an expired entry is reused first: two connections", 2, g_d);
    check("an expired entry is reused first: the oldest live entry stays", 0, open_to("f4.invalid", "reality"));
    check("the oldest live entry stays: one connection", 1, g_d);

    tr_nopq_skip_s = 300;
    check("silent on both: a timeout", TLS13_ETIMEOUT, open_to("dead2.invalid", "reality"));
    check("silent on both: two connections the first time", 2, g_d);
    check("silent on both, again: a timeout", TLS13_ETIMEOUT, open_to("dead2.invalid", "reality"));
    check("silent on both, again: no retry for 5 min", 1, g_d);
    check("silent on both, again: the long Hello is still tried", 1, g_pq);
    check("silent on both, another port: retried", TLS13_ETIMEOUT, open_at("dead2.invalid", 8443, "reality"));
    check("silent on both, another port: two connections", 2, g_d);
    check("short Hello refused, skip on: a refusal", TLS13_ETIMEOUT, open_to("camo2.invalid", "reality"));
    check("short Hello refused, skip on: retried next time", TLS13_ETIMEOUT, open_to("camo2.invalid", "reality"));
    check("short Hello refused, skip on: two connections", 2, g_d);
    for (int i = 0; i < TR_NOPQ_MAX; i++) {
        snprintf(h, sizeof h, "deadu%d.invalid", i);
        open_to(h, "reality");
    }
    open_to("dpiq.invalid", "reality");
    open_to("dpir.invalid", "reality");
    int kept = 0;
    for (int i = 2; i < TR_NOPQ_MAX; i++) {
        snprintf(h, sizeof h, "deadu%d.invalid", i);
        open_to(h, "reality");
        kept += g_d == 1;
    }
    check("useless entries are evicted oldest first, not as free slots", TR_NOPQ_MAX - 2, kept);
    tr_nopq_skip_s = 0;
    check("skip ttl 0: a timeout", TLS13_ETIMEOUT, open_to("dead3.invalid", "reality"));
    check("skip ttl 0, again: retried", TLS13_ETIMEOUT, open_to("dead3.invalid", "reality"));
    check("skip ttl 0, again: two connections", 2, g_d);

    tr_nopq_skip_s = 300;
    g_fp = "Firefox";
    /* catches: a Firefox node retried with the short Chrome Hello, or the retry's error returned */
    check("firefox, long Hello dropped: the timeout is the answer", TLS13_ETIMEOUT, open_to("dpiff.invalid", "reality"));
    check("firefox, long Hello dropped: one connection", 1, g_d);
    g_fp = "chrome";
    /* catches: a Firefox failure written to the fallback table as short or useless */
    check("firefox left no entry: chrome falls back afresh", 0, open_to("dpiff.invalid", "reality"));
    check("firefox left no entry: two connections", 2, g_d);
    /* catches: the fallback lost for Chrome along with Firefox */
    check("chrome, long Hello dropped: the short Hello gets through", 0, open_to("dpich.invalid", "reality"));
    check("chrome, long Hello dropped: two connections", 2, g_d);
    g_fp = "Firefox";
    /* catches: Firefox sent the short Hello from an entry Chrome left for the node */
    check("firefox after chrome's entry: the timeout is the answer", TLS13_ETIMEOUT, open_to("dpich.invalid", "reality"));
    check("firefox after chrome's entry: one connection", 1, g_d);
    check("firefox after chrome's entry: the Hello offers the hybrid", 1, g_pq);
    check("firefox after chrome's entry: the long Firefox Hello", 1890, (int)g_n);
    g_fp = "chrome";
    tr_nopq_skip_s = 0;

    setenv("STEER_NOPQ", "1", 1);
    check("STEER_NOPQ: a clean node opens", 0, open_to("ok.invalid", "reality"));
    check("STEER_NOPQ: no hybrid", 0, g_pq);
    check("STEER_NOPQ: a silent node times out", TLS13_ETIMEOUT, open_to("dead.invalid", "reality"));
    check("STEER_NOPQ: no retry", 1, g_d);

    /* Catches the Reality state (ephemeral key, ML-KEM key, authkey) or the ECH buffers left in memory after the handshake. */
    {
        g_fp = "chrome";
        g_st_wipes = 0;
        check("wipe: a handshake that succeeds", 0, open_to("ok.invalid", "reality"));
        check("wipe: the state wiped once after success", 1, g_st_wipes);
        g_st_wipes = 0;
        check("wipe: a handshake the server refuses", TLS13_ECERT, open_to("rej.invalid", "reality"));
        check("wipe: the state wiped once after the refusal", 1, g_st_wipes);
        g_st_wipes = 0;
        g_build_rc = REALITY_EBADKEY;
        check("wipe: a Hello that cannot be built", REALITY_EBADKEY, open_to("ok.invalid", "reality"));
        check("wipe: the state wiped once after the build failure", 1, g_st_wipes);
        g_build_rc = 0;
        struct tr_node en = { .host = "ok.invalid", .port = 443, .type = "tcp", .security = "tls",
                              .sni = "www.example.com", .fp = "chrome", .ech = "AAAA" };
        struct tr_link l;
        g_st_wipes = g_other_wipes = 0;
        check("wipe: an ECH config that does not parse", ECH_EPARSE, tr_link_open(&l, &en, NULL, 1));
        check("wipe: the ECH buffers wiped", 1, g_other_wipes);
        check("wipe: the state wiped after the ECH failure", 1, g_st_wipes);
    }
    g_fp = "chrome";
    tr_nopq_skip_s = 0;
    unsetenv("STEER_NOPQ");
    /* catches: the first of two links not retried with the short Hello after a timeout */
    check("two links, first behind the middlebox: both open", 0, open_two("dpi-2a.invalid", "ok.invalid"));
    check("two links, first behind the middlebox: three connections", 3, g_d);
    /* catches: the second of two links not retried with the short Hello after a timeout */
    check("two links, second behind the middlebox: both open", 0, open_two("ok.invalid", "dpi-2b.invalid"));
    check("two links, second behind the middlebox: three connections", 3, g_d);
    /* catches: the second handshake finished although the first was refused */
    check("two links, first refused: the refusal", TLS13_ECERT, open_two("rej.invalid", "ok.invalid"));
    check("two links, first refused: one handshake", 1, g_h);
    /* catches: the second link left open when the first is refused */
    check("two links, first refused: both closed", 1, g_fa == -1 && g_fb == -1);
    /* catches: the second link's Reality state left unwiped when the first is refused */
    check("two links, first refused: the second's state wiped", 1, g_st_wipes);
    /* catches: the first link left open when the second is refused */
    check("two links, second refused: the refusal", TLS13_ECERT, open_two("ok.invalid", "rej.invalid"));
    check("two links, second refused: the first closed once", 1, g_fa == -1 && g_fb == -1 && g_closes == 1);
    /* catches: the first link left open when the second cannot be dialled */
    check("two links, second not dialled: the dial's error", TR_ECONNECT, open_two("ok.invalid", "nodial.invalid"));
    check("two links, second not dialled: the first closed", 1, g_fa == -1 && g_fb == -1);
    check("two links, second not dialled: no handshake finished", 0, g_h);
    /* catches: a link finished although neither answered within the timeout */
    check("two links, neither answers: both open on the retry", 0, open_two("mute-a.invalid", "mute-b.invalid"));
    check("two links, neither answers: two retries, four connections, two handshakes", 42, g_d * 10 + g_h);
    /* catches: links without a handshake to finish waited on as if their answer were late */
    g_sec2 = "none";
    check("two links, security none: both open", 0, open_two("mute-c.invalid", "mute-d.invalid"));
    check("two links, security none: two connections, no handshake", 20, g_d * 10 + g_h);
    g_sec2 = "reality";
    /* catches: a timed-out link retried although the other link was refused */
    check("two links, first silent, second refused: the timeout", TLS13_ETIMEOUT, open_two("dead-2c.invalid", "rej.invalid"));
    check("two links, first silent, second refused: no retry, two connections", 2, g_d);
    check("two links, first silent, second refused: both closed", 1, g_fa == -1 && g_fb == -1);
    /* catches: the second link left open when the first stays silent after its retry */
    check("two links, first silent: the timeout", TLS13_ETIMEOUT, open_two("dead-2a.invalid", "ok.invalid"));
    check("two links, first silent: the second closed once", 1, g_fa == -1 && g_fb == -1 && g_closes == 1);
    check("two links, first silent: the first retried, three connections", 3, g_d);
    return unit_done("pqfallbackmatch");
}
