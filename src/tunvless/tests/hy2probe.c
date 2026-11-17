#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

#include "quic.h"
#include "hy2conn.h"
#include "hy2run.h"
#include "sockmark.h"

struct opt {
    char host[256];
    uint16_t port;
    const char *sni, *auth, *obfs, *ca;
    uint8_t pin[32];
    int has_pin, insecure, chacha, aes, no_batch;
    uint32_t mark;
    const char *mode;
    char thost[256];
    uint16_t tport;
    unsigned long size, count, secs, deadline;
};

static int usage(void) {
    fprintf(stderr,
            "usage: hy2probe --server <ip>:<port> --sni <name> --auth <pw> [--obfs <pw>]\n"
            "                [--pin <hex> | --insecure | --ca <pem>] [--chacha | --aes] [--no-batch] [-m <mark>]\n"
            "                [--deadline <seconds>] <mode>\n"
            "  --no-batch       no UDP GSO/GRO\n"
            "  --deadline       the whole run's time limit (default 25 s)\n"
            "modes: auth | tcp <host:port> <size> | fetch <host:port> <size> | udp <host:port> <size> <count>\n"
            "       down <host:port> <seconds> | up <host:port> <seconds>\n");
    return 2;
}

static int hostport(const char *s, char *host, size_t cap, uint16_t *port) {
    const char *c;
    size_t hl;
    if (s[0] == '[') {
        const char *e = strchr(s, ']');
        if (!e || e[1] != ':') return -1;
        hl = (size_t)(e - s - 1);
        s++;
        c = e + 1;
    } else {
        c = strrchr(s, ':');
        if (!c) return -1;
        hl = (size_t)(c - s);
    }
    if (!hl || hl >= cap) return -1;
    char *end;
    unsigned long p = strtoul(c + 1, &end, 10);
    if (*end || !c[1] || !p || p > 65535) return -1;
    memcpy(host, s, hl);
    host[hl] = 0;
    *port = (uint16_t)p;
    return 0;
}

static int num(const char *s, unsigned long *v) {
    int base = 10;
    if (s && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        base = 16;
        s += 2;
    }
    if (!s || !((*s >= '0' && *s <= '9') || (base == 16 && ((*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')))))
        return -1;
    char *end;
    *v = strtoul(s, &end, base);
    return *end ? -1 : 0;
}

static int hexpin(const char *s, uint8_t *out) {
    size_t n = 0;
    for (; *s; s++) {
        if (*s == ':') continue;
        int v;
        if (*s >= '0' && *s <= '9') v = *s - '0';
        else if (*s >= 'a' && *s <= 'f') v = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F') v = *s - 'A' + 10;
        else return -1;
        if (n >= 64) return -1;
        if (n & 1) out[n / 2] |= (uint8_t)v;
        else out[n / 2] = (uint8_t)(v << 4);
        n++;
    }
    return n == 64 ? 0 : -1;
}

static int parse(int argc, char **argv, struct opt *o) {
    memset(o, 0, sizeof *o);
    int i = 1, verify = 0, srv = 0;
    for (; i < argc && argv[i][0] == '-'; i++) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(a, "--insecure")) { o->insecure = 1; verify++; continue; }
        if (!strcmp(a, "--chacha")) { o->chacha = 1; continue; }
        if (!strcmp(a, "--aes")) { o->aes = 1; continue; }
        if (!strcmp(a, "--no-batch")) { o->no_batch = 1; continue; }
        if (!v) return -1;
        i++;
        if (!strcmp(a, "--server")) {
            if (hostport(v, o->host, sizeof o->host, &o->port) != 0) return -1;
            srv = 1;
        } else if (!strcmp(a, "--sni")) o->sni = v;
        else if (!strcmp(a, "--auth")) o->auth = v;
        else if (!strcmp(a, "--obfs")) o->obfs = v;
        else if (!strcmp(a, "--ca")) { o->ca = v; verify++; }
        else if (!strcmp(a, "--pin")) {
            if (hexpin(v, o->pin) != 0) return -1;
            o->has_pin = 1;
            verify++;
        } else if (!strcmp(a, "-m")) {
            unsigned long m;
            if (num(v, &m) != 0 || m > 0xffffffffUL) return -1;
            o->mark = (uint32_t)m;
        } else if (!strcmp(a, "--deadline")) {
            if (num(v, &o->deadline) != 0 || !o->deadline || o->deadline > 86400) return -1;
        } else return -1;
    }
    if (!srv || !o->sni || !o->auth || verify > 1 || (o->chacha && o->aes) || i >= argc) return -1;
    o->mode = argv[i++];
    int left = argc - i;
    if (!strcmp(o->mode, "auth")) return left == 0 ? 0 : -1;
    if (left < 2 || hostport(argv[i], o->thost, sizeof o->thost, &o->tport) != 0) return -1;
    if (!strcmp(o->mode, "tcp") || !strcmp(o->mode, "fetch"))
        return left == 2 && num(argv[i + 1], &o->size) == 0 && o->size ? 0 : -1;
    if (!strcmp(o->mode, "udp"))
        return left == 3 && num(argv[i + 1], &o->size) == 0 && o->size && num(argv[i + 2], &o->count) == 0 && o->count ? 0 : -1;
    if (!strcmp(o->mode, "down") || !strcmp(o->mode, "up"))
        return left == 2 && num(argv[i + 1], &o->secs) == 0 && o->secs ? 0 : -1;
    return -1;
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}

static uint64_t g_end;

static uint64_t until(uint64_t ns) {
    uint64_t e = now_ns() + ns;
    return e < g_end ? e : g_end;
}

static uint8_t pat(uint64_t i) { return (uint8_t)((i * 31 + 7) % 251); }

struct app {
    struct opt *o;
    struct hy2c *c;
    int ready, closed, reason, udp;
    uint64_t peer_rx;
    char why[200];
    int64_t sid;
    int have_sid, sclosed, show, refused, fin, finished;
    char rmsg[200];
    uint64_t got, consumed, sent, bad_at;
    int bad;
    uint8_t *msg;
    size_t msg_n;
    int msg_ok;
    uint32_t sess;
    char want_addr[300];
    unsigned long udp_other;
    struct hy2_run_stats rs;
    int (*done)(struct app *);
    const uint8_t *src;
    size_t src_n;
    int orc;
    const uint8_t *um;
};

static void cb_ready(void *u, uint64_t rx, int udp) {
    struct app *a = u;
    a->ready = 1;
    a->peer_rx = rx;
    a->udp = udp;
}

static void cb_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct app *a = u;
    if (!a->have_sid || sid != a->sid) return;
    if (!strcmp(a->o->mode, "tcp") || !strcmp(a->o->mode, "fetch"))
        for (size_t i = 0; i < n && !a->bad; i++)
            if (d[i] != pat(a->got + i)) {
                a->bad = 1;
                a->bad_at = a->got + i;
            }
    a->got += n;
    if (fin) a->fin = 1;
}

static void cb_writable(void *u, int64_t sid) { (void)u; (void)sid; }

static void cb_streams_open(void *u) { (void)u; }

static void cb_refused(void *u, int64_t sid, const char *msg) {
    struct app *a = u;
    if (!a->have_sid || sid != a->sid) return;
    a->refused = 1;
    snprintf(a->rmsg, sizeof a->rmsg, "%s", msg ? msg : "");
}

static void cb_sclose(void *u, int64_t sid, int how) {
    struct app *a = u;
    if (!a->have_sid || sid != a->sid) return;
    a->sclosed = 1;
    a->show = how;
    if (how == HY2C_END_CLEAN && a->got > a->consumed) {
        hy2c_conn_consumed(a->c, (size_t)(a->got - a->consumed));
        a->consumed = a->got;
    }
}

static const char *end_name(int how) {
    switch (how) {
    case HY2C_END_CLEAN: return "clean";
    case HY2C_END_RESET: return "reset";
    case HY2C_END_LINK: return "with the link";
    }
    return "unknown";
}

static void cb_udp(void *u, uint32_t session, const char *addr, size_t addr_n, const uint8_t *d, size_t n) {
    struct app *a = u;
    int mine = session == a->sess && addr_n == strlen(a->want_addr) && memcmp(addr, a->want_addr, addr_n) == 0;
    if (!mine) {
        a->udp_other++;
        return;
    }
    if (a->msg && n == a->msg_n && memcmp(d, a->msg, n) == 0) a->msg_ok = 1;
}

static void cb_closed(void *u, int reason, const char *why) {
    struct app *a = u;
    a->closed = 1;
    a->reason = reason;
    snprintf(a->why, sizeof a->why, "%s", why ? why : "");
}

static const struct hy2c_ops g_ops = {
    .on_ready = cb_ready,
    .on_stream_data = cb_data,
    .on_stream_writable = cb_writable,
    .on_streams_open = cb_streams_open,
    .on_stream_refused = cb_refused,
    .on_stream_close = cb_sclose,
    .on_udp = cb_udp,
    .on_closed = cb_closed,
};

static const char *reason_name(int r) {
    switch (r) {
    case QC_CLOSE_LOCAL: return "local";
    case QC_CLOSE_PEER: return "peer";
    case QC_CLOSE_IDLE: return "idle";
    case QC_CLOSE_HANDSHAKE: return "handshake";
    case QC_CLOSE_ERROR: return "error";
    case HY2C_CLOSE_AUTH: return "auth";
    }
    return "unknown";
}

static void work(struct app *a, const uint8_t *src, size_t src_n) {
    if (a->closed || !a->have_sid || a->sclosed) return;
    if (a->got > a->consumed) {
        hy2c_tcp_consumed(a->c, a->sid, (size_t)(a->got - a->consumed));
        a->consumed = a->got;
    }
    if (!src) return;
    int tcp = !strcmp(a->o->mode, "tcp");
    while (!tcp || a->sent < a->o->size) {
        size_t n = src_n;
        if (tcp) {
            n = a->o->size - a->sent < src_n ? (size_t)(a->o->size - a->sent) : src_n;
            if (n > src_n - a->sent % 251) n = src_n - a->sent % 251;
        }
        ssize_t w = hy2c_tcp_send(a->c, a->sid, src + (tcp ? a->sent % 251 : 0), n);
        if (w <= 0) break;
        a->sent += (uint64_t)w;
        if ((size_t)w < n) break;
    }
    if (tcp && a->sent == a->o->size && !a->finished && hy2c_tcp_finish(a->c, a->sid) == 0) a->finished = 1;
}

static int step(void *u) {
    struct app *a = u;
    work(a, a->src, a->src_n);
    return a->done(a);
}

static void run(struct app *a, uint64_t e, int (*done)(struct app *), const uint8_t *src, size_t src_n) {
    a->done = done;
    a->src = src;
    a->src_n = src_n;
    if (!done(a)) (void)hy2_run(a->c, e, step, a, &a->rs);
}

static int done_ready(struct app *a) { return a->ready || a->closed; }

static int done_closed(struct app *a) { return a->closed; }

static int done_never(struct app *a) { (void)a; return 0; }

static int done_open(struct app *a) {
    a->orc = hy2c_tcp_open(a->c, a->o->thost, a->o->tport, &a->sid);
    return a->orc != QC_EAGAIN || a->closed;
}

static int done_tcp(struct app *a) {
    return a->closed || a->sclosed || a->refused || a->bad || a->got >= a->o->size;
}

static int done_stream(struct app *a) { return a->closed || a->sclosed || a->refused; }

static int done_usend(struct app *a) {
    a->orc = hy2c_udp_send(a->c, a->sess, a->o->thost, a->o->tport, a->um, a->o->size);
    return a->orc != QC_EAGAIN || a->closed;
}

static int done_msg(struct app *a) { return a->msg_ok || a->closed; }

static void closed_line(struct app *a, const char *what) {
    printf("%s: closed %s: %s\n", what, reason_name(a->reason), a->why);
}

static void shut(struct app *a) {
    if (!a->closed) hy2c_close(a->c);
    run(a, now_ns() + 2000000000u, done_closed, NULL, 0);
}

static double cpu_s(const struct timeval *t) { return (double)t->tv_sec + (double)t->tv_usec / 1e6; }

static void stats_line(struct app *a) {
    struct qc_stats st;
    struct rusage ru;
    hy2c_stats(a->c, &st);
    getrusage(RUSAGE_SELF, &ru);
    printf("stats gso %d gro %d rtt_ms %.2f cwnd %llu lost %llu pkts_sent %llu pkts_recv %llu tx_calls %llu rx_calls %llu"
           " dg_rx %llu short_sleeps %llu/%llu (%.1f%%) cpu %.2f %.2f\n",
           st.gso, st.gro, (double)st.rtt_us / 1000.0, (unsigned long long)st.cwnd, (unsigned long long)st.pkt_lost,
           (unsigned long long)st.pkt_sent, (unsigned long long)st.pkt_recv, (unsigned long long)st.tx_calls,
           (unsigned long long)st.rx_calls, (unsigned long long)st.dg_rx, (unsigned long long)a->rs.short_sleeps,
           (unsigned long long)a->rs.sleeps, a->rs.sleeps ? 100.0 * (double)a->rs.short_sleeps / (double)a->rs.sleeps : 0.0,
           cpu_s(&ru.ru_utime), cpu_s(&ru.ru_stime));
}

static int open_stream(struct app *a) {
    run(a, until(10000000000u), done_open, NULL, 0);
    int rc = a->orc;
    if (rc != 0) {
        if (a->closed) closed_line(a, "open");
        else printf("open failed: %d\n", rc);
        return -1;
    }
    a->have_sid = 1;
    return 0;
}

static int run_tcp(struct app *a) {
    uint8_t src[65536 + 251];
    for (size_t i = 0; i < sizeof src; i++) src[i] = pat(i);
    if (open_stream(a) != 0) return 1;
    run(a, g_end, done_tcp, src, 65536 + 251);
    int ok = !a->bad && a->got == a->o->size;
    if (a->bad) printf("differs at offset %llu\n", (unsigned long long)a->bad_at);
    else if (ok) printf("echoed %llu ok\n", (unsigned long long)a->got);
    else if (a->refused) printf("echoed %llu of %lu: refused: %s\n", (unsigned long long)a->got, a->o->size, a->rmsg);
    else if (a->closed) printf("echoed %llu of %lu: closed %s: %s\n", (unsigned long long)a->got, a->o->size, reason_name(a->reason), a->why);
    else if (a->sclosed) printf("echoed %llu of %lu: stream closed %s\n", (unsigned long long)a->got, a->o->size, end_name(a->show));
    else printf("echoed %llu of %lu: timed out, sent %llu\n", (unsigned long long)a->got, a->o->size, (unsigned long long)a->sent);
    if (!a->closed) {
        stats_line(a);
        if (!a->sclosed) hy2c_tcp_close(a->c, a->sid);
    }
    shut(a);
    return ok ? 0 : 1;
}

static int run_fetch(struct app *a) {
    if (open_stream(a) != 0) return 1;
    run(a, g_end, done_stream, NULL, 0);
    unsigned long long n = (unsigned long long)a->got;
    int ok = 0;
    if (a->refused) printf("fetched %llu of %lu: refused: %s\n", n, a->o->size, a->rmsg);
    else if (a->bad) printf("fetched %llu of %lu: differs at offset %llu\n", n, a->o->size, (unsigned long long)a->bad_at);
    else if (a->got != a->o->size) printf("fetched %llu of %lu%s, %s%s\n", n, a->o->size, a->fin ? ", fin" : ", no fin",
                                          a->sclosed ? "closed " : "not closed", a->sclosed ? end_name(a->show) : "");
    else if (!a->fin) printf("fetched %llu ok, no fin%s%s\n", n, a->sclosed ? ", closed " : "", a->sclosed ? end_name(a->show) : "");
    else if (!a->sclosed) printf("fetched %llu ok, fin, not closed%s%s\n", n, a->closed ? ": session closed " : "", a->closed ? a->why : "");
    else if (a->show != HY2C_END_CLEAN) printf("fetched %llu ok, fin, closed %s\n", n, end_name(a->show));
    else {
        printf("fetched %llu ok closed clean\n", n);
        ok = 1;
    }
    if (!a->closed) {
        stats_line(a);
        if (!a->sclosed) hy2c_tcp_close(a->c, a->sid);
    }
    shut(a);
    return ok ? 0 : 1;
}

static int run_load(struct app *a) {
    int up = !strcmp(a->o->mode, "up");
    static uint8_t src[65536];
    for (size_t i = 0; i < sizeof src; i++) src[i] = pat(i);
    if (open_stream(a) != 0) return 1;
    uint64_t t0 = now_ns();
    run(a, until((uint64_t)a->o->secs * 1000000000u), done_stream, up ? src : NULL, sizeof src);
    double secs = (double)(now_ns() - t0) / 1e9;
    uint64_t b = up ? a->sent : a->got;
    int ok = !a->closed && !a->sclosed && !a->refused;
    if (ok) printf("bytes %llu seconds %.3f\n", (unsigned long long)b, secs);
    else if (a->closed) printf("bytes %llu seconds %.3f: closed %s: %s\n", (unsigned long long)b, secs, reason_name(a->reason), a->why);
    else printf("bytes %llu seconds %.3f: stream %s%s\n", (unsigned long long)b, secs, a->refused ? "refused: " : "closed", a->rmsg);
    if (!a->closed) {
        stats_line(a);
        if (!a->sclosed) hy2c_tcp_close(a->c, a->sid);
    }
    shut(a);
    return ok ? 0 : 1;
}

static int run_udp(struct app *a) {
    struct qc_stats st0, st;
    uint32_t sess = hy2c_udp_session(a->c);
    if (!sess) { printf("no udp session\n"); return 1; }
    a->sess = sess;
    snprintf(a->want_addr, sizeof a->want_addr, strchr(a->o->thost, ':') ? "[%s]:%u" : "%s:%u", a->o->thost,
             (unsigned)a->o->tport);
    uint8_t *m = malloc(a->o->size);
    if (!m) return 1;
    hy2c_stats(a->c, &st0);
    unsigned long ok = 0;
    int err = 0;
    for (unsigned long k = 0; k < a->o->count && !a->closed && !err; k++) {
        for (size_t i = 0; i < a->o->size; i++) m[i] = pat(k * 7 + i);
        a->msg = m;
        a->msg_n = a->o->size;
        a->msg_ok = 0;
        uint64_t e = until(1000000000u);
        a->um = m;
        run(a, e, done_usend, NULL, 0);
        int rc = a->orc;
        if (rc != 0 && rc != QC_EAGAIN) {
            printf("udp send failed: %d\n", rc);
            err = 1;
            break;
        }
        if (rc == 0) run(a, e, done_msg, NULL, 0);
        ok += a->msg_ok;
    }
    run(a, 0, done_never, NULL, 0);
    a->msg = NULL;
    hy2c_stats(a->c, &st);
    free(m);
    if (err) {
        shut(a);
        return 1;
    }
    printf("echoed %lu of %lu datagrams %llu%s%s\n", ok, a->o->count, (unsigned long long)(st.dg_rx - st0.dg_rx),
           a->closed ? ": closed " : "", a->closed ? a->why : "");
    if (a->udp_other) printf("udp: %lu replies with another session or address\n", a->udp_other);
    if (!a->closed) stats_line(a);
    hy2c_udp_end(a->c, sess);
    shut(a);
    return ok == a->o->count ? 0 : 1;
}

int main(int argc, char **argv) {
    struct opt o;
    if (parse(argc, argv, &o) != 0) return usage();
    setvbuf(stdout, NULL, _IOLBF, 0);
    struct hy2c_cfg cc;
    memset(&cc, 0, sizeof cc);
    cc.qc.host = o.host;
    cc.qc.port = o.port;
    cc.qc.sni = o.sni;
    cc.qc.insecure = o.insecure;
    cc.qc.pin_sha256 = o.has_pin ? o.pin : NULL;
    cc.qc.pin_n = o.has_pin ? 1 : 0;
    cc.qc.ca_file = o.ca;
    cc.qc.prefer_chacha = o.chacha;
    cc.qc.no_batch = o.no_batch;
    transport_set_sock_mark(o.mark);
    cc.qc.prepare = tr_sock_prepare;
    cc.auth = o.auth;
    cc.obfs_password = o.obfs;

    static struct app a;
    a.o = &o;
    int rc = hy2c_open(&cc, &g_ops, &a, &a.c);
    if (rc != 0) { printf("open failed: %d\n", rc); return 1; }
    g_end = now_ns() + (uint64_t)(o.deadline ? o.deadline : 25) * 1000000000u;
    run(&a, until(20000000000ull), done_ready, NULL, 0);
    int ret = 1;
    if (!a.ready) {
        if (a.closed) closed_line(&a, "auth");
        else printf("auth: timed out\n");
    } else if (!strcmp(o.mode, "auth")) {
        struct qc_stats st;
        hy2c_stats(a.c, &st);
        printf("ready rx %llu cipher 0x%04x gso %d gro %d rcvbuf %u sndbuf %u udp %d\n", (unsigned long long)a.peer_rx,
               st.cipher, st.gso, st.gro, st.rcvbuf, st.sndbuf, a.udp);
        shut(&a);
        ret = 0;
    } else if (!strcmp(o.mode, "tcp")) {
        ret = run_tcp(&a);
    } else if (!strcmp(o.mode, "fetch")) {
        ret = run_fetch(&a);
    } else if (!strcmp(o.mode, "udp")) {
        ret = run_udp(&a);
    } else {
        ret = run_load(&a);
    }
    hy2c_free(a.c);
    return ret;
}
