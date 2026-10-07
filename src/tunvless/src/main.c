/* tunvless: a TUN device whose TCP and UDP traffic goes to a VLESS server.
 *
 * Everything here is the command line around four pieces: the nodes (vless:// links, or files of
 * links or Xray / sing-box / Clash configs — proto/vless/sub.c), the stack that turns the device's
 * packets into flows (tunnel/stack.c), the node pool that keeps one or more of the nodes active and
 * replaces a dead one (tunnel/pool.c), and the VLESS dialer that carries each flow to its node
 * (proto/vless/vldial.c). The process lives as long as the device: a signal ends both, and the
 * kernel removes the device and every route into it when the process exits.
 *
 * Exit codes: 2 — the command line or the node is wrong (restarting will not help); 1 — the
 * tunnel did not come up or stopped carrying traffic; 0 — stopped by SIGINT, SIGTERM or SIGHUP.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/prctl.h>

#include "vless.h"
#include "vlink.h"
#include "client.h"
#include "vldial.h"
#include "stack.h"
#include "pool.h"
#include "ifcfg.h"
#include "transport.h"
#include "roots.h"
#include "control.h"
#include "nodes.h"
#include "ctlnodes.h"

#ifndef TUNVLESS_VERSION
#define TUNVLESS_VERSION "dev"
#endif

#define LOG_W "tunvless[warn]: "
#define LOG_I "tunvless[info]: "

#define ROUTES_MAX 64
#define RETRY_MAX_S 60
#define ACTIVE_MAX 64
#define CTL_ACTIVE_MAX 8
#define CTL_STDIN_MAX (1u << 20)
#define CTL_RESOLVE_MS 5000

struct route { uint32_t dst; int prefix; };

static struct {
    char **sources;
    int sources_n;
    int *want;                  /* --node: candidates in order of preference */
    size_t want_n, want_cap;
    int active, by, interval_s;
    int list, probe, no_probe, no_retry, insecure, control;
    const char *ca;
    const char *bind_dev;
    uint32_t mark;
    uint32_t table;
    int silence_s, timeout_s;
    struct tun_cfg tc;
    struct route routes[ROUTES_MAX];
    int routes_n;
} g = {
    .active = 1,
    .by = POOL_BY_CONNECTION,
    .interval_s = POOL_INTERVAL_S,
    .silence_s = POOL_SILENCE_S,
    .timeout_s = 8,
    .tc = { .dev = "tunvless0", .prefix = 32 },
};

static int g_links_only;        /* every source was a link, none a file */
static int *g_sel;              /* candidates: --node, or every node */
static size_t g_sel_n;

static void usage(FILE *f) {
    fprintf(f,
"Usage: tunvless [options] <vless://link | file | ->...\n"
"       tunvless --control [options]    nodes on stdin (one link per line, an empty line\n"
"                                       ends them), events as JSON lines on stdout\n"
"                                       then \"nodes\", links and an empty line replace\n"
"                                       them without recreating the device\n"
"\n"
"Creates a TUN device and carries its TCP and UDP traffic to VLESS servers\n"
"(Reality, TLS or none; tcp, grpc, xhttp, ws or httpupgrade; Vision; VLESS encryption).\n"
"\n"
"The nodes (every source adds its nodes, numbered from 0 in order, as --list shows):\n"
"  vless://...            a VLESS link\n"
"  file                   vless:// links (plain or base64), or an Xray, sing-box or\n"
"                         Clash config with VLESS outbounds\n"
"  -                      vless:// links on stdin, one per line (an empty line ends them)\n"
"  -n, --node N[,N...]    candidates, in order of preference; repeatable; default: every\n"
"                         node. A single one is used without a probe at startup\n"
"  -l, --list             print the usable nodes and exit\n"
"  -p, --probe            check the candidates and exit\n"
"      --no-probe         start with the first candidate without checking it\n"
"      --insecure         accept allowInsecure nodes; do not verify certificates of\n"
"                         security=tls nodes\n"
"      --ca FILE          trusted roots (PEM) for security=tls\n"
"\n"
"The device:\n"
"  -d, --dev NAME         device name (default tunvless0)\n"
"  -a, --addr CIDR        device address (default 198.51.100.1/32)\n"
"  -r, --route CIDR       route CIDR into the device once it is up; repeatable;\n"
"                         \"default\" means 0.0.0.0/1 and 128.0.0.0/1\n"
"  -T, --table N          routing table for --route (default main)\n"
"\n"
"Failover (the first candidate that answers is active at startup; a dead active node\n"
"is replaced by the next candidate that answers, without a restart):\n"
"  -A, --active N         keep N nodes active at once and spread new connections over\n"
"                         them (default 1, at most %d)\n"
"      --by MODE          how connections are spread: connection (each to a random\n"
"                         active node), site (by destination address), site-client\n"
"                         (by client and destination); default connection\n"
"      --interval S       health check period of each active node (default %d)\n"
"\n"
"Keeping the tunnel's own connections out of the tunnel (without either, a --route\n"
"that covers a candidate's server gets a host route to it through its current gateway):\n"
"  -m, --mark N           SO_MARK on sockets to the server\n"
"  -b, --bind-dev IFACE   send sockets to the server out of IFACE (SO_BINDTODEVICE)\n"
"\n"
"Other:\n"
"  -t, --timeout S        probe timeout at startup and for --probe, seconds (default 8)\n"
"      --silence S        reset a connection whose server stays silent for S seconds\n"
"                         (default 20, 0 — never)\n"
"      --no-retry         exit when no candidate resolves or none answers at startup,\n"
"                         instead of retrying\n"
"  -V, --version\n"
"  -h, --help\n", ACTIVE_MAX, POOL_INTERVAL_S);
}

static int parse_uint(const char *s, uint32_t *out) {
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 0);
    if (!*s || *end || errno || v > 0xffffffffUL) return -1;
    *out = (uint32_t)v;
    return 0;
}

static int add_route(const char *s) {
    if (!strcmp(s, "default")) return add_route("0.0.0.0/1") || add_route("128.0.0.0/1");
    if (g.routes_n >= ROUTES_MAX) {
        fprintf(stderr, "tunvless: more than %d routes\n", ROUTES_MAX);
        return -1;
    }
    struct route *r = &g.routes[g.routes_n];
    if (ifcfg_parse_cidr(s, &r->dst, &r->prefix) != 0) {
        fprintf(stderr, "tunvless: %s is not an IPv4 prefix\n", s);
        return -1;
    }
    g.routes_n++;
    return 0;
}

/* --node "3", "3,5,7"; repeatable, so the list is appended to. */
static int add_nodes(const char *s) {
    char *end;
    for (;;) {
        errno = 0;
        unsigned long v = strtoul(s, &end, 10);
        if (end == s || errno || v > 1000000 || (*end && *end != ',')) return -1;
        if (g.want_n == g.want_cap) {
            size_t cap = g.want_cap ? g.want_cap * 2 : 8;
            int *w = realloc(g.want, cap * sizeof(*w));
            if (!w) return -1;
            g.want = w;
            g.want_cap = cap;
        }
        g.want[g.want_n++] = (int)v;
        if (!*end) return 0;
        s = end + 1;
    }
}

enum { OPT_NO_PROBE = 256, OPT_INSECURE, OPT_CA, OPT_SILENCE, OPT_NO_RETRY, OPT_BY, OPT_INTERVAL, OPT_CONTROL };

static int parse_args(int argc, char **argv) {
    static const struct option opts[] = {
        { "node",     required_argument, NULL, 'n' },
        { "list",     no_argument,       NULL, 'l' },
        { "probe",    no_argument,       NULL, 'p' },
        { "no-probe", no_argument,       NULL, OPT_NO_PROBE },
        { "insecure", no_argument,       NULL, OPT_INSECURE },
        { "ca",       required_argument, NULL, OPT_CA },
        { "dev",      required_argument, NULL, 'd' },
        { "addr",     required_argument, NULL, 'a' },
        { "route",    required_argument, NULL, 'r' },
        { "table",    required_argument, NULL, 'T' },
        { "mark",     required_argument, NULL, 'm' },
        { "bind-dev", required_argument, NULL, 'b' },
        { "timeout",  required_argument, NULL, 't' },
        { "silence",  required_argument, NULL, OPT_SILENCE },
        { "no-retry", no_argument,       NULL, OPT_NO_RETRY },
        { "active",   required_argument, NULL, 'A' },
        { "by",       required_argument, NULL, OPT_BY },
        { "interval", required_argument, NULL, OPT_INTERVAL },
        { "control",  no_argument,       NULL, OPT_CONTROL },
        { "version",  no_argument,       NULL, 'V' },
        { "help",     no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    const char *addr = "198.51.100.1/32";
    uint32_t v;
    int c;
    while ((c = getopt_long(argc, argv, "n:lpd:a:r:T:m:b:t:A:Vh", opts, NULL)) != -1) {
        switch (c) {
        case 'n': if (add_nodes(optarg) != 0) goto bad; break;
        case 'l': g.list = 1; break;
        case 'p': g.probe = 1; break;
        case OPT_NO_PROBE: g.no_probe = 1; break;
        case OPT_INSECURE: g.insecure = 1; break;
        case OPT_CA: g.ca = optarg; break;
        case 'd':
            if (!optarg[0] || strlen(optarg) >= IFNAMSIZ) {
                fprintf(stderr, "tunvless: device name must be 1..%d characters\n", IFNAMSIZ - 1);
                return 2;
            }
            g.tc.dev = optarg;
            break;
        case 'a': addr = optarg; break;
        case 'r': if (add_route(optarg) != 0) return 2; break;
        case 'T': if (parse_uint(optarg, &g.table) != 0) goto bad; break;
        case 'm': if (parse_uint(optarg, &g.mark) != 0) goto bad; break;
        case 'b':
            if (!optarg[0] || strlen(optarg) >= IFNAMSIZ) goto bad;
            g.bind_dev = optarg;
            break;
        case 't':
            if (parse_uint(optarg, &v) != 0 || v == 0 || v > 600) goto bad;
            g.timeout_s = (int)v;
            break;
        case OPT_SILENCE:
            if (parse_uint(optarg, &v) != 0 || v > 3600) goto bad;
            g.silence_s = (int)v;
            break;
        case OPT_NO_RETRY: g.no_retry = 1; break;
        case 'A':
            if (parse_uint(optarg, &v) != 0 || v == 0 || v > ACTIVE_MAX) goto bad;
            g.active = (int)v;
            break;
        case OPT_BY:
            if ((g.by = pool_by_parse(optarg)) < 0) goto bad;
            break;
        case OPT_INTERVAL:
            if (parse_uint(optarg, &v) != 0 || v < 5 || v > 86400) goto bad;
            g.interval_s = (int)v;
            break;
        case OPT_CONTROL: g.control = 1; break;
        case 'V': printf("tunvless %s\n", TUNVLESS_VERSION); exit(0);
        case 'h': usage(stdout); exit(0);
        default: usage(stderr); return 2;
        }
    }
    if (g.control) {
        if (optind < argc) {
            fprintf(stderr, LOG_W "--control takes nodes on stdin, not as arguments\n");
            return 2;
        }
        if (g.list || g.probe) {
            fprintf(stderr, LOG_W "--control does not combine with --list or --probe\n");
            return 2;
        }
        if (g.active > CTL_ACTIVE_MAX) {
            fprintf(stderr, LOG_W "--control allows at most %d active nodes\n", CTL_ACTIVE_MAX);
            return 2;
        }
    } else if (optind >= argc) { usage(stderr); return 2; }
    g.sources = argv + optind;
    g.sources_n = argc - optind;
    if (ifcfg_parse_cidr(addr, &g.tc.addr, &g.tc.prefix) != 0) {
        fprintf(stderr, "tunvless: --addr %s is not an IPv4 address\n", addr);
        return 2;
    }
    return 0;
bad:
    fprintf(stderr, "tunvless: bad option value: %s\n", optarg);
    return 2;
}

/* ---- the nodes ------------------------------------------------------------------------ */

static const struct vless_node *vnode(int i) { return node_at(i); }

static int append_nodes(const struct vless_node *n, size_t cnt, const char *key) {
    for (size_t i = 0; i < cnt; i++)
        if (nodes_add(&n[i], key) < 0) {
            fprintf(stderr, "tunvless: no room for %zu nodes\n", (size_t)nodes_count() + cnt - i);
            return 1;
        }
    return 0;
}

static int load_link(const char *src) {
    struct vless_node n;
    memset(&n, 0, sizeof(n));
    int r = vless_parse_url(src, &n);
    if (r < 0) {
        fprintf(stderr, "tunvless: not a vless:// link: %.64s\n", src);
        return 2;
    }
    if (r > 0) {
        fprintf(stderr, "tunvless: link %s cannot be used: %s\n", n.name, n.skip_reason);
        return 2;
    }
    return append_nodes(&n, 1, NULL);
}

static int load_file(const char *src) {
    struct vless_sub_stats st;
    size_t cnt = 0;
    struct vless_node *n = vless_load_sub(src, &cnt, &st);
    if (!n) {
        fprintf(stderr, "tunvless: %s cannot be read\n", src);
        return 2;
    }
    if (cnt == 0 || st.skipped)
        fprintf(stderr, "%s%s: %zu usable VLESS nodes (skipped %zu, other protocols %zu)\n",
                cnt ? LOG_I : LOG_W, src, cnt, st.skipped, st.foreign);
    for (size_t i = 0; i < st.reasons_n; i++)
        fprintf(stderr, "%s  %s — %zu node(s)%s%s\n", cnt ? LOG_I : LOG_W, st.reasons[i].reason,
                st.reasons[i].count, st.reasons[i].example[0] ? ", e.g. " : "",
                st.reasons[i].example);
    int rc = append_nodes(n, cnt, NULL);
    free(n);
    return rc;
}

static int load_stdin_nodes(void) {
    char *line = NULL;
    size_t cap = 0, total = 0, lineno = 0;
    ssize_t len;
    while ((len = getline(&line, &cap, stdin)) > 0) {
        total += (size_t)len;
        if (total > CTL_STDIN_MAX) {
            fprintf(stderr, LOG_W "nodes on stdin exceed %u bytes\n", CTL_STDIN_MAX);
            free(line);
            return 2;
        }
        lineno++;
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = 0;
        if (len == 0) break;
        struct vless_node n;
        memset(&n, 0, sizeof(n));
        int r = vless_parse_url(line, &n);
        if (r < 0) {
            fprintf(stderr, LOG_W "line %zu: not a vless:// link\n", lineno);
            continue;
        }
        if (r > 0) {
            fprintf(stderr, LOG_W "line %zu: link cannot be used: %s\n", lineno, n.skip_reason);
            continue;
        }
        if (g.control) vless_name_cut(n.name);
        if (append_nodes(&n, 1, g.control ? line : NULL) != 0) { free(line); return 1; }
    }
    free(line);
    return 0;
}

/* Every source, then the candidates: --node in its order (repeats dropped), or every node. */
static int load_nodes(void) {
    g_links_only = 1;
    nodes_init(sizeof(struct vless_node));
    if (g.control) {
        int rc = load_stdin_nodes();
        if (rc) return rc;
    }
    for (int i = 0; i < g.sources_n && !g.control; i++) {
        const char *src = g.sources[i];
        int link = !strncmp(src, "vless://", 8), in = !strcmp(src, "-");
        if (!link && !in) g_links_only = 0;
        int rc = in ? load_stdin_nodes() : link ? load_link(src) : load_file(src);
        if (rc) return rc;
    }
    int cnt = nodes_count();
    if (!cnt) {
        fprintf(stderr, "tunvless: no usable VLESS node\n");
        return 2;
    }
    g_sel = calloc(g.want_n ? g.want_n : (size_t)cnt, sizeof(*g_sel));
    if (!g_sel) return 1;
    if (!g.want_n) {
        for (int i = 0; i < cnt; i++) g_sel[g_sel_n++] = i;
        return 0;
    }
    for (size_t i = 0; i < g.want_n; i++) {
        int n = g.want[i], dup = 0;
        if (n >= cnt) {
            fprintf(stderr, "tunvless: there is no node %d (usable nodes: %d)\n", n, cnt);
            return 2;
        }
        for (size_t j = 0; j < g_sel_n && !dup; j++) dup = g_sel[j] == n;
        if (!dup) g_sel[g_sel_n++] = n;
    }
    return 0;
}

static int cmd_list(void) {
    for (int i = 0; i < nodes_count(); i++) {
        const struct vless_node *n = vnode(i);
        printf("%d\t%s\t%s:%u\t%s/%s%s%s\n", i, n->name, n->host, n->port, n->type, n->security,
               n->flow[0] ? " vision" : "", n->encryption ? " encryption" : "");
    }
    return 0;
}

/* --probe: the same check as at startup, with timings. */
static int cmd_probe(void) {
    int found = 0;
    for (size_t k = 0; k < g_sel_n; k++) {
        int i = g_sel[k];
        char why[256] = "";
        int hs = -1, ttfb = -1;
        int rc = vless_probe_timed(vnode(i), g.timeout_s, why, sizeof(why), &hs, &ttfb);
        if (rc == 0) {
            found = 1;
            printf("%d\t%s\tok\thandshake %d ms, first byte %d ms\n", i, vnode(i)->name, hs, ttfb);
        } else {
            printf("%d\t%s\tfailed\t%s\n", i, vnode(i)->name, why);
        }
        fflush(stdout);
    }
    return found ? 0 : 1;
}

/* Wait before the next attempt: 5 s, doubling up to a minute. 0 — do not retry. */
static int retry_wait(unsigned *step, const char *what) {
    if (g.no_retry) return 0;
    fprintf(stderr, LOG_I "%s — next attempt in %u s\n", what, *step);
    ctl_emit_no_node((int)*step);
    sleep(*step);
    *step = *step * 2 > RETRY_MAX_S ? RETRY_MAX_S : *step * 2;
    return 1;
}

/* A single candidate named by the person (one --node, or one link and nothing else) is used
 * without a probe at startup; the pool checks it as soon as the device is up. */
static int named(void) {
    return g_sel_n == 1 && (g.want_n || g_links_only);
}

/* Resolve every candidate's name once, before any route points into the device (trdial.c says
 * why). A candidate whose name does not resolve is left out: the pool could not reach it later
 * without a DNS query that may itself go into the tunnel. -1 — none resolves. */
static int pin_candidates(void) {
    unsigned step = 5;
    char *ok = calloc(g_sel_n, 1);
    if (!ok) return -1;
    for (;;) {
        size_t n_ok = 0;
        const char *failed = NULL;
        for (size_t k = 0; k < g_sel_n; k++) {
            int rc = transport_pin_host(vnode(g_sel[k])->host);
            ok[k] = rc > 0 ? 1 : rc == TR_EPINFULL ? 2 : 0;
            if (ok[k] == 1) n_ok++;
            else failed = vnode(g_sel[k])->host;
        }
        if (n_ok) {
            size_t w = 0;
            for (size_t k = 0; k < g_sel_n; k++) {
                if (ok[k] != 1) {
                    const struct vless_node *n = vnode(g_sel[k]);
                    if (ok[k] == 2)
                        fprintf(stderr, LOG_W "node %s: the pin table is full — left out of the "
                                        "candidates\n", n->name);
                    else
                        fprintf(stderr, LOG_W "node %s: %s does not resolve — left out of the "
                                        "candidates\n", n->name, n->host);
                    continue;
                }
                g_sel[w++] = g_sel[k];
            }
            g_sel_n = w;
            free(ok);
            return 0;
        }
        char what[192];
        if (g_sel_n == 1) snprintf(what, sizeof(what), "%s does not resolve", failed);
        else snprintf(what, sizeof(what), "no candidate's name resolves (%s, ...)", failed);
        if (!retry_wait(&step, what)) {
            fprintf(stderr, LOG_W "%s\n", what);
            free(ok);
            return -1;
        }
    }
}

/* The node to bring the device up with: a named one, or with --no-probe the first candidate, as it
 * is; otherwise the first candidate that answers a probe. -1 — none. *checked — it was probed. */
static int choose_node(int *checked) {
    *checked = 0;
    if (named() || g.no_probe) return g_sel[0];
    unsigned step = 5;
    for (;;) {
        for (size_t k = 0; k < g_sel_n; k++) {
            const struct vless_node *n = vnode(g_sel[k]);
            char why[256] = "";
            if (vless_probe(n, g.timeout_s, why, sizeof(why)) == 0) {
                fprintf(stderr, LOG_I "chose %s (%s)\n", n->name, why);
                *checked = 1;
                return g_sel[k];
            }
            fprintf(stderr, LOG_I "%s — %s\n", n->name, why);
        }
        if (!retry_wait(&step, "no node answered")) return -1;
    }
}

/* The pool's view of a node. */
static int pool_probe(const void *node, int timeout_s, char *why, size_t why_n) {
    return vless_probe(node, timeout_s, why, why_n);
}
static const char *pool_name(const void *node) {
    return ((const struct vless_node *)node)->name;
}

/* ---- routes --------------------------------------------------------------------------- */

/* Host routes added for the servers (keep_server_out). Unlike the routes into the device, they go
 * through a real interface and would outlive the process, so they are removed on the way out. */
static struct kept { uint32_t dst, gw; unsigned oif; } *g_kept;
static int g_kept_n, g_kept_cap;
static pthread_mutex_t g_kept_mu = PTHREAD_MUTEX_INITIALIZER;

static void kept_remove(void) {
    pthread_mutex_lock(&g_kept_mu);
    for (int i = 0; i < g_kept_n; i++)
        ifcfg_route_unvia(g_kept[i].dst, g_kept[i].gw, g_kept[i].oif, g.table);
    g_kept_n = 0;
    pthread_mutex_unlock(&g_kept_mu);
}

static int covered(uint32_t a, const struct route *r) {
    uint32_t mask = r->prefix ? htonl(~0u << (32 - r->prefix)) : 0;
    return (a & mask) == (r->dst & mask);
}

/* Server addresses of every candidate, each once: the pool may move to any of them. */
static int server_addrs(uint32_t **out) {
    int n = 0, cap = 0;
    uint32_t *all = NULL;
    for (size_t k = 0; k < g_sel_n; k++) {
        uint32_t a[16];
        int an = transport_pinned_addrs(vnode(g_sel[k])->host, a, 16);
        for (int i = 0; i < an; i++) {
            int dup = 0;
            for (int j = 0; j < n && !dup; j++) dup = all[j] == a[i];
            if (dup) continue;
            if (n == cap) {
                cap = cap ? cap * 2 : 16;
                uint32_t *p = realloc(all, (size_t)cap * sizeof(*p));
                if (!p) { *out = all; return n; }
                all = p;
            }
            all[n++] = a[i];
        }
    }
    *out = all;
    return n;
}

/* Add a host route and record it, under one lock: a stop in between would otherwise leave it. */
static int kept_add(uint32_t dst, uint32_t gw, unsigned oif) {
    int rc = 0;
    pthread_mutex_lock(&g_kept_mu);
    if (g_kept_n == g_kept_cap) {
        int cap = g_kept_cap ? g_kept_cap * 2 : 16;
        struct kept *p = realloc(g_kept, (size_t)cap * sizeof(*p));
        if (p) { g_kept = p; g_kept_cap = cap; }
        else rc = -ENOMEM;
    }
    if (rc == 0) rc = ifcfg_route_via(dst, gw, oif, g.table);
    if (rc == 0) g_kept[g_kept_n++] = (struct kept){ dst, gw, oif };
    pthread_mutex_unlock(&g_kept_mu);
    return rc;
}

/* Without --mark and --bind-dev, sockets to the servers follow the routing table, so a route that
 * covers a server would send the tunnel's own connections into the tunnel. Such addresses keep the
 * route they have now, as a host route next to ours. */
static void keep_server_out(void) {
    uint32_t *addrs;
    int k = server_addrs(&addrs);
    for (int i = 0; i < k; i++) {
        int hit = 0;
        for (int j = 0; j < g.routes_n && !hit; j++) hit = covered(addrs[i], &g.routes[j]);
        if (!hit) continue;
        char a[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addrs[i], a, sizeof(a));
        uint32_t gw;
        unsigned oif;
        int rc = ifcfg_route_get(addrs[i], &gw, &oif);
        if (rc == 1) continue;                  /* an address of this machine */
        if (rc == 0) rc = kept_add(addrs[i], gw, oif);
        /* The table already has a host route for the server (the person's own): it stands, and it
         * is not ours to remove. */
        if (rc == -EEXIST) {
            fprintf(stderr, LOG_I "server %s already has a host route — left as it is\n", a);
            continue;
        }
        if (rc != 0)
            fprintf(stderr, LOG_W "server %s is covered by --route, and its own route was not kept "
                            "(%s) — use --bind-dev or --mark\n", a, strerror(-rc));
        else
            fprintf(stderr, LOG_I "server %s keeps its route outside the tunnel\n", a);
    }
    free(addrs);
}

static void *ctl_thread(void *arg) {
    (void)arg;
    ctln_read(stdin);
    return NULL;
}

static void ctl_start(void) {
    static const struct ctln_hooks h = {
        .select = pool_select, .ack = ctl_emit_nodes, .pins_full = ctl_emit_pins_full,
        .resolve_ms = CTL_RESOLVE_MS,
    };
    int err = ctln_start(&h);
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    if (!err) err = pthread_create(&t, &a, ctl_thread, NULL);
    pthread_attr_destroy(&a);
    if (err) fprintf(stderr, LOG_W "no stdin thread (%s) — nodes cannot be replaced\n", strerror(err));
}

static void on_ready(void *arg, const char *dev) {
    (void)arg;
    if (g.routes_n && !g.mark && !g.bind_dev) keep_server_out();
    int ok = 0;
    for (int i = 0; i < g.routes_n; i++) {
        int rc = ifcfg_route_add(dev, g.routes[i].dst, g.routes[i].prefix, g.table);
        char a[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g.routes[i].dst, a, sizeof(a));
        if (rc != 0)
            fprintf(stderr, LOG_W "route %s/%d into %s not added: %s\n", a, g.routes[i].prefix,
                    dev, strerror(-rc));
        else
            ok++;
    }
    if (g.routes_n)
        fprintf(stderr, LOG_I "%s: %d of %d routes added%s\n", dev, ok, g.routes_n,
                g.table ? " (table set with --table)" : "");
    ctl_emit_ready(dev);
    if (g.control) ctl_start();
}

/* ---- stopping ------------------------------------------------------------------------- */

/* SIGINT, SIGTERM and SIGHUP are blocked in every thread (the stack's threads inherit the mask) and
 * taken by this one: it removes the server's host routes and ends the process. The device and the
 * routes into it go with the process. */
static sigset_t g_stop_set;

static void *stop_waiter(void *arg) {
    (void)arg;
    int sig = 0;
    if (sigwait(&g_stop_set, &sig) != 0) return NULL;
    fprintf(stderr, LOG_I "signal %d: stopping\n", sig);
    kept_remove();
    _exit(0);
}

static void stop_on_signals(void) {
    sigemptyset(&g_stop_set);
    sigaddset(&g_stop_set, SIGINT);
    sigaddset(&g_stop_set, SIGTERM);
    sigaddset(&g_stop_set, SIGHUP);
    pthread_sigmask(SIG_BLOCK, &g_stop_set, NULL);
    pthread_t t;
    if (pthread_create(&t, NULL, stop_waiter, NULL) == 0) {
        pthread_detach(t);
    } else {
        /* No thread to take them: leave the signals to their default action. */
        pthread_sigmask(SIG_UNBLOCK, &g_stop_set, NULL);
    }
}

int main(int argc, char **argv) {
    /* A write to a socket the server has already closed must be an error, not the end of the
     * process (and of every other connection with it). */
    signal(SIGPIPE, SIG_IGN);
    int rc = parse_args(argc, argv);
    if (rc) return rc;
    ctl_init(g.control);
    if (g.control) {
        ctl_close_inherited_fds();
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() == 1) _exit(1);
    }

    /* Before the nodes are parsed: whether allowInsecure nodes are usable depends on it. */
    vless_set_insecure(g.insecure);
    if (g.ca) tls_set_cert_roots(g.ca);
    /* Before the first connection, so probes go the way the tunnel will. */
    transport_set_sock_mark(g.mark, g.mark != 0);
    transport_set_bind_dev(g.bind_dev);

    rc = load_nodes();
    if (rc) return rc;
    if (g.list) return cmd_list();
    if (g.probe) return cmd_probe();

    stop_on_signals();
    fprintf(stderr, LOG_I "tunvless %s\n", TUNVLESS_VERSION);
    if (g.insecure)
        fprintf(stderr, LOG_W "--insecure: certificates of security=tls nodes are NOT verified\n");
    if (pin_candidates() != 0) {
        ctl_emit_no_node(0);
        return 1;
    }
    int checked;
    int first = choose_node(&checked);
    if (first < 0) {
        fprintf(stderr, LOG_W "no node answered\n");
        ctl_emit_no_node(0);
        return 1;
    }
    static const struct pool_proto proto = {
        .ops = &vless_dialer, .probe = pool_probe, .name = pool_name,
    };
    struct pool_cfg pc = {
        .proto = &proto,
        .node = node_at,
        .sel = g_sel,
        .sel_n = g_sel_n,
        .first = first,
        .checked = checked,
        .active = g.active,
        .by = g.by,
        .interval_s = g.interval_s,
        .silence_s = g.silence_s,
    };
    rc = vless_tunnel_run(&g.tc, &pc, on_ready, NULL);
    kept_remove();
    return rc;
}
