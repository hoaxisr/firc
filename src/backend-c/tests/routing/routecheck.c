#define _GNU_SOURCE /* NOLINT(bugprone-reserved-identifier) */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "firc/dnspipeline.h"
#include "firc/dnsproxy.h"
#include "firc/fakeip.h"
#include "firc/ipset_to_link.h"
#include "firc/log.h"
#include "firc/mark.h"
#include "firc/match.h"
#include "firc/models.h"
#include "firc/netfilter_cleaner.h"
#include "firc/pool_reject.h"
#include "firc/ruleset.h"
#include "firc/rulesnap.h"
#include "firc/setnl.h"
#include "firc/xtables.h"
#include "../../src/xtables/xt_internal.h"
#include "xt_golden.h"

static int addr_of(const char *ip, const char *port, struct sockaddr_storage *sa, socklen_t *len)
{
    memset(sa, 0, sizeof(*sa));
    struct sockaddr_in *a4 = (struct sockaddr_in *)sa;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)sa;
    if (inet_pton(AF_INET, ip, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons((uint16_t)atoi(port));
        *len = sizeof(*a4);
        return 0;
    }
    if (inet_pton(AF_INET6, ip, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons((uint16_t)atoi(port));
        *len = sizeof(*a6);
        return 0;
    }
    return -1;
}

static const char *addr_text(const struct sockaddr_storage *sa, char *buf, size_t n)
{
    const void *a = sa->ss_family == AF_INET6 ? (const void *)&((const struct sockaddr_in6 *)sa)->sin6_addr
                                              : (const void *)&((const struct sockaddr_in *)sa)->sin_addr;
    return inet_ntop(sa->ss_family, a, buf, (socklen_t)n) != NULL ? buf : "?";
}

static int do_send(const char *ip, const char *port, const char *mark_hex, const char *sport)
{
    const firc_dnsproxy_sock_ops_t *ops = &firc_dnsproxy_sock_ops_real;
    struct sockaddr_storage dst;
    socklen_t dl = 0;
    if (addr_of(ip, port, &dst, &dl) != 0) { return 3; }
    uint32_t mark = (uint32_t)strtoul(mark_hex, NULL, 16);
    int fd = ops->open(ops->ud, dst.ss_family, SOCK_DGRAM | SOCK_CLOEXEC);
    if (fd < 0) { perror("socket"); return 3; }
    if (mark != 0 && ops->set_mark(ops->ud, fd, mark) != 0) {
        printf("mark-refused\n");
        return 2;
    }
    if (sport != NULL) {
        struct sockaddr_storage from;
        socklen_t froml = 0;
        int one = 1;
        if (addr_of(dst.ss_family == AF_INET6 ? "::" : "0.0.0.0", sport, &from, &froml) != 0 ||
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
            bind(fd, (struct sockaddr *)&from, froml) != 0) {
            perror("bind");
            return 3;
        }
    }
    if (ops->connect(ops->ud, fd, (struct sockaddr *)&dst, dl) != 0) {
        printf("src=none reply=no\n");
        return 0;
    }
    struct sockaddr_storage src;
    socklen_t sl = sizeof(src);
    char sb[INET6_ADDRSTRLEN];
    const char *s = getsockname(fd, (struct sockaddr *)&src, &sl) == 0 ? addr_text(&src, sb, sizeof(sb)) : "?";
    (void)ops->send(ops->ud, fd, "firc", 4, MSG_NOSIGNAL);
    struct pollfd p = {.fd = fd, .events = POLLIN};
    char buf[16];
    bool replied = poll(&p, 1, 1000) == 1 && recv(fd, buf, sizeof(buf), 0) == 4;
    printf("src=%s reply=%s\n", s, replied ? "yes" : "no");
    close(fd);
    return 0;
}

static int do_serve(const char *ip, const char *port, const char *tag)
{
    struct sockaddr_storage at;
    socklen_t al = 0;
    if (addr_of(ip, port, &at, &al) != 0) { return 3; }
    int fd = socket(at.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&at, al) != 0) { perror("bind"); return 3; }
    for (;;) {
        char buf[512];
        struct sockaddr_storage from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n <= 0) { continue; }
        if (tag != NULL) {
            (void)sendto(fd, tag, strlen(tag), 0, (struct sockaddr *)&from, fl);
        } else {
            (void)sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&from, fl);
        }
    }
}

static int do_ask(const char *ip, const char *port)
{
    struct sockaddr_storage dst;
    socklen_t dl = 0;
    if (addr_of(ip, port, &dst, &dl) != 0) { return 3; }
    int fd = socket(dst.ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return 3; }
    if (connect(fd, (struct sockaddr *)&dst, dl) != 0) {
        printf("from=none\n");
        close(fd);
        return 0;
    }
    (void)send(fd, "firc", 4, MSG_NOSIGNAL);
    struct pollfd p = {.fd = fd, .events = POLLIN};
    char buf[64];
    ssize_t n = poll(&p, 1, 2000) == 1 ? recv(fd, buf, sizeof(buf) - 1, 0) : -1;
    if (n > 0) {
        buf[n] = '\0';
        printf("from=%s\n", buf);
    } else {
        printf("from=none\n");
    }
    close(fd);
    return 0;
}

typedef struct {
    const char *name;
    uint32_t mark;
} pol_t;
static pol_t g_pol[8];
static size_t g_npol;

typedef struct {
    const char *name;
    firc_ip_t net;
    uint8_t prefix;
} seg_t;
static seg_t g_seg[8];
static size_t g_nseg;
static firc_ipv4_subnet_t g_sub[8];
static size_t g_nsub;

static firc_err_t arg_nets(const char *policy, bool deny, firc_devsel_net_fn cb, void *cb_ud, void *ud)
{
    (void)deny;
    (void)ud;
    for (size_t i = 0; i < g_nseg; i++) {
        if (strcmp(g_seg[i].name, policy) == 0) { cb(&g_seg[i].net, g_seg[i].prefix, cb_ud); }
    }
    return FIRC_OK;
}

static bool arg_mark(const char *policy, uint32_t *mark, void *ud)
{
    (void)ud;
    for (size_t i = 0; i < g_npol; i++) {
        if (strcmp(g_pol[i].name, policy) == 0) {
            *mark = g_pol[i].mark;
            return true;
        }
    }
    return false;
}

static int push_entry(char ***list, size_t *n, const char *text)
{
    char **grown = realloc(*list, (*n + 1) * sizeof(*grown));
    if (grown == NULL) { return -1; }
    *list = grown;
    grown[*n] = strdup(text);
    if (grown[*n] == NULL) { return -1; }
    (*n)++;
    return 0;
}

static firc_fakeip_cfg_t routing_pool_cfg(void)
{
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4;
    c.v4.base.b[0] = 198;
    c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15;
    c.v4.chunk_cidr = 24;
    c.v6.base.len = 16;
    c.v6.base.b[0] = 0xfd;
    c.v6.base.b[1] = 0x37;
    c.v6.pool_cidr = 48;
    c.v6.chunk_cidr = 64;
    c.max_names = 64;
    c.idle_secs = 86400;
    c.clamp_secs = 300;
    return c;
}

static int open_sets(firc_setnl_t **out)
{
    firc_setnl_caps_t caps;
    firc_err_t err = firc_setnl_new(out);
    if (err == FIRC_OK) { err = firc_setnl_probe(*out, &caps); }
    if (err == FIRC_OK && !caps.has_type) { err = FIRC_ERR_NOSYS; }
    if (err == FIRC_OK) { return 0; }
    firc_setnl_free(*out);
    *out = NULL;
    if (err == FIRC_ERR_NOSYS) { return 77; }
    fprintf(stderr, "ip_set: %s\n", firc_err_str(err));
    return 3;
}

static int stage_bare_set(const char *chain)
{
    firc_nf_prefix_t v[sizeof(g_sub) / sizeof(g_sub[0])];
    size_t n = 0;
    for (size_t i = 0; i < g_nsub; i++) {
        if (!firc_subnet4_is_bare(&g_sub[i])) { continue; }
        memset(&v[n], 0, sizeof(v[n]));
        v[n].family = 4;
        v[n].cidr = g_sub[i].cidr;
        memcpy(v[n].addr, g_sub[i].addr, 4);
        n++;
    }
    if (n == 0) { return 0; }
    char live[FIRC_SET_NAME_MAX], scratch[FIRC_SET_NAME_MAX];
    if (firc_ipset_to_link_set_name_of(chain, 4, false, live, sizeof(live)) != FIRC_OK ||
        firc_ipset_to_link_set_name_of(chain, 4, true, scratch, sizeof(scratch)) != FIRC_OK) {
        return 3;
    }
    firc_setnl_t *sets = NULL;
    int rc = open_sets(&sets);
    if (rc != 0) { return rc; }
    firc_err_t err = firc_setnl_replace(sets, live, scratch, 4, v, n);
    firc_setnl_free(sets);
    if (err != FIRC_OK) {
        fprintf(stderr, "ip_set %s: %s\n", live, firc_err_str(err));
        return 3;
    }
    return 0;
}

static int do_unset(const char *name)
{
    firc_setnl_t *sets = NULL;
    int rc = open_sets(&sets);
    if (rc != 0) { return rc == 77 ? 0 : rc; }
    firc_err_t err = firc_setnl_destroy(sets, name);
    firc_setnl_free(sets);
    if (err != FIRC_OK) {
        fprintf(stderr, "unset %s: %s\n", name, firc_err_str(err));
        return 3;
    }
    return 0;
}

static int do_devchain(int argc, char **argv)
{
    char *end = NULL;
    uint32_t field = (uint32_t)strtoul(argv[2], &end, 10), mark = 0;
    if (end == argv[2] || *end != '\0' || !firc_mark_for_field(field, &mark) || (argc - 3) % 2 != 0) {
        fprintf(stderr,
                "usage: devchain <field 1-255> [policy NAME=HEX | segment NAME=CIDR | subnet CIDR | allow ENTRY | deny ENTRY]...\n");
        return 64;
    }
    firc_group_t *g = firc_group_new();
    if (g == NULL) { return 3; }
    for (int i = 3; i + 1 < argc; i += 2) {
        if (strcmp(argv[i], "policy") == 0) {
            char *eq = strchr(argv[i + 1], '=');
            if (eq == NULL) {
                fprintf(stderr, "devchain: policy wants NAME=HEX, got \"%s\"\n", argv[i + 1]);
                return 64;
            }
            if (g_npol == sizeof(g_pol) / sizeof(g_pol[0])) {
                fprintf(stderr, "devchain: at most %zu policies\n", sizeof(g_pol) / sizeof(g_pol[0]));
                return 64;
            }
            *eq = '\0';
            g_pol[g_npol].name = argv[i + 1];
            g_pol[g_npol].mark = (uint32_t)strtoul(eq + 1, NULL, 16);
            g_npol++;
        } else if (strcmp(argv[i], "segment") == 0) {
            char *eq = strchr(argv[i + 1], '=');
            if (eq == NULL || g_nseg == sizeof(g_seg) / sizeof(g_seg[0]) ||
                !firc_ip_parse_cidr(eq + 1, &g_seg[g_nseg].net, &g_seg[g_nseg].prefix)) {
                fprintf(stderr, "devchain: segment wants NAME=CIDR (at most %zu), got \"%s\"\n",
                        sizeof(g_seg) / sizeof(g_seg[0]), argv[i + 1]);
                return 64;
            }
            *eq = '\0';
            g_seg[g_nseg++].name = argv[i + 1];
        } else if (strcmp(argv[i], "subnet") == 0) {
            if (g_nsub == sizeof(g_sub) / sizeof(g_sub[0]) || !firc_rule_parse_subnet4(argv[i + 1], &g_sub[g_nsub])) {
                fprintf(stderr, "devchain: subnet wants CIDR (at most %zu), got \"%s\"\n",
                        sizeof(g_sub) / sizeof(g_sub[0]), argv[i + 1]);
                return 64;
            }
            g_nsub++;
        } else if (strcmp(argv[i], "allow") == 0) {
            if (push_entry(&g->devices.allow, &g->devices.n_allow, argv[i + 1]) != 0) { return 3; }
        } else if (strcmp(argv[i], "deny") == 0) {
            if (push_entry(&g->devices.deny, &g->devices.n_deny, argv[i + 1]) != 0) { return 3; }
        } else {
            fprintf(stderr, "devchain: unknown word \"%s\"\n", argv[i]);
            return 64;
        }
    }
    int staged = stage_bare_set("FIRCSEL");
    if (staged != 0) {
        firc_group_free(g);
        return staged;
    }
    firc_ruleset_lookup_t lk = {arg_mark, NULL, NULL, arg_nets, NULL, NULL};
    firc_nf_devices_t dev;
    if (firc_ruleset_render_devices(g, &lk, &dev) != FIRC_OK) { return 3; }

    firc_fakeip_cfg_t c = routing_pool_cfg();
    firc_fakeip_t *pool = NULL;
    firc_ip_t v4, v6;
    if (firc_fakeip_new(&c, &pool) != FIRC_OK ||
        firc_fakeip_get(pool, "selector.test", "g", 1000, &v4, &v6) != FIRC_OK) {
        return 3;
    }
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    if (snap == NULL) { return 3; }
    firc_xt_t *xt = firc_xt_real_new(FIRC_IPT_PROTO_IPV4);
    if (xt == NULL) {
        perror("x_tables raw socket");
        return 3;
    }
    firc_ipt_t *ipt = firc_ipt_new(xt, "FIRC");
    if (ipt == NULL) { return 3; }
    char fake[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, v4.b, fake, sizeof(fake));
    printf("# fake %s\n", fake);
    firc_err_t err = firc_netfilter_register_base_chains(ipt, NULL);
    if (err == FIRC_OK) { err = firc_ipset_to_link_build_rules_dev(ipt, "FIRCSEL", "tun0", mark, field, snap, "g", &dev); }
    if (err == FIRC_OK) {
        err = firc_ipset_to_link_build_subnet_rules_dev(ipt, "FIRCSEL", mark, g_sub, g_nsub, NULL, 0, &dev);
    }
    if (err == FIRC_OK) { err = firc_ipt_commit(ipt); }
    fflush(stdout);
    firc_ipt_free(ipt);
    firc_fakeip_snapshot_free(snap);
    firc_fakeip_free(pool);
    firc_nf_devices_clear(&dev);
    firc_group_free(g);
    if (err != FIRC_OK) {
        fprintf(stderr, "devchain: %s\n", firc_err_str(err));
        return 3;
    }
    return 0;
}

#define SETS_CHAIN "FIRCNET"
#define SETS_FIELD 5

static const char *const sets_first4[] = {"10.77.0.0/16", "192.0.2.0/24"};
static const char *const sets_then4[] = {"10.78.0.0/16"};
static const char *const sets_v6[] = {"2001:db8::/32"};

static int sets_fill(firc_setnl_t *s, uint8_t family, const char *const *cidrs, size_t n)
{
    firc_nf_prefix_t v[2];
    if (n > sizeof(v) / sizeof(v[0])) { return 3; }
    for (size_t i = 0; i < n; i++) {
        firc_ip_t net;
        uint8_t len = 0;
        if (!firc_ip_parse_cidr(cidrs[i], &net, &len)) { return 3; }
        memset(&v[i], 0, sizeof(v[i]));
        v[i].family = family;
        v[i].cidr = len;
        memcpy(v[i].addr, net.b, family == 6 ? 16 : 4);
    }
    char live[FIRC_SET_NAME_MAX], scratch[FIRC_SET_NAME_MAX];
    if (firc_ipset_to_link_set_name_of(SETS_CHAIN, family, false, live, sizeof(live)) != FIRC_OK ||
        firc_ipset_to_link_set_name_of(SETS_CHAIN, family, true, scratch, sizeof(scratch)) != FIRC_OK) {
        return 3;
    }
    firc_err_t err = firc_setnl_replace(s, live, scratch, family, v, n);
    if (err != FIRC_OK) {
        fprintf(stderr, "ip_set %s: %s\n", live, firc_err_str(err));
        return 3;
    }
    return 0;
}

static int sets_commit(bool rules)
{
    firc_log_set_fd(STDERR_FILENO);
    firc_ipv4_subnet_t sub4[2];
    firc_ipv6_subnet_t sub6[1];
    uint32_t mark = 0;
    if (!firc_mark_for_field(SETS_FIELD, &mark) || !firc_rule_parse_subnet4(sets_first4[0], &sub4[0]) ||
        !firc_rule_parse_subnet4(sets_first4[1], &sub4[1]) || !firc_rule_parse_subnet6(sets_v6[0], &sub6[0])) {
        return 3;
    }
    for (int f = 0; f < 2; f++) {
        bool v6 = f == 1;
        firc_xt_t *xt = firc_xt_real_new(v6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4);
        if (xt == NULL) {
            perror("x_tables raw socket");
            return 3;
        }
        firc_ipt_t *ipt = firc_ipt_new(xt, "FIRC");
        if (ipt == NULL) { return 3; }
        firc_err_t err = firc_netfilter_register_base_chains(v6 ? NULL : ipt, v6 ? ipt : NULL);
        if (err == FIRC_OK && rules) {
            err = firc_ipset_to_link_build_rules(ipt, SETS_CHAIN, "tun0", mark, SETS_FIELD, NULL, NULL);
        }
        if (err == FIRC_OK && rules) {
            err = firc_ipset_to_link_build_subnet_rules_dev(ipt, SETS_CHAIN, mark, sub4, 2, sub6, 1, NULL);
        }
        if (err == FIRC_OK) { err = firc_ipt_commit(ipt); }
        firc_ipt_free(ipt);
        if (err != FIRC_OK) {
            fprintf(stderr, "sets: %s commit: %s\n", v6 ? "v6" : "v4", firc_err_str(err));
            return 3;
        }
    }
    return 0;
}

static void sets_count(const char *name, void *ud)
{
    if (strncmp(name, SETS_CHAIN, strlen(SETS_CHAIN)) == 0) {
        printf("left %s\n", name);
        (*(size_t *)ud)++;
    }
}

static int do_sets(const char *op)
{
    firc_setnl_t *s = NULL;
    int rc = open_sets(&s);
    if (rc != 0) { return rc; }
    if (strcmp(op, "write") == 0) {
        rc = sets_fill(s, 4, sets_first4, 2);
        if (rc == 0) { rc = sets_fill(s, 6, sets_v6, 1); }
        if (rc == 0) { rc = sets_commit(true); }
    } else if (strcmp(op, "swap") == 0) {
        rc = sets_fill(s, 4, sets_then4, 1);
    } else if (strcmp(op, "destroy") == 0) {
        for (uint8_t family = 4; family <= 6; family = (uint8_t)(family + 2)) {
            char live[FIRC_SET_NAME_MAX];
            if (firc_ipset_to_link_set_name_of(SETS_CHAIN, family, false, live, sizeof(live)) != FIRC_OK) {
                rc = 3;
                break;
            }
            firc_err_t err = firc_setnl_destroy(s, live);
            printf("destroy %s: %s\n", live, firc_err_str(err));
            if (err != FIRC_ERR_AGAIN) { rc = 1; }
        }
    } else if (strcmp(op, "sweep") == 0) {
        rc = sets_commit(false);
        size_t destroyed = 0, left = 0;
        firc_err_t err = rc == 0 ? firc_setnl_sweep(s, SETS_CHAIN, NULL, 0, &destroyed) : FIRC_ERR_IO;
        if (err == FIRC_OK) { err = firc_setnl_names(s, sets_count, &left); }
        printf("sweep: %s, destroyed %zu, left %zu\n", firc_err_str(err), destroyed, left);
        if (rc == 0 && (err != FIRC_OK || destroyed != 2 || left != 0)) { rc = 1; }
    } else {
        rc = 64;
    }
    firc_setnl_free(s);
    return rc;
}

static size_t shared_answer(uint8_t *b)
{
    static const uint8_t head[] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0};
    static const uint8_t name[] = {6, 's', 'h', 'a', 'r', 'e', 'd', 4, 't', 'e', 's', 't', 0};
    static const uint8_t question[] = {0, 1, 0, 1};
    static const uint8_t record[] = {0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 9, 9, 9, 9};
    size_t p = 0;
    memcpy(b + p, head, sizeof(head));
    p += sizeof(head);
    memcpy(b + p, name, sizeof(name));
    p += sizeof(name);
    memcpy(b + p, question, sizeof(question));
    p += sizeof(question);
    memcpy(b + p, name, sizeof(name));
    p += sizeof(name);
    memcpy(b + p, record, sizeof(record));
    return p + sizeof(record);
}

static firc_group_t *shared_group(uint8_t id, const char *name, const char *allow)
{
    firc_group_t *g = firc_group_new();
    firc_rule_t *r = firc_rule_new();
    if (g == NULL || r == NULL) { return NULL; }
    g->id = (firc_id_t){{id, 0, 0, 0}};
    g->enable = true;
    r->id = (firc_id_t){{id, 1, 0, 0}};
    r->enable = true;
    if (firc_strset(&g->name, name) != FIRC_OK || firc_strset(&r->type, "namespace") != FIRC_OK ||
        firc_strset(&r->rule, "shared.test") != FIRC_OK) {
        return NULL;
    }
    firc_group_add_rule(g, r);
    if (allow != NULL && push_entry(&g->devices.allow, &g->devices.n_allow, allow) != 0) { return NULL; }
    return g;
}

static int fake_for(firc_dns_pipeline_t *p, const char *client_text, firc_ip_t *out)
{
    firc_ip_t client = {{0}, 4};
    if (inet_pton(AF_INET, client_text, client.b) != 1) { return 64; }
    uint8_t buf[128];
    size_t len = shared_answer(buf);
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(buf, len, &msg) != FIRC_OK) { return 3; }
    firc_dns_verdict_t v = firc_dns_pipeline_handle_message(p, msg, 1000, &client, NULL);
    int rc = 3;
    for (size_t i = 0; i < msg->n_answers; i++) {
        const firc_dns_rr_t *rr = &msg->answers[i];
        if ((v == FIRC_DNS_HOLD || v == FIRC_DNS_REWRITTEN) && rr->rtype == FIRC_DNS_TYPE_A && rr->rdata_len == 4) {
            memcpy(out->b, rr->rdata, 4);
            out->len = 4;
            rc = 0;
        }
    }
    firc_dns_msg_free(msg);
    return rc;
}

static int do_shared(const char *client_a, const char *client_b)
{
    firc_config_t cfg;
    if (firc_config_init_defaults(&cfg) != FIRC_OK) { return 3; }
    firc_group_t *a = shared_group(1, "a", client_a);
    firc_group_t *b = shared_group(2, "b", NULL);
    if (a == NULL || b == NULL) { return 3; }
    firc_config_add_group(&cfg, a);
    firc_config_add_group(&cfg, b);
    firc_fakeip_cfg_t c = routing_pool_cfg();
    firc_fakeip_t *pool = NULL;
    firc_dns_pipeline_t *p = firc_dns_pipeline_create();
    firc_ruleset_snapshot_t *rules = firc_ruleset_snapshot_build(&cfg);
    if (p == NULL || rules == NULL || firc_fakeip_new(&c, &pool) != FIRC_OK) { return 3; }
    firc_dns_pipeline_set_snapshot(p, rules);
    firc_dns_pipeline_set_pool(p, pool, 300);
    firc_ip_t fa = {{0}, 0}, fb = {{0}, 0};
    int rc = fake_for(p, client_a, &fa);
    if (rc == 0) { rc = fake_for(p, client_b, &fb); }
    if (rc != 0) {
        fprintf(stderr, "shared: the pipeline issued no fake address\n");
        return rc;
    }
    firc_ruleset_lookup_t lk = {arg_mark, NULL, NULL, arg_nets, NULL, NULL};
    firc_nf_devices_t dev_a, dev_b;
    uint32_t mark_a = 0, mark_b = 0;
    if (firc_ruleset_render_devices(a, &lk, &dev_a) != FIRC_OK || firc_ruleset_render_devices(b, &lk, &dev_b) != FIRC_OK ||
        !firc_mark_for_field(5, &mark_a) || !firc_mark_for_field(6, &mark_b)) {
        return 3;
    }
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    firc_xt_t *xt = firc_xt_real_new(FIRC_IPT_PROTO_IPV4);
    if (snap == NULL || xt == NULL) {
        perror("x_tables raw socket");
        return 3;
    }
    firc_ipt_t *ipt = firc_ipt_new(xt, "FIRC");
    if (ipt == NULL) { return 3; }
    char ta[INET_ADDRSTRLEN], tb[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, fa.b, ta, sizeof(ta));
    inet_ntop(AF_INET, fb.b, tb, sizeof(tb));
    printf("# fake-a %s\n# fake-b %s\n", ta, tb);
    firc_err_t err = firc_netfilter_register_base_chains(ipt, NULL);
    if (err == FIRC_OK) { err = firc_ipset_to_link_build_rules_dev(ipt, "FIRCA", "tun0", mark_a, 5, snap, "01000000", &dev_a); }
    if (err == FIRC_OK) { err = firc_ipset_to_link_build_rules_dev(ipt, "FIRCB", "tun1", mark_b, 6, snap, "02000000", &dev_b); }
    if (err == FIRC_OK) { err = firc_ipt_commit(ipt); }
    fflush(stdout);
    firc_ipt_free(ipt);
    firc_fakeip_snapshot_free(snap);
    firc_dns_pipeline_destroy(p);
    firc_fakeip_free(pool);
    firc_nf_devices_clear(&dev_a);
    firc_nf_devices_clear(&dev_b);
    firc_config_clear(&cfg);
    if (err != FIRC_OK) {
        fprintf(stderr, "shared: %s\n", firc_err_str(err));
        return 3;
    }
    return 0;
}

static int do_xtparse(const char *path, const char *fam_text) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) { perror(path); return 2; }
    static uint8_t buf[16u << 20];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < XT_GETINFO_LEN) { fprintf(stderr, "%s: shorter than a GET_INFO answer\n", path); return 2; }
    xt_getinfo_t g;
    memcpy(&g, buf, sizeof(g));
    if (n - XT_GETINFO_LEN != g.size) { fprintf(stderr, "%s: %zu bytes of entries, GET_INFO said %u\n", path, n - XT_GETINFO_LEN, g.size); return 2; }
    firc_xt_info_t info;
    info.valid_hooks = g.valid_hooks;
    memcpy(info.hook_entry, g.hook_entry, sizeof(info.hook_entry));
    memcpy(info.underflow, g.underflow, sizeof(info.underflow));
    info.num_entries = g.num_entries;
    info.size = g.size;
    firc_xt_table_t t;
    const char *why = NULL;
    firc_ipt_proto_t fam = strcmp(fam_text, "v6") == 0 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4;
    if (firc_xt_parse(fam, &info, buf + XT_GETINFO_LEN, &t, &why) != FIRC_OK) {
        fprintf(stderr, "refused: %s\n", why != NULL ? why : "out of memory");
        return 1;
    }
    for (size_t i = 0; i < t.n_chains; i++) { printf("%s %zu\n", t.chains[i].name, t.chains[i].n_rules); }
    firc_xt_table_clear(&t);
    return 0;
}

static int do_xtnat(const char *what, const char *fam_text) {
    firc_log_set_fd(STDERR_FILENO);
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    bool v6 = strcmp(fam_text, "v6") == 0;
    if (!v6 && strcmp(fam_text, "v4") != 0) { return 64; }
    firc_xt_t *xt = firc_xt_real_new(v6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4);
    if (xt == NULL) {
        perror("x_tables raw socket");
        return 3;
    }
    if (strcmp(what, "probe") == 0) {
        int rc = firc_xt_probe(xt) == FIRC_OK ? 0 : 5;
        firc_xt_free(xt);
        return rc;
    }
    static const char *const j1_4[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    static const char *const j1_6[] = {"-d", "fd37:9a00::/48", "-j", "FIRC_DNAT"};
    static const char *const m1[] = {"-o", "tun0", "-m", "mark", "--mark", "0x10000/0xff0000", "-j", "MASQUERADE"};
    static const char *const j2[] = {"-j", "FIRC_g1"};
    bool out = strcmp(what, "output") == 0;
    firc_ipt_proto_t fam = v6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4;
    uint8_t fake[2][16] = {{198, 18, 0, 1}, {198, 18, 0, 2}}, real[2][16] = {{9, 9, 9, 9}, {9, 9, 9, 8}};
    if (v6) {
        for (int i = 0; i < 2; i++) {
            const uint8_t f6[16] = {0xfd, 0x37, 0x9a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (uint8_t)(i + 1)};
            const uint8_t r6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (uint8_t)(9 - i)};
            memcpy(fake[i], f6, 16);
            memcpy(real[i], r6, 16);
        }
    }
    firc_xt_block_t dnat;
    firc_xt_block_init(&dnat);
    firc_err_t err = FIRC_OK;
    for (int i = 0; i < 2 && err == FIRC_OK; i++) { err = firc_xt_block_add_dnat(&dnat, fam, fake[i], real[i]); }
    firc_ipt_rule_t *masq[1] = {firc_ipt_rule_new(m1, 8)};
    firc_xt_patch_op_t pre = {FIRC_IPT_OP_APPEND, 0, firc_ipt_rule_new(v6 ? j1_6 : j1_4, 4)};
    firc_xt_patch_op_t post = {FIRC_IPT_OP_APPEND, 0, firc_ipt_rule_new(j2, 2)};
    firc_xt_stage_chain_t chains[] = {
        {"FIRC_DNAT", FIRC_XT_STAGE_OVERRIDE, NULL, 0, NULL, 0, &dnat},
        {out ? "OUTPUT" : "PREROUTING", FIRC_XT_STAGE_PATCH, NULL, 0, &pre, 1, NULL},
        {"FIRC_g1", FIRC_XT_STAGE_OVERRIDE, masq, 1, NULL, 0, NULL},
        {"POSTROUTING", FIRC_XT_STAGE_PATCH, NULL, 0, &post, 1, NULL},
    };
    bool sweep = strcmp(what, "sweep") == 0;
    firc_xt_stage_t stage = {chains, sweep ? 0 : out ? 2 : 4, sweep ? "FIRC_" : NULL, false};
    if (err == FIRC_OK) {
        err = sweep || out || strcmp(what, "write") == 0 ? firc_xt_commit(xt, "nat", &stage, NULL) : FIRC_ERR_INVAL;
    }
    firc_xt_block_free(&dnat);
    firc_ipt_rule_free(masq[0]);
    firc_ipt_rule_free(pre.rule);
    firc_ipt_rule_free(post.rule);
    firc_xt_free(xt);
    return err == FIRC_OK ? 0 : err == FIRC_ERR_AGAIN ? 4 : 5;
}

static int do_barrier(const char *fam_text) {
    firc_log_set_fd(STDERR_FILENO);
    bool v6 = strcmp(fam_text, "v6") == 0;
    if (!v6 && strcmp(fam_text, "v4") != 0) { return 64; }
    firc_xt_t *xt = firc_xt_real_new(v6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4);
    if (xt == NULL) {
        perror("x_tables raw socket");
        return 3;
    }
    firc_ipt_t *ipt = firc_ipt_new(xt, "FIRC_");
    if (ipt == NULL) { return 3; }
    firc_ip_t base;
    uint8_t len = 0;
    if (!firc_ip_parse_cidr(v6 ? "fd37:9a00::/48" : "198.18.0.0/15", &base, &len)) { return 3; }
    firc_err_t err = firc_xt_probe(xt);
    if (err == FIRC_OK) { err = firc_netfilter_register_base_chains(ipt, NULL); }
    if (err == FIRC_OK) { err = firc_pool_reject_build_rules(ipt, "FIRC_", &base, len); }
    if (err == FIRC_OK) { err = firc_ipt_commit(ipt); }
    firc_ipt_free(ipt);
    if (err != FIRC_OK) {
        fprintf(stderr, "barrier: %s\n", firc_err_str(err));
        return 5;
    }
    return 0;
}

static int do_egress(const char *fam_text, const char *iface) {
    firc_log_set_fd(STDERR_FILENO);
    bool v6 = strcmp(fam_text, "v6") == 0;
    if (!v6 && strcmp(fam_text, "v4") != 0) { return 64; }
    firc_xt_t *xt = firc_xt_real_new(v6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4);
    if (xt == NULL) {
        perror("x_tables raw socket");
        return 3;
    }
    firc_ipt_t *ipt = firc_ipt_new(xt, "FIRC_");
    if (ipt == NULL) { return 3; }
    firc_ip_t base;
    uint8_t len = 0;
    uint32_t mark = 0;
    if (!firc_ip_parse_cidr(v6 ? "fd37:9a00::/48" : "198.18.0.0/15", &base, &len) || !firc_mark_for_field(1, &mark)) {
        return 3;
    }
    firc_err_t err = firc_xt_probe(xt);
    if (err == FIRC_OK) { err = firc_netfilter_register_base_chains(v6 ? NULL : ipt, v6 ? ipt : NULL); }
    if (err == FIRC_OK) { err = firc_ipset_to_link_build_rules(ipt, "FIRC_g1", iface, mark, 1, NULL, NULL); }
    if (err == FIRC_OK) { err = firc_pool_reject_build_rules(ipt, "FIRC_", &base, len); }
    if (err == FIRC_OK) { err = firc_ipt_commit(ipt); }
    firc_ipt_free(ipt);
    if (err != FIRC_OK) {
        fprintf(stderr, "egress: %s\n", firc_err_str(err));
        return 5;
    }
    return 0;
}

static bool index_namer(void *ud, uint16_t index, char *out)
{
    (void)ud;
    snprintf(out, 32, "#%u", (unsigned)index);
    return true;
}

static int do_xtdump(const char *table, const char *fam_text) {
    bool v6 = strcmp(fam_text, "v6") == 0;
    if (!v6 && strcmp(fam_text, "v4") != 0) { return 64; }
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
    if (fd < 0) { perror("raw socket"); return 3; }
    int level = v6 ? XT_SOL_IPV6 : XT_SOL_IP;
    xt_getinfo_t g;
    memset(&g, 0, sizeof(g));
    snprintf(g.name, sizeof(g.name), "%s", table);
    socklen_t gl = sizeof(g);
    if (getsockopt(fd, level, XT_SO_GET_INFO, &g, &gl) != 0) { perror("GET_INFO"); close(fd); return 5; }
    size_t len = XT_GET_ENTRIES_HDR_LEN + g.size;
    uint8_t *buf = calloc(1, len);
    if (buf == NULL) { close(fd); return 5; }
    memcpy(buf, g.name, sizeof(g.name));
    memcpy(buf + offsetof(xt_get_entries_hdr_t, size), &g.size, sizeof(g.size));
    socklen_t bl = (socklen_t)len;
    int rc = getsockopt(fd, level, XT_SO_GET_ENTRIES, buf, &bl);
    close(fd);
    if (rc != 0) { perror("GET_ENTRIES"); free(buf); return 5; }
    firc_xt_info_t info;
    info.valid_hooks = g.valid_hooks;
    memcpy(info.hook_entry, g.hook_entry, sizeof(info.hook_entry));
    memcpy(info.underflow, g.underflow, sizeof(info.underflow));
    info.num_entries = g.num_entries;
    info.size = g.size;
    char *text = firc_test_xt_print_named(v6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4, table, &info,
                                          buf + XT_GET_ENTRIES_HDR_LEN, index_namer, NULL);
    free(buf);
    if (text == NULL) { fprintf(stderr, "%s: the printer refused the table\n", table); return 5; }
    fputs(text, stdout);
    free(text);
    return 0;
}

static uint16_t fold_sum(uint32_t sum, const uint8_t *b, size_t n)
{
    for (size_t i = 0; i + 1 < n; i += 2) { sum += (uint32_t)((b[i] << 8) | b[i + 1]); }
    if (n % 2 != 0) { sum += (uint32_t)(b[n - 1] << 8); }
    while (sum >> 16 != 0) { sum = (sum & 0xffffu) + (sum >> 16); }
    return (uint16_t)~sum;
}

static int do_inject(const char *src_ip, const char *sport, const char *dst_ip, const char *dport, const char *mark_hex)
{
    struct sockaddr_storage src, dst;
    socklen_t sl = 0, dl = 0;
    if (addr_of(src_ip, sport, &src, &sl) != 0 || addr_of(dst_ip, "0", &dst, &dl) != 0 ||
        src.ss_family != dst.ss_family) {
        return 3;
    }
    char *end = NULL;
    unsigned long sp_l = strtoul(sport, &end, 10);
    if (*sport == '\0' || *end != '\0' || sp_l == 0 || sp_l > 65535) { return 3; }
    unsigned long dp_l = strtoul(dport, &end, 10);
    if (*dport == '\0' || *end != '\0' || dp_l == 0 || dp_l > 65535) { return 3; }
    unsigned long mark_l = strtoul(mark_hex, &end, 16);
    if (*mark_hex == '\0' || *end != '\0' || mark_l > 0xffffffffUL) { return 3; }
    uint32_t mark = (uint32_t)mark_l;
    bool v6 = dst.ss_family == AF_INET6;
    size_t ip_len = v6 ? 40 : 20;
    uint8_t pkt[64] = {0};
    uint8_t *udp = pkt + ip_len;
    const uint8_t payload[4] = {'z', 'a', 'p', 'r'};
    uint16_t udp_len = (uint16_t)(8 + sizeof(payload));
    uint16_t sp = (uint16_t)sp_l, dp = (uint16_t)dp_l;
    udp[0] = (uint8_t)(sp >> 8); udp[1] = (uint8_t)sp;
    udp[2] = (uint8_t)(dp >> 8); udp[3] = (uint8_t)dp;
    udp[4] = (uint8_t)(udp_len >> 8); udp[5] = (uint8_t)udp_len;
    memcpy(udp + 8, payload, sizeof(payload));
    uint8_t pseudo[40] = {0};
    size_t alen = v6 ? 16 : 4;
    const void *sa = v6 ? (const void *)&((struct sockaddr_in6 *)&src)->sin6_addr
                        : (const void *)&((struct sockaddr_in *)&src)->sin_addr;
    const void *da = v6 ? (const void *)&((struct sockaddr_in6 *)&dst)->sin6_addr
                        : (const void *)&((struct sockaddr_in *)&dst)->sin_addr;
    memcpy(pseudo, sa, alen);
    memcpy(pseudo + alen, da, alen);
    uint32_t sum = 17u + udp_len;
    for (size_t i = 0; i < 2 * alen; i += 2) { sum += (uint32_t)((pseudo[i] << 8) | pseudo[i + 1]); }
    uint16_t ck = fold_sum(sum, udp, udp_len);
    if (ck == 0) { ck = 0xffff; }
    udp[6] = (uint8_t)(ck >> 8); udp[7] = (uint8_t)ck;
    if (v6) {
        pkt[0] = 0x60;
        pkt[4] = (uint8_t)(udp_len >> 8); pkt[5] = (uint8_t)udp_len;
        pkt[6] = 17;
        pkt[7] = 64;
        memcpy(pkt + 8, sa, 16);
        memcpy(pkt + 24, da, 16);
    } else {
        pkt[0] = 0x45;
        pkt[3] = (uint8_t)(ip_len + udp_len);
        pkt[8] = 64;
        pkt[9] = 17;
        memcpy(pkt + 12, sa, 4);
        memcpy(pkt + 16, da, 4);
    }
    int fd = socket(dst.ss_family, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW);
    if (fd < 0) { perror("raw socket"); return 3; }
    int rc = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) {
        perror("SO_MARK");
        rc = 3;
    } else if (sendto(fd, pkt, ip_len + udp_len, 0, (struct sockaddr *)&dst, dl) < 0) {
        perror("sendto");
        rc = 3;
    }
    close(fd);
    return rc;
}

int main(int argc, char **argv)
{
    if ((argc == 5 || argc == 6) && strcmp(argv[1], "send") == 0) {
        return do_send(argv[2], argv[3], argv[4], argc == 6 ? argv[5] : NULL);
    }
    if (argc == 3 && strcmp(argv[1], "barrier") == 0) { return do_barrier(argv[2]); }
    if (argc == 7 && strcmp(argv[1], "inject") == 0) {
        return do_inject(argv[2], argv[3], argv[4], argv[5], argv[6]);
    }
    if (argc == 4 && strcmp(argv[1], "egress") == 0) { return do_egress(argv[2], argv[3]); }
    if ((argc == 4 || argc == 5) && strcmp(argv[1], "serve") == 0) {
        return do_serve(argv[2], argv[3], argc == 5 ? argv[4] : NULL);
    }
    if (argc == 4 && strcmp(argv[1], "ask") == 0) { return do_ask(argv[2], argv[3]); }
    if (argc >= 3 && strcmp(argv[1], "devchain") == 0) { return do_devchain(argc, argv); }
    if (argc == 3 && strcmp(argv[1], "unset") == 0) { return do_unset(argv[2]); }
    if (argc == 3 && strcmp(argv[1], "sets") == 0) { return do_sets(argv[2]); }
    if (argc == 4 && strcmp(argv[1], "shared") == 0) { return do_shared(argv[2], argv[3]); }
    if (argc == 4 && strcmp(argv[1], "xtparse") == 0) { return do_xtparse(argv[2], argv[3]); }
    if (argc == 4 && strcmp(argv[1], "xtnat") == 0) { return do_xtnat(argv[2], argv[3]); }
    if (argc == 4 && strcmp(argv[1], "xtdump") == 0) { return do_xtdump(argv[2], argv[3]); }
    fprintf(stderr, "usage: %s send <ipv4> <port> <mark-hex> [source port] | barrier v4|v6 | inject <src> <sport> <dst> <dport> <mark-hex> | egress v4|v6 <iface> | serve <ipv4> <port> [tag] | ask <ipv4> <port> | "
                    "devchain <field> [...] | unset <set> | sets write|swap|destroy|sweep | xtparse <file> v4|v6 | xtnat write|output|sweep|probe v4|v6 | xtdump <table> v4|v6\n", argv[0]);
    return 64;
}
