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

#include "firc/dnsproxy.h"
#include "firc/fakeip.h"
#include "firc/ipset_to_link.h"
#include "firc/log.h"
#include "firc/mark.h"
#include "firc/match.h"
#include "firc/models.h"
#include "firc/netfilter_cleaner.h"
#include "firc/ruleset.h"
#include "firc/xtables.h"
#include "../../src/xtables/xt_internal.h"
#include "xt_golden.h"

static int addr_of(const char *ip, const char *port, struct sockaddr_in *sa)
{
    memset(sa, 0, sizeof(*sa));
    sa->sin_family = AF_INET;
    sa->sin_port = htons((uint16_t)atoi(port));
    return inet_pton(AF_INET, ip, &sa->sin_addr) == 1 ? 0 : -1;
}

static int do_send(const char *ip, const char *port, const char *mark_hex)
{
    const firc_dnsproxy_sock_ops_t *ops = &firc_dnsproxy_sock_ops_real;
    struct sockaddr_in dst;
    if (addr_of(ip, port, &dst) != 0) { return 3; }
    uint32_t mark = (uint32_t)strtoul(mark_hex, NULL, 16);
    int fd = ops->open(ops->ud, AF_INET, SOCK_DGRAM | SOCK_CLOEXEC);
    if (fd < 0) { perror("socket"); return 3; }
    if (mark != 0 && ops->set_mark(ops->ud, fd, mark) != 0) {
        printf("mark-refused\n");
        return 2;
    }
    if (ops->connect(ops->ud, fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
        printf("src=none reply=no\n");
        return 0;
    }
    struct sockaddr_in src;
    socklen_t sl = sizeof(src);
    char s[INET_ADDRSTRLEN] = "?";
    if (getsockname(fd, (struct sockaddr *)&src, &sl) == 0) { inet_ntop(AF_INET, &src.sin_addr, s, sizeof(s)); }
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
    struct sockaddr_in at;
    if (addr_of(ip, port, &at) != 0) { return 3; }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&at, sizeof(at)) != 0) { perror("bind"); return 3; }
    for (;;) {
        char buf[512];
        struct sockaddr_in from;
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
    struct sockaddr_in dst;
    if (addr_of(ip, port, &dst) != 0) { return 3; }
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { perror("socket"); return 3; }
    if (connect(fd, (struct sockaddr *)&dst, sizeof(dst)) != 0) {
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

/* An empty kernel to save from, so every chain is written whole. */
static firc_err_t pr_save(firc_ipt_executable_t *self, const char *table, uint8_t **out, size_t *len)
{
    (void)self;
    (void)table;
    *out = calloc(1, 1);
    *len = 0;
    return *out != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}
static firc_err_t pr_restore(firc_ipt_executable_t *self, const uint8_t *data, size_t len)
{
    (void)self;
    return fwrite(data, 1, len, stdout) == len ? FIRC_OK : FIRC_ERR_IO;
}
static firc_ipt_proto_t pr_proto(firc_ipt_executable_t *self)
{
    (void)self;
    return FIRC_IPT_PROTO_IPV4;
}
static void pr_destroy(firc_ipt_executable_t *self) { free(self); }
static const firc_ipt_executable_ops_t k_print_ops = {pr_save, pr_restore, pr_proto, pr_destroy, NULL};

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
    firc_ruleset_lookup_t lk = {arg_mark, NULL, NULL, arg_nets, NULL, NULL};
    firc_nf_devices_t dev;
    if (firc_ruleset_render_devices(g, &lk, &dev) != FIRC_OK) { return 3; }

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
    firc_fakeip_t *pool = NULL;
    firc_ip_t v4, v6;
    if (firc_fakeip_new(&c, &pool) != FIRC_OK ||
        firc_fakeip_get(pool, "selector.test", "g", 1000, &v4, &v6) != FIRC_OK) {
        return 3;
    }
    firc_fakeip_snapshot_t *snap = firc_fakeip_snapshot_take(pool);
    firc_ipt_executable_t *exe = malloc(sizeof(*exe));
    if (snap == NULL || exe == NULL) { return 3; }
    exe->ops = &k_print_ops;
    firc_xt_t *xt = firc_xt_real_new(FIRC_IPT_PROTO_IPV4);
    if (xt == NULL) {
        perror("x_tables raw socket");
        return 3;
    }
    firc_ipt_t *ipt = firc_ipt_new(exe, xt);
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
    firc_log_set_level(FIRC_LOG_DEBUG);
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
    static const char *const d1_4[] = {"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination", "9.9.9.9"};
    static const char *const d2_4[] = {"-d", "198.18.0.2/32", "-j", "DNAT", "--to-destination", "9.9.9.8"};
    static const char *const j1_4[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    static const char *const d1_6[] = {"-d", "fd37:9a00::1/128", "-j", "DNAT", "--to-destination", "2001:db8::9"};
    static const char *const d2_6[] = {"-d", "fd37:9a00::2/128", "-j", "DNAT", "--to-destination", "2001:db8::8"};
    static const char *const j1_6[] = {"-d", "fd37:9a00::/48", "-j", "FIRC_DNAT"};
    static const char *const m1[] = {"-o", "tun0", "-m", "mark", "--mark", "0x10000/0xff0000", "-j", "MASQUERADE"};
    static const char *const j2[] = {"-j", "FIRC_g1"};
    firc_ipt_rule_t *dnat[2] = {firc_ipt_rule_new(v6 ? d1_6 : d1_4, 6), firc_ipt_rule_new(v6 ? d2_6 : d2_4, 6)};
    firc_ipt_rule_t *masq[1] = {firc_ipt_rule_new(m1, 8)};
    firc_xt_patch_op_t pre = {FIRC_IPT_OP_APPEND, 0, firc_ipt_rule_new(v6 ? j1_6 : j1_4, 4)};
    firc_xt_patch_op_t post = {FIRC_IPT_OP_APPEND, 0, firc_ipt_rule_new(j2, 2)};
    firc_xt_stage_chain_t chains[] = {
        {"FIRC_DNAT", FIRC_XT_STAGE_OVERRIDE, dnat, 2, NULL, 0},
        {"FIRC_g1", FIRC_XT_STAGE_OVERRIDE, masq, 1, NULL, 0},
        {"PREROUTING", FIRC_XT_STAGE_PATCH, NULL, 0, &pre, 1},
        {"POSTROUTING", FIRC_XT_STAGE_PATCH, NULL, 0, &post, 1},
    };
    bool sweep = strcmp(what, "sweep") == 0;
    firc_xt_stage_t stage = {chains, sweep ? 0 : 4, sweep ? "FIRC_" : NULL};
    firc_err_t err = sweep || strcmp(what, "write") == 0 ? firc_xt_commit(xt, "nat", &stage, NULL) : FIRC_ERR_INVAL;
    firc_ipt_rule_free(dnat[0]);
    firc_ipt_rule_free(dnat[1]);
    firc_ipt_rule_free(masq[0]);
    firc_ipt_rule_free(pre.rule);
    firc_ipt_rule_free(post.rule);
    firc_xt_free(xt);
    return err == FIRC_OK ? 0 : err == FIRC_ERR_AGAIN ? 4 : 5;
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
    char *text = firc_test_xt_print(v6 ? FIRC_IPT_PROTO_IPV6 : FIRC_IPT_PROTO_IPV4, &info, buf + XT_GET_ENTRIES_HDR_LEN);
    free(buf);
    if (text == NULL) { fprintf(stderr, "%s: the printer refused the table\n", table); return 5; }
    fputs(text, stdout);
    free(text);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 5 && strcmp(argv[1], "send") == 0) { return do_send(argv[2], argv[3], argv[4]); }
    if ((argc == 4 || argc == 5) && strcmp(argv[1], "serve") == 0) {
        return do_serve(argv[2], argv[3], argc == 5 ? argv[4] : NULL);
    }
    if (argc == 4 && strcmp(argv[1], "ask") == 0) { return do_ask(argv[2], argv[3]); }
    if (argc >= 3 && strcmp(argv[1], "devchain") == 0) { return do_devchain(argc, argv); }
    if (argc == 4 && strcmp(argv[1], "xtparse") == 0) { return do_xtparse(argv[2], argv[3]); }
    if (argc == 4 && strcmp(argv[1], "xtnat") == 0) { return do_xtnat(argv[2], argv[3]); }
    if (argc == 4 && strcmp(argv[1], "xtdump") == 0) { return do_xtdump(argv[2], argv[3]); }
    fprintf(stderr, "usage: %s send <ipv4> <port> <mark-hex> | serve <ipv4> <port> [tag] | ask <ipv4> <port> | "
                    "devchain <field> [...] | xtparse <file> v4|v6 | xtnat write|sweep|probe v4|v6 | xtdump <table> v4|v6\n", argv[0]);
    return 64;
}
