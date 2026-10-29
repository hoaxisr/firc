#define _GNU_SOURCE
#include "unit.h"
#include "../src/proto/transport/trdial.c"
#include "../src/ctlinb.h"
#include "../src/ctlnodes.h"
#include "../src/control.h"
#include "nodes.h"
#include "vless.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#define UUID "b831381d-6324-4d53-ad4f-8cda48b30811"
#define LA "vless://" UUID "@ha:443?security=none&type=tcp#A"
#define LB "vless://" UUID "@hb:443?security=none&type=tcp#B"

static unsigned fake_resolve(const char *host, struct in_addr out[ADDR_MAX]) {
    (void)host;
    out[0].s_addr = htonl(0x0a000001u);
    return 1;
}

static int g_sel;
static int on_select(const int *sel, size_t n) {
    (void)sel;
    (void)n;
    __atomic_add_fetch(&g_sel, 1, __ATOMIC_SEQ_CST);
    return 0;
}
static void on_ack(int c) { (void)c; }
static void on_full(void) {}

static char g_err[8192], g_out[8192];

static int slurp(int fd, char *buf, size_t cap) {
    ssize_t k = pread(fd, buf, cap - 1, 0);
    buf[k > 0 ? k : 0] = 0;
    return 0;
}

static int feed(const char *body) {
    char pe[] = "/tmp/ctlinbe-XXXXXX", po[] = "/tmp/ctlinbo-XXXXXX";
    int efd = mkstemp(pe), ofd = mkstemp(po);
    unlink(pe);
    unlink(po);
    fflush(stdout);
    int se = dup(2), so = dup(1);
    dup2(efd, 2);
    dup2(ofd, 1);
    FILE *f = fmemopen((void *)body, strlen(body), "r");
    char *line = NULL;
    size_t cap = 0;
    sl_set_interner(nodes_intern);
    int n = ctlinb_read_cmd(f, &line, &cap);
    sl_set_interner(NULL);
    free(line);
    fclose(f);
    fflush(stderr);
    fflush(stdout);
    dup2(se, 2);
    dup2(so, 1);
    close(se);
    close(so);
    slurp(efd, g_err, sizeof g_err);
    slurp(ofd, g_out, sizeof g_out);
    close(efd);
    close(ofd);
    return n;
}

static int warns(void) {
    int k = 0;
    for (const char *p = g_err; (p = strstr(p, "tunvless[warn]")) != NULL; p++) k++;
    return k;
}

static int idx_of(const char *link) { return nodes_find(link); }

int main(void) {
    g_resolve = fake_resolve;
    nodes_init(sizeof(struct vless_node));
    ctl_init(1);
    ctlinb_init();
    static const struct ctln_hooks h = { on_select, on_ack, on_full, 2000, NULL };
    check("resolver thread started", 0, ctln_start(&h));
    struct ib_cfg c[20];
    unsigned gen0, gen;
    ctlinb_take(c, 20, &gen0);

    int n = feed("192.168.1.1:1081 - - " LA "\n192.168.1.1:1082 alice s%20t " LB "\n\n");
    /* catches: a line dropped, or the count not the lines taken */
    check("two lines taken", 2, n);
    check("ack printed", 0, strcmp(g_out, "{\"type\":\"inbounds\",\"count\":2}\n"));
    check("take returns both", 2, (int)ctlinb_take(c, 20, &gen));
    /* catches: the generation not moving on a command */
    check("generation grew by one", (int)gen0 + 1, (int)gen);
    check("first address", (int)inet_addr("192.168.1.1"), (int)c[0].addr);
    check("first port", 1081, c[0].port);
    check_str("first user empty", "", c[0].user);
    check_str("second user", "alice", c[1].user);
    /* catches: the percent escape left in the password */
    check_str("second password decoded", "s t", c[1].pass);
    check("second port", 1082, c[1].port);
    check("distinct nodes", 1, c[0].node >= 0 && c[1].node >= 0 && c[0].node != c[1].node);
    check("node of the first link", idx_of(LA), c[0].node);
    check("node of the second link", idx_of(LB), c[1].node);

    feed("192.168.1.1:1081 - - -\n\n");
    ctlinb_take(c, 20, &gen);
    /* catches: a dash link taking a node index */
    check("a dash link is node minus one", -1, c[0].node);

    int nodes0 = nodes_count();
    check("a star line taken", 1, feed("192.168.1.1:1081 - - *\n\n"));
    ctlinb_take(c, 20, &gen);
    /* catches: a star taken as a link, or as no node at all */
    check("a star is the whole pool", IB_NODE_POOL, c[0].node);
    check("a star adds no node", nodes0, nodes_count());

    feed("192.168.1.1:1081 - - " LA "\n192.168.1.1:1082 - - " LA "\n\n");
    ctlinb_take(c, 20, &gen);
    /* catches: one link added as two nodes */
    check("the same link twice is one node", 1, c[0].node == c[1].node && c[0].node >= 0);

    ctlinb_take(c, 20, &gen0);
    feed("192.168.1.1:1081 - - " LA "\n\n");
    check("an empty command takes zero", 0, feed("\n"));
    check("an empty command clears", 0, (int)ctlinb_take(c, 20, &gen));
    /* catches: an empty command not published, or the generation skipped */
    check("generation grew by two", (int)gen0 + 2, (int)gen);

    n = feed("0.0.0.0:1081 - - " LA "\n1.2.3.4:0 - - " LA "\n1.2.3.4:70000 - - " LA
             "\n1.2.3.4:1090 - - http://x\n1.2.3.4:1091 - - " LA "\n\n");
    /* catches: a bad address, port or link taken, or a bad line left without its warning */
    check("bad lines: only the good one taken", 1, n);
    check("bad lines: one warning each", 4, warns());
    ctlinb_take(c, 20, &gen);
    check("bad lines: the good one is published", 1091, c[0].port);

    char big[4096] = "";
    for (int i = 0; i < 17; i++) {
        char l[128];
        snprintf(l, sizeof l, "192.168.1.1:%d - - " LA "\n", 2000 + i);
        strcat(big, l);
    }
    strcat(big, "\n");
    n = feed(big);
    /* catches: the cap ignored, or the 17th line dropped without a warning */
    check("17 lines: 16 taken", 16, n);
    check("17 lines: one warning", 1, warns());
    check("17 lines: 16 published", 16, (int)ctlinb_take(c, 20, &gen));
    check("17 lines: the 17th is the one left out", 2015, c[15].port);

    feed("192.168.1.1:1081 %2D - " LA "\n\n");
    ctlinb_take(c, 20, &gen);
    /* catches: an encoded dash read as the no-user marker */
    check_str("a lone %2D is a dash user", "-", c[0].user);

    feed("192.168.1.1:1081 bob hunter2%zz " LA "\n\n");
    /* catches: the line, with its password, echoed in the warning */
    check("a bad escape is skipped", 1, warns());
    check("the warning names the line number", 1, strstr(g_err, "line 1") != NULL);
    check("the password is not in the warning", 1, strstr(g_err, "hunter2") == NULL);

    int sel = g_sel;
    feed("192.168.1.1:1081 - - vless://" UUID "@newhost:443?security=none&type=tcp#N\n\n");
    struct timespec ts = { 0, 200000000 };
    nanosleep(&ts, NULL);
    uint32_t a;
    /* catches: a host of an inbound link never pinned */
    check("a new host is pinned", 1, transport_pinned_addrs("newhost", &a, 1));
    /* catches: an inbound link changing the pool selection */
    check("the pool selection is untouched", sel, g_sel);

    int fd = ctlinb_wake_fd();
    check("a wake fd exists", 1, fd >= 0);
    uint64_t v = 0;
    /* catches: a command that does not wake the loop */
    check("a command armed the wake fd", 1, read(fd, &v, sizeof v) == (ssize_t)sizeof v && v > 0);

    n = feed("192.168.1.1:1081 - - " LA "\n");
    check("EOF in a command is -1", -1, n);
    return unit_done("ctlinbmatch");
}
