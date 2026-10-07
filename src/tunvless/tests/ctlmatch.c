#include "unit.h"
#include "../src/control.h"
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static void up_a(void) { ctl_emit_node_up("A", 4); }
static void down_a(void) { ctl_emit_node_down("A", 4, "x"); }
static void ack2(void) { ctl_emit_nodes(2); }
static void full(void) { ctl_emit_pins_full(); }

static void capture(char *out, size_t cap, void (*f)(void)) {
    int p[2];
    out[0] = 0;
    if (pipe(p) != 0) return;
    int saved = dup(1);
    dup2(p[1], 1);
    f();
    dup2(saved, 1);
    close(saved);
    close(p[1]);
    ssize_t n = read(p[0], out, cap - 1);
    close(p[0]);
    out[n > 0 ? n : 0] = 0;
}

int main(void) {
    char b[64];
    /* catches: a quote or backslash in a node name breaking the JSON line */
    check("fits", 1, ctl_json_str(b, sizeof b, "a\"b\\c") > 0);
    check_str("quote and backslash escaped", "\"a\\\"b\\\\c\"", b);
    /* catches: a newline in a name splitting one event into two lines */
    ctl_json_str(b, sizeof b, "x\ny\x01");
    check_str("control bytes escaped", "\"x\\u000ay\\u0001\"", b);
    /* catches: an overlong name written past the buffer */
    char big[200]; memset(big, 'n', sizeof big - 1); big[sizeof big - 1] = 0;
    check("refused when it does not fit", 0, (long)ctl_json_str(b, sizeof b, big));
    /* catches: eight long names with a quote overflowing the line and the event being dropped */
    char nm[8][101];
    const char *names[8];
    for (int i = 0; i < 8; i++) {
        memset(nm[i], 'a' + i, 100);
        nm[i][100] = 0;
        nm[i][50] = '"';
        names[i] = nm[i];
    }
    int p[2];
    check("pipe", 0, pipe(p));
    int saved = dup(1);
    dup2(p[1], 1);
    ctl_init(1);
    static const int idx[8] = { 0, 1, 2, 3, 4, 5, 6, 1234567 };
    ctl_emit_active(names, idx, 8);
    dup2(saved, 1);
    close(p[1]);
    char line[2048];
    ssize_t n = read(p[0], line, sizeof line - 1);
    line[n > 0 ? n : 0] = 0;
    check("active line within 1024 bytes", 1, n > 0 && n <= 1024);
    check("active line ends in a newline", '\n', line[n - 1]);
    int found = 0;
    for (int i = 0; i < 8; i++) {
        char key[8] = { (char)('a' + i), (char)('a' + i), (char)('a' + i), 0 };
        found += strstr(line, key) != NULL;
    }
    check("all eight names present", 8, found);
    /* catches: the index list cut off when the names fill the line */
    check("all eight indexes present", 1, strstr(line, "],\"index\":[0,1,2,3,4,5,6,1234567]}\n") != NULL);
    char ev[512];
    /* catches: a node event without the node's index */
    check_str("node_up with index", "{\"type\":\"node_up\",\"node\":\"A\",\"index\":4}\n",
              (capture(ev, sizeof ev, up_a), ev));
    check_str("node_down with index", "{\"type\":\"node_down\",\"node\":\"A\",\"index\":4,\"why\":\"x\"}\n",
              (capture(ev, sizeof ev, down_a), ev));
    /* catches: a nodes command not acknowledged with its count */
    check_str("nodes ack", "{\"type\":\"nodes\",\"count\":2}\n", (capture(ev, sizeof ev, ack2), ev));
    /* catches: a full pin table with no event fircd can act on */
    check_str("pins full", "{\"type\":\"pins_full\"}\n", (capture(ev, sizeof ev, full), ev));
    /* catches: a descriptor inherited from fircd's parent kept open by a tunnel for its lifetime */
    int high = dup2(0, 200);
    int many = 0;
    for (int i = 0; i < 300; i++) many += dup(0) >= 0;
    check("fds opened", 1, high == 200 && many == 300);
    ctl_close_inherited_fds();
    check("inherited fd closed", -1, fcntl(200, F_GETFD));
    int left = 0;
    for (int fd = 3; fd < 1024; fd++) left += fcntl(fd, F_GETFD) != -1;
    check("no fd above 2 left", 0, left);
    check("stdio kept", 1, fcntl(0, F_GETFD) != -1 && fcntl(1, F_GETFD) != -1 && fcntl(2, F_GETFD) != -1);
    return unit_done("ctlmatch");
}
