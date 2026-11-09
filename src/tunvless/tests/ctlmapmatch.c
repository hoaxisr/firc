#define _GNU_SOURCE
#include "unit.h"
#include "../src/ctlmap.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#define POOL 0xc6120000u

static uint32_t be(uint32_t host) { return htonl(host); }

static uint32_t ip(const char *s) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) abort();
    return a.s_addr;
}

static char g_err[4096];

static int feed(const char *body, int all, int close_cmd) {
    char path[] = "/tmp/ctlmapmatch-XXXXXX";
    int efd = mkstemp(path);
    unlink(path);
    int saved = dup(2);
    dup2(efd, 2);
    FILE *f = fmemopen((void *)body, strlen(body), "r");
    char *line = NULL;
    size_t cap = 0;
    int n = close_cmd ? ctlmap_read_close(f, &line, &cap) : ctlmap_read_cmd(f, &line, &cap, all);
    free(line);
    fclose(f);
    fflush(stderr);
    dup2(saved, 2);
    close(saved);
    ssize_t k = pread(efd, g_err, sizeof g_err - 1, 0);
    g_err[k > 0 ? k : 0] = 0;
    close(efd);
    return n;
}

static int map(const char *body) { return feed(body, 0, 0); }
static int mapall(const char *body) { return feed(body, 1, 0); }
static int closes(const char *body) { return feed(body, 0, 1); }

static int lines_of(const char *s) {
    int n = 0;
    for (; *s; s++) n += *s == '\n';
    return n;
}

struct body { char *s; size_t n; };

static void put_line(struct body *b, uint32_t fake_h, uint32_t real_h) {
    char l[40];
    int k = real_h
        ? snprintf(l, sizeof l, "%u.%u.%u.%u %u.%u.%u.%u\n", fake_h >> 24, (fake_h >> 16) & 255,
                   (fake_h >> 8) & 255, fake_h & 255, real_h >> 24, (real_h >> 16) & 255,
                   (real_h >> 8) & 255, real_h & 255)
        : snprintf(l, sizeof l, "%u.%u.%u.%u -\n", fake_h >> 24, (fake_h >> 16) & 255,
                   (fake_h >> 8) & 255, fake_h & 255);
    memcpy(b->s + b->n, l, (size_t)k);
    b->n += (size_t)k;
    b->s[b->n] = 0;
}

static struct body body_new(size_t lines) {
    struct body b = { malloc(lines * 40 + 2), 0 };
    b.s[0] = 0;
    return b;
}

static const char *body_end(struct body *b) {
    b->s[b->n++] = '\n';
    b->s[b->n] = 0;
    return b->s;
}

static uint32_t v4_of(const struct cm_real *r) {
    uint32_t a;
    memcpy(&a, r->b, 4);
    return a;
}

static uint32_t real_of(uint32_t fake_h) {
    struct cm_real r;
    return ctlmap_lookup(be(fake_h), &r) == CM_REAL && !r.v6 ? ntohl(v4_of(&r)) : 0;
}

static uint64_t drain(void) {
    uint64_t v = 0, sum = 0;
    while (read(ctlmap_wake_fd(), &v, sizeof v) == (ssize_t)sizeof v) sum += v;
    return sum;
}

static uint32_t g_rng = 2463534242u;
static uint32_t rnd(void) {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 17;
    g_rng ^= g_rng << 5;
    return g_rng;
}

static void a_line_maps_and_dash_forgets(void) {
    enum { N = 40000 };
    static uint32_t fake[N];
    static uint8_t seen[1u << 17];
    for (int i = 0; i < N;) {
        uint32_t off = rnd() & 0x1ffffu;
        if (seen[off]) continue;
        seen[off] = 1;
        fake[i++] = POOL + off;
    }
    int taken = 0, sent = 0;
    for (int i = 0; i < N; i += 4000) {
        struct body b = body_new(4000);
        for (int k = i; k < i + 4000; k++) put_line(&b, fake[k], 0x0b000000u + (uint32_t)k);
        taken += i ? map(body_end(&b)) : mapall(body_end(&b));
        sent += 4000;
        free(b.s);
    }
    check("every line of the fill is taken", sent, taken);
    taken = 0;
    for (int i = 0; i < N; i += 8000) {
        struct body b = body_new(4000);
        for (int k = i; k < i + 8000; k += 2) put_line(&b, fake[k], 0);
        taken += map(body_end(&b));
        free(b.s);
    }
    check("every dash line is taken", N / 2, taken);
    int kept = 0, gone = 0;
    for (int i = 0; i < N; i++) {
        uint32_t r = real_of(fake[i]);
        if (i % 2 == 0) gone += r == 0;
        else kept += r == 0x0b000000u + (uint32_t)i;
    }
    /* catches: a delete that empties its slot without shifting the probe chain back */
    check("every entry left keeps its real address", N / 2, kept);
    check("every dashed entry reads none", N / 2, gone);
    check("a fake never sent reads none", CM_NONE, ctlmap_lookup(be(POOL + 0x1ffffu), &(struct cm_real){ { 0 }, 0 }));
}

static void mapall_clears_stale_entries(void) {
    check("map takes two lines", 2, map("198.18.0.1 1.1.1.1\n198.18.0.2 2.2.2.2\n\n"));
    check("mapall takes its one line", 1, mapall("198.18.0.3 3.3.3.3\n\n"));
    /* catches: a mapall that adds without clearing, leaving drifted entries live */
    check("an entry the mapall lacks is gone", 0, real_of(0xc6120001u) | real_of(0xc6120002u));
    check("the mapall's own entry is there", 0x03030303, real_of(0xc6120003u));
}

static void the_cap_drops_and_does_not_count(void) {
    int taken = 0;
    for (uint32_t i = 0; i < 65536; i += 4096) {
        struct body b = body_new(4096);
        for (uint32_t k = i; k < i + 4096; k++) put_line(&b, POOL + k, 0x0c000000u + k);
        taken += i ? map(body_end(&b)) : mapall(body_end(&b));
        free(b.s);
    }
    check("65536 entries fit", 65536, taken);
    /* catches: a count that hides the drop from fircd */
    check("the 65537th entry is not counted", 0, map("198.19.0.0 9.9.9.9\n\n"));
    check("the 65537th entry is not there", 0, real_of(POOL + 65536));
    check_str("one warning for the drop",
              "tunvless[warn]: the address map is full (65536), later lines are dropped\n", g_err);
    /* catches: a full map that refuses a new real address for a fake it holds */
    check("an update at the cap is taken", 1, map("198.18.0.0 9.9.9.9\n\n"));
    check("the update is applied", 0x09090909, real_of(POOL));
    check("a dash frees room for a new entry", 2, map("198.18.0.1 -\n198.19.0.0 9.9.9.8\n\n"));
    check("the new entry is there", 0x09090908, real_of(POOL + 65536));
    check("a second drop is not counted", 0, map("198.19.0.1 9.9.9.7\n\n"));
    check_str("the warning is once per run", "", g_err);
    struct cm_real r;
    check("a fake past the cap is asked", 1, ctlmap_ask(be(POOL + 70000)));
    /* catches: a miss answer past the cap acked 0, so fircd reads drift and stops resending */
    check("its answer is counted", 1, map("198.19.17.112 9.9.9.6\n\n"));
    check("and recorded for the waiting connection", CM_REAL, ctlmap_answer(be(POOL + 70000), &r));
    check("with its real address", 0x09090906, ntohl(v4_of(&r)));
    check("but not put in the full table", 0, real_of(POOL + 70000));
    ctlmap_unask(be(POOL + 70000));
}

static void a_command_takes_4096_lines(void) {
    struct body b = body_new(4097);
    for (uint32_t k = 0; k < 4097; k++) put_line(&b, POOL + k, 0x0d000000u + k);
    /* catches: a command of any length accepted, or the 4096th line dropped */
    check("4096 of 4097 lines taken", 4096, mapall(body_end(&b)));
    free(b.s);
    check("the 4096th line is applied", 0x0d000fffu, real_of(POOL + 4095));
    check("the 4097th line is not", 0, real_of(POOL + 4096));
    check("one warning for the long command", 1, lines_of(g_err));
}

static void an_asked_fake_records_real_and_dash(void) {
    uint32_t f = ip("198.18.7.1"), g = ip("198.18.7.2");
    struct cm_real r;
    mapall("\n");
    check("the first ask is the asker", 1, ctlmap_ask(f));
    /* catches: a second miss sent for a fake already asked */
    check("a second ask is not", 0, ctlmap_ask(f));
    check("asked, not answered: pending", CM_PENDING, ctlmap_answer(f, &r));
    check("an unasked fake has no answer", CM_NONE, ctlmap_answer(g, &r));
    mapall("198.18.7.3 3.3.3.3\n\n");
    /* catches: a mapall that clears the asked set, so the fake reads none and is asked again */
    check("a mapall without the fake keeps it pending", CM_PENDING, ctlmap_answer(f, &r));
    check("and does not make it a new asker", 0, ctlmap_ask(f));
    map("198.18.7.1 5.6.7.8\n\n");
    check("the answer is recorded", CM_REAL, ctlmap_answer(f, &r));
    check("with its real address", (long)ip("5.6.7.8"), (long)v4_of(&r));
    check("and the table has it", 0x05060708, real_of(0xc6120701u));
    check("a second fake is asked", 1, ctlmap_ask(g));
    map("198.18.7.2 -\n\n");
    /* catches: a dash indistinguishable from not answered yet */
    check("a dash answers denied", CM_DENIED, ctlmap_answer(g, &r));
    check("and the table has no entry", 0, real_of(0xc6120702u));
    uint32_t h = ip("198.18.7.4");
    map("198.18.7.4 4.4.4.4\n\n");
    /* catches: a fake mapped between the loop's lookup and its ask waiting on a miss */
    check("an ask for a mapped fake sends no miss", 0, ctlmap_ask(h));
    check("and reads its real address", CM_REAL, ctlmap_answer(h, &r));
    check("the mapped real", (long)ip("4.4.4.4"), (long)v4_of(&r));
    ctlmap_unask(h);
    ctlmap_unask(f);
    ctlmap_unask(g);
    check("unasked: no answer", CM_NONE, ctlmap_answer(f, &r));
    /* catches: an unask that leaves the fake asked, so its next miss is never sent */
    check("unasked: the next ask is the asker", 1, ctlmap_ask(g));
    ctlmap_unask(g);
}

static void the_257th_ask_is_refused(void) {
    int first = 0;
    for (uint32_t i = 0; i < 256; i++) first += ctlmap_ask(be(POOL + 0x100u + i)) == 1;
    check("256 asks are taken", 256, first);
    /* catches: an unbounded asked set */
    check("the 257th is refused", -1, ctlmap_ask(be(POOL + 0x200u)));
    check("a fake already asked is still known", 0, ctlmap_ask(be(POOL + 0x100u)));
    ctlmap_unask(be(POOL + 0x100u));
    /* catches: an unask that removes another fake than the one named */
    check("the unasked fake is gone", CM_NONE, ctlmap_answer(be(POOL + 0x100u), &(struct cm_real){ { 0 }, 0 }));
    check("the last asked is kept", 0, ctlmap_ask(be(POOL + 0x1ffu)));
    /* catches: a slot freed by unask never reused */
    check("an unask makes room", 1, ctlmap_ask(be(POOL + 0x200u)));
    for (uint32_t i = 1; i < 256; i++) ctlmap_unask(be(POOL + 0x100u + i));
    ctlmap_unask(be(POOL + 0x200u));
    check("all unasked: a new ask is taken", 1, ctlmap_ask(be(POOL + 0x300u)));
    ctlmap_unask(be(POOL + 0x300u));
}

static void a_line_outside_the_pool_is_not_taken(void) {
    mapall("\n");
    /* catches: a fake outside the pool, or a malformed line, taken and counted */
    check("only the good line is taken", 1,
          map("10.0.0.1 1.2.3.4\n198.18.0.9 1.2.3.4\nbad\n198.18.0.10 x\n198.18.0.11 1.2.3\n"
              "198.18.0.12  1.2.3.4\n198.17.255.255 1.2.3.4\n198.20.0.0 1.2.3.4\n\n"));
    check("the good line is applied", 0x01020304, real_of(0xc6120009u));
    check("the malformed ones are not", 0, real_of(0xc612000au) | real_of(0xc612000bu) | real_of(0xc612000cu));
    check("pool: last address in", 1, ctlmap_in_pool(ip("198.19.255.255")));
    check("pool: one past it out", 0, ctlmap_in_pool(ip("198.20.0.0")));
    check("pool: one before it out", 0, ctlmap_in_pool(ip("198.17.255.255")));
    ctlmap_init(ip("198.18.200.1"), 15);
    /* catches: a pool with host bits that matches nothing */
    check("host bits of the pool are ignored", 1, ctlmap_in_pool(ip("198.19.0.7")));
    ctlmap_init(0, 0);
    check("no pool: nothing is in it", 0, ctlmap_in_pool(ip("198.18.0.1")));
    check("no pool: no line is taken", 0, map("198.18.0.1 1.2.3.4\n\n"));
    ctlmap_init(be(POOL), 15);
}

static void a_real_of_zero_is_taken_as_a_dash(void) {
    uint32_t f = ip("198.18.0.15");
    struct cm_real r;
    mapall("198.18.0.13 1.2.3.4\n\n");
    /* catches: an upstream's 0.0.0.0 answer refused, so fircd reads drift and stops resending */
    check("real 0.0.0.0 lines are counted", 2, map("198.18.0.13 0.0.0.0\n198.18.0.14 0.0.0.0\n\n"));
    check("and forget the entry", 0, real_of(0xc612000du) | real_of(0xc612000eu));
    ctlmap_ask(f);
    check("an asked fake answered 0.0.0.0 is counted", 1, map("198.18.0.15 0.0.0.0\n\n"));
    check("and reads denied", CM_DENIED, ctlmap_answer(f, &r));
    ctlmap_unask(f);
}

static uint32_t slot_home(uint32_t host) { return (host * 2654435761u) >> 15; }

static uint32_t homed(uint32_t want, uint32_t after) {
    for (uint32_t h = after + 1;; h++)
        if (slot_home(h) == want) return h;
}

static void line_of(char *b, uint32_t h, const char *real) {
    sprintf(b + strlen(b), "%u.%u.%u.%u %s\n", h >> 24, (h >> 16) & 255, (h >> 8) & 255, h & 255, real);
}

static void a_chain_across_the_last_slot_survives_a_delete(void) {
    ctlmap_init(ip("10.0.0.0"), 8);
    mapall("\n");
    uint32_t a = homed(131069, 0x0a000000u), b = homed(131070, a), c = homed(131071, b), d = homed(131071, c);
    char cmd[256] = "";
    line_of(cmd, a, "1.1.1.1");
    line_of(cmd, b, "2.2.2.2");
    line_of(cmd, c, "3.3.3.3");
    line_of(cmd, d, "4.4.4.4");
    strcat(cmd, "\n");
    map(cmd);
    cmd[0] = 0;
    line_of(cmd, a, "-");
    strcat(cmd, "\n");
    map(cmd);
    /* catches: a wrapped entry moved before its home (unmasked home distance) */
    check("wrap: an entry past slot 0 is still found", 0x04040404, real_of(d));
    check("wrap: the others are kept", 1, real_of(b) == 0x02020202 && real_of(c) == 0x03030303);
    mapall("\n");
    cmd[0] = 0;
    line_of(cmd, c, "3.3.3.3");
    line_of(cmd, d, "4.4.4.4");
    strcat(cmd, "\n");
    map(cmd);
    cmd[0] = 0;
    line_of(cmd, c, "-");
    strcat(cmd, "\n");
    map(cmd);
    /* catches: a wrapped entry left behind its emptied home (unmasked gap distance) */
    check("wrap: an entry moved back across slot 0 is found", 0x04040404, real_of(d));
    check("wrap: the dashed one is gone", 0, real_of(c));
    mapall("\n");
    ctlmap_init(be(POOL), 15);
}

static void a_command_cut_by_eof_is_dropped(void) {
    mapall("\n");
    /* catches: a command cut by EOF applied as if complete */
    check("cut map: -1", -1, map("198.18.0.1 1.2.3.4\n"));
    check("cut map: nothing applied", 0, real_of(POOL + 1));
    map("198.18.0.2 1.2.3.4\n\n");
    check("cut mapall: -1", -1, mapall("198.18.0.3 1.2.3.4\n"));
    check("cut mapall: nothing cleared", 0x01020304, real_of(POOL + 2));
    drain();
    check("cut close: -1", -1, closes("198.18.4.0/24\n"));
    uint32_t b[4];
    uint8_t l[4];
    int e = -1;
    check("cut close: nothing queued", 0, (long)ctlmap_take_closes(b, l, 4, &e) + e);
}

static void close_prefixes_are_queued_and_woken(void) {
    check("a wake fd exists", 1, ctlmap_wake_fd() >= 0);
    drain();
    check("close takes the two good lines", 2,
          closes("198.18.4.7/24\n10.0.0.0/8\nbad\n1.2.3.4/33\n1.2.3.4\n\n"));
    /* catches: a close the loop is never woken for */
    check("the loop is woken", 1, drain() > 0);
    uint32_t b[4] = { 0 };
    uint8_t l[4] = { 0 };
    int e = -1;
    check("one taken when one fits", 1, (long)ctlmap_take_closes(b, l, 1, &e));
    /* catches: a command's end reported before its last prefix is taken */
    check("  its command not ended yet", 0, e);
    /* catches: a prefix with host bits that the loop compares unmasked */
    check("first prefix, host bits cleared", 1, b[0] == ip("198.18.4.0") && l[0] == 24);
    check("then the second", 1, (long)ctlmap_take_closes(b, l, 4, &e));
    check("  and the command ends with it", 1, e);
    check("second prefix", 1, b[0] == ip("10.0.0.0") && l[0] == 8);
    /* catches: a prefix handed to the loop twice */
    check("then none", 0, (long)ctlmap_take_closes(b, l, 4, &e) + e);
    closes("10.1.0.0/16\n\n");
    closes("10.2.0.0/16\n\n");
    closes("\n");
    /* catches: two commands merged into one take, so the loop acks them once */
    check("two commands: the first alone", 1, (long)ctlmap_take_closes(b, l, 4, &e) == 1 && e == 1 && b[0] == ip("10.1.0.0"));
    /* catches: an empty command never acked */
    check("  then the second with the empty one after it", 1,
          (long)ctlmap_take_closes(b, l, 4, &e) == 1 && e == 2 && b[0] == ip("10.2.0.0"));
    closes("\n");
    check("an empty command alone ends with no prefix", 1, (long)ctlmap_take_closes(b, l, 4, &e) == 0 && e == 1);
    drain();
    char *big = malloc(4096 * 20 + 2);
    int posted = 0;
    for (int c = 0; c < 4; c++) {
        size_t o = 0;
        for (int k = 0; k < 4096; k++) o += (size_t)sprintf(big + o, "10.%d.%d.0/24\n", c, k & 255);
        strcpy(big + o, "\n");
        posted += closes(big);
    }
    free(big);
    check("16384 prefixes wait", 16384, posted);
    closes("192.0.2.0/24\n\n");
    /* catches: a close past the queue's cap dropped, keeping flows on routing they lost */
    check("past the cap: everything is closed", 1, (long)ctlmap_take_closes(b, l, 4, &e));
    check("the first is 0.0.0.0/0, ending the four commands it replaced", 1, b[0] == 0 && l[0] == 0 && e == 4);
    check("then the new one", 1, (long)ctlmap_take_closes(b, l, 4, &e));
    check("  ending its own command", 1, b[0] == ip("192.0.2.0") && l[0] == 24 && e == 1);
    drain();
    map("198.18.0.1 1.2.3.4\n\n");
    /* catches: a map answer the parked connections are never woken for */
    check("a map wakes the loop", 1, drain() > 0);
    mapall("\n");
    check("a mapall wakes the loop", 1, drain() > 0);
    check("nothing else wakes it", 0, (long)drain());
    check("the wake fd does not block", 1, (fcntl(ctlmap_wake_fd(), F_GETFL) & O_NONBLOCK) != 0);
    check("the wake fd is close-on-exec", 1, (fcntl(ctlmap_wake_fd(), F_GETFD) & FD_CLOEXEC) != 0);
}

static int g_stop;

static void *loop_side(void *arg) {
    (void)arg;
    struct cm_real r;
    uint32_t b[8];
    uint8_t l[8];
    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) {
        ctlmap_lookup(be(POOL + 5), &r);
        if (ctlmap_ask(be(POOL + 6)) >= 0 && ctlmap_answer(be(POOL + 6), &r) != CM_PENDING) ctlmap_unask(be(POOL + 6));
        ctlmap_take_closes(b, l, 8, NULL);
        ctlmap_in_pool(be(POOL + 7));
    }
    return NULL;
}

static void the_loop_reads_while_stdin_writes(void) {
    pthread_t t;
    g_stop = 0;
    pthread_create(&t, NULL, loop_side, NULL);
    for (int i = 0; i < 2000; i++) {
        mapall("198.18.0.5 1.1.1.1\n198.18.0.6 2.2.2.2\n\n");
        map("198.18.0.5 -\n198.18.0.6 -\n\n");
        closes("198.18.0.0/24\n\n");
    }
    __atomic_store_n(&g_stop, 1, __ATOMIC_RELEASE);
    pthread_join(t, NULL);
    ctlmap_unask(be(POOL + 6));
    while (ctlmap_take_closes((uint32_t[8]){ 0 }, (uint8_t[8]){ 0 }, 8, &(int){ 0 }) > 0) {}
    drain();
    /* catches: a table access outside the mutex (under SANITIZE=thread), or the last command not winning */
    check("after the race the last command stands", 0, real_of(POOL + 5) | real_of(POOL + 6));
}

static const uint8_t g_db8_7[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07 };

static int is_v6(uint32_t fake_be, const uint8_t *want) {
    struct cm_real r;
    return ctlmap_lookup(fake_be, &r) == CM_REAL && r.v6 == 1 && !memcmp(r.b, want, 16);
}

static int answered_v6(uint32_t fake_be, const uint8_t *want) {
    struct cm_real r;
    return ctlmap_answer(fake_be, &r) == CM_REAL && r.v6 == 1 && !memcmp(r.b, want, 16);
}

static void put_v6_line(struct body *b, uint32_t fake_h, uint32_t tail) {
    b->n += (size_t)sprintf(b->s + b->n, "%u.%u.%u.%u 2001:db8::%x:%x\n", fake_h >> 24, (fake_h >> 16) & 255,
                            (fake_h >> 8) & 255, fake_h & 255, tail >> 16, tail & 0xffffu);
}

static void db8_of(uint8_t *a, uint32_t tail) {
    static const uint8_t p[12] = { 0x20, 0x01, 0x0d, 0xb8 };
    memcpy(a, p, 12);
    a[12] = (uint8_t)(tail >> 24);
    a[13] = (uint8_t)(tail >> 16);
    a[14] = (uint8_t)(tail >> 8);
    a[15] = (uint8_t)tail;
}

/* Catches: a v6 real refused, stored without its family, or lost on the way to an asked fake */
static void a_line_maps_a_v6_real(void) {
    mapall("\n");
    static const uint8_t full[16] = { 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78,
                                      0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78 };
    static const uint8_t db8_8[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08 };
    check("two v6 lines and a v4 one are taken", 3,
          map("198.18.9.1 2001:db8::7\n198.18.9.2 2001:db8:1234:5678:9abc:def0:1234:5678\n198.18.9.3 1.2.3.4\n\n"));
    check("the short form reads its 16 bytes, family v6", 1, is_v6(ip("198.18.9.1"), g_db8_7));
    check("the longest form fits", 1, is_v6(ip("198.18.9.2"), full));
    check("the v4 line beside them reads v4", 0x01020304, real_of(0xc6120903u));
    check_str("no warning", "", g_err);
    check("a mapped v6 fake sends no miss", 0, ctlmap_ask(ip("198.18.9.1")));
    check("and the ask reads the v6 real", 1, answered_v6(ip("198.18.9.1"), g_db8_7));
    ctlmap_unask(ip("198.18.9.1"));
    check("an unmapped fake is asked", 1, ctlmap_ask(ip("198.18.9.4")));
    map("198.18.9.4 2001:db8::8\n\n");
    check("its v6 answer is recorded", 1, answered_v6(ip("198.18.9.4"), db8_8));
    check("and the table has it", 1, is_v6(ip("198.18.9.4"), db8_8));
    ctlmap_unask(ip("198.18.9.4"));
}

/* Catches: a malformed v6 text taken, or a bad line counted */
static void a_bad_v6_real_is_not_taken(void) {
    mapall("\n");
    check("only the good line is taken", 1,
          map("198.18.9.5 2001:db8::zz\n198.18.9.6 2001:db8:::1\n198.18.9.7 1:2:3:4:5:6:7:8:9\n"
              "198.18.9.8 2001:db8:0000:0000:0000:0000:0000:0000:1\n198.18.9.9 2001:db8::7\n\n"));
    check_str("the four are malformed", "tunvless[warn]: map: 4 malformed lines left out\n", g_err);
    check("none of them is there", CM_NONE, ctlmap_lookup(ip("198.18.9.5"), &(struct cm_real){ { 0 }, 0 }) |
          ctlmap_lookup(ip("198.18.9.6"), &(struct cm_real){ { 0 }, 0 }) |
          ctlmap_lookup(ip("198.18.9.7"), &(struct cm_real){ { 0 }, 0 }) |
          ctlmap_lookup(ip("198.18.9.8"), &(struct cm_real){ { 0 }, 0 }));
    check("the good one is", 1, is_v6(ip("198.18.9.9"), g_db8_7));
}

/* Catches: an unbounded v6 table, a line past its cap counted, or room never given back */
static void a_v6_line_past_the_cap_is_counted_bad(void) {
    mapall("\n");
    struct body b = body_new(4096);
    for (uint32_t k = 0; k < 4096; k++) put_v6_line(&b, POOL + k, 0x10000u + k);
    check("4096 v6 lines are taken", 4096, map(body_end(&b)));
    free(b.s);
    uint8_t want[16];
    db8_of(want, 0x10000u + 4095);
    check("the last of them is there", 1, is_v6(be(POOL + 4095), want));
    check("the 4097th is not counted", 0, map("198.18.16.0 2001:db8::1\n\n"));
    check_str("and counted as malformed", "tunvless[warn]: map: 1 malformed lines left out\n", g_err);
    check("nor is it there", CM_NONE, ctlmap_lookup(be(POOL + 4096), &(struct cm_real){ { 0 }, 0 }));
    check("a v4 line for a new fake still goes in", 1, map("198.18.16.1 1.1.1.1\n\n"));
    check("an update of a v6 fake at the cap is taken", 1, map("198.18.0.0 2001:db8::7\n\n"));
    check("and applied", 1, is_v6(be(POOL), g_db8_7));
    check("a dash frees room for a new v6 fake", 2, map("198.18.0.1 -\n198.18.16.0 2001:db8::7\n\n"));
    check("the new one is there", 1, is_v6(be(POOL + 4096), g_db8_7));
    check("a v4 line for a v6 fake frees room too", 2, map("198.18.0.2 2.2.2.2\n198.18.16.2 2001:db8::7\n\n"));
    check("the next new one is there", 1, is_v6(be(POOL + 4098), g_db8_7));
    check("a fake past the cap is asked", 1, ctlmap_ask(be(POOL + 5000)));
    check("its v6 answer is counted", 1, map("198.18.19.136 2001:db8::7\n\n"));
    check("and recorded for the waiting connection", 1, answered_v6(be(POOL + 5000), g_db8_7));
    check("but not put in the full table", CM_NONE, ctlmap_lookup(be(POOL + 5000), &(struct cm_real){ { 0 }, 0 }));
    ctlmap_unask(be(POOL + 5000));
    mapall("\n");
    check("a mapall clears the v6 table", CM_NONE, ctlmap_lookup(be(POOL + 4095), &(struct cm_real){ { 0 }, 0 }));
    check("and makes room again", 1, map("198.18.16.3 2001:db8::7\n\n"));
}

/* Catches: a v6 real left behind a v4 line for its fake, or a v4 real behind a v6 line */
static void a_v4_line_replaces_a_v6_real_and_back(void) {
    mapall("\n");
    uint32_t f = ip("198.18.9.10");
    map("198.18.9.10 2001:db8::7\n\n");
    check("first the v6 real", 1, is_v6(f, g_db8_7));
    check("a v4 line is taken", 1, map("198.18.9.10 5.5.5.5\n\n"));
    check("and the fake reads v4", 0x05050505, real_of(0xc612090au));
    check("a v6 line is taken", 1, map("198.18.9.10 2001:db8::7\n\n"));
    check("and the fake reads v6 again", 1, is_v6(f, g_db8_7));
    check("asked while mapped, it reads the v6 real", 1, ctlmap_ask(f) == 0 && answered_v6(f, g_db8_7));
    map("198.18.9.10 6.6.6.6\n\n");
    struct cm_real r;
    check("a v4 answer replaces the v6 one in the asked set", 1,
          ctlmap_answer(f, &r) == CM_REAL && !r.v6 && v4_of(&r) == ip("6.6.6.6") && !memcmp(r.b + 4, (uint8_t[12]){ 0 }, 12));
    ctlmap_unask(f);
}

/* Catches: a v6 real kept after a dash or a mapall without it */
static void a_dash_forgets_a_v6_real(void) {
    mapall("\n");
    uint32_t f = ip("198.18.9.11");
    map("198.18.9.11 2001:db8::7\n\n");
    check("a dash for a v6 fake is counted", 1, map("198.18.9.11 -\n\n"));
    check("and forgets it", CM_NONE, ctlmap_lookup(f, &(struct cm_real){ { 0 }, 0 }));
    map("198.18.9.11 2001:db8::7\n\n");
    check("asked while mapped", 0, ctlmap_ask(f));
    map("198.18.9.11 -\n\n");
    check("a dash answers denied", CM_DENIED, ctlmap_answer(f, &(struct cm_real){ { 0 }, 0 }));
    ctlmap_unask(f);
    map("198.18.9.11 2001:db8::7\n\n");
    mapall("198.18.9.12 1.1.1.1\n\n");
    check("a mapall without it forgets it", CM_NONE, ctlmap_lookup(f, &(struct cm_real){ { 0 }, 0 }));
    mapall("\n");
}

/* Catches: a close dropping the v6 reals of its prefix, so every cross pair of a routed group misses */
static void a_close_leaves_a_v6_real(void) {
    mapall("198.18.10.2 1.1.1.1\n\n");
    map("198.18.10.1 2001:db8::7\n\n");
    closes("198.18.10.0/24\n\n");
    while (ctlmap_take_closes((uint32_t[8]){ 0 }, (uint8_t[8]){ 0 }, 8, &(int){ 0 }) > 0) {}
    drain();
    check("a close leaves a v6 real inside its prefix", 1, is_v6(ip("198.18.10.1"), g_db8_7));
    check("as it leaves a v4 real", 0x01010101, real_of(0xc6120a02u));
    mapall("\n");
}

int main(void) {
    check("init", 0, ctlmap_init(be(POOL), 15));
    a_line_maps_and_dash_forgets();
    mapall_clears_stale_entries();
    the_cap_drops_and_does_not_count();
    a_command_takes_4096_lines();
    an_asked_fake_records_real_and_dash();
    the_257th_ask_is_refused();
    a_line_outside_the_pool_is_not_taken();
    a_real_of_zero_is_taken_as_a_dash();
    a_chain_across_the_last_slot_survives_a_delete();
    a_command_cut_by_eof_is_dropped();
    close_prefixes_are_queued_and_woken();
    the_loop_reads_while_stdin_writes();
    a_line_maps_a_v6_real();
    a_bad_v6_real_is_not_taken();
    a_v6_line_past_the_cap_is_counted_bad();
    a_v4_line_replaces_a_v6_real_and_back();
    a_dash_forgets_a_v6_real();
    a_close_leaves_a_v6_real();
    return unit_done("ctlmapmatch");
}
