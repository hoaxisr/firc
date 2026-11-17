#include <stdio.h>
#include "unit.h"
#include "../src/lib/portpick.h"

static uint16_t pick(const char *spec, uint32_t x) {
    struct port_range r[PORT_RANGES_MAX];
    size_t n = port_ranges(spec, r, PORT_RANGES_MAX);
    return n ? port_pick(r, n, x) : 0;
}

static void the_pick_counts_ports_not_ranges(void) {
    check("1-3,10 x 0", 1, pick("1-3,10", 0));
    check("1-3,10 x 2", 3, pick("1-3,10", 2));
    check("1-3,10 x 3", 10, pick("1-3,10", 3));
    check("1-3,10 x 4 wraps", 1, pick("1-3,10", 4));
    check("1-3,10 x 7 wraps", 10, pick("1-3,10", 7));
    check("20000-30000 x 10000", 30000, pick("20000-30000", 10000));
    check("20000-30000 x 10001 wraps", 20000, pick("20000-30000", 10001));
    check("every port of 443,20000-20002 is reachable: 0", 443, pick("443,20000-20002", 0));
    check("every port of 443,20000-20002 is reachable: 1", 20000, pick("443,20000-20002", 1));
    check("every port of 443,20000-20002 is reachable: 2", 20001, pick("443,20000-20002", 2));
    check("every port of 443,20000-20002 is reachable: 3", 20002, pick("443,20000-20002", 3));
    check("a duplicate weighs twice: x 0", 5, pick("5,5-6", 0));
    check("a duplicate weighs twice: x 1", 5, pick("5,5-6", 1));
    check("a duplicate weighs twice: x 2", 6, pick("5,5-6", 2));
    check("the largest x", 65535, pick("65535", 0xffffffffu));
    check("a full range at the top x", 65535, pick("1-65535", 65534));
}

static void the_list_reader_keeps_order_and_bounds(void) {
    struct port_range r[PORT_RANGES_MAX];
    check("two items", 2, (long)port_ranges("443,20000-30000", r, PORT_RANGES_MAX));
    check("first lo", 443, r[0].lo);
    check("first hi", 443, r[0].hi);
    check("second lo", 20000, r[1].lo);
    check("second hi", 30000, r[1].hi);
    check("single", 1, (long)port_ranges("5000", r, PORT_RANGES_MAX));
    check("empty", 0, (long)port_ranges("", r, PORT_RANGES_MAX));
    check("reversed", 0, (long)port_ranges("6000-5000", r, PORT_RANGES_MAX));
    check("zero", 0, (long)port_ranges("0", r, PORT_RANGES_MAX));
    check("zero low", 0, (long)port_ranges("0-5", r, PORT_RANGES_MAX));
    check("too big", 0, (long)port_ranges("65536", r, PORT_RANGES_MAX));
    check("empty item", 0, (long)port_ranges("443,,80", r, PORT_RANGES_MAX));
    check("trailing comma", 0, (long)port_ranges("443,", r, PORT_RANGES_MAX));
    check("junk", 0, (long)port_ranges("44a", r, PORT_RANGES_MAX));
    check("dash only", 0, (long)port_ranges("5-", r, PORT_RANGES_MAX));
    check("wrong separator", 0, (long)port_ranges("5;6", r, PORT_RANGES_MAX));
    check("a range of three", 0, (long)port_ranges("5-6-7", r, PORT_RANGES_MAX));
    check("space", 0, (long)port_ranges("5, 6", r, PORT_RANGES_MAX));
    check("a long number does not wrap", 0, (long)port_ranges("4294967297", r, PORT_RANGES_MAX));
    check("cap reached exactly", 2, (long)port_ranges("1,2", r, 2));
    check("one over the cap", 0, (long)port_ranges("1,2,3", r, 2));
    check("zero cap", 0, (long)port_ranges("1", r, 0));
    char many[256];
    size_t o = 0;
    for (int i = 1; i <= PORT_RANGES_MAX; i++) o += (size_t)snprintf(many + o, sizeof many - o, "%s%d", i > 1 ? "," : "", i);
    check("PORT_RANGES_MAX items", PORT_RANGES_MAX, (long)port_ranges(many, r, PORT_RANGES_MAX));
    snprintf(many + o, sizeof many - o, ",99");
    check("PORT_RANGES_MAX plus one", 0, (long)port_ranges(many, r, PORT_RANGES_MAX));
}

static void no_ranges_pick_nothing(void) {
    struct port_range r[1] = { { 1, 2 } };
    check("n 0", 0, port_pick(r, 0, 5));
}

int main(void) {
    the_pick_counts_ports_not_ranges();
    the_list_reader_keeps_order_and_bounds();
    no_ranges_pick_nothing();
    return unit_done("portpickmatch");
}
