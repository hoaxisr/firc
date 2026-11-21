#include "greatest.h"

#include <string.h>

#include "firc/cfrange.h"

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {{a, b, c, d}, 4};
    return ip;
}

static firc_ip_t v6(uint8_t a, uint8_t b, uint8_t last) {
    firc_ip_t ip = {{a, b}, 16};
    ip.b[15] = last;
    return ip;
}

TEST known_edges_are_inside(void) {
    firc_ip_t in4[] = {v4(104, 16, 0, 1), v4(188, 114, 96, 1), v4(172, 64, 155, 209), v4(162, 159, 128, 233),
                       v4(104, 23, 255, 255), v4(131, 0, 75, 255)};
    for (size_t i = 0; i < sizeof(in4) / sizeof(in4[0]); i++) {
        ASSERT_EQm("v4 inside", true, firc_cf_contains(&in4[i]));
    }
    firc_ip_t a = v6(0x26, 0x06, 1);
    a.b[2] = 0x47;
    ASSERT(firc_cf_contains(&a));
    firc_ip_t c = v6(0x2a, 0x06, 1);
    c.b[2] = 0x98;
    c.b[3] = 0xc7;
    ASSERT(firc_cf_contains(&c));
    PASS();
}

TEST neighbours_and_others_are_outside(void) {
    firc_ip_t out4[] = {v4(104, 15, 255, 255), v4(104, 32, 0, 0), v4(8, 8, 8, 8), v4(149, 154, 167, 99),
                        v4(131, 0, 76, 0)};
    for (size_t i = 0; i < sizeof(out4) / sizeof(out4[0]); i++) {
        ASSERT_EQm("v4 outside", false, firc_cf_contains(&out4[i]));
    }
    firc_ip_t a = v6(0x26, 0x06, 1);
    a.b[2] = 0x47;
    a.b[3] = 0x01;
    ASSERT_FALSE(firc_cf_contains(&a));
    firc_ip_t c = v6(0x2a, 0x06, 1);
    c.b[2] = 0x98;
    c.b[3] = 0xc8;
    ASSERT_FALSE(firc_cf_contains(&c));
    firc_ip_t empty;
    memset(&empty, 0, sizeof(empty));
    ASSERT_FALSE(firc_cf_contains(&empty));
    ASSERT_FALSE(firc_cf_contains(NULL));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(known_edges_are_inside);
    RUN_TEST(neighbours_and_others_are_outside);
    GREATEST_MAIN_END();
}
