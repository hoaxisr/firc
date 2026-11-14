#include "greatest.h"

#include <stddef.h>

#include "firc/tunvless_name.h"

/* Catches: a non-canonical or out-of-range device given a port, or a canonical one refused. */
TEST only_a_canonical_tunvless_device_has_a_number(void) {
    ASSERT_EQ(0, firc_tunvless_index("tunvless0"));
    ASSERT_EQ(3, firc_tunvless_index("tunvless3"));
    ASSERT_EQ(42, firc_tunvless_index("tunvless42"));
    ASSERT_EQ(99, firc_tunvless_index("tunvless99"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless100"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless03"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless00"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless3a"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless-1"));
    ASSERT_EQ(-1, firc_tunvless_index("Tunvless3"));
    ASSERT_EQ(-1, firc_tunvless_index("eth0"));
    ASSERT_EQ(9, firc_tunvless_index("tunvless9"));
    ASSERT_EQ(-1, firc_tunvless_index("tunvless01"));
    ASSERT_EQ(-1, firc_tunvless_index(""));
    ASSERT_EQ(-1, firc_tunvless_index("tunvlessx"));
    ASSERT_EQ(-1, firc_tunvless_index(NULL));
    PASS();
}

/* Catches: opkgtun<N> refused, or numbered differently from tunvless<N>. */
TEST opkgtun_is_numbered_like_tunvless(void) {
    ASSERT_EQ(0, firc_tunvless_index("opkgtun0"));
    ASSERT_EQ(42, firc_tunvless_index("opkgtun42"));
    ASSERT_EQ(99, firc_tunvless_index("opkgtun99"));
    ASSERT_EQ(-1, firc_tunvless_index("opkgtun100"));
    ASSERT_EQ(-1, firc_tunvless_index("opkgtun01"));
    ASSERT_EQ(-1, firc_tunvless_index("opkgtun"));
    ASSERT_EQ(-1, firc_tunvless_index("opkgtunx"));
    ASSERT(firc_tunvless_prefixed("opkgtun7"));
    ASSERT(firc_tunvless_prefixed("tunvless7"));
    ASSERT(!firc_tunvless_prefixed("br0"));
    ASSERT(!firc_tunvless_prefixed(NULL));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(only_a_canonical_tunvless_device_has_a_number);
    RUN_TEST(opkgtun_is_numbered_like_tunvless);
    GREATEST_MAIN_END();
}
