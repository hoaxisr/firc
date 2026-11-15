#include "greatest.h"

#include <stddef.h>

#include "firc/tunvless_name.h"

/* Catches: a non-canonical or out-of-range device given a port, or a canonical one refused. */
TEST only_a_canonical_tunvless_device_has_a_number(void) {
    ASSERT_EQ(0, firc_tundev_name_index("tunvless0"));
    ASSERT_EQ(3, firc_tundev_name_index("tunvless3"));
    ASSERT_EQ(42, firc_tundev_name_index("tunvless42"));
    ASSERT_EQ(99, firc_tundev_name_index("tunvless99"));
    ASSERT_EQ(-1, firc_tundev_name_index("tunvless100"));
    ASSERT_EQ(-1, firc_tundev_name_index("tunvless03"));
    ASSERT_EQ(-1, firc_tundev_name_index("tunvless00"));
    ASSERT_EQ(-1, firc_tundev_name_index("tunvless"));
    ASSERT_EQ(-1, firc_tundev_name_index("tunvless3a"));
    ASSERT_EQ(-1, firc_tundev_name_index("tunvless-1"));
    ASSERT_EQ(-1, firc_tundev_name_index("Tunvless3"));
    ASSERT_EQ(-1, firc_tundev_name_index("eth0"));
    ASSERT_EQ(9, firc_tundev_name_index("tunvless9"));
    ASSERT_EQ(-1, firc_tundev_name_index("tunvless01"));
    ASSERT_EQ(-1, firc_tundev_name_index(""));
    ASSERT_EQ(-1, firc_tundev_name_index("tunvlessx"));
    ASSERT_EQ(-1, firc_tundev_name_index(NULL));
    PASS();
}

/* Catches: opkgtun<N> refused, numbered differently from tunvless<N>, or held to the tunvless bound. */
TEST opkgtun_is_numbered_up_to_the_router_s_limit(void) {
    ASSERT_EQ(0, firc_tundev_name_index("opkgtun0"));
    ASSERT_EQ(3, firc_tundev_name_index("opkgtun3"));
    ASSERT_EQ(10, firc_tundev_name_index("opkgtun10"));
    ASSERT_EQ(16, firc_tundev_name_index("opkgtun16"));
    ASSERT_EQ(-1, firc_tundev_name_index("opkgtun17"));
    ASSERT_EQ(-1, firc_tundev_name_index("opkgtun42"));
    ASSERT_EQ(-1, firc_tundev_name_index("opkgtun99"));
    ASSERT_EQ(-1, firc_tundev_name_index("opkgtun100"));
    ASSERT_EQ(-1, firc_tundev_name_index("opkgtun01"));
    ASSERT_EQ(-1, firc_tundev_name_index("opkgtun"));
    ASSERT_EQ(-1, firc_tundev_name_index("opkgtunx"));
    ASSERT_EQ(17, firc_tundev_name_index("tunvless17"));
    ASSERT(firc_tundev_is_opkg("opkgtun7"));
    ASSERT(firc_tundev_is_opkg("opkgtun"));
    ASSERT(!firc_tundev_is_opkg("tunvless7"));
    ASSERT(!firc_tundev_is_opkg("opkgtu"));
    ASSERT(!firc_tundev_is_opkg(NULL));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(only_a_canonical_tunvless_device_has_a_number);
    RUN_TEST(opkgtun_is_numbered_up_to_the_router_s_limit);
    GREATEST_MAIN_END();
}
