#include "greatest.h"

#include <string.h>

#include "firc/crypt.h"

static enum greatest_test_res check(const char *pw, const char *salt, const char *want) {
    char out[128];
    firc_err_t err = firc_crypt_password(pw, salt, out, sizeof(out));
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_STR_EQ(want, out);
    PASS();
}

TEST md5_crypt_vectors(void) {
    CHECK_CALL(check("hunter2", "$1$abcdefgh", "$1$abcdefgh$vhxKZ/s1ygZHyCEDPyqtQ/"));
    CHECK_CALL(check("password123", "$1$saltsalt", "$1$saltsalt$4WS.Uhxmahm1YZiMsUNcc0"));
    CHECK_CALL(check("", "$1$abcdefgh", "$1$abcdefgh$M55TzYaaccxVGbptZWaxX/"));
    PASS();
}

TEST sha256_crypt_vectors(void) {
    CHECK_CALL(check("hunter2", "$5$abcdefghijklmnop",
                     "$5$abcdefghijklmnop$/xm2M1oTvGc2fCTR8/zBr3MgGwgm.aL3PLXlM2aQy86"));
    CHECK_CALL(check("hunter2", "$5$rounds=10000$abcdefghijklmnop",
                     "$5$rounds=10000$abcdefghijklmnop$pm5juhOHzqF9LR1KWcvuet2HL//."
                     "ixPWtkp2DBGUWfB"));
    PASS();
}

TEST sha512_crypt_vectors(void) {
    CHECK_CALL(check("hunter2", "$6$abcdefghijklmnop",
                     "$6$abcdefghijklmnop$EC.xeLW9zNWcX0r23FSpQaV7PG.Ibd4QnLe3w6UC47i3/"
                     "vkPQouEDwvUpGtqFiad5mzQG96cD/LywQiXv9WfH/"));
    CHECK_CALL(check("hunter2", "$6$rounds=10000$abcdefghijklmnop",
                     "$6$rounds=10000$abcdefghijklmnop$"
                     "2jAMCbARNQ6ZKCEt2BhJF2f6KsGfyxSWQr.lONjoATHYakwUDfXRWfU8/mwmX4f4Ll"
                     "japsp4H.w54IxzKneAm1"));
    PASS();
}

TEST sha512_crypt_long_password(void) {
    CHECK_CALL(check("a very long password indeed that is more than sixty four bytes "
                     "in length for sure",
                     "$6$saltsalt12345678",
                     "$6$saltsalt12345678$gLMxtCMuwQ711i5VH05X9Qy6bspp/IwxO2LoZNuzvXp8c"
                     "L/LphiNHZZX8pXif1FLMXttrdv0WXPUZG8MjhcXi."));
    PASS();
}

TEST unsupported_prefix_is_invalid(void) {
    char out[128];
    ASSERT_EQ(FIRC_ERR_INVAL, firc_crypt_password("x", "$2b$10$abcdefgh", out, sizeof(out)));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(md5_crypt_vectors);
    RUN_TEST(sha256_crypt_vectors);
    RUN_TEST(sha512_crypt_vectors);
    RUN_TEST(sha512_crypt_long_password);
    RUN_TEST(unsupported_prefix_is_invalid);
    GREATEST_MAIN_END();
}
