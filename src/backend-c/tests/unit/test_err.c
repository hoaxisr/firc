#include "greatest.h"

#include <errno.h>
#include <string.h>

#include "firc/err.h"

TEST every_code_has_a_string(void)
{
    for (int e = FIRC_OK; e <= FIRC_ERR_CANCELED; e++) {
        const char *s = firc_err_str((firc_err_t)e);
        ASSERT(s != NULL);
        ASSERT(strlen(s) > 0);
        ASSERT(strcmp(s, "unknown error") != 0);
    }
    PASS();
}

TEST errno_mapping(void)
{
    ASSERT_EQ(FIRC_OK, firc_err_from_errno(0));
    ASSERT_EQ(FIRC_ERR_NOMEM, firc_err_from_errno(ENOMEM));
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_err_from_errno(EAGAIN));
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_err_from_errno(EINTR));
    ASSERT_EQ(FIRC_ERR_TIMEOUT, firc_err_from_errno(ETIMEDOUT));
    ASSERT_EQ(FIRC_ERR_NOENT, firc_err_from_errno(ENOENT));
    ASSERT_EQ(FIRC_ERR_EXIST, firc_err_from_errno(EEXIST));
    ASSERT_EQ(FIRC_ERR_SYS, firc_err_from_errno(E2BIG));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(every_code_has_a_string);
    RUN_TEST(errno_mapping);
    GREATEST_MAIN_END();
}
