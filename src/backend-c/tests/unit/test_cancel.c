#include "greatest.h"

#include <poll.h>

#include "firc/cancel.h"

static bool fd_readable(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    return poll(&p, 1, 0) == 1 && (p.revents & POLLIN) != 0;
}

TEST starts_lowered(void) {
    firc_cancel_t *c = firc_cancel_new();
    ASSERT(c != NULL);
    ASSERT(!firc_cancel_raised(c));
    ASSERT(!fd_readable(firc_cancel_fd(c)));
    firc_cancel_free(c);
    PASS();
}

TEST raise_is_visible_both_ways(void) {
    firc_cancel_t *c = firc_cancel_new();
    firc_cancel_raise(c);
    ASSERT(firc_cancel_raised(c));
    ASSERT(fd_readable(firc_cancel_fd(c)));
    firc_cancel_free(c);
    PASS();
}

TEST clear_lowers_and_drains(void) {
    firc_cancel_t *c = firc_cancel_new();
    firc_cancel_raise(c);
    firc_cancel_clear(c);
    ASSERT(!firc_cancel_raised(c));
    ASSERT(!fd_readable(firc_cancel_fd(c)));
    firc_cancel_free(c);
    PASS();
}

/* Catches: raises piling up until the pipe is full and the requester blocks. */
TEST repeated_raises_do_not_fill_the_pipe(void) {
    firc_cancel_t *c = firc_cancel_new();
    for (int i = 0; i < 100000; i++) { firc_cancel_raise(c); }
    ASSERT(firc_cancel_raised(c));
    firc_cancel_clear(c);
    ASSERT(!firc_cancel_raised(c));
    ASSERT(!fd_readable(firc_cancel_fd(c)));
    firc_cancel_free(c);
    PASS();
}

TEST reraise_after_clear(void) {
    firc_cancel_t *c = firc_cancel_new();
    firc_cancel_raise(c);
    firc_cancel_clear(c);
    firc_cancel_raise(c);
    ASSERT(firc_cancel_raised(c));
    ASSERT(fd_readable(firc_cancel_fd(c)));
    firc_cancel_free(c);
    PASS();
}

TEST null_is_never_raised(void) {
    ASSERT(!firc_cancel_raised(NULL));
    ASSERT_EQ(-1, firc_cancel_fd(NULL));
    firc_cancel_raise(NULL);
    firc_cancel_clear(NULL);
    firc_cancel_free(NULL);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(starts_lowered);
    RUN_TEST(raise_is_visible_both_ways);
    RUN_TEST(clear_lowers_and_drains);
    RUN_TEST(repeated_raises_do_not_fill_the_pipe);
    RUN_TEST(reraise_after_clear);
    RUN_TEST(null_is_never_raised);
    GREATEST_MAIN_END();
}
