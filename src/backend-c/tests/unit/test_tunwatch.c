#include "greatest.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "firc/events.h"
#include "firc/log.h"
#include "firc/tunwatch.h"

#define MIN (60 * 1000)

static size_t journal(firc_event_t *out, size_t cap) {
    uint64_t next = 0, dropped = 0;
    return firc_event_read(0, out, cap, &next, &dropped);
}

static void quiet(bool on) {
    static int fd = -1;
    if (on) {
        firc_event_reset_for_test();
        fd = open("/dev/null", O_WRONLY);
        firc_log_set_fd(fd);
        return;
    }
    firc_log_set_fd(STDOUT_FILENO);
    close(fd);
}

/* Catches: the alarm said before five minutes, never said, said without its device, or not at ERROR. */
TEST five_minutes_without_a_node_is_one_error(void) {
    quiet(true);
    firc_tunwatch_t w = {0};
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_NO_NODE, 1000);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_BACKOFF, 1000 + 5 * MIN - 1);
    firc_event_t ev[8];
    size_t before = journal(ev, 8);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_STARTING, 1000 + 5 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_NO_NODE, 1000 + 6 * MIN);
    size_t n = journal(ev, 8);
    quiet(false);
    ASSERT_EQ_FMT((size_t)0, before, "%zu");
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_EQ(FIRC_LOG_ERROR, ev[0].u.log.level);
    ASSERT_STR_EQ("tunvless0", ev[0].u.log.source);
    ASSERT_STR_EQ("no node has worked for 5 min; groups on it fail closed", ev[0].u.log.text);
    PASS();
}

/* Catches: no reminder while it lasts, a reminder sooner than ten minutes after the last, one that keeps the first duration, or a cause other than the nodes worded as a node failure. */
TEST it_is_said_again_every_ten_minutes_while_it_lasts(void) {
    quiet(true);
    firc_tunwatch_t w = {0};
    firc_tunwatch_see(&w, "tunvless1", FIRC_TUN_ST_WAITING, 0);
    firc_tunwatch_see(&w, "tunvless1", FIRC_TUN_ST_WAITING, 5 * MIN);
    firc_tunwatch_see(&w, "tunvless1", FIRC_TUN_ST_WAITING, 15 * MIN - 1);
    firc_tunwatch_see(&w, "tunvless1", FIRC_TUN_ST_UPLINK_DOWN, 15 * MIN);
    firc_tunwatch_see(&w, "tunvless1", FIRC_TUN_ST_BAD_CONFIG, 24 * MIN);
    firc_tunwatch_see(&w, "tunvless1", FIRC_TUN_ST_BAD_CONFIG, 25 * MIN);
    firc_event_t ev[8];
    size_t n = journal(ev, 8);
    quiet(false);
    ASSERT_EQ_FMT((size_t)3, n, "%zu");
    ASSERT_STR_EQ("it has had no nodes to use for 5 min; groups on it fail closed", ev[0].u.log.text);
    ASSERT_STR_EQ("its uplink has been down for 15 min; groups on it fail closed", ev[1].u.log.text);
    ASSERT_EQ(FIRC_LOG_ERROR, ev[1].u.log.level);
    ASSERT_STR_EQ("its configuration has been refused for 25 min; groups on it fail closed", ev[2].u.log.text);
    PASS();
}

/* Catches: a recovery not said after the alarm, said without one, or the next outage timed from the first. */
TEST a_working_node_ends_it_with_an_info(void) {
    quiet(true);
    firc_tunwatch_t w = {0};
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_NO_NODE, 0);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_UP, 4 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_NO_NODE, 4 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_NO_NODE, 8 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_NO_NODE, 9 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_UP, 17 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_UP, 18 * MIN);
    firc_event_t ev[8];
    size_t n = journal(ev, 8);
    quiet(false);
    ASSERT_EQ_FMT((size_t)2, n, "%zu");
    ASSERT_STR_EQ("no node has worked for 5 min; groups on it fail closed", ev[0].u.log.text);
    ASSERT_EQ(FIRC_LOG_INFO, ev[1].u.log.level);
    ASSERT_STR_EQ("tunvless0", ev[1].u.log.source);
    ASSERT_STR_EQ("recovered: a node works again after 13 min without one", ev[1].u.log.text);
    PASS();
}

/* Catches: a tunnel switched off counted as down, or its earlier outage carried into the next one. */
TEST an_off_tunnel_starts_over_without_a_word(void) {
    quiet(true);
    firc_tunwatch_t w = {0};
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_NO_NODE, 0);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_NO_NODE, 6 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_OFF, 7 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_OFF, 30 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_STARTING, 31 * MIN);
    firc_tunwatch_see(&w, "tunvless0", FIRC_TUN_ST_STARTING, 35 * MIN);
    firc_event_t ev[8];
    size_t n = journal(ev, 8);
    quiet(false);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_EQ(FIRC_LOG_ERROR, ev[0].u.log.level);
    PASS();
}

/* Catches: a tunnel held for its router interface worded as a node failure. */
TEST a_router_interface_not_ready_is_said_as_such(void) {
    quiet(true);
    firc_tunwatch_t w = {0};
    firc_tunwatch_see(&w, "opkgtun3", FIRC_TUN_ST_ROUTER, 0);
    firc_tunwatch_see(&w, "opkgtun3", FIRC_TUN_ST_ROUTER, 5 * MIN);
    firc_event_t ev[8];
    size_t n = journal(ev, 8);
    quiet(false);
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT_STR_EQ("its router interface has not been ready for 5 min; groups on it fail closed", ev[0].u.log.text);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(five_minutes_without_a_node_is_one_error);
    RUN_TEST(it_is_said_again_every_ten_minutes_while_it_lasts);
    RUN_TEST(a_working_node_ends_it_with_an_info);
    RUN_TEST(an_off_tunnel_starts_over_without_a_word);
    RUN_TEST(a_router_interface_not_ready_is_said_as_such);
    GREATEST_MAIN_END();
}
