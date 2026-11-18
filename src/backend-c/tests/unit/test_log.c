#include "greatest.h"

#include <time.h>

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "firc/events.h"
#include "firc/log.h"

static ssize_t capture(int level_to_log, const char *msg, char *out,
                       size_t out_len)
{
    int fds[2];
    if (pipe(fds) != 0) {
        return -1;
    }
    firc_log_set_fd(fds[1]);
    firc_log((firc_log_level_t)level_to_log, "%s", msg);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    ssize_t n = read(fds[0], out, out_len - 1);
    close(fds[0]);
    if (n < 0) {
        n = 0;
    }
    out[n] = '\0';
    return n;
}

/* Catches: a level threshold that keeps any of the four levels out of the journal. */
TEST the_journal_records_every_level(void) {
    firc_event_reset_for_test();
    int devnull = open("/dev/null", O_WRONLY);
    ASSERT(devnull >= 0);
    firc_log_set_fd(devnull);
    FIRC_DEBUG("d");
    FIRC_INFO("i");
    FIRC_WARN("w");
    FIRC_ERROR("e");
    firc_log_set_fd(STDOUT_FILENO);
    close(devnull);
    firc_event_t out[8];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)4, firc_event_read(0, out, 8, &next, &dropped), "%zu");
    static const firc_log_level_t want[] = {FIRC_LOG_DEBUG, FIRC_LOG_INFO, FIRC_LOG_WARN, FIRC_LOG_ERROR};
    for (size_t i = 0; i < 4; i++) { ASSERT_EQ(want[i], out[i].u.log.level); }
    PASS();
}

/* Catches: a source lost on the way to the journal, kept in the text, or missing from the output line. */
TEST a_line_from_a_tunnel_carries_its_device(void) {
    firc_event_reset_for_test();
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_fd(fds[1]);
    firc_log_from(FIRC_LOG_WARN, "tunvless0", "node %s does not answer", "A");
    FIRC_INFO("plain");
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    char buf[512];
    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    ASSERT(n > 0);
    buf[n] = '\0';
    ASSERT(strstr(buf, " WRN tunvless0: node A does not answer\n") != NULL);
    ASSERT(strstr(buf, " INF plain\n") != NULL);
    firc_event_t out[4];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)2, firc_event_read(0, out, 4, &next, &dropped), "%zu");
    ASSERT_STR_EQ("tunvless0", out[0].u.log.source);
    ASSERT_STR_EQ("node A does not answer", out[0].u.log.text);
    ASSERT_EQ(FIRC_LOG_WARN, out[0].u.log.level);
    ASSERT_STR_EQ("", out[1].u.log.source);
    ASSERT_STR_EQ("plain", out[1].u.log.text);
    PASS();
}

/* Catches: an output floor that also starves the journal, or lets a line under it through. */
TEST the_output_floor_thins_the_output_but_not_the_journal(void) {
    firc_event_reset_for_test();
    firc_log_set_output_floor(FIRC_LOG_INFO);
    firc_log_set_output_floor(FIRC_LOG_WARN);
    char out[256];
    ssize_t quiet = capture(FIRC_LOG_INFO, "kept for the journal", out, sizeof(out));
    ssize_t loud = capture(FIRC_LOG_WARN, "said everywhere", out, sizeof(out));
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    ASSERT_EQ_FMT((ssize_t)0, quiet, "%zd");
    ASSERT(loud > 0 && strstr(out, " WRN said everywhere") != NULL);
    firc_event_t ev[4];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)2, firc_event_read(0, ev, 4, &next, &dropped), "%zu");
    ASSERT_STR_EQ("kept for the journal", ev[0].u.log.text);
    PASS();
}

/* Catches: the ring not keeping the lines the daemon logged. */
TEST the_ring_keeps_what_the_daemon_said(void) {
    firc_event_reset_for_test();
    firc_log_set_output_floor(FIRC_LOG_INFO);
    int devnull = open("/dev/null", O_WRONLY);
    ASSERT(devnull >= 0);
    firc_log_set_fd(devnull);

    FIRC_INFO("first %d", 1);
    FIRC_WARN("second");
    FIRC_ERROR("third %s", "thing");

    firc_event_t out[8];
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(0, out, 8, &next, &dropped);
    ASSERT_EQ_FMT((size_t)3, n, "%zu");
    ASSERT_EQ_FMTm("nothing was lost", 0ULL, (unsigned long long)dropped, "%llu");
    ASSERT_STR_EQ("first 1", out[0].u.log.text);
    ASSERT_STR_EQ("second", out[1].u.log.text);
    ASSERT_STR_EQ("third thing", out[2].u.log.text);
    ASSERT_EQ(FIRC_LOG_INFO, out[0].u.log.level);
    ASSERT_EQ(FIRC_LOG_WARN, out[1].u.log.level);
    ASSERT_EQ(FIRC_LOG_ERROR, out[2].u.log.level);
    ASSERTm("each line has a time", out[0].at > 0);
    ASSERTm("the sequence rises", out[0].seq < out[1].seq && out[1].seq < out[2].seq);

    size_t m = firc_event_read(out[1].seq, out, 8, &next, &dropped);
    ASSERT_EQ_FMTm("only the third", (size_t)1, m, "%zu");
    ASSERT_STR_EQ("third thing", out[0].u.log.text);
    ASSERT_EQ_FMTm("and the cursor is that line", (unsigned long long)out[0].seq,
                   (unsigned long long)next, "%llu");

    ASSERT_EQ_FMT((size_t)0, firc_event_read(next, out, 8, &next, &dropped), "%zu");
    close(devnull);
    PASS();
}

/* Catches: a reader that fell behind not told the size of the hole. */
TEST a_reader_that_fell_behind_is_told_how_much_it_missed(void) {
    firc_event_reset_for_test();
    firc_log_set_output_floor(FIRC_LOG_INFO);
    int devnull = open("/dev/null", O_WRONLY);
    ASSERT(devnull >= 0);
    firc_log_set_fd(devnull);

    for (int i = 0; i < FIRC_EVENTS_LOG_RING + 88; i++) { FIRC_INFO("line %d", i); }

    firc_event_t *out = malloc(sizeof(*out) * FIRC_EVENTS_LOG_RING);
    ASSERT(out != NULL);
    uint64_t next = 0, dropped = 0;
    size_t n = firc_event_read(1, out, FIRC_EVENTS_LOG_RING, &next, &dropped);
    ASSERT_EQ_FMTm("the ring holds what it holds", (size_t)FIRC_EVENTS_LOG_RING, n, "%zu");
    ASSERT_EQ_FMTm("and says what fell out after the cursor", 87ULL, (unsigned long long)dropped, "%llu");
    ASSERT_STR_EQm("the oldest kept line is the 89th", "line 88", out[0].u.log.text);
    char last[32];
    snprintf(last, sizeof(last), "line %d", FIRC_EVENTS_LOG_RING + 87);
    ASSERT_STR_EQ(last, out[n - 1].u.log.text);
    free(out);
    close(devnull);
    PASS();
}

/* Catches: a long line dropped instead of cut. */
TEST a_line_longer_than_the_ring_holds_is_cut_not_dropped(void) {
    firc_event_reset_for_test();
    firc_log_set_output_floor(FIRC_LOG_INFO);
    int devnull = open("/dev/null", O_WRONLY);
    ASSERT(devnull >= 0);
    firc_log_set_fd(devnull);

    char big[FIRC_EVENT_TEXT * 2];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    FIRC_INFO("%s", big);

    firc_event_t out[4];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMTm("the line is there", (size_t)1, firc_event_read(0, out, 4, &next, &dropped),
                   "%zu");
    ASSERT_EQ_FMTm("cut to what the ring holds", (size_t)(FIRC_EVENT_TEXT - 1),
                   strlen(out[0].u.log.text), "%zu");
    ASSERT_EQ_FMTm("and it is the beginning", 'x', out[0].u.log.text[0], "%c");
    close(devnull);
    PASS();
}

TEST level_filtering(void)
{
    char buf[256];
    firc_log_set_output_floor(FIRC_LOG_WARN);
    ASSERT_EQ(0, capture(FIRC_LOG_INFO, "hidden", buf, sizeof(buf)));
    ASSERT(capture(FIRC_LOG_ERROR, "shown", buf, sizeof(buf)) > 0);
    ASSERT(strstr(buf, "ERR") != NULL);
    ASSERT(strstr(buf, "shown") != NULL);
    firc_log_set_output_floor(FIRC_LOG_INFO);
    PASS();
}

TEST line_format_has_timestamp_and_tag(void)
{
    char buf[256];
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    struct timespec before, after;
    clock_gettime(CLOCK_REALTIME, &before);
    ASSERT(capture(FIRC_LOG_INFO, "fmt-check", buf, sizeof(buf)) > 0);
    clock_gettime(CLOCK_REALTIME, &after);
    ASSERT_EQ('2', buf[0]);
    ASSERT_EQ('T', buf[10]);
    ASSERT_EQ('Z', buf[19]);
    ASSERT(strstr(buf, " INF fmt-check\n") != NULL);
    {
        char got[21];
        memcpy(got, buf, 20);
        got[20] = '\0';
        bool utc_second = false;
        for (time_t s = before.tv_sec; s <= after.tv_sec && !utc_second; s++) {
            struct tm utc;
            gmtime_r(&s, &utc);
            char expect[24];
            strftime(expect, sizeof(expect), "%Y-%m-%dT%H:%M:%SZ", &utc);
            utc_second = strcmp(got, expect) == 0;
        }
        ASSERTm("the timestamp is UTC, not local time wearing a Z", utc_second);
    }
    firc_log_set_output_floor(FIRC_LOG_INFO);
    PASS();
}

/* Catches: a control character in a logged value, such as a group name with a newline, splitting or garbling the line. */
TEST control_characters_never_reach_a_line(void)
{
    firc_event_reset_for_test();
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    char out[256];
    ASSERT(capture(FIRC_LOG_INFO, "group \"a\nb\tc\rd\x7f\x1b[0m\" \xd0\x96", out, sizeof(out)) > 0);
    firc_log_set_output_floor(FIRC_LOG_INFO);
    ASSERT(strstr(out, " INF group \"a?b?c?d??[0m\" \xd0\x96\n") != NULL);
    ASSERT_EQ(strchr(out, '\n'), out + strlen(out) - 1);
    firc_event_t ev[2];
    uint64_t next = 0, dropped = 0;
    ASSERT_EQ_FMT((size_t)1, firc_event_read(0, ev, 2, &next, &dropped), "%zu");
    ASSERT_STR_EQ("group \"a?b?c?d??[0m\" \xd0\x96", ev[0].u.log.text);
    PASS();
}

/* Catches: a level name dropped or mapped to the wrong level, or a removed name still accepted by the output floor. */
TEST exactly_four_level_names_parse(void)
{
    firc_log_level_t l = FIRC_LOG_ERROR;
    ASSERT(firc_log_level_parse("debug", &l));
    ASSERT_EQ(FIRC_LOG_DEBUG, l);
    ASSERT(firc_log_level_parse("info", &l));
    ASSERT_EQ(FIRC_LOG_INFO, l);
    ASSERT(firc_log_level_parse("warn", &l));
    ASSERT_EQ(FIRC_LOG_WARN, l);
    ASSERT(firc_log_level_parse("error", &l));
    ASSERT_EQ(FIRC_LOG_ERROR, l);
    static const char *const gone[] = {"trace", "fatal", "panic", "nolevel", "disabled", "Info", ""};
    for (size_t i = 0; i < sizeof(gone) / sizeof(gone[0]); i++) {
        l = FIRC_LOG_WARN;
        ASSERT_FALSEm(gone[i], firc_log_level_parse(gone[i], &l));
        ASSERT_EQm(gone[i], FIRC_LOG_WARN, l);
    }
    ASSERT_FALSE(firc_log_level_parse(NULL, &l));
    PASS();
}

/* Catches: a level below debug that the threshold or the output floor could still name. */
TEST debug_is_the_lowest_level(void)
{
    ASSERT_EQ(0, (int)FIRC_LOG_DEBUG);
    char buf[256];
    firc_log_set_output_floor(FIRC_LOG_DEBUG);
    ASSERT(capture(FIRC_LOG_DEBUG, "lowest", buf, sizeof(buf)) > 0);
    ASSERT(strstr(buf, " DBG lowest\n") != NULL);
    firc_log_set_output_floor(FIRC_LOG_INFO);
    PASS();
}

/* Catches: a stalled reader of the stdout pipe blocking the logging thread. */
TEST a_pipe_nobody_reads_does_not_block_the_logger(void)
{
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_fd(fds[1]);
    firc_log_nonblocking();
    ASSERT(fcntl(fds[1], F_GETFL) & O_NONBLOCK);
    char junk[4096];
    memset(junk, 'x', sizeof(junk));
    while (write(fds[1], junk, sizeof(junk)) > 0) { }
    while (write(fds[1], junk, 1) > 0) { }
    int before = 0, after = 0;
    ASSERT_EQ(0, ioctl(fds[0], FIONREAD, &before));
    firc_log(FIRC_LOG_ERROR, "%s", "dropped, not waited for");
    ASSERT_EQ(0, ioctl(fds[0], FIONREAD, &after));
    ASSERT_EQ_FMTm("the line was dropped, not queued", before, after, "%d");
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[0]);
    close(fds[1]);
    PASS();
}

TEST only_pipes_and_sockets_are_made_non_blocking(void)
{
    int sv[2];
    ASSERT_EQ(0, socketpair(AF_UNIX, SOCK_STREAM, 0, sv));
    firc_log_set_fd(sv[1]);
    firc_log_nonblocking();
    ASSERT(fcntl(sv[1], F_GETFL) & O_NONBLOCK);
    close(sv[0]);
    close(sv[1]);
    char path[] = "/tmp/firc-log-XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    firc_log_set_fd(fd);
    firc_log_nonblocking();
    ASSERT_FALSEm("a regular file is left alone", fcntl(fd, F_GETFL) & O_NONBLOCK);
    firc_log_set_fd(STDOUT_FILENO);
    close(fd);
    unlink(path);
    PASS();
}

/* Catches: repeated lines collapsed, which loses levels and timestamps. */
TEST the_only_rate_limiting_is_the_level(void)
{
    char buf[2048];
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_output_floor(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    for (int i = 0; i < 4; i++) { firc_log(FIRC_LOG_WARN, "the same thing"); }
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    ASSERT(n > 0);
    buf[n] = '\0';
    int said = 0;
    const char *q = buf;
    while ((q = strstr(q, "the same thing")) != NULL) { said++; q += 1; }
    ASSERT_EQ_FMTm("every line is written, with its own level and time", 4, said, "%d");
    ASSERTm("nothing is summarised", strstr(buf, "repeated") == NULL);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_journal_records_every_level);
    RUN_TEST(a_line_from_a_tunnel_carries_its_device);
    RUN_TEST(the_ring_keeps_what_the_daemon_said);
    RUN_TEST(the_output_floor_thins_the_output_but_not_the_journal);
    RUN_TEST(a_reader_that_fell_behind_is_told_how_much_it_missed);
    RUN_TEST(a_line_longer_than_the_ring_holds_is_cut_not_dropped);
    RUN_TEST(level_filtering);
    RUN_TEST(line_format_has_timestamp_and_tag);
    RUN_TEST(control_characters_never_reach_a_line);
    RUN_TEST(exactly_four_level_names_parse);
    RUN_TEST(debug_is_the_lowest_level);
    RUN_TEST(the_only_rate_limiting_is_the_level);
    RUN_TEST(a_pipe_nobody_reads_does_not_block_the_logger);
    RUN_TEST(only_pipes_and_sockets_are_made_non_blocking);
    GREATEST_MAIN_END();
}
