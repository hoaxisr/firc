#include <stdint.h>
#include <string.h>
#include "unit.h"
#include "../src/proto/hysteria2/hy2loss.h"

struct iv { uint64_t sent, lost; int hop; uint64_t ms; };

static const char *steps(struct hy2loss *s, const struct iv *v, size_t n, char *out) {
    for (size_t i = 0; i < n; i++) out[i] = (char)('0' + hy2loss_step(s, v[i].sent, v[i].lost, v[i].hop, v[i].ms));
    out[n] = 0;
    return out;
}

#define RUN(s, out, ...)                                                                                              \
    steps(s, (const struct iv[]){ __VA_ARGS__ }, sizeof((const struct iv[]){ __VA_ARGS__ }) / sizeof(struct iv), out)

#define LOSSY_IV { 1000, 50, 0, 1000 }
#define CLEAN_IV { 1000, 20, 0, 1000 }

static void two_lossy_windows_say_lossy_once(void) {
    struct hy2loss s;
    char o[64];
    memset(&s, 0, sizeof s);
    check_str("1000/50 twice: lossy on the second", "01", RUN(&s, o, LOSSY_IV, LOSSY_IV));
    check("1000/50 twice: the deciding windows sent 2000", 2000, (long)s.run_sent);
    check("1000/50 twice: and lost 100", 100, (long)s.run_lost);
    check_str("two more lossy windows say lossy again", "01", RUN(&s, o, { 1000, 60, 0, 1000 }, { 1000, 70, 0, 1000 }));
    check("the repeat's deciding windows lost 130", 130, (long)s.run_lost);
}

static void a_grey_window_neither_counts_nor_resets(void) {
    struct hy2loss s;
    char o[64];
    memset(&s, 0, sizeof s);
    check_str("1000/50, 1000/49, 1000/50: lossy on the third", "001",
              RUN(&s, o, LOSSY_IV, { 1000, 49, 0, 1000 }, LOSSY_IV));
    check("grey between: the deciding windows sent 2000", 2000, (long)s.run_sent);
    check("grey between: and lost 100", 100, (long)s.run_lost);
}

static void a_clean_window_resets_the_run(void) {
    struct hy2loss s;
    char o[64];
    memset(&s, 0, sizeof s);
    check_str("1000/50, 1000/20, 1000/50: nothing", "000", RUN(&s, o, LOSSY_IV, CLEAN_IV, LOSSY_IV));
    check_str("one more 1000/50: lossy", "1", RUN(&s, o, LOSSY_IV));
    check("the deciding windows are the last two, 2000 sent", 2000, (long)s.run_sent);
}

static void intervals_add_up_to_a_window(void) {
    struct hy2loss s;
    char o[64];
    memset(&s, 0, sizeof s);
    struct iv v = { 100, 6, 0, 200 };
    check_str("ten intervals of 100/6: lossy on the tenth", "0000000001",
              RUN(&s, o, v, v, v, v, v, v, v, v, v, v));
    check("ten intervals: the deciding windows sent 1000", 1000, (long)s.run_sent);
    check("ten intervals: and lost 60", 60, (long)s.run_lost);
}

static void a_slow_window_is_dropped(void) {
    struct hy2loss s;
    char o[64];
    memset(&s, 0, sizeof s);
    check_str("499 packets over 10001 ms are dropped, one more starts afresh", "0000",
              RUN(&s, o, LOSSY_IV, { 250, 250, 0, 5000 }, { 249, 249, 0, 5001 }, { 1, 1, 0, 1 }));
    memset(&s, 0, sizeof s);
    check_str("499 packets over 10000 ms are kept, one more is judged", "0001",
              RUN(&s, o, LOSSY_IV, { 250, 250, 0, 5000 }, { 249, 249, 0, 5000 }, { 1, 1, 0, 1 }));
}

static void a_long_interval_is_dropped(void) {
    struct hy2loss s;
    char o[64];
    memset(&s, 0, sizeof s);
    check_str("an interval of exactly 10000 ms is judged", "01", RUN(&s, o, LOSSY_IV, { 1000, 50, 0, 10000 }));
    memset(&s, 0, sizeof s);
    check_str("an interval of 20000 ms with 5000/500 is dropped", "00",
              RUN(&s, o, LOSSY_IV, { 5000, 500, 0, 20000 }));
    memset(&s, 0, sizeof s);
    check_str("it takes the window it lands in along", "0000",
              RUN(&s, o, LOSSY_IV, { 400, 400, 0, 1000 }, { 5000, 500, 0, 20000 }, { 100, 0, 0, 1000 }));
}

static void a_hop_starts_a_new_run(void) {
    struct hy2loss s;
    char o[64];
    memset(&s, 0, sizeof s);
    check_str("a hop between two lossy windows: nothing, two more: lossy", "0001",
              RUN(&s, o, LOSSY_IV, { 1000, 50, 1, 1000 }, LOSSY_IV, LOSSY_IV));
    memset(&s, 0, sizeof s);
    check_str("a hop drops the window it ends", "00000",
              RUN(&s, o, LOSSY_IV, { 400, 400, 0, 1000 }, { 0, 0, 1, 1000 }, { 100, 100, 0, 1000 }, LOSSY_IV));
}

static void a_clean_window_after_a_verdict_starts_over(void) {
    struct hy2loss s;
    char o[64];
    memset(&s, 0, sizeof s);
    check_str("lossy, lossy, clean, lossy: nothing, one more lossy: lossy", "010001",
              RUN(&s, o, LOSSY_IV, LOSSY_IV, LOSSY_IV, CLEAN_IV, LOSSY_IV, LOSSY_IV));
}

static void an_idle_link_decides_nothing(void) {
    struct hy2loss s;
    memset(&s, 0, sizeof s);
    int said = 0;
    uint64_t most = 0;
    for (int i = 0; i < 100000; i++) {
        said |= hy2loss_step(&s, 0, 0, 0, 1000);
        if (s.ms > most) most = s.ms;
    }
    check("100000 idle seconds say nothing", 0, said);
    check("the window never holds more than 10000 ms", 10000, (long)most);
}

static void huge_counts_do_not_wrap(void) {
    struct hy2loss s;
    char o[64];
    const uint64_t n = UINT64_MAX / 200, l = n / 20;
    memset(&s, 0, sizeof s);
    check_str("UINT64_MAX/200 sent, a twentieth lost, twice: grey", "00",
              RUN(&s, o, { n, l, 0, 1000 }, { n, l, 0, 1000 }));
    memset(&s, 0, sizeof s);
    check_str("one packet more lost each time: lossy", "01",
              RUN(&s, o, { n, l + 1, 0, 1000 }, { n, l + 1, 0, 1000 }));
    memset(&s, 0, sizeof s);
    check_str("UINT64_MAX/200 sent, a quarter lost, twice: lossy", "01",
              RUN(&s, o, { n, n / 4, 0, 1000 }, { n, n / 4, 0, 1000 }));
    memset(&s, 0, sizeof s);
    check_str("UINT64_MAX/200 sent, a nineteenth lost, twice: lossy", "01",
              RUN(&s, o, { n, n / 19, 0, 1000 }, { n, n / 19, 0, 1000 }));
}

int main(void) {
    two_lossy_windows_say_lossy_once();
    a_grey_window_neither_counts_nor_resets();
    a_clean_window_resets_the_run();
    intervals_add_up_to_a_window();
    a_slow_window_is_dropped();
    a_long_interval_is_dropped();
    a_hop_starts_a_new_run();
    a_clean_window_after_a_verdict_starts_over();
    an_idle_link_decides_nothing();
    huge_counts_do_not_wrap();
    return unit_done("hy2lossmatch");
}
