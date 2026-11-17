#include <stdio.h>
#include "unit.h"
#include "../src/proto/quic/qcbrutal.h"

#define SEC 1000000000ull

static void c64(const char *what, unsigned long long want, unsigned long long got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "FAIL");
    if (want == got) { unit_pass++; return; }
    unit_fail++;
    printf("     want: %llu\n     got:  %llu\n", want, got);
}

static void feed(struct qcb *b, uint64_t ts, int acked, int lost) {
    for (int i = 0; i < acked; i++) qcb_acked(b, ts);
    for (int i = 0; i < lost; i++) qcb_lost(b, ts);
    qcb_rate(b, ts);
}

static void out_at(struct qcb *b, uint64_t srtt_ns, struct qcb_out *o) {
    qcb_out(b, 1, srtt_ns, 1452, o);
}

static void pacing_and_window_come_from_the_rate(void) {
    struct qcb b;
    struct qcb_out o;
    qcb_init(&b, 1048576, 0);
    out_at(&b, 100000000ull, &o);
    c64("1 MiB/s 100 ms cwnd", 209715, o.cwnd);
    c64("1 MiB/s interval_m", 976562, o.interval_m);
    c64("1 MiB/s quantum", 14520, o.quantum);
    qcb_init(&b, 12500000, 0);
    out_at(&b, 50000000ull, &o);
    c64("12.5 MB/s 50 ms cwnd", 1250000, o.cwnd);
    c64("12.5 MB/s interval_m", 81920, o.interval_m);
    c64("12.5 MB/s quantum", 50000, o.quantum);
    qcb_init(&b, 4194304, 0);
    out_at(&b, 50000000ull, &o);
    c64("32 mbps quantum", 16777, o.quantum);
}

static void no_rtt_and_tiny_windows(void) {
    struct qcb b;
    struct qcb_out o;
    qcb_init(&b, 1048576, 0);
    qcb_out(&b, 0, 100000000ull, 1452, &o);
    c64("no rtt cwnd", 10240, o.cwnd);
    qcb_init(&b, 65536, 0);
    out_at(&b, 1000000ull, &o);
    c64("tiny window is raised to mds", 1452, o.cwnd);
}

static void xrays_own_loss_table(void) {
    static const struct { int a, l; uint32_t want; } t[] = {
        {100, 0, 65536}, {80, 20, 52429}, {50, 50, 52429}, {10, 5, 65536}};
    char name[64];
    struct qcb b;
    for (int i = 0; i < 4; i++) {
        qcb_init(&b, 1048576, 0);
        feed(&b, 2 * SEC, t[i].a, t[i].l);
        snprintf(name, sizeof name, "table %d/%d", t[i].a, t[i].l);
        c64(name, t[i].want, b.ack_q16);
        qcb_init(&b, 1048576, 1);
        feed(&b, 2 * SEC, t[i].a, t[i].l);
        snprintf(name, sizeof name, "table %d/%d no_comp", t[i].a, t[i].l);
        c64(name, 65536, b.ack_q16);
    }
}

static void fifty_samples_and_the_floor(void) {
    struct qcb b;
    struct qcb_out o;
    uint64_t t = 10200000000ull;
    qcb_init(&b, 1048576, 0);
    feed(&b, t, 45, 4);
    c64("49 samples", 65536, b.ack_q16);
    qcb_acked(&b, t);
    qcb_rate(&b, t);
    c64("46/50 ack_q16", 60293, b.ack_q16);
    out_at(&b, 100000000ull, &o);
    c64("46/50 interval_m", 898436, o.interval_m);
    c64("46/50 cwnd", 227951, o.cwnd);
    qcb_init(&b, 1048576, 0);
    feed(&b, t, 30, 30);
    c64("30/30 ack_q16", 52429, b.ack_q16);
    out_at(&b, 100000000ull, &o);
    c64("30/30 interval_m", 781252, o.interval_m);
    c64("30/30 cwnd", 262143, o.cwnd);
}

static void five_seconds_of_samples(void) {
    struct qcb b;
    qcb_init(&b, 1048576, 0);
    feed(&b, SEC / 2, 30, 30);
    feed(&b, 4 * SEC + SEC / 2, 50, 0);
    c64("slot of second 0 still counts at 4.5 s", 52429, b.ack_q16);
    qcb_rate(&b, 5 * SEC + SEC / 2);
    c64("no event, no recompute", 52429, b.ack_q16);
    qcb_init(&b, 1048576, 0);
    feed(&b, SEC / 2, 30, 30);
    feed(&b, 5 * SEC + SEC / 2, 50, 0);
    c64("slot of second 0 is reset at 5.5 s", 65536, b.ack_q16);
}

static void a_stale_slot_at_another_index_is_not_counted(void) {
    struct qcb b;
    qcb_init(&b, 1048576, 0);
    feed(&b, SEC / 2, 30, 30);
    feed(&b, 7 * SEC + SEC / 2, 50, 0);
    c64("slot of second 0 is stale at 7.5 s", 65536, b.ack_q16);
}

static void a_reset_slot_starts_its_acked_count_from_zero(void) {
    struct qcb b;
    qcb_init(&b, 1048576, 0);
    feed(&b, SEC / 2, 30, 30);
    feed(&b, 5 * SEC + SEC / 2, 46, 4);
    c64("46/50 after the reset at 5.5 s", 60293, b.ack_q16);
}

static void no_wrap_at_any_accepted_rate(void) {
    struct qcb b;
    struct qcb_out o;
    qcb_init(&b, QCB_BPS_MAX, 0);
    out_at(&b, 60 * SEC, &o);
    c64("2^37 B/s 60 s cwnd", 16492674416640ull, o.cwnd);
    c64("2^37 B/s interval_m", 7, o.interval_m);
    c64("2^37 B/s quantum", 65536, o.quantum);
    qcb_init(&b, QCB_BPS_MAX, 0);
    feed(&b, 10 * SEC, 30, 30);
    out_at(&b, 60 * SEC, &o);
    c64("2^37 B/s floor cwnd", 20615764377840ull, o.cwnd);
    c64("2^37 B/s floor interval_m", 5, o.interval_m);
    c64("2^37 B/s floor quantum", 65536, o.quantum);
    qcb_init(&b, 125000000000000000ull, 0);
    out_at(&b, 60 * SEC, &o);
    c64("parser maximum is clamped, cwnd", 16492674416640ull, o.cwnd);
    c64("parser maximum is clamped, interval_m", 7, o.interval_m);
    c64("parser maximum is clamped, quantum", 65536, o.quantum);
    qcb_init(&b, QCB_BPS_MAX, 0);
    out_at(&b, 120 * SEC, &o);
    c64("120 s srtt gives the 60 s cwnd", 16492674416640ull, o.cwnd);
    qcb_init(&b, 0, 0);
    out_at(&b, 100000000ull, &o);
    c64("zero rate is one byte per second, interval_m", 1024000000000ull, o.interval_m);
    c64("zero rate, cwnd", 1452, o.cwnd);
    c64("zero rate, quantum", 14520, o.quantum);
}

int main(void) {
    pacing_and_window_come_from_the_rate();
    no_rtt_and_tiny_windows();
    xrays_own_loss_table();
    fifty_samples_and_the_floor();
    five_seconds_of_samples();
    a_stale_slot_at_another_index_is_not_counted();
    a_reset_slot_starts_its_acked_count_from_zero();
    no_wrap_at_any_accepted_rate();
    return unit_done("brutalmatch");
}
