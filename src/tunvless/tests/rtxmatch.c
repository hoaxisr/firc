/* The retransmit ring (src/tunnel/rtx.c) at its edges.
 *
 * A mistake in the modular arithmetic does not look like a mistake: the ring hands the client the
 * wrong bytes for a retransmit, with a valid checksum, and the transfer stalls now and then, which
 * on live traffic is indistinguishable from having no retransmission at all. So the ring is
 * checked on its own: wrap at the end, an ack beyond what was sent, a contiguous piece for a
 * retransmit, many full turns, growth with data across the end.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "../src/tunnel/rtx.h"

static int fails;

static void check(int ok, const char *what) {
    printf("%-62s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) fails++;
}

/* Byte number i of the stream. The value depends on the position, so handing out the wrong
 * place is caught instead of matching by chance. */
static unsigned char byte_at(uint64_t i) {
    return (unsigned char)(i * 131u + 17u);
}

/* Whether the whole unacknowledged rest, collected through peeks, is the stream from base. */
static int unacked_ok(const struct rtx *r, uint64_t base) {
    uint32_t off = 0;
    struct rtx copy = *r;                   /* peek does not change the ring, drop does */
    uint32_t left = r->len;
    while (left) {
        const unsigned char *p = NULL;
        uint32_t n = rtx_peek(&copy, left, &p);
        if (!n) return 0;
        for (uint32_t i = 0; i < n; i++) {
            if (p[i] != byte_at(base + off + i)) {
                printf("     byte %u differs (stream offset %llu)\n", off + i,
                       (unsigned long long)(base + off + i));
                return 0;
            }
        }
        off += n;
        left -= n;
        rtx_drop(&copy, n);                 /* the rest continues from the start of the ring */
    }
    return off == r->len;
}

static void verify_unacked(const struct rtx *r, uint64_t base, const char *what) {
    check(unacked_ok(r, base), what);
}

int main(void) {
    const uint32_t CAP = 1000;              /* not a power of two: masking instead of a modulo
                                             * would break exactly here */
    struct rtx r;
    if (rtx_init(&r, CAP) != 0) { printf("out of memory\n"); return 2; }

    static unsigned char stream[100000];
    for (size_t i = 0; i < sizeof(stream); i++) stream[i] = byte_at(i);

    /* ---- empty ---- */
    const unsigned char *p = NULL;
    check(rtx_room(&r) == CAP, "empty: room is the whole capacity");
    check(rtx_peek(&r, 100, &p) == 0, "empty: nothing to retransmit");
    check(rtx_drop(&r, 50) == 0, "empty: nothing to acknowledge");

    /* ---- filling without a wrap ---- */
    rtx_push(&r, stream, 400);
    check(r.len == 400, "after 400 bytes: length");
    check(rtx_room(&r) == CAP - 400, "after 400 bytes: room");
    check(rtx_peek(&r, 1000, &p) == 400, "after 400 bytes: peek returns all of it");
    verify_unacked(&r, 0, "after 400 bytes: content");

    /* ---- partial ack ---- */
    check(rtx_drop(&r, 150) == 150, "ack of 150 bytes");
    check(r.len == 250, "after the ack: length");
    verify_unacked(&r, 150, "after the ack: content");

    /* ---- wrap at the end ---- */
    rtx_push(&r, stream + 400, 700);        /* 250 + 700 = 950 <= 1000 */
    check(r.len == 950, "wrap: length");
    /* The head is at 150, so 850 bytes are contiguous up to the end, not all 950. */
    check(rtx_peek(&r, 950, &p) == 850, "wrap: peek returns only the contiguous part");
    verify_unacked(&r, 150, "wrap: content");

    /* ---- an ack beyond what was sent ---- */
    check(rtx_drop(&r, 5000) == 950, "an ack beyond the sent data is cut to it");
    check(r.len == 0, "after that ack the ring is empty");

    /* ---- overflow leaves the ring intact ---- */
    rtx_push(&r, stream, 900);
    uint32_t before = r.len;
    rtx_push(&r, stream, 200);              /* more than the room left */
    check(r.len == before, "overflow: length unchanged");
    verify_unacked(&r, 0, "overflow: content intact");
    rtx_drop(&r, 900);

    /* ---- many turns in a row, as on a real transfer ----
     *
     * In uneven pieces: even ones would always meet the end of the ring the same way, and a wrap in
     * the middle of a piece would never be tested. The stream is contiguous, so after every push
     * the unacknowledged bytes are checked against their position in it. */
    uint64_t sent = 0, acked = 0;
    int bounds_ok = 1, content_ok = 1, wrapped = 0;
    for (int step = 0; step < 5000; step++) {
        uint32_t n = 1 + (uint32_t)((step * 37) % 400);
        if (n > rtx_room(&r)) n = rtx_room(&r);
        if (n && sent + n <= sizeof(stream)) {
            if (r.head + r.len >= CAP) wrapped++;
            rtx_push(&r, stream + sent, n);
            sent += n;
            if (content_ok && !unacked_ok(&r, acked)) content_ok = 0;
        }
        /* Acknowledge less than was sent, so the ring stays full. */
        uint32_t a = (uint32_t)((step * 29) % 350);
        if (a > r.len) a = r.len;
        acked += rtx_drop(&r, a);
        if (r.len > CAP || r.head >= CAP) bounds_ok = 0;
        if (sent + 400 > sizeof(stream)) break;
    }
    check(bounds_ok, "turns: length and head stay within the capacity");
    check(sent - acked == r.len, "turns: sent minus acknowledged is the length");
    check(sent / CAP >= 50 && wrapped >= 100,
          "turns: >= 50 turns, >= 100 pushes starting past the end");
    check(content_ok, "turns: after every push the unacknowledged bytes are right");

    /* ---- a wrap exactly at the end ---- */
    rtx_drop(&r, r.len);
    r.head = CAP - 10;                      /* put the head right before the end */
    rtx_push(&r, stream, 10);
    check(rtx_peek(&r, 10, &p) == 10, "end: 10 bytes up to the end are contiguous");
    check(memcmp(p, stream, 10) == 0, "end: content up to the end");
    rtx_push(&r, stream + 10, 10);          /* these start at 0 */
    check(rtx_peek(&r, 20, &p) == 10, "end: a peek stops at the end");
    rtx_drop(&r, 10);
    check(rtx_peek(&r, 10, &p) == 10, "end: after the ack the tail comes from the start");
    check(memcmp(p, stream + 10, 10) == 0, "end: content past the end");

    rtx_done(&r);

    /* ---- growth ----
     *
     * What makes growth dangerous is data lying across the end: copying the buffer as it is into
     * a bigger one would move the end, and a retransmit would send the wrong bytes. */
    struct rtx g;
    check(rtx_init(&g, 64) == 0, "grow: small ring allocated");
    rtx_push(&g, stream, 60);
    rtx_drop(&g, 50);                       /* the head is near the end: 10 bytes left */
    rtx_push(&g, stream + 60, 40);          /* 14 up to the end, the rest from 0 */
    check(g.len == 50, "grow: 50 unacknowledged bytes before growing");
    check(rtx_peek(&g, 50, &p) < 50, "grow: before growing the piece is split by the end");

    check(rtx_grow(&g, 4096) == 0, "grow: growing succeeds");
    check(g.cap == 4096 && g.len == 50 && g.head == 0, "grow: the ring is straightened");
    check(rtx_peek(&g, 50, &p) == 50, "grow: the whole piece is now contiguous");
    check(memcmp(p, stream + 50, 50) == 0, "grow: content kept, in order");
    check(rtx_grow(&g, 100) == -1 && rtx_grow(&g, 4096) == -1,
          "grow: shrinking or same size is refused");
    /* The ring must stay usable after a refusal: callers rely on it. */
    check(g.cap == 4096 && rtx_peek(&g, 50, &p) == 50 && memcmp(p, stream + 50, 50) == 0,
          "grow: a refusal leaves the ring as it was");
    rtx_done(&g);

    if (fails) printf("\nrtxmatch: %d FAILED\n", fails);
    else printf("\nrtxmatch: all checks passed\n");
    return fails ? 1 : 0;
}
