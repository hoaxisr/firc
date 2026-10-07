/* Parsing a Vision stream on fixtures: no network, no server, no root.
 *
 * vision_unwrap reads the stream FROM THE SERVER, that is untrusted bytes, and it parses as a
 * stream: state carries over between calls. So what matters is less the content than the
 * SLICING: where exactly a TLS record boundary falls. The live stand (tests/run-tunnel.sh) cannot
 * choose the slicing and does not reach these cases; it runs the good path end to end and needs
 * root with ip netns.
 *
 * Checked: a stream start that arrives in pieces (bytes before the UUID is recognized must not be
 * lost, or the parser loses sync and hands frame header bytes to the client as data); the frames
 * after it at every slicing (payload kept, padding dropped, `end` and `direct` switching to the
 * plain stream); a UUID that is not ours (the stream passes as is); and an invalid command (it
 * must fail every time, never leave the parser consuming zero bytes forever).
 *
 * The module is linked with the test, not included: the state checked here is the fields of
 * struct vision, declared in vision.h, and nothing static in vision.c is needed. */
#include <stdio.h>
#include <string.h>
#include "../src/proto/vless/vision.h"

static int fails;

static void check(const char *what, long want, long got) {
    if (want == got) { printf("%-58s ok\n", what); return; }
    printf("%-58s FAIL: expected %ld, got %ld\n", what, want, got);
    fails++;
}

static const unsigned char UUID[16] = {
    0x96, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};

/* One frame: command, payload length, padding length, the payload and the padding. The same
 * shape vision_wrap builds on the other side. Padding bytes are 0xEE: any of them reaching the
 * client makes the output longer than the payloads. */
static size_t put_frame(unsigned char *out, unsigned char cmd, const void *data, size_t data_n,
                        size_t pad_n) {
    size_t i = 0;
    out[i++] = cmd;
    out[i++] = (unsigned char)(data_n >> 8);
    out[i++] = (unsigned char)(data_n & 0xFF);
    out[i++] = (unsigned char)(pad_n >> 8);
    out[i++] = (unsigned char)(pad_n & 0xFF);
    memcpy(out + i, data, data_n); i += data_n;
    memset(out + i, 0xEE, pad_n); i += pad_n;
    return i;
}

/* A server stream: UUID and one frame without padding. */
static size_t make_stream(unsigned char *out, unsigned char cmd,
                          const char *data, size_t data_n) {
    memcpy(out, UUID, 16);
    return 16 + put_frame(out + 16, cmd, data, data_n, 0);
}

static void vinit(struct vision *v) {
    memset(v, 0, sizeof(*v));
    memcpy(v->uuid, UUID, 16);
}

/* Feed the whole stream to the parser in chunks of step bytes and collect the output. */
static size_t drain(struct vision *v, const unsigned char *in, size_t n, size_t step,
                    char *out, size_t out_cap, int *rc_out) {
    size_t got = 0, pos = 0;
    *rc_out = 0;
    while (pos < n) {
        size_t chunk = n - pos < step ? n - pos : step;
        size_t off = 0;
        /* Loop within a chunk while the parser consumes or returns something, as
         * downstream_pump in stack.c does. */
        for (;;) {
            size_t used = 0, pl_n = 0;
            const unsigned char *pl = NULL;
            int rc = vision_unwrap(v, in + pos + off, chunk - off, &used, &pl, &pl_n);
            if (rc != 0) { *rc_out = rc; return got; }
            if (pl_n) {
                if (got + pl_n > out_cap) return got;
                memcpy(out + got, pl, pl_n);
                got += pl_n;
            }
            off += used;
            if (!used && !pl_n) break;
            if (off >= chunk) break;
        }
        pos += chunk;
    }
    return got;
}

/* Every chunk size from 1 byte to the whole stream, a fresh parser each time. Returns the first
 * size whose output is not want (or that fails), -1 if every size gives want. */
static int every_step(const unsigned char *in, size_t n, const unsigned char *want, size_t want_n) {
    for (size_t step = 1; step <= n; step++) {
        struct vision v;
        vinit(&v);
        static char out[2048];
        int rc = 0;
        size_t got = drain(&v, in, n, step, out, sizeof(out), &rc);
        if (rc != 0 || got != want_n || memcmp(out, want, want_n) != 0) return (int)step;
    }
    return -1;
}

int main(void) {
    unsigned char stream[256];
    const char *msg = "the payload of one Vision frame";
    size_t msg_n = strlen(msg);
    size_t n = make_stream(stream, VISION_CMD_CONTINUE, msg, msg_n);

    /* The whole stream in one chunk: the base case. */
    {
        struct vision v;
        vinit(&v);
        char out[256];
        int rc = 0;
        size_t got = drain(&v, stream, n, n, out, sizeof(out), &rc);
        check("stream in one chunk: no error", 0, rc);
        check("stream in one chunk: payload length", (long)msg_n, (long)got);
        check("stream in one chunk: payload content", 0, memcmp(out, msg, msg_n));
    }

    /* Every chunk size, down to 1 byte. A chunk shorter than the 21-byte start (UUID and
     * first frame header) must be kept, not dropped: otherwise the UUID is compared at a
     * shifted offset, does not match, and the parser slips. */
    check("any chunk size down to 1 byte gives the same payload", -1,
          every_step(stream, n, (const unsigned char *)msg, msg_n));

    /* The frames after the start, at every chunk size: a record boundary may fall inside a
     * header, a payload or the padding. A payload and a padding longer than 255 bytes (both
     * length bytes count), then a frame with `end`, then the plain stream. The client gets the
     * payloads and the plain tail, not one byte of padding or header. */
    {
        static unsigned char s[1024], want[1024];
        unsigned char p1[300];
        for (size_t i = 0; i < sizeof(p1); i++) p1[i] = (unsigned char)(i * 7 + 1);
        const char *p2 = "the second frame, with end";
        const char *tail = "the plain stream after end";
        size_t sn = 0, wn = 0;
        memcpy(s, UUID, 16);
        sn = 16;
        sn += put_frame(s + sn, VISION_CMD_CONTINUE, p1, sizeof(p1), 300);
        sn += put_frame(s + sn, VISION_CMD_END, p2, strlen(p2), 7);
        memcpy(s + sn, tail, strlen(tail));
        sn += strlen(tail);
        memcpy(want, p1, sizeof(p1));
        wn = sizeof(p1);
        memcpy(want + wn, p2, strlen(p2));
        wn += strlen(p2);
        memcpy(want + wn, tail, strlen(tail));
        wn += strlen(tail);
        check("padded frames, end, plain tail: any chunk size", -1, every_step(s, sn, want, wn));

        /* An end frame with neither payload nor padding: the server ends padding this way. */
        const char *p3 = "one frame";
        memcpy(s, UUID, 16);
        sn = 16;
        sn += put_frame(s + sn, VISION_CMD_CONTINUE, p3, strlen(p3), 3);
        sn += put_frame(s + sn, VISION_CMD_END, "", 0, 0);
        memcpy(s + sn, tail, strlen(tail));
        sn += strlen(tail);
        memcpy(want, p3, strlen(p3));
        memcpy(want + strlen(p3), tail, strlen(tail));
        check("empty end frame, plain tail: any chunk size", -1,
              every_step(s, sn, want, strlen(p3) + strlen(tail)));
    }

    /* `direct` ends the padding as `end` does, and the reader must also be told: the server then
     * writes the stream without its TLS records, and reading it as records breaks mid-transfer.
     * `end` must not tell the reader that. */
    for (int direct = 0; direct <= 1; direct++) {
        unsigned char s[128];
        const char *p = "the last frame";
        const char *tail = "+raw tail";
        memcpy(s, UUID, 16);
        size_t sn = 16 + put_frame(s + 16, direct ? VISION_CMD_DIRECT : VISION_CMD_END,
                                   p, strlen(p), 5);
        memcpy(s + sn, tail, strlen(tail));
        sn += strlen(tail);
        struct vision v;
        vinit(&v);
        char out[128];
        int rc = 0;
        size_t got = drain(&v, s, sn, sn, out, sizeof(out), &rc);
        int same = rc == 0 && got == strlen(p) + strlen(tail) &&
                   memcmp(out, p, strlen(p)) == 0 &&
                   memcmp(out + strlen(p), tail, strlen(tail)) == 0;
        if (direct) {
            check("direct: the payload, then the stream as is", 1, same);
            check("direct: the reader is told to bypass TLS", 1, v.recv_direct);
        } else {
            check("end: the payload, then the stream as is", 1, same);
            check("end: the reader is not told to bypass TLS", 0, v.recv_direct);
        }
    }

    /* Another UUID: the stream is not wrapped and passes as is. The start collected while
     * looking for the UUID must reach the client whole, not stay in the parser's buffer. */
    {
        unsigned char plain[64];
        memset(plain, 0, sizeof(plain));
        memcpy(plain, "not a Vision stream: plain data, byte by byte.", 46);
        struct vision v;
        vinit(&v);                           /* the stream does not carry this UUID */
        char out[128];
        int rc = 0;
        size_t got = drain(&v, plain, 46, 7, out, sizeof(out), &rc);
        check("another UUID: no error", 0, rc);
        check("another UUID: the whole stream comes through", 46, (long)got);
        check("another UUID: content unchanged", 0, memcmp(out, plain, 46));
    }

    /* A UUID that differs from ours in ONE byte, the first or the last included, is another
     * UUID: a compare that skips a byte would take the stream as wrapped and strip 21 bytes. */
    {
        int bad_k = -1;
        for (int k = 0; k < 16 && bad_k < 0; k++) {
            unsigned char s[64];
            size_t sn = make_stream(s, VISION_CMD_CONTINUE, msg, msg_n);
            s[k] ^= 0x01;
            struct vision v;
            vinit(&v);
            char out[128];
            int rc = 0;
            size_t got = drain(&v, s, sn, sn, out, sizeof(out), &rc);
            if (rc != 0 || got != sn || memcmp(out, s, sn) != 0) bad_k = k;
        }
        check("UUID off in any one byte: the stream passes as is", -1, bad_k);
    }

    /* An invalid command: an error, not endless re-reading of one frame. */
    {
        unsigned char bad[64];
        size_t bn = make_stream(bad, 0x7F, "xx", 2);   /* there is no command 0x7F */
        struct vision v;
        vinit(&v);
        char out[64];
        int rc = 0;
        drain(&v, bad, bn, bn, out, sizeof(out), &rc);
        check("invalid command: parser returns VISION_EPROTO", VISION_EPROTO, rc);
    }

    /* The broken frame stays: the next call must give EPROTO again, even on bytes that form a
     * valid frame. Parsing them would read the rest of a broken stream as frames, and a success
     * that consumes nothing would leave a live connection re-reading the frame forever. */
    {
        unsigned char bad[64];
        size_t bn = make_stream(bad, 0x7F, "xx", 2);
        struct vision v;
        vinit(&v);
        size_t used = 0, pl_n = 0;
        const unsigned char *pl = NULL;
        int rc1 = vision_unwrap(&v, bad, bn, &used, &pl, &pl_n);
        check("broken frame: error on the first call", VISION_EPROTO, rc1);
        unsigned char good[16];
        size_t gn = put_frame(good, VISION_CMD_CONTINUE, "ok", 2, 0);
        int rc2 = vision_unwrap(&v, good, gn, &used, &pl, &pl_n);
        check("broken frame: error again on the next call, even on a valid frame",
              VISION_EPROTO, rc2);
    }

    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed");
    return fails ? 1 : 0;
}
