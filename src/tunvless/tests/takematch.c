/* Spare sessions: a connection set up ahead of time is moved into the client's session, and the
 * pointers the transport keeps to itself must follow it.
 *
 * Needs the crypto library: the VLESS dialer pulls in the transport, TLS 1.3 and Reality. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stack.h"
#include "vldial.h"

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-66s %s\n", what, want == got ? "ok" : "FAIL");
    if (want != got) {
        printf("     want: %ld\n     got:  %ld\n", want, got);
        fails++;
    }
}

int main(void) {
    /* Taking a spare copies the link from the pool slot into the connection's session (memcpy),
     * and the transport fixes its self-pointer (grpc_moved): h2.io.ctx. Left unfixed, it points
     * into the abandoned slot, which the next spare reuses at once, and one connection's data
     * goes into another connection's socket.
     *
     * The self-pointer is checked on the real transport, and so is that the move does not
     * overwrite the connection's own state (UUID and Vision, set up before the take). Releasing
     * the pool slot is the stack's job and is checked in tests/tunnelmatch.c. */
    printf("\n== spare pool: the self-pointer fixed after the move ==\n");
    {
        static struct vl_sess spare, out, before;
        static struct transport want, got;
        /* Every byte of the slot holds a value of its own, the flow fields too (left from the
         * slot's previous connection): a short copy, or one that takes those fields, shows. */
        unsigned char *b = (unsigned char *)&spare;
        for (size_t i = 0; i < sizeof(spare); i++) b[i] = (unsigned char)(i * 31 + 7);
        spare.t.link.fd = -1;
        spare.t.fr = &tr_grpc;
        spare.t.h2.io.ctx = &spare.t.link;
        memcpy(&want, &spare.t, sizeof(want));
        memset(&out, 0, sizeof(out));
        out.uuid[0] = 0x5a;
        out.vis.need_uuid = 1;
        memcpy(&before, &out, sizeof(out));
        vless_dialer.take(&out, &spare);
        /* The transport byte for byte, except the self-pointers, which are checked next. */
        memcpy(&got, &out.t, sizeof(got));
        got.h2.io.ctx = NULL;
        want.h2.io.ctx = NULL;
        check("transport state moved, byte for byte", 1, memcmp(&got, &want, sizeof(got)) == 0);
        check("h2.io.ctx points to the new struct", 1, out.t.h2.io.ctx == &out.t.link);
        check("UUID, Vision and the other flow fields kept", 1,
              memcmp(&out, &before, offsetof(struct vl_sess, t)) == 0);
    }

    printf("\n== spare pool: an xhttp spare moves only what xhttp uses ==\n");
    {
        static struct vl_sess spare, out;
        unsigned char *b = (unsigned char *)&spare, *o = (unsigned char *)&out;
        for (size_t i = 0; i < sizeof(spare); i++) b[i] = (unsigned char)(i * 31 + 7);
        for (size_t i = 0; i < sizeof(out); i++) o[i] = (unsigned char)(i * 17 + 3);
        spare.t.fr = &tr_xhttp;
        vless_dialer.take(&out, &spare);
        size_t used = offsetof(struct transport, xh) + sizeof(struct xh_state);
        int tail = 1;
        const unsigned char *ot = (const unsigned char *)&out.t;
        for (size_t i = used; i < sizeof(out.t); i++)
            if (ot[i] != (unsigned char)((offsetof(struct vl_sess, t) + i) * 17 + 3)) tail = 0;
        /* catches: an xhttp move that misses part of the flow state */
        check("xhttp: the flow state moved, byte for byte", 1, memcmp(&out.t, &spare.t, used) == 0);
        /* catches: an xhttp move that still copies the whole transport */
        check("xhttp: the bytes past it untouched", 1, tail);
    }

    {
        static struct vl_sess sess;
        memset(&sess, 0, sizeof(sess));
        sess.t.fr = &tr_xhttp;
        sess.t.xh.mode = XH_PACKET_UP;
        vless_dialer.clear(&sess);
        /* catches: a cleared xhttp session's state overwritten by the main link's descriptor */
        check("xhttp: clearing the session leaves its mode", XH_PACKET_UP, sess.t.xh.mode);
    }

    printf(fails ? "\nFAILED: %d\n" : "\nall checks passed\n", fails);
    return fails ? 1 : 0;
}
