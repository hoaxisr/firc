/* Stubs for the unit tests that link transport.c without a crypto library (wsmatch, xhupmatch).
 * Their connections are plain, so the VLESS encryption layer (trvenc.c) is never reached. The real
 * layer is tested on the real library against a real Xray: tests/vencprobe.c and tests/venc.sh in
 * `make interop`. */
#include <stddef.h>
#include "transport.h"
#include "ech.h"

/* The same for ECH (ech.c, HPKE on the crypto library): trsec.c calls it only for a node with
 * `ech`, and these tests have none. The real ECH is tested by tests/echmatch.c
 * (`make crypto-test`) and tests/ech.sh (`make interop`). */
int ech_b64_decode(const char *in, uint8_t *out, size_t cap) { (void)in; (void)out; (void)cap; return -1; }
int ech_pick(const uint8_t *list, size_t n, struct ech_cfg *out) { (void)list; (void)n; (void)out; return ECH_ENOCONFIG; }
int ech_wrap(const struct ech_cfg *cfg, const uint8_t *hello, size_t hello_n, uint8_t *out, size_t cap,
             size_t *out_n, struct ech_state *st)
    { (void)cfg; (void)hello; (void)hello_n; (void)out; (void)cap; (void)out_n; (void)st; return ECH_ENOCONFIG; }

int tr_venc_open(struct transport *t, const struct tr_node *n, int timeout_s)
    { (void)t; (void)n; (void)timeout_s; return TR_EVENC; }
int tr_venc_write(struct transport *t, const unsigned char *d, size_t n)
    { (void)t; (void)d; (void)n; return TR_EVENC; }
int tr_venc_read(struct transport *t, unsigned char *d, size_t cap, size_t *got)
    { (void)t; (void)d; (void)cap; *got = 0; return TR_EVENC; }
int tr_venc_pending(const struct transport *t) { (void)t; return 0; }
void tr_venc_close(struct transport *t) { (void)t; }
const char *tr_venc_reason(void) { return ""; }
