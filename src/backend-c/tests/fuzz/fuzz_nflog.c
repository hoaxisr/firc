#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "firc/nflog.h"

static const uint8_t *g_lo, *g_hi;

static void check(const uint8_t *pkt, size_t len, void *ud) {
    (void)ud;
    if (pkt < g_lo || pkt > g_hi || len > (size_t)(g_hi - pkt)) { abort(); }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    uint8_t *exact = malloc(size ? size : 1);
    if (exact == NULL) { return 0; }
    memcpy(exact, data, size);

    const uint8_t *out = NULL;
    size_t out_len = 0;
    if (firc_nflog_payload(exact, size, &out, &out_len)) {
        if (out < exact || out + out_len > exact + size) { abort(); }
    }

    g_lo = exact;
    g_hi = exact + size;
    (void)firc_nflog_walk(exact, size, check, NULL);

    free(exact);
    return 0;
}
