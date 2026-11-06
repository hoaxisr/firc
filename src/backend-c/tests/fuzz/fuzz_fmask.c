#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fmask.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    const char *in = (const char *)data;
    char why[128], why2[128], out[FM_JSON_MAX + 1], out2[FM_JSON_MAX + 1];
    struct fm_cfg cfg;
    int rc = fm_parse(in, size, &cfg, why, sizeof why);
    if (rc == 0) { fm_cfg_free(&cfg); }
    size_t k = fm_compact(in, size, out, sizeof out);
    if (rc == 0 && k == 0) { abort(); }
    if (k == 0) { return 0; }
    if (k > FM_JSON_MAX || out[k] != '\0') { abort(); }
    if (fm_parse(out, k, NULL, why2, sizeof why2) != rc || strcmp(why, why2) != 0) { abort(); }
    if (fm_compact(out, k, out2, sizeof out2) != k || memcmp(out, out2, k) != 0) { abort(); }
    return 0;
}
