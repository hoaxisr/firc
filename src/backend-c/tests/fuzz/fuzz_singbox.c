#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "firc/subparse.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *body = malloc(size + 1);
    if (body == NULL) { return 0; }
    memcpy(body, data, size);
    body[size] = '\0';
    firc_sub_rules_t rs;
    firc_sub_rules_init(&rs);
    firc_sub_parse_stats_t st;
    if (firc_sub_parse_rules_stats(body, &rs, &st, NULL, NULL) == FIRC_OK) {
        for (size_t i = 0; i < rs.n; i++) {
            (void)firc_sub_rules_proto(&rs, i);
            (void)firc_sub_rules_ports(&rs, i);
        }
    }
    firc_sub_rules_free(&rs);
    free(body);
    return 0;
}
