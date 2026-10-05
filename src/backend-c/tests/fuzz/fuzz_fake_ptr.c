#include <stdint.h>
#include <stdlib.h>

#include "firc/dnswire.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    firc_dns_msg_t *query = NULL;
    if (firc_dns_msg_parse(data, size, &query) != FIRC_OK) {
        return 0;
    }
    firc_ip_t addr;
    if (firc_dns_ptr_query_addr(query, &addr)) {
        const char *targets[] = {NULL, "shop.example.com"};
        for (size_t i = 0; i < 2; i++) {
            uint8_t *resp = NULL;
            size_t rlen = 0;
            if (firc_dns_make_ptr_response(query, targets[i], 300, &resp, &rlen) == FIRC_OK) {
                firc_dns_msg_t *msg = NULL;
                if (firc_dns_msg_parse(resp, rlen, &msg) != FIRC_OK) {
                    abort();
                }
                firc_dns_msg_free(msg);
                free(resp);
            }
        }
    }
    firc_dns_msg_free(query);
    return 0;
}
