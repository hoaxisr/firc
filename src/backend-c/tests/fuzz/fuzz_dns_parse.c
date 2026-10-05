#include <stdint.h>
#include <stdlib.h>

#include "firc/dnswire.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    firc_dns_msg_t *msg = NULL;
    if (firc_dns_msg_parse(data, size, &msg) != FIRC_OK) {
        return 0;
    }

    firc_ip_t addr;
    (void)firc_dns_ptr_query_addr(msg, &addr);

    uint8_t *packed = NULL;
    size_t plen = 0;
    if (firc_dns_msg_pack(msg, &packed, &plen) == FIRC_OK) {
        firc_dns_msg_t *rt = NULL;
        if (firc_dns_msg_parse(packed, plen, &rt) == FIRC_OK) {
            firc_dns_msg_strip_aaaa(rt);
            uint8_t *p2 = NULL;
            size_t p2len = 0;
            if (firc_dns_msg_pack(rt, &p2, &p2len) == FIRC_OK) {
                free(p2);
            }
            firc_dns_msg_free(rt);
        }
        free(packed);
    }

    char name[1100];
    if (msg->n_questions > 0) {
        (void)firc_dns_name_to_string(msg->questions[0].name,
                                    msg->questions[0].name_len, name,
                                    sizeof(name), NULL);
    }
    firc_dns_msg_free(msg);
    return 0;
}
