#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "firc/clienthello.h"
#include "firc/tappacket.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    firc_tap_packet_t p;
    if (firc_tap_packet_parse(data, size, &p)) {
        if (p.payload != NULL) {
            if (p.payload < data || p.payload + p.payload_len > data + size) {
                __builtin_trap();
            }
            char name[64];
            (void)firc_tls_client_hello_sni(p.payload, p.payload_len, name, sizeof(name));
        } else if (p.payload_len != 0) {
            __builtin_trap();
        }
        if (p.src.len != 4 && p.src.len != 16) { __builtin_trap(); }
        if (p.dst.len != p.src.len) { __builtin_trap(); }
    }

    firc_tap_head_t h;
    if (firc_tap_head_parse(data, size, &h)) {
        if (h.src.len != 4 && h.src.len != 16) { __builtin_trap(); }
        if (h.dst.len != h.src.len) { __builtin_trap(); }
    }
    return 0;
}
