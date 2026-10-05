#include <stdint.h>
#include <string.h>

#include "firc/clienthello.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char name[64];
    if (firc_tls_client_hello_sni(data, size, name, sizeof(name))) {
        size_t n = strnlen(name, sizeof(name));
        if (n == sizeof(name)) { __builtin_trap(); }
    }

    char tiny[2];
    (void)firc_tls_client_hello_sni(data, size, tiny, sizeof(tiny));
    return 0;
}
