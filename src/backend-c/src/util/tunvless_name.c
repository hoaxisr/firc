#include "firc/tunvless_name.h"

#include <stdbool.h>
#include <string.h>

static const char *const stems[] = {"tunvless", "opkgtun"};

bool firc_tunvless_prefixed(const char *name) {
    if (name == NULL) { return false; }
    for (size_t i = 0; i < sizeof stems / sizeof stems[0]; i++) {
        if (strncmp(name, stems[i], strlen(stems[i])) == 0) { return true; }
    }
    return false;
}

int firc_tunvless_index(const char *name) {
    if (name == NULL) { return -1; }
    for (size_t i = 0; i < sizeof stems / sizeof stems[0]; i++) {
        size_t n = strlen(stems[i]);
        if (strncmp(name, stems[i], n) != 0) { continue; }
        const char *d = name + n;
        if (d[0] < '0' || d[0] > '9') { return -1; }
        if (d[1] == '\0') { return d[0] - '0'; }
        if (d[0] == '0' || d[1] < '0' || d[1] > '9' || d[2] != '\0') { return -1; }
        return (d[0] - '0') * 10 + (d[1] - '0');
    }
    return -1;
}
