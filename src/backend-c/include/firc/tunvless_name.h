#ifndef FIRC_TUNVLESS_NAME_H
#define FIRC_TUNVLESS_NAME_H

#include <stdbool.h>

bool firc_tunvless_prefixed(const char *name);

/* N of a canonical tunvless<N> or opkgtun<N> (N 0..99, no leading zero), else -1; NULL is -1. */
int firc_tunvless_index(const char *name);

#endif
