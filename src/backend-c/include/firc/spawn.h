#ifndef FIRC_SPAWN_H
#define FIRC_SPAWN_H

#include "firc/err.h"

/* Runs `path arg` detached (own session, stdio on /dev/null); FIRC_OK once exec'd, else the exec errno. */
firc_err_t firc_spawn_detached(const char *path, const char *arg);

#endif
