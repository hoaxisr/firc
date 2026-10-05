#ifndef FIRC_SYSTEM_H
#define FIRC_SYSTEM_H

#include <stddef.h>
#include <stdint.h>

#include "firc/app.h"
#include "firc/httpd.h"

typedef struct firc_system_ctx {
    void *policies; /* Keenetic policy resolver; NULL before main starts it, empty before its first read */
    void *resolvers; /* firmware per-interface resolvers; NULL before main starts it, empty before its first read */
    firc_app_t *app;
    const char *config_path; /* NULL makes a save a no-op write (still 200) */
    const char *config_version;
    const char *init_script; /* NULL is FIRC_INIT_SCRIPT; a test gives a stand-in */
    int64_t restart_started_ms; /* monotonic ms a restart was asked for, 0 if none; loop thread only */
    int64_t restart_timeout_ms; /* 0 takes FIRC_RESTART_TIMEOUT_MS; a test shortens it */
} firc_system_ctx_t;

void firc_system_register_routes(firc_httpd_t *h, firc_system_ctx_t *ctx);

#define FIRC_RESTART_TIMEOUT_MS 90000

void firc_settings_register_routes(firc_httpd_t *h, firc_system_ctx_t *ctx);

/* whether next's listeners could be bound now (one matching running's is skipped); FIRC_ERR_INVAL sets *field/why */
firc_err_t firc_settings_probe_listeners(const firc_app_config_t *next,
                                         const firc_app_config_t *running, const char **field,
                                         char *why, size_t why_cap);

#endif /* FIRC_SYSTEM_H */
