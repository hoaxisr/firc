#ifndef FIRC_SUB_FETCH_H
#define FIRC_SUB_FETCH_H

#include <stdbool.h>
#include <stddef.h>

#include "firc/err.h"

#define FIRC_SUB_FETCH_TIMEOUT_SECONDS 15
#define FIRC_SUB_FETCH_MAX_REDIRECTS 5
#define FIRC_SUB_FETCH_MAX_BODY_BYTES ((size_t)8 * 1024 * 1024)

/* Call once at startup before any thread calls firc_sub_fetch_list*; pair with the cleanup call. */
void firc_sub_fetch_global_init(void);
void firc_sub_fetch_global_cleanup(void);

/* True for a well-formed http/https URL with a non-empty host; the same test the fetch itself makes. */
bool firc_sub_url_is_supported(const char *url);

/* Called with bytes received so far and the declared total (0 if unknown); false aborts as FIRC_ERR_CANCELED. */
typedef bool (*firc_sub_fetch_progress_fn)(void *ud, size_t bytes, size_t total);

/* Fetches url, following only 301/302 redirects, up to FIRC_SUB_FETCH_MAX_REDIRECTS hops; *out_body is a
 * NUL-terminated malloc'd buffer the caller frees. FIRC_ERR_INVAL/LIMIT/PROTO/IO/NOMEM/CANCELED on failure. */
firc_err_t firc_sub_fetch_list_ex(const char *url, char **out_body, size_t *out_len,
                                  firc_sub_fetch_progress_fn progress, void *ud, long *out_http_status);

/* firc_sub_fetch_list(url, body, len) == firc_sub_fetch_list_ex(url, body, len, NULL, NULL, NULL). */
firc_err_t firc_sub_fetch_list(const char *url, char **out_body, size_t *out_len);

#endif /* FIRC_SUB_FETCH_H */
