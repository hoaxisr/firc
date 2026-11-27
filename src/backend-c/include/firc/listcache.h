#ifndef FIRC_LISTCACHE_H
#define FIRC_LISTCACHE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "firc/err.h"

typedef bool (*firc_listcache_room_fn)(uint64_t fs_total, uint64_t fs_free, uint64_t held,
                                       uint64_t size);

/* Replaces firc_listcache_room inside firc_listcache_write when set; tests only. */
extern firc_listcache_room_fn firc_listcache_room_hook_for_test;

/* out = first 16 hex digits of SHA-256(url), NUL-terminated. */
void firc_listcache_key(const char *url, char out[17]);

/* True when a file of size bytes fits the cache's share of a filesystem. */
bool firc_listcache_room(uint64_t fs_total, uint64_t fs_free, uint64_t held, uint64_t size);

/* Stores body as dir/<key>-<hash16>, then removes the key's other files; FIRC_ERR_LIMIT when refused. */
firc_err_t firc_listcache_write(const char *dir, const char *key, const uint8_t *body, size_t len,
                                const uint8_t hash[32]);

/* Reads the key's newest intact body (malloc'd) with its SHA-256 and mtime; a damaged file is
 * removed (FIRC_ERR_NOENT when none is left); FIRC_ERR_NOMEM or FIRC_ERR_IO keeps the file. */
firc_err_t firc_listcache_read(const char *dir, const char *key, uint8_t **body, size_t *len,
                               uint8_t hash[32], time_t *mtime);

/* Removes dir/<key>-<hash16>; a missing file is FIRC_OK. */
firc_err_t firc_listcache_remove(const char *dir, const char *key, const uint8_t hash[32]);

/* keys NULL: removes temp files only; else removes every cache file whose key is not listed. */
firc_err_t firc_listcache_sweep(const char *dir, const char *const *keys, size_t n);

#endif
