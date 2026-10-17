#ifndef FIRC_ROUTER_ID_H
#define FIRC_ROUTER_ID_H

#include <stdbool.h>

#include "firc/err.h"

typedef struct {
    char hwid[17];
    char release[64];
    char model[64];
} firc_router_id_t;

typedef firc_err_t (*firc_router_id_get_fn)(void *ud, const char *path, char **body);

/* The first 16 hex digits of sha256("firc-hwid\0" serial). */
void firc_router_id_from_serial(const char *serial, char out[17]);

/* Zeroes out, then asks show version and show defaults up to tries rounds, pause_ms apart, until either answers;
   FIRC_ERR_UPSTREAM when none did, FIRC_ERR_NOSYS for a NULL get. */
firc_err_t firc_router_id_read_rci(firc_router_id_get_fn get, void *ud, int tries, int pause_ms,
                                   firc_router_id_t *out);

/* The id stored at path wins over id->hwid; else a hwid already set is stored, or, when random_ok, a random one is
   made and stored (0600, parents 0700); else hwid stays empty. A failed write keeps the id for this run. */
void firc_router_id_settle(firc_router_id_t *id, const char *path, bool random_ok);

typedef struct firc_router_id_retry firc_router_id_retry_t;

/* Asks RCI on a thread of its own, up to tries rounds pause_ms apart, until one gives a serial, keeping the latest
   firmware and model; NULL when it cannot start. */
firc_router_id_retry_t *firc_router_id_retry_start(firc_router_id_get_fn get, void *ud, int tries, int pause_ms);

/* True once, when the thread has ended on a serial or out of tries, with what it gathered in out; once nothing is
   left to take, stops it and sets *r to NULL. Never waits on RCI; NULL-safe. */
bool firc_router_id_retry_poll(firc_router_id_retry_t **r, firc_router_id_t *out);

void firc_router_id_retry_hook_for_test(firc_router_id_retry_t *r, void (*between)(void *ud), void *ud); /* test seam */

/* True when the thread has ended, answered or out of tries. */
bool firc_router_id_retry_done(firc_router_id_retry_t *r);

/* Stops and joins the thread: a pause ends within 50 ms, an RCI call in flight runs to its timeout. NULL-safe. */
void firc_router_id_retry_stop(firc_router_id_retry_t *r);

/* One RCI round into out, its id settled at path. No serial: starts the retry, and without a stored id leaves
   out->hwid empty while it runs (random when it cannot start). Returns the retry, NULL when none runs. */
firc_router_id_retry_t *firc_router_id_begin(firc_router_id_get_fn get, void *ud, int tries, int pause_ms,
                                             const char *path, firc_router_id_t *out);

/* True when out holds the identity to apply now: the retry's late answer, or what it settles to once the retry gave
   up; *r is NULL from then on. Never waits on RCI; NULL-safe. */
bool firc_router_id_next(firc_router_id_retry_t **r, const char *path, firc_router_id_t *out);

#endif
