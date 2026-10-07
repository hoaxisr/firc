#ifndef FIRC_TUNSUP_H
#define FIRC_TUNSUP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "firc/err.h"
#include "firc/loop.h"
#include "firc/tunnels.h"
#include "firc/tunproto.h"

typedef enum {
    FIRC_TUN_ST_OFF,
    FIRC_TUN_ST_STARTING,
    FIRC_TUN_ST_UP,
    FIRC_TUN_ST_NO_NODE,
    FIRC_TUN_ST_BACKOFF,
    FIRC_TUN_ST_BAD_CONFIG,
    FIRC_TUN_ST_WAITING,
    FIRC_TUN_ST_UPLINK_DOWN
} firc_tun_status_t;

typedef struct {
    size_t n_active;
    int64_t since_ms;
    firc_tun_status_t status;
    int backoff_s;
    int last_exit;
    bool uplink_ok;
    char id[16];
    char device[16];
    char active[8][128];
} firc_tun_state_t;

typedef struct firc_tunsup firc_tunsup_t;

/* ev is the child's event, or NULL when the supervisor itself changed the status (start, exit, stop). */
typedef void (*firc_tun_event_fn)(const firc_tun_state_t *st, const firc_tev_t *ev, void *ud);

/* Loop thread only, like every call below; children are spawned from this thread. */
firc_tunsup_t *firc_tunsup_new(firc_loop_t *loop, const char *binary, firc_tun_event_fn on_event, void *ud);

/* Starts, restarts and stops children to match want; marks[i] is the socket mark of want->t[i], 0 for none. */
firc_err_t firc_tunsup_apply(firc_tunsup_t *s, const firc_tunnels_t *want, const uint32_t *marks);

/* Copies up to cap states of the configured tunnels; returns how many there are. */
size_t firc_tunsup_states(const firc_tunsup_t *s, firc_tun_state_t *out, size_t cap);

/* SIGTERM to every child, SIGKILL after grace_ms; returns with every child reaped, each tunnel reported OFF. */
void firc_tunsup_stop(firc_tunsup_t *s, int grace_ms);

void firc_tunsup_free(firc_tunsup_t *s);

typedef void (*firc_tun_reap_fn)(const char *id, pid_t pid, void *ud);

/* fn runs once child pid of tunnel id has been reaped, removed tunnels included, before any respawn. */
void firc_tunsup_set_on_reap(firc_tunsup_t *s, firc_tun_reap_fn fn, void *ud);

/* Sets the uplink_ok the states of tunnel id report. */
void firc_tunsup_set_uplink_ok(firc_tunsup_t *s, const char *id, bool ok);

/* True while a child of tunnel id started with mark is not reaped, retired tunnels included. */
bool firc_tunsup_holds(const firc_tunsup_t *s, const char *id, uint32_t mark);

/* Restarts the child of tunnel id even when nothing changed; FIRC_ERR_NOENT unknown, FIRC_ERR_STATE disabled. */
firc_err_t firc_tunsup_restart(firc_tunsup_t *s, const char *id);

/* A counter raised each time a child is (re)started or sent new nodes; started() and updated() are its
   value at id's last start and last node update, 0 never. */
uint64_t firc_tunsup_start_seq(const firc_tunsup_t *s);
uint64_t firc_tunsup_started(const firc_tunsup_t *s, const char *id);
uint64_t firc_tunsup_updated(const firc_tunsup_t *s, const char *id);

void firc_tunsup_set_second_ms_for_test(firc_tunsup_t *s, int ms); /* test seam: length of a backoff second */

#endif
