#ifndef FIRC_TUNRUN_H
#define FIRC_TUNRUN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/err.h"
#include "firc/log.h"
#include "firc/loop.h"
#include "firc/rtnl.h"
#include "firc/tunnels.h"
#include "firc/tunnodes.h"
#include "firc/tunsubs.h"
#include "firc/tunsup.h"

typedef struct firc_tunrun firc_tunrun_t;

/* Loop thread only, like every call below: tunvless children are spawned from this thread. */
firc_tunrun_t *firc_tunrun_new(firc_loop_t *loop, firc_rtnl_t *r, uint32_t start_table, const char *binary);

/* Takes want over (left empty); writes uplinks, then starts, restarts and stops tunvless to match.
   An uplink a child no longer needs is removed only once that child has been reaped. */
firc_err_t firc_tunrun_apply(firc_tunrun_t *t, firc_tunnels_t *want);

/* Takes subscription bodies from subs from the next apply on; NULL detaches. */
void firc_tunrun_set_subs(firc_tunrun_t *t, firc_tunsubs_t *subs);

/* The changed() of firc_tunsubs_new, ud the tunrun: rebuilds every node list from the running config and
   sends the new list to the tunnels whose list changed. */
void firc_tunrun_bodies_changed(void *ud);

/* Copies up to cap states, one per configured tunnel in config order, waiting and failed uplinks included. */
size_t firc_tunrun_states(const firc_tunrun_t *t, firc_tun_state_t *out, size_t cap);

/* The running configuration; valid until the next apply. */
const firc_tunnels_t *firc_tunrun_config(const firc_tunrun_t *t);

/* Restarts the child of tunnel id even when nothing changed; FIRC_ERR_NOENT unknown, FIRC_ERR_STATE no child. */
firc_err_t firc_tunrun_restart(firc_tunrun_t *t, const char *id);

/* See firc_tunsup_start_seq, firc_tunsup_started and firc_tunsup_updated. */
uint64_t firc_tunrun_start_seq(const firc_tunrun_t *t);
uint64_t firc_tunrun_started(const firc_tunrun_t *t, const char *id);
uint64_t firc_tunrun_updated(const firc_tunrun_t *t, const char *id);

/* The node rows last built for tunnel id, links removed; NULL when none were built. */
const firc_tun_nodes_t *firc_tunrun_nodes(const firc_tunrun_t *t, const char *id);

/* True while tunvless reports the node with this key of tunnel id down; since_ms is monotonic. */
bool firc_tunrun_node_down(const firc_tunrun_t *t, const char *id, const char *key, int64_t *since_ms);

/* True while the node with this key of tunnel id is among tunvless's active ones. */
bool firc_tunrun_node_active(const firc_tunrun_t *t, const char *id, const char *key);

/* False when id is not configured; mark is its uplink mark (0 for auto), held while a child runs with it. */
bool firc_tunrun_mark_of(const firc_tunrun_t *t, const char *id, uint32_t *mark, bool *held);

/* Rewrites the default route of every tunnel leaving through ifname. */
void firc_tunrun_link_up(firc_tunrun_t *t, const char *ifname);

/* Stops every child (SIGKILL after grace_ms), then removes every uplink. */
void firc_tunrun_stop(firc_tunrun_t *t, int grace_ms);

void firc_tunrun_free(firc_tunrun_t *t);

void firc_tunrun_set_list_max_for_test(firc_tunrun_t *t, size_t bytes); /* test seam: tunvless's stdin limit */

/* The journal line for an event, or for a status change when ev is NULL; false when there is none. */
bool firc_tun_journal_line(const firc_tun_state_t *st, const firc_tev_t *ev, char *buf, size_t cap,
                           firc_log_level_t *level);

#endif
