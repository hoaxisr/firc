#ifndef FIRC_APP_H
#define FIRC_APP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/cancel.h"
#include "firc/fakeip.h"
#include "firc/dnspipeline.h"
#include "firc/dnsproxy.h"
#include "firc/loop.h"
#include "firc/nfcommit.h"
#include "firc/err.h"
#include "firc/id.h"
#include "firc/iptables.h"
#include "firc/models.h"
#include "firc/sub_worker.h"
#include "firc/port_remap.h"
#include "firc/conntrack.h"
#include "firc/rtnl.h"
#include "firc/ruleset.h"
#include "firc/settings.h"
#include "firc/yamlio.h"
#include "firc/nflogsock.h"
#include "firc/resolveroute.h"
#include "firc/keenetic_resolvers.h"

typedef struct firc_app firc_app_t;

/* all pointers borrowed, must outlive the app; pipeline is republished after every mutation here, or by the caller
 * if it edits rules in place outside this module's mutators */
typedef struct firc_app_deps {
    firc_config_t *cfg;
    firc_ipt_t *ipt4;
    firc_ipt_t *ipt6;
    firc_rtnl_t *rtnl;
    firc_ct_t *ct; /* optional */
    firc_dns_pipeline_t *pipeline;
    firc_fakeip_t *pool; /* nullable; without it the group logs its table unprotected */
    firc_loop_t *loop; /* nullable; without it a completed pass reports synchronously */
    firc_dnsproxy_t *proxy;
    firc_resolve_router_t *router; /* nullable; without it no resolve routes publish */
    firc_kn_resolvers_t *resolvers; /* nullable; without it only resolve.server groups get a resolver */
    uint32_t start_idx;
    firc_nflog_t *(*nflog_open)(uint16_t group, uint16_t copy_range); /* NULL takes firc_nflog_open */
    unsigned (*iface_index)(const char *name); /* NULL takes if_nametoindex */
    int64_t capture_seconds; /* 0 takes FIRC_CAPTURE_SECONDS */
    uint64_t (*mono_ms)(void); /* NULL takes CLOCK_MONOTONIC */
    const char *config_path; /* nullable; NULL means write nothing */
    const char *config_version;
} firc_app_deps_t;

/* rebuilds/republishes the DNS-matching snapshot (no-op if pipeline NULL); an in-place rule edit must call this */
firc_err_t firc_app_republish_dns_snapshot(firc_app_t *app);

/* rebuilds every group's resolve route and publishes it to the router; loop thread */
void firc_app_republish_resolve_routes(firc_app_t *app);

const firc_fakeip_t *firc_app_pool(const firc_app_t *app);

typedef struct firc_app_resolver_info {
    firc_resolve_source_t source;
    size_t n_servers;
    firc_resolver_addr_t servers[FIRC_RESOLVE_MAX_SERVERS];
    uint64_t fallbacks;
} firc_app_resolver_info_t;
void firc_app_group_resolver(const firc_app_t *app, const firc_group_t *g, firc_app_resolver_info_t *out);

/* loop thread only; takes the netfilter lock so a publish cannot land mid-pass; call after a pool change */
firc_err_t firc_app_refresh_pool_snapshot(firc_app_t *app);

/* publishes a fresh pool snapshot and asks for a pass that does not abort one in flight; loop thread */
void firc_app_pool_changed(firc_app_t *app);

/* a pass that wrote snapshot generation gen completed: tells the pool, releases every held answer now in the kernel */
void firc_app_pass_committed(firc_app_t *app, uint64_t gen);

/* whether every pair a held answer depends on is in the kernel; public for tests */
bool firc_app_answer_ready(firc_app_t *app, const firc_dns_msg_t *msg);

/* the snapshot a group's rules build from: the running pass's, or the current one with none running; public for tests */
const firc_fakeip_snapshot_t *firc_app_rules_snapshot(firc_app_t *app);

/* takes the netfilter lock, yielding the committer's pass first; every iptables-driving path must hold it; recursive */
void firc_app_nf_enter(firc_app_t *app);
void firc_app_nf_leave(firc_app_t *app);

firc_app_t *firc_app_create(const firc_app_deps_t *deps);
/* disables and frees every group's ruleset; does not touch cfg */
void firc_app_destroy(firc_app_t *app);

/* marks the app running; once true firc_app_add_group enables at once; firc_app_start_groups calls this at startup */
void firc_app_set_running(firc_app_t *app, bool running);
bool firc_app_is_running(const firc_app_t *app);

/* startup: enables every group (chains left to the committer), marks the app running, publishes the view and routes;
 * a failed enable is logged and left out; only a failed view publish returns an error */
firc_err_t firc_app_start_groups(firc_app_t *app);

size_t firc_app_user_group_count(const firc_app_t *app);
firc_ruleset_t *firc_app_user_group_at(const firc_app_t *app, size_t idx);
firc_ruleset_t *firc_app_find_group_by_id(const firc_app_t *app, firc_id_t id); /* linear search; NULL if not found */

/* takes ownership of group either way; FIRC_ERR_EXIST duplicate id, FIRC_ERR_INVAL dup rule id, or enable's error */
firc_err_t firc_app_add_group(firc_app_t *app, firc_group_t *group);

#define FIRC_APP_WHY_MAX 256 /* bytes for firc_app_add_group_why's message */
/* like firc_app_add_group; on a failed enable, why gets group "<name>": <step>: <error> */
firc_err_t firc_app_add_group_why(firc_app_t *app, firc_group_t *group, char *why, size_t why_len);

/* whether the group is routed right now; *reason is disabled/not-enabled/no-interface/not-written in that order,
 * or NULL when live; before firc_app_set_running every enabled group reads not-enabled */
bool firc_app_group_live(const firc_app_t *app, firc_id_t id, const char **reason);

/* retries every group whose enable failed and is due, spaced 1s to 60s; true if one came up; no-op if not running */
bool firc_app_retry_groups(firc_app_t *app, const char *iface);
bool firc_app_retry_timer_for_test(const firc_app_t *app, uint64_t *delay_ms); /* test seam */
#define FIRC_APP_RETRY_MIN_MS 1000u
#define FIRC_APP_RETRY_MAX_MS 60000u

/* the committer's health: first-pass-pending / failing-since; both false without a committer; loop thread */
void firc_app_netfilter_health(const firc_app_t *app, firc_nfcommit_health_t *out);

/* re-syncs rs's chain after its rules changed, asking for a pass only if its subnet prefixes changed */
firc_err_t firc_app_sync_group(firc_app_t *app, firc_ruleset_t *rs);

/* disables, frees and removes every group */
void firc_app_clear_groups(firc_app_t *app);

/* clears and re-adds groups under one lock; takes ownership of the array and its elements either way. A group that
 * fails to add (duplicate id) stops the batch, keeping the ones before it; a list sharing a live id+url keeps its
 * rules/hash/sync in flight; ends by requesting every list with no rules yet. */
firc_err_t firc_app_replace_groups(firc_app_t *app, firc_group_t **groups, size_t n);

/* PUT /groups/{id}: moves built's fields into the live group in place, taking it down and up around the move;
 * takes ownership of built either way. FIRC_ERR_NOENT if id is unknown, FIRC_OK otherwise. */
firc_err_t firc_app_update_group(firc_app_t *app, firc_id_t id, firc_group_t *built);

typedef struct {
    firc_id_t rule;
    bool has_enable, enable;
    const char *type; /* NULL: unchanged */
} firc_list_rule_edit_t;

/* edits the list of group id in place; two passes: first validates every edit, second applies. FIRC_ERR_NOENT unknown
 * id/list/rule, FIRC_ERR_INVAL bad type (msg set), FIRC_ERR_NOMEM otherwise. Caller saves the file. */
firc_err_t firc_app_patch_list_rules(firc_app_t *app, firc_id_t id, const firc_list_rule_edit_t *edits,
                                     size_t n, char *msg, size_t msg_len);

uint64_t firc_app_nf_enters_for_test(const firc_app_t *app); /* test seam */
uint64_t firc_app_nf_passes_for_test(const firc_app_t *app); /* test seam */
uint64_t firc_app_nf_last_completed_pass_for_test(const firc_app_t *app); /* test seam */
uint64_t firc_app_nf_change_for_test(const firc_app_t *app); /* test seam, under firc_app_nf_enter */
void firc_app_pay_flushes_for_test(firc_app_t *app, uint64_t ticket); /* test seam */
size_t firc_app_tombstones_for_test(const firc_app_t *app); /* test seam, under firc_app_nf_enter */

/* removes the group from the kernel (ip rules/routes at once, chain by tombstone) then the config and DNS view */
void firc_app_remove_group_by_index(firc_app_t *app, size_t idx);
bool firc_app_remove_group_by_id(firc_app_t *app, firc_id_t id);

/* starts the worker thread; needs deps->loop since every result comes back via it; FIRC_ERR_STATE if already started */
firc_err_t firc_app_start_list_worker(firc_app_t *app);

/* raises the cancel token, aborts the transfer in flight, joins; idempotent */
void firc_app_stop_list_worker(firc_app_t *app);

/* test seam: posted/result/dropped sync-event counts, process-wide, monotonic; any out-pointer may be NULL */
void firc_app_sync_event_counts_for_test(size_t *out_posted, size_t *out_results,
                                         size_t *out_dropped);

/* builds a job and enqueues it (list goes QUEUED); answer arrives as events. FIRC_ERR_NOENT unknown id/no list,
 * FIRC_ERR_INVAL no url, FIRC_ERR_STATE no worker, FIRC_ERR_LIMIT queue full (jobs fold by id) */
firc_err_t firc_app_request_sync(firc_app_t *app, firc_id_t id);

/* stores url on the list and, if changed, writes the groups file under the lock. FIRC_ERR_NOENT unknown id/no list,
 * FIRC_ERR_INVAL unsupported url; a failed file write is logged, not returned. */
firc_err_t firc_app_set_list_url(firc_app_t *app, firc_id_t id, const char *url);

/* requests every enabled list with a url but no body yet; not a re-fetch of everything the ticker already owns */
void firc_app_request_sync_missing(firc_app_t *app);

/* requests every list firc_sub_is_due says is due; a list already in flight is asked again, not skipped: a lost
 * result would otherwise never be retried; the queue folds the duplicate by id */
void firc_app_request_sync_due(firc_app_t *app, int64_t now_unix);

/* consumes one worker event (frees it and any rules it carries); STARTED/PROGRESS move state, RESULT applies it */
void firc_app_on_sync_event(firc_app_t *app, firc_sub_event_t *ev, int64_t now_unix);

/* the apply half of a sync under the lock: inherit ids, apply overrides, compare, and on a real change swap the
 * arena, resync, republish, save. Does not free ev. Stale seq is FIRC_OK, *out_changed false; gone group/list is
 * FIRC_ERR_NOENT; an ERROR result returns the worker's own error. */
firc_err_t firc_app_apply_sync_result(firc_app_t *app, firc_sub_event_t *ev, int64_t now_unix,
                                      bool *out_changed);

/* runs a sync on the calling thread, no worker/queue; a test seam and the CLI path, never called by the daemon.
 * Listener-silent. url_override replaces the list's url for this run only, restored on failure. */
firc_err_t firc_app_sync_list_now(firc_app_t *app, firc_id_t id, int64_t now_unix,
                                  const char *url_override, bool *out_changed);

/* told after every sync event for owner; done means the job finished; list must not be kept past the call */
typedef void (*firc_app_sync_listener_fn)(void *ud, firc_id_t owner, const firc_group_list_t *list,
                                          bool done);
void firc_app_set_sync_listener(firc_app_t *app, firc_app_sync_listener_fn fn, void *ud);

/* running is cfg->app (what the daemon reads at run time); saved is the app's own copy of firc.conf; a live
 * setting is copied to running when applied, a restart setting never is */
const firc_app_config_t *firc_app_saved_settings(const firc_app_t *app);
const firc_app_config_t *firc_app_running_settings(const firc_app_t *app);

/* writes next to conf_path as firc.conf alone (atomic), makes it the saved copy, applies every differing live
 * setting; NULL conf_path writes nothing. FIRC_OK takes and zeroes next; error leaves it the caller's. live_err
 * (may be NULL) reports a live-apply failure that happens after the write already landed. */
firc_err_t firc_app_put_settings(firc_app_t *app, firc_app_config_t *next, const char *conf_path,
                                 const char *version, bool applied[FIRC_SETTINGS_COUNT],
                                 firc_err_t *live_err);

/* the WebUI took port instead of the saved one: running and saved both say port, even when rewriting firc.conf fails */
firc_err_t firc_app_move_web_port(firc_app_t *app, uint16_t port, const char *conf_path,
                                  const char *version);

/* SIGHUP: the re-read app block becomes the saved copy, live settings apply as in a PUT; writes nothing */
firc_err_t firc_app_reload_settings(firc_app_t *app, const firc_app_config_t *from_file,
                                    bool applied[FIRC_SETTINGS_COUNT]);

/* pending[i] true for each restart row whose saved value differs from running; returns the count */
size_t firc_app_pending_restart(const firc_app_t *app, bool pending[FIRC_SETTINGS_COUNT]);

typedef struct firc_iface_info {
    char id[16];   /* IFNAMSIZ */
    char name[64]; /* friendly alias; empty unless built with FIRC_ENTWARE_KN */
} firc_iface_info_t;

/* enumerates system interfaces (getifaddrs, deduped); without showAllInterfaces keeps only IFF_POINTOPOINT ones */
firc_err_t firc_app_list_interfaces(const firc_app_t *app, firc_iface_info_t **out, size_t *out_n);

bool firc_iface_is_ignored_for_test(const char *name); /* test seam, always false without FIRC_ENTWARE_KN */

/* two files sharing one path; _save_groups writes only groups.yaml; _save_config writes both, from the saved copy */
firc_err_t firc_app_save_groups(firc_app_t *app, const char *conf_path,
                                const char *version);
firc_err_t firc_app_save_config(firc_app_t *app, const char *conf_path, const char *version);

/* brings the netfilter tables back in line with the live groups; with a committer this only asks it to abort+rebuild */
firc_err_t firc_app_force_commit_iptables(firc_app_t *app);

/* lets the rebuild reach the port-53 DNAT chain owned by main(); NULL disables remap53 */
void firc_app_set_port_remap(firc_app_t *app, firc_port_remap_t *remap);

/* stages the pool's FORWARD reject barrier on both engines without committing; every pass does this */
firc_err_t firc_app_stage_pool_reject(firc_app_t *app);

#define FIRC_CAPTURE_SECONDS 300 /* the only length a capture ever runs */
#define FIRC_TAP_TOKEN_CHARS 16 /* hex chars, no terminator counted; 8 random bytes */

/* readable by anything that can reach the API, which is why the stop token is deliberately not in here */
typedef struct firc_capture_status {
    bool running;
    int64_t ends_at; /* wall clock at start + length, for display only */
    int64_t seconds_left; /* monotonic countdown, never below zero */
} firc_capture_status_t;

/* starts a FIRC_CAPTURE_SECONDS capture on the LAN interfaces of app.link; FIRC_ERR_EXIST one runs, FIRC_ERR_INVAL
 * bad/empty link, FIRC_ERR_STATE no pool, FIRC_ERR_NOSYS kernel refuses the rules, FIRC_ERR_SYS NFLOG bind/watch
 * failed, FIRC_ERR_IO no token entropy, FIRC_ERR_NOMEM deadline not armed. On success token_out holds the stop token. */
firc_err_t firc_app_capture_start(firc_app_t *app, int64_t now_unix,
                                  char token_out[FIRC_TAP_TOKEN_CHARS + 1]);

/* stops it: unstages the rules, takes the readers down, asks for a pass, logs the summary; not an error when
 * nothing runs. token must match the running capture's (FIRC_ERR_NOENT otherwise); NULL is the daemon's own stop. */
firc_err_t firc_app_capture_stop(firc_app_t *app, const char *token);

void firc_app_capture_status(const firc_app_t *app, firc_capture_status_t *out); /* out is always filled */

/* the resolvers a policy-named selector is answered with, for the capture's judgement; must match the DNS pipeline's */
void firc_app_set_policy_resolver(firc_app_t *app, firc_devsel_policy_fn policy,
                                  firc_devsel_device_fn device, void *ud);

/* the packet path's selector lookups, wired in before the groups start; without them a policy entry marks nothing */
void firc_app_set_device_lookup(firc_app_t *app, firc_devsel_mark_fn mark, firc_devsel_hosts_fn hosts,
                                firc_devsel_policy_hosts_fn policy_hosts, firc_devsel_policy_nets_fn policy_nets,
                                void *ud);

/* Until read(ud) holds (ud as given to set_device_lookup; NULL read: always), a chain naming a policy marks nobody. */
void firc_app_set_policies_read(firc_app_t *app, bool (*read)(void *ud));

/* the firmware's host table changed: every routed group with a selector is re-rendered and compared before the
 * lock is taken, which is taken only if something moved; a narrowed chain flushes the group's flows by mark after
 * the pass. */
void firc_app_devices_changed(firc_app_t *app);

/* stages the capture's chain when one runs; every pass does this */
firc_err_t firc_app_stage_tap(firc_app_t *app);

firc_err_t firc_app_rebuild_netfilter(firc_app_t *app, firc_cancel_t *cancel);

/* full wipes everything first (firmware rewrite, first pass); otherwise one commit writes over what is there */
firc_err_t firc_app_rebuild_netfilter_kind(firc_app_t *app, firc_cancel_t *cancel, bool full);

/* starts the committer thread and with it the netfilter lock; call once everything the rebuild touches is up */
firc_err_t firc_app_start_netfilter_committer(firc_app_t *app);

/* stops and joins the committer, aborting a write in flight; must run before the rebuild's dependencies are torn down */
void firc_app_stop_netfilter_committer(firc_app_t *app);

firc_nfcommit_t *firc_app_committer_for_test(firc_app_t *app); /* test seam */

#endif /* FIRC_APP_H */
