#include "firc/app.h"

#include <errno.h>
#include <stdarg.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "firc/keenetic_rci.h"
#include "firc/mark.h"
#include "firc/json.h"
#include "firc/hash.h"
#include "firc/log.h"
#include "firc/match.h"
#include "firc/dnat.h"
#include "firc/pool_reject.h"
#include "firc/ifacename.h"
#include "firc/rand.h"
#include "firc/taprules.h"
#include "firc/tapwindow.h"
#include "firc/events.h"
#include "firc/recall.h"
#include "firc/netfilter_cleaner.h"
#include "firc/nfcommit.h"
#include "firc/rulesnap.h"
#include "firc/sub_fetch.h"
#include "firc/sub_worker.h"
#include "firc/subparse.h"

/* no ticket: the lock proves it was written before the pass that clears it */
typedef struct nf_tombstone {
    char chain[128];
    bool devices; /* a devices chain alone */
} nf_tombstone_t;

/* a flow flush a pass must carry before it runs */
typedef struct nf_flush {
    uint32_t value; /* firc_mark_group_value(field) */
    firc_id_t owner;
    char owner_s[FIRC_ID_STR_LEN];
    char iface[64];
    uint64_t ticket;
    bool narrowed; /* owner's selector narrowed: if routed again the same way, only its chunk flows go, not none */
} nf_flush_t;

struct firc_app {
    bool owed_full_sweep; /* a failed-to-report full pass asked for one more; cleared by the next landed report */
    firc_config_t *cfg;
    firc_app_config_t saved; /* what firc.conf holds; cfg->app is what the daemon RUNS, read at run time */
    firc_ipt_t *ipt4;
    firc_ipt_t *ipt6;
    firc_rtnl_t *rtnl;
    firc_ct_t *ct;
    firc_fakeip_t *pool;                /* borrowed, nullable; loop thread only */
    firc_loop_t *loop;                  /* borrowed, nullable */
    firc_dnsproxy_t *proxy;             /* borrowed, nullable */
    /* a pass copies pool_snap into pass_snap at its start, so a mid-pass refresh never changes its view */
    pthread_mutex_t snap_mu;
    firc_fakeip_snapshot_t *pool_snap;      /* owned */
    const firc_fakeip_snapshot_t *pass_snap; /* what the running pass reads */
    firc_fakeip_snapshot_t **retired;
    size_t n_retired;
    firc_dns_pipeline_t *pipeline;
    firc_resolve_router_t *router;   /* borrowed, nullable */
    firc_kn_resolvers_t *resolvers;  /* borrowed, nullable */
    uint32_t start_idx;
    bool running;

    firc_ruleset_t **rulesets;
    size_t n_rulesets;
    size_t cap_rulesets;

    firc_port_remap_t *port_remap; /* borrowed, nullable (main() owns it) */

    /* recursive: entry points can grow into nesting; lock/unlock is a no-op pair until a committer starts */
    pthread_mutex_t nf_mu;
    bool nf_mu_ready;
    uint64_t nf_enters; /* acquisitions of nf_mu through app_nf_enter, loop thread's only; test seam */
    firc_nfcommit_t *committer;
    /* written by the loop under nf_mu; cleared by the pass that carries it, before it releases nf_mu */
    nf_tombstone_t *tombs;
    size_t n_tombs;
    size_t cap_tombs;
    uint64_t nf_change; /* moved on under nf_mu by every mutation that asks for a pass; a pass reads it once, at lock time */
    nf_flush_t *flushes; /* loop thread only, at most one entry per mark field (FIRC_MARK_MAX_GROUPS) */
    size_t n_flushes;
    size_t cap_flushes;

    firc_sub_worker_t *sub_worker;
    uint64_t sync_seq_counter; /* monotonic across the app, not per list */
    firc_app_sync_listener_fn sync_listener;
    void *sync_listener_ud;
    bool sync_listener_muted; /* raised for the length of firc_app_sync_list_now, a test seam with no stream watching it */
    const char *config_path; /* borrowed; NULL means an applied sync writes no file */
    const char *config_version;
    /* _Atomic/relaxed: committer reads it per pass while the loop writes it; a plain bool here is a data race */
    _Atomic bool tap_open;
    int64_t tap_ends_at;
    int64_t tap_ends_mono; /* the real deadline, on a clock no NTP step moves; tap_ends_at is for printing only */
    int64_t tap_seconds; /* FIRC_CAPTURE_SECONDS, or a test's */
    uint64_t (*mono_ms)(void); /* a failed group's retry spacing */
    int retry_timer; /* the loop timer armed for the earliest due retry, 0 when none */
    uint64_t retry_timer_at;
    uint64_t retry_timer_delay;
    char tap_token[FIRC_TAP_TOKEN_CHARS + 1];
    int tap_timer; /* 0 when none: the deadline, armed on the loop */
    /* [0] new-connection socket, [1] ClientHello socket; loop-thread state, no lock needed */
    firc_nflog_t *(*tap_nflog_open)(uint16_t group, uint16_t copy_range);
    unsigned (*tap_iface_index)(const char *name);
    struct tap_reader {
        firc_app_t *app;
        firc_nflog_t *sock;
        int which;
    } tap_reader[2];
    char **tap_lan; /* capture's LAN interfaces, copied from app.link at start; read under nf_mu, like tap_open */
    size_t n_tap_lan;
    firc_tap_report_t *tap_report;
    firc_tap_pool_t tap_pool;
    /* counted by the committer, folded into the report by the loop; atomic since the loop must not take nf_mu here */
    _Atomic uint32_t tap_failed_passes;
    uint32_t tap_failed_passes_seen; /* loop thread only */
    firc_devsel_policy_fn tap_policy;
    firc_devsel_device_fn tap_device;
    void *tap_resolver_ud;
    firc_ruleset_lookup_t lookup; /* filled after the rulesets exist; read on the loop thread when a selector renders */

    firc_ip_t reject_base[2]; /* the pool prefixes, for the FORWARD barrier */
    uint8_t reject_len[2];
    bool reject_has[2];
};

/* every entry point that mutates the registry or drives an iptables engine must hold this */
static void app_nf_enter(firc_app_t *app);
static void app_nf_leave(firc_app_t *app);
static firc_err_t firc_tap_rules_remove_all(firc_app_t *app);
static void on_tap_readable(firc_loop_t *loop, int fd, uint32_t events, void *ud);
static void tap_reader_down(firc_app_t *app);
static void on_tap_deadline(firc_loop_t *loop, void *ud);
static void report_committed(firc_app_t *app, uint64_t gen, bool full, uint64_t ticket);
static const firc_fakeip_snapshot_t *rules_snapshot(void *ud);
static void pool_forget_group_id(firc_app_t *app, firc_id_t gid);
static void firc_app_request_sync_missing_unlocked(firc_app_t *app); /* needed from inside app_nf_enter below */

firc_err_t firc_app_refresh_pool_snapshot(firc_app_t *app) {
    if (app == NULL) { return FIRC_ERR_INVAL; }
    firc_fakeip_snapshot_t *fresh = firc_fakeip_snapshot_take(app->pool);
    if (fresh == NULL && app->pool != NULL) { return FIRC_ERR_NOMEM; }

    pthread_mutex_lock(&app->snap_mu);
    firc_fakeip_snapshot_t *old = app->pool_snap;
    app->pool_snap = fresh;
    bool in_use = old != NULL && old == app->pass_snap;
    if (in_use) {
        firc_fakeip_snapshot_t **grown =
            realloc(app->retired, (app->n_retired + 1) * sizeof(*grown));
        if (grown == NULL) { /* can't remember it: keep the old one current and drop the fresh copy */
            app->pool_snap = old;
            pthread_mutex_unlock(&app->snap_mu);
            firc_fakeip_snapshot_free(fresh);
            return FIRC_ERR_NOMEM;
        }
        app->retired = grown;
        app->retired[app->n_retired++] = old;
        old = NULL;
    }
    pthread_mutex_unlock(&app->snap_mu);
    firc_fakeip_snapshot_free(old);
    return FIRC_OK;
}

/* a group edit never writes a chain without its chunk rules: a pass reads its own snapshot */
static const firc_fakeip_snapshot_t *rules_snapshot(void *ud) {
    return firc_app_rules_snapshot(ud);
}

const firc_fakeip_snapshot_t *firc_app_rules_snapshot(firc_app_t *app) {
    pthread_mutex_lock(&app->snap_mu);
    const firc_fakeip_snapshot_t *s = app->pass_snap != NULL ? app->pass_snap : app->pool_snap;
    pthread_mutex_unlock(&app->snap_mu);
    return s;
}

static uint64_t pass_snapshot_begin(firc_app_t *app) {
    pthread_mutex_lock(&app->snap_mu);
    app->pass_snap = app->pool_snap;
    uint64_t gen = firc_fakeip_snapshot_gen(app->pass_snap);
    pthread_mutex_unlock(&app->snap_mu);
    return gen;
}

static void pass_snapshot_end(firc_app_t *app) {
    pthread_mutex_lock(&app->snap_mu);
    app->pass_snap = NULL;
    firc_fakeip_snapshot_t **retired = app->retired;
    size_t n = app->n_retired;
    app->retired = NULL;
    app->n_retired = 0;
    pthread_mutex_unlock(&app->snap_mu);
    for (size_t i = 0; i < n; i++) { firc_fakeip_snapshot_free(retired[i]); }
    free(retired);
}

void firc_app_nf_enter(firc_app_t *app) { app_nf_enter(app); }
void firc_app_nf_leave(firc_app_t *app) { app_nf_leave(app); }

static void app_nf_enter(firc_app_t *app) {
    if (!app->nf_mu_ready) { return; }
    firc_nfcommit_interrupt(app->committer);
    pthread_mutex_lock(&app->nf_mu);
    app->nf_enters++;
}

static void app_nf_leave(firc_app_t *app) {
    if (!app->nf_mu_ready) { return; }
    pthread_mutex_unlock(&app->nf_mu);
}

static firc_ruleset_deps_t ruleset_deps(firc_app_t *app) {
    firc_ruleset_deps_t deps = {
        .ipt4 = app->ipt4,
        .ipt6 = app->ipt6,
        .rtnl = app->rtnl,
        .ct = app->ct,
        .pool = app->pool,
        .snap = rules_snapshot,
        .snap_ud = app,
        .chain_prefix = app->cfg->app.netfilter.iptables.chain_prefix,
        .start_idx = app->start_idx,
        .lookup = &app->lookup,
    };
    return deps;
}

static firc_err_t rulesets_push(firc_app_t *app, firc_ruleset_t *rs) {
    if (app->n_rulesets == app->cap_rulesets) {
        size_t new_cap = app->cap_rulesets ? app->cap_rulesets * 2 : 8;
        firc_ruleset_t **na = realloc(app->rulesets, new_cap * sizeof(*na));
        if (!na) { return FIRC_ERR_NOMEM; }
        app->rulesets = na;
        app->cap_rulesets = new_cap;
    }
    app->rulesets[app->n_rulesets++] = rs;
    return FIRC_OK;
}

static void rulesets_remove_at(firc_app_t *app, size_t idx) {
    for (size_t i = idx; i + 1 < app->n_rulesets; i++) {
        app->rulesets[i] = app->rulesets[i + 1];
    }
    app->n_rulesets--;
}

static firc_nf_write_t app_write_mode(const firc_app_t *app) {
    return app->committer != NULL ? FIRC_NF_WRITE_BY_COMMITTER : FIRC_NF_WRITE_NOW;
}

/* never a full pass: a full one commits its flush before its refill (the fail-open window) */
static void app_request_more_locked(firc_app_t *app) {
    app->nf_change++;
    firc_nfcommit_request_more(app->committer);
}

static void group_chain_name(const firc_app_t *app, firc_id_t id, char *out, size_t cap) {
    firc_ruleset_chain_name_for(app->cfg->app.netfilter.iptables.chain_prefix, id, out, cap);
}

static void tombstone_remove(firc_app_t *app, const char *chain) {
    for (size_t i = 0; i < app->n_tombs; i++) {
        if (strcmp(app->tombs[i].chain, chain) != 0) { continue; }
        app->tombs[i] = app->tombs[--app->n_tombs];
        return;
    }
}

static void tombstone_add_kind(firc_app_t *app, const char *chain, bool devices) {
    for (size_t i = 0; i < app->n_tombs; i++) {
        if (strcmp(app->tombs[i].chain, chain) == 0) { return; }
    }
    if (app->n_tombs == app->cap_tombs) {
        size_t cap = app->cap_tombs != 0 ? app->cap_tombs * 2 : 8;
        nf_tombstone_t *grown = realloc(app->tombs, cap * sizeof(*grown));
        if (grown == NULL) { /* a full pass's cleaner removes every chain of ours anyway; the lesser harm than one that marks traffic forever */
            FIRC_WARN("no memory to remember that chain %s is to be deleted; asking for a full rebuild",
                      chain);
            firc_nfcommit_request(app->committer);
            return;
        }
        app->tombs = grown;
        app->cap_tombs = cap;
    }
    snprintf(app->tombs[app->n_tombs].chain, sizeof(app->tombs[0].chain), "%s", chain);
    app->tombs[app->n_tombs].devices = devices;
    app->n_tombs++;
}

static void tombstone_add(firc_app_t *app, const char *chain) { tombstone_add_kind(app, chain, false); }

/* a group chain's delete takes its devices chain with it; a devices tombstone deletes that chain alone */
static firc_err_t stage_tombstone(firc_ipt_t *ipt, const nf_tombstone_t *t) {
    return t->devices ? firc_ipset_to_link_stage_delete_devices(ipt, t->chain)
                      : firc_ipset_to_link_stage_delete(ipt, t->chain);
}

/* once no pass will run again: each chain's delete, both engines, committed at once */
static void write_tombstones_now(firc_app_t *app) {
    if (app->n_tombs == 0) { return; }
    firc_ipt_t *engines[] = {app->ipt4, app->ipt6};
    for (size_t e = 0; e < 2; e++) {
        if (engines[e] == NULL) { continue; }
        firc_err_t err = FIRC_OK;
        for (size_t i = 0; i < app->n_tombs && err == FIRC_OK; i++) {
            err = stage_tombstone(engines[e], &app->tombs[i]);
        }
        if (err == FIRC_OK) { err = firc_ipt_commit(engines[e]); } else { firc_ipt_discard(engines[e]); }
        if (err != FIRC_OK) {
            FIRC_WARN("%zu removed group chain(s) not deleted at stop (%s): the next start's clean "
                      "removes them", app->n_tombs, firc_err_str(err));
        }
    }
    app->n_tombs = 0;
}

static bool flush_queued_for(const firc_app_t *app, firc_id_t owner) {
    for (size_t i = 0; i < app->n_flushes; i++) {
        if (firc_id_equal(app->flushes[i].owner, owner)) { return true; }
    }
    return false;
}

/* a narrowed selector flushes only the group's chunk flows; subnet flows stay, not scoped by the selector */
static void flush_chunk_flows(firc_app_t *app, uint32_t value, const char *who) {
    if (app->ct == NULL || value == 0) { return; }
    size_t dropped = 0;
    firc_err_t err = firc_ct_flush_group_chunk_flows(
        app->ct, value, app->reject_has[0] ? app->reject_base[0].b : NULL, app->reject_has[0] ? app->reject_len[0] : 0,
        app->reject_has[1] ? app->reject_base[1].b : NULL, app->reject_has[1] ? app->reject_len[1] : 0, &dropped);
    if (dropped > 0) { FIRC_DEBUG("dropped %zu flow(s) to the chunks of group %s: its selector narrowed", dropped, who); }
    if (err != FIRC_OK) {
        FIRC_WARN("could not drop all flows to the chunks of group %s after its selector narrowed: %s; a device "
                  "no longer selected keeps its route for those until they end", who, firc_err_str(err));
    }
}

/* a field already queued keeps its entry (and interface) with the new ticket, so A->B->A leaves flows where they were */
static void flush_queue_add(firc_app_t *app, uint32_t value, const firc_group_t *g, bool narrowed) {
    uint64_t ticket = ++app->nf_change;
    for (size_t i = 0; i < app->n_flushes; i++) {
        if (app->flushes[i].value == value) {
            app->flushes[i].ticket = ticket;
            app->flushes[i].narrowed = app->flushes[i].narrowed || narrowed; /* never cleared by a merge */
            return;
        }
    }
    char who[FIRC_ID_STR_LEN];
    firc_id_format(g->id, who);
    if (app->n_flushes == app->cap_flushes) {
        size_t cap = app->cap_flushes != 0 ? app->cap_flushes * 2 : 8;
        nf_flush_t *grown = realloc(app->flushes, cap * sizeof(*grown));
        if (grown == NULL) { /* early rather than never, as a teardown flush always did */
            FIRC_WARN("no memory to queue the flush of group %s; flushing now", who);
            if (narrowed) {
                flush_chunk_flows(app, value, who);
            } else {
                firc_ipset_to_link_flush_mark(app->ct, value, who);
            }
            return;
        }
        app->flushes = grown;
        app->cap_flushes = cap;
    }
    nf_flush_t *e = &app->flushes[app->n_flushes++];
    e->value = value;
    e->owner = g->id;
    snprintf(e->owner_s, sizeof(e->owner_s), "%s", who);
    snprintf(e->iface, sizeof(e->iface), "%s", g->iface != NULL ? g->iface : "");
    e->ticket = ticket;
    e->narrowed = narrowed;
}

/* an owner routed again the same way (A->B->A) holds its field again, so its flows are skipped unpaid */
static void pay_flushes(firc_app_t *app, uint64_t ticket) {
    size_t kept = 0;
    for (size_t i = 0; i < app->n_flushes; i++) {
        nf_flush_t e = app->flushes[i];
        if (e.ticket > ticket) {
            app->flushes[kept++] = e;
            continue;
        }
        firc_ruleset_t *rs = firc_app_find_group_by_id(app, e.owner);
        const char *now = rs != NULL ? firc_ruleset_group(rs)->iface : NULL;
        if (rs != NULL && firc_ruleset_routed(rs) && now != NULL && strcmp(now, e.iface) == 0 &&
            firc_ruleset_mark_field(rs) == e.value) {
            if (e.narrowed) { /* routed again, narrower selector: flush only the chunk flows for devices no longer named */
                flush_chunk_flows(app, e.value, e.owner_s);
            } else {
                FIRC_DEBUG("group %s routes through %s again: its flows are its own, not flushed", e.owner_s,
                           e.iface);
            }
            continue;
        }
        firc_ipset_to_link_flush_mark(app->ct, e.value, e.owner_s);
        if (rs == NULL) { firc_rtnl_forget_mark_field(app->rtnl, e.owner_s); }
    }
    app->n_flushes = kept;
}

static uint64_t real_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool retry_pending(firc_ruleset_t *rs) {
    return firc_ruleset_group(rs)->enable && !firc_ruleset_runtime_enabled(rs) &&
           firc_ruleset_retry(rs)->backoff_ms != 0;
}

static void on_retry_timer(firc_loop_t *loop, void *ud) {
    (void)loop;
    firc_app_t *app = ud;
    app->retry_timer = 0; /* a one-shot: the loop retired it */
    app->retry_timer_at = 0;
    (void)firc_app_retry_groups(app, NULL); /* re-arms for what is left */
}

/* keeps one loop timer armed for the earliest due retry; makes a try happen even if nothing else arrives */
static void retry_rearm(firc_app_t *app) {
    uint64_t earliest = 0;
    for (size_t i = 0; i < app->n_rulesets; i++) {
        firc_ruleset_t *rs = app->rulesets[i];
        if (!retry_pending(rs)) { continue; }
        uint64_t at = firc_ruleset_retry(rs)->at_ms;
        if (earliest == 0 || at < earliest) { earliest = at; }
    }
    if (app->retry_timer != 0 && earliest == app->retry_timer_at) { return; }
    if (app->retry_timer != 0) { (void)firc_loop_del_timer(app->loop, app->retry_timer); }
    app->retry_timer = 0;
    app->retry_timer_at = 0;
    if (earliest == 0 || app->loop == NULL || !app->running) { return; } /* nothing is tried before the app runs */
    uint64_t now = app->mono_ms();
    uint64_t delay = earliest > now ? earliest - now : 1; /* 0 would disarm a timerfd */
    int id = 0;
    if (firc_loop_add_timer(app->loop, delay, 0, on_retry_timer, app, &id) != FIRC_OK) {
        FIRC_WARN("could not arm the retry of a group that failed to come up; the next link "
                  "event or completed pass tries it");
        return;
    }
    app->retry_timer = id;
    app->retry_timer_at = earliest;
    app->retry_timer_delay = delay;
}

/* 1s after the first failure, doubling to 60s; fresh (not a retry's own failure) restarts the run at 1s */
static void retry_note_failure(firc_app_t *app, firc_ruleset_t *rs, bool fresh) {
    firc_ruleset_retry_t *r = firc_ruleset_retry(rs);
    if (fresh) { *r = (firc_ruleset_retry_t){0}; }
    uint32_t next = r->backoff_ms == 0 ? FIRC_APP_RETRY_MIN_MS : r->backoff_ms * 2u;
    r->backoff_ms = next < FIRC_APP_RETRY_MAX_MS ? next : FIRC_APP_RETRY_MAX_MS;
    r->at_ms = app->mono_ms() + r->backoff_ms;
    retry_rearm(app);
}

static void retry_note_success(firc_app_t *app, firc_ruleset_t *rs) {
    *firc_ruleset_retry(rs) = (firc_ruleset_retry_t){0};
    retry_rearm(app);
}

/* a routed group's name comes off the tombstones, or the pass would write then delete its chain */
static firc_err_t app_group_up_ex(firc_app_t *app, firc_ruleset_t *rs, char *why, size_t why_len,
                                  bool quiet) {
    firc_nf_write_t mode = app_write_mode(app);
    const firc_group_t *g = firc_ruleset_group(rs);
    char chain[128];
    group_chain_name(app, g->id, chain, sizeof(chain));
    const char *step = NULL;
    firc_err_t err = firc_ruleset_enable(rs, mode, &step);
    if (err != FIRC_OK) {
        char line[256];
        snprintf(line, sizeof(line), "group \"%s\": %s: %s", g->name != NULL ? g->name : "",
                 step != NULL ? step : "enable", firc_err_str(err));
        if (!quiet) { FIRC_ERROR("%s", line); }
        if (why != NULL && why_len > 0) { snprintf(why, why_len, "%s", line); }
        retry_note_failure(app, rs, !quiet);
    } else {
        retry_note_success(app, rs);
    }
    if (mode == FIRC_NF_WRITE_BY_COMMITTER) {
        if (firc_ruleset_routed(rs)) {
            tombstone_remove(app, chain);
            /* losing its selector must drop the devices chain too, or the engine keeps writing it back */
            char dchain[128];
            firc_ruleset_devices_chain_name_for(app->cfg->app.netfilter.iptables.chain_prefix, g->id, dchain,
                                                sizeof(dchain));
            if (firc_ruleset_has_devices(rs)) {
                tombstone_remove(app, dchain);
            } else {
                tombstone_add_kind(app, dchain, true);
            }
        } else {
            tombstone_add(app, chain); /* stage_delete takes <chain>D with it */
        }
        app_request_more_locked(app);
    }
    return err;
}

static firc_err_t app_group_up(firc_app_t *app, firc_ruleset_t *rs, char *why, size_t why_len) {
    return app_group_up_ex(app, rs, why, why_len, false);
}

/* an rtnetlink error is logged and returned, but no caller stops on it: the next enable deletes a stale rule first */
static firc_err_t app_group_down(firc_app_t *app, firc_ruleset_t *rs, firc_flows_t flows) {
    firc_nf_write_t mode = app_write_mode(app);
    const firc_group_t *g = firc_ruleset_group(rs);
    bool had_chain = firc_ruleset_routed(rs);
    uint32_t value = firc_ruleset_mark_field(rs);
    char chain[128];
    group_chain_name(app, g->id, chain, sizeof(chain));
    firc_err_t err = firc_ruleset_disable(rs, flows, mode);
    if (err != FIRC_OK) {
        FIRC_WARN("group \"%s\": teardown: %s", g->name != NULL ? g->name : "", firc_err_str(err));
    }
    if (mode == FIRC_NF_WRITE_BY_COMMITTER && had_chain) {
        tombstone_add(app, chain);
        /* queued even for a KEEP: pay_flushes skips it if the group comes back on the same interface/field */
        if (value != 0) { flush_queue_add(app, value, g, false); }
        app_request_more_locked(app);
    }
    return err;
}

/* newly routed: its pairs are uncommitted, so their next answer waits for a pass whose snapshot stages the chain */
static void hold_if_newly_routed(firc_app_t *app, firc_ruleset_t *rs, bool was_routed) {
    if (was_routed || app->pool == NULL || !firc_ruleset_routed(rs)) { return; }
    char id[FIRC_ID_STR_LEN];
    firc_id_format(firc_ruleset_group(rs)->id, id);
    if (firc_fakeip_uncommit_group(app->pool, id) > 0) { firc_app_pool_changed(app); }
}

/* the flush waits for the pass that writes the narrower chain, or the old one would mark the next packet again */
static void note_narrowed(firc_app_t *app, firc_ruleset_t *rs) {
    uint32_t value = firc_ruleset_mark_field(rs);
    if (value == 0 || !firc_ruleset_routed(rs)) { return; }
    const firc_group_t *g = firc_ruleset_group(rs);
    if (app->committer != NULL) {
        flush_queue_add(app, value, g, true);
        return;
    }
    char who[FIRC_ID_STR_LEN];
    firc_id_format(g->id, who);
    flush_chunk_flows(app, value, who);
}

/* kept across a teardown so the enable after it can compare; ok false (OOM) counts as a narrowing */
typedef struct {
    firc_nf_devices_t dev;
    bool ok;
} devices_before_t;

static devices_before_t devices_before(const firc_ruleset_t *rs) {
    devices_before_t b = {{0}, true};
    const firc_nf_devices_t *d = firc_ruleset_devices(rs);
    if (d != NULL) { b.ok = firc_nf_devices_copy(&b.dev, d) == FIRC_OK; }
    return b;
}

/* a host table collected since the render can move a device with no edit, so a later refresh would compare equal */
static bool devices_narrowed_since(const firc_ruleset_t *rs, const devices_before_t *b) {
    const firc_nf_devices_t *now = firc_ruleset_devices(rs);
    if (now == NULL) { return false; }
    return !b->ok || firc_nf_devices_narrows(&b->dev, now);
}

static void republish_or_log(firc_app_t *app) {
    firc_err_t err = firc_app_republish_dns_snapshot(app);
    if (err != FIRC_OK) { FIRC_ERROR("failed to republish DNS-matching snapshot: %s", firc_err_str(err)); }
}

/* drops the snapshot before building the next one: holding both has OOM-killed the daemon on a large list before */
static void release_dns_snapshot(firc_app_t *app) {
    if (app->pipeline != NULL) { firc_dns_pipeline_set_snapshot(app->pipeline, NULL); }
}

/* without this a DELETE mid-sync leaves the socket held forever: the worker's result is dropped for a gone owner */
static void sync_end_for_removed_list(firc_app_t *app, firc_id_t owner, firc_group_list_t *l,
                                      const char *why) {
    if (app->sync_listener == NULL) { return; }
    l->sync_state = FIRC_SUB_SYNC_ERROR;
    snprintf(l->sync_error, sizeof(l->sync_error), "%s", why);
    app->sync_listener(app->sync_listener_ud, owner, l, true);
}

/* an idle list has no stream open; handle_get_sync_events answers one with its terminal event directly */
static void end_sync_in_flight(firc_app_t *app, firc_group_t *g, const char *why) {
    if (g->list == NULL) { return; }
    if (g->list->sync_state != FIRC_SUB_SYNC_QUEUED && g->list->sync_state != FIRC_SUB_SYNC_FETCHING) {
        return;
    }
    sync_end_for_removed_list(app, g->id, g->list, why);
}

/* a firmware-listed resolver inside firc's own pool routes nowhere; filtered here, the one place both are held */
static size_t drop_pool_addrs(firc_resolver_addr_t *arr, size_t n, const firc_fakeip_t *pool) {
    if (pool == NULL) { return n; }
    size_t kept = 0;
    for (size_t i = 0; i < n; i++) {
        if (firc_fakeip_overlaps(pool, &arr[i].ip, (uint8_t)(arr[i].ip.len * 8u))) { continue; }
        arr[kept++] = arr[i];
    }
    return kept;
}

void firc_app_republish_resolve_routes(firc_app_t *app) {
    if (app == NULL || app->router == NULL) { return; }
    size_t n = app->n_rulesets;
    firc_resolve_input_t *in = n ? calloc(n, sizeof(*in)) : NULL;
    firc_resolver_addr_t (*fw)[FIRC_RESOLVE_MAX_SERVERS] = n ? calloc(n, sizeof(*fw)) : NULL;
    if (n != 0 && (in == NULL || fw == NULL)) {
        free(in);
        free(fw);
        FIRC_ERROR("failed to rebuild the group resolver routes: out of memory");
        return;
    }
    for (size_t i = 0; i < n; i++) {
        firc_ruleset_t *rs = app->rulesets[i];
        const firc_group_t *g = firc_ruleset_group(rs);
        uint32_t field = firc_ruleset_mark_field(rs); /* shifted, 0 when not in the kernel */
        in[i].group = g;
        in[i].mark = (field != 0 && firc_ruleset_runtime_enabled(rs) && g->enable) ? (field | FIRC_MARK_HANDLED) : 0;
        in[i].blackhole = g->iface != NULL && strcmp(g->iface, FIRC_IPSET_TO_LINK_BLACKHOLE) == 0;
        in[i].v6_route = firc_ruleset_has_iface_route(rs, AF_INET6);
        in[i].firmware = fw[i];
        in[i].n_firmware = firc_kn_resolvers_for(app->resolvers, g->iface, fw[i], FIRC_RESOLVE_MAX_SERVERS);
        in[i].n_firmware = drop_pool_addrs(fw[i], in[i].n_firmware, app->pool);
    }
    firc_resolve_table_t t;
    firc_err_t err = firc_resolve_table_build(in, n, firc_resolve_router_table(app->router), &t);
    free(in);
    free(fw);
    if (err != FIRC_OK) {
        FIRC_ERROR("failed to rebuild the group resolver routes: %s", firc_err_str(err));
        return;
    }
    /* computed before the publish frees the old table; on OOM nothing is closed, sockets just stay on the old route */
    const firc_resolve_table_t *prev = firc_resolve_router_table(app->router);
    size_t n_prev = prev != NULL ? prev->n : 0;
    firc_id_t *stale = n_prev ? calloc(2 * n_prev, sizeof(*stale)) : NULL;
    size_t n_stale = stale != NULL ? firc_resolve_table_stale(prev, &t, stale, n_prev) : 0;
    size_t n_gone = stale != NULL ? firc_resolve_table_gone(prev, &t, stale + n_prev, n_prev) : 0;
    firc_resolve_router_publish(app->router, &t);
    for (size_t i = 0; app->proxy != NULL && i < n_stale; i++) {
        firc_dnsproxy_close_group_pools(app->proxy, stale[i]);
    }
    for (size_t i = 0; app->proxy != NULL && i < n_gone; i++) {
        firc_dnsproxy_forget_group(app->proxy, stale[n_prev + i]);
    }
    free(stale);
}

const firc_fakeip_t *firc_app_pool(const firc_app_t *app) {
    return app != NULL ? app->pool : NULL;
}

void firc_app_group_resolver(const firc_app_t *app, const firc_group_t *g, firc_app_resolver_info_t *out) {
    memset(out, 0, sizeof(*out));
    firc_resolve_route_t r;
    if (app != NULL && firc_resolve_router_route(app->router, g->id, &r)) {
        out->source = r.source;
        if (firc_resolve_route_usable(&r)) { /* a route with no mark lists no servers: queries go to the common upstream */
            out->n_servers = r.n_servers;
            memcpy(out->servers, r.servers, sizeof(out->servers));
        }
    } else { /* no router: not published yet */
        out->source = g->resolve.tunnel ? FIRC_RESOLVE_SOURCE_NONE : FIRC_RESOLVE_SOURCE_OFF;
    }
    if (app != NULL && app->proxy != NULL) { out->fallbacks = firc_dnsproxy_group_fallbacks(app->proxy, g->id); }
}

static bool group_in_view(const firc_group_t *g, void *ud) {
    return firc_ruleset_in_view(firc_app_find_group_by_id(ud, g->id));
}

/* the DNS-matching snapshot alone; a capture reads this same snapshot fresh from the pipeline, no second holder */
static firc_err_t republish_dns_matching_only(firc_app_t *app) {
    /* while running, the view is the groups actually in it (a failed enable is left out); before, the config is the view */
    firc_ruleset_snapshot_t *snap = app->running ? firc_ruleset_snapshot_build_where(app->cfg, group_in_view, app)
                                                 : firc_ruleset_snapshot_build(app->cfg);
    if (snap == NULL) { return FIRC_ERR_NOMEM; }
    if (app->pipeline != NULL) {
        firc_dns_pipeline_set_snapshot(app->pipeline, snap);
    } else {
        firc_ruleset_snapshot_free(snap);
    }
    return FIRC_OK;
}

/* resolve routes read the kernel's marks, not the snapshot: a just-enabled group needs its route either way */
firc_err_t firc_app_republish_dns_snapshot(firc_app_t *app) {
    firc_err_t err = republish_dns_matching_only(app);
    firc_app_republish_resolve_routes(app);
    return err;
}

firc_app_t *firc_app_create(const firc_app_deps_t *deps) {
    firc_app_t *app = calloc(1, sizeof(*app));
    if (!app) { return NULL; }
    app->cfg = deps->cfg;
    app->ipt4 = deps->ipt4;
    app->ipt6 = deps->ipt6;
    app->rtnl = deps->rtnl;
    app->ct = deps->ct;
    app->router = deps->router;
    app->resolvers = deps->resolvers;
    app->pool = deps->pool;
    /* pool prefixes never change; copied so a pass reads no live pool */
    for (unsigned fam = 0; fam < 2; fam++) {
        app->reject_has[fam] = deps->pool != NULL &&
            firc_fakeip_pool_prefix(deps->pool, fam == 0 ? FIRC_FAM_V4 : FIRC_FAM_V6, &app->reject_base[fam], &app->reject_len[fam]);
    }
    app->loop = deps->loop;
    app->tap_nflog_open = deps->nflog_open != NULL ? deps->nflog_open : firc_nflog_open;
    app->tap_iface_index = deps->iface_index != NULL ? deps->iface_index : if_nametoindex;
    app->tap_seconds = deps->capture_seconds > 0 ? deps->capture_seconds : FIRC_CAPTURE_SECONDS;
    app->mono_ms = deps->mono_ms != NULL ? deps->mono_ms : real_mono_ms;
    app->proxy = deps->proxy;
    app->pool_snap = firc_fakeip_snapshot_take(deps->pool); /* so a pass before anything is issued still has a consistent view */
    pthread_mutex_init(&app->snap_mu, NULL);
    app->pipeline = deps->pipeline;
    app->config_path = deps->config_path;
    app->config_version = deps->config_version;
    app->start_idx = deps->start_idx;

    firc_ruleset_deps_t rdeps = ruleset_deps(app);
    for (size_t i = 0; i < app->cfg->n_groups; i++) {
        firc_ruleset_t *rs = firc_ruleset_new(app->cfg->groups[i], &rdeps);
        if (!rs || rulesets_push(app, rs) != FIRC_OK) {
            firc_ruleset_free(rs);
            firc_app_destroy(app);
            return NULL;
        }
    }
    if (firc_app_config_copy(&app->saved, &app->cfg->app) != FIRC_OK) {
        firc_app_destroy(app);
        return NULL;
    }
    return app;
}

void firc_app_destroy(firc_app_t *app) {
    if (!app) { return; }
    firc_app_stop_netfilter_committer(app); /* nothing below is safe while a rebuild can still read the registry */
    if (app->retry_timer != 0) { (void)firc_loop_del_timer(app->loop, app->retry_timer); }
    app->retry_timer = 0;
    firc_app_stop_list_worker(app); /* before the config it reports about goes: a result it posts could reach a loop whose app no longer exists */
    write_tombstones_now(app); /* no pass will run again, so write directly; before the flushes, so a flushed flow meets no chain to re-mark it */
    pay_flushes(app, UINT64_MAX); /* before the groups go, so an owner routed again is still recognised */
    for (size_t i = 0; i < app->n_rulesets; i++) {
        firc_ruleset_disable(app->rulesets[i], FIRC_FLOWS_KEEP, FIRC_NF_WRITE_NOW); /* pool is saved/restored, same names/addrs/marks, so in-flight flows stay correct across a restart */
        firc_ruleset_free(app->rulesets[i]);
    }
    free(app->rulesets);
    free(app->tombs);
    free(app->flushes);
    /* stops (not merely unregisters) first, or the commit below reinstalls NFLOG rules nobody binds */
    (void)firc_app_capture_stop(app, NULL);

    /* a fake address no longer routed must not be rewritten to the real one, or a client is sent out the WAN in the clear */
    const char *prefix = app->cfg->app.netfilter.iptables.chain_prefix;
    firc_ipt_t *engines[] = {app->ipt4, app->ipt6};
    for (size_t i = 0; i < 2; i++) {
        if (engines[i] == NULL) { continue; }
        firc_err_t err = firc_dnat_delete_rules(engines[i], prefix, app->pool_snap);
        if (err == FIRC_OK) { err = firc_ipt_commit(engines[i]); } else { firc_ipt_discard(engines[i]); }
        if (err != FIRC_OK) {
            FIRC_WARN("dnat chain not removed (%s): a client still holding a fake address is rewritten "
                      "to the real one until the next start sweeps it", firc_err_str(err));
        }
    }
    firc_fakeip_snapshot_free(app->pool_snap);
    app->pool_snap = NULL;
    for (size_t i = 0; i < app->n_retired; i++) { firc_fakeip_snapshot_free(app->retired[i]); }
    free(app->retired);
    pthread_mutex_destroy(&app->snap_mu);
    firc_app_config_clear(&app->saved);
    free(app);
}

void firc_app_set_running(firc_app_t *app, bool running) {
    app->running = running;
}
bool firc_app_is_running(const firc_app_t *app) { return app->running; }

/* enabled as a mutation would, chain by the committer's first full pass, so nothing here writes iptables directly */
firc_err_t firc_app_start_groups(firc_app_t *app) {
    app_nf_enter(app);
    for (size_t i = 0; i < app->n_rulesets; i++) {
        firc_ruleset_t *rs = app->rulesets[i];
        const char *step = NULL;
        firc_err_t err = firc_ruleset_enable(rs, FIRC_NF_WRITE_BY_COMMITTER, &step);
        if (err != FIRC_OK) {
            const char *name = firc_ruleset_group(rs)->name;
            FIRC_ERROR("failed to enable group \"%s\": %s: %s", name != NULL ? name : "",
                       step != NULL ? step : "enable", firc_err_str(err));
            retry_note_failure(app, rs, true);
        }
    }
    app->running = true;
    retry_rearm(app); /* the failures above could not arm it before running */
    firc_nfcommit_request_more(app->committer); /* no-op in the daemon (committer starts after this); a caller with one running still gets a pass */
    firc_err_t err = firc_app_republish_dns_snapshot(app); /* also republishes resolve routes */
    app_nf_leave(app);
    if (err != FIRC_OK) { FIRC_ERROR("failed to publish the DNS view: %s", firc_err_str(err)); }
    return err;
}

size_t firc_app_user_group_count(const firc_app_t *app) {
    return app->n_rulesets;
}

firc_ruleset_t *firc_app_user_group_at(const firc_app_t *app, size_t idx) {
    return idx < app->n_rulesets ? app->rulesets[idx] : NULL;
}

firc_ruleset_t *firc_app_find_group_by_id(const firc_app_t *app, firc_id_t id) {
    for (size_t i = 0; i < app->n_rulesets; i++) {
        if (firc_id_equal(firc_ruleset_group(app->rulesets[i])->id, id)) { return app->rulesets[i]; }
    }
    return NULL;
}

/* rolls the add back on failure; only while running and only for a single add */
static firc_err_t activate_group_at(firc_app_t *app, size_t idx, char *why, size_t why_len) {
    firc_ruleset_t *rs = app->rulesets[idx];
    firc_err_t err = app_group_up(app, rs, why, why_len); /* carries the prefixes already */
    if (err == FIRC_OK) { hold_if_newly_routed(app, rs, false); } /* defensive: an id re-added after a delete may have parked mappings */
    if (err != FIRC_OK) {
        rulesets_remove_at(app, idx); /* the enable rolled itself back; its tombstone is app_group_up's */
        firc_ruleset_free(rs);
        /* no snapshot release: it borrows nothing of this group, built before the group existed */
        end_sync_in_flight(app, app->cfg->groups[idx], "group removed");
        firc_config_remove_group_by_index(app->cfg, idx);
        retry_rearm(app); /* the failure armed a try for a group that is gone */
    }
    return err;
}

/* activate false adds without enabling: a batch adds every group first, activates them afterwards */
static firc_err_t firc_app_add_group_unlocked(firc_app_t *app, firc_group_t *group, bool activate,
                                              char *why, size_t why_len) {
    firc_err_t err = FIRC_OK; /* every refusal below frees group; in a replace it may carry a list whose sync-in-flight stream ends here */
    for (size_t i = 0; err == FIRC_OK && i < app->cfg->n_groups; i++) {
        if (firc_id_equal(app->cfg->groups[i]->id, group->id)) { err = FIRC_ERR_EXIST; }
    }
    for (size_t i = 0; err == FIRC_OK && i < group->n_rules; i++) {
        for (size_t j = i + 1; j < group->n_rules; j++) {
            if (firc_id_equal(group->rules[i]->id, group->rules[j]->id)) { err = FIRC_ERR_INVAL; }
        }
    }
    if (err == FIRC_OK) { err = firc_config_add_group(app->cfg, group); }
    if (err != FIRC_OK) {
        end_sync_in_flight(app, group, "group removed");
        firc_group_free(group);
        return err;
    }
    size_t group_idx = app->cfg->n_groups - 1;

    firc_ruleset_deps_t rdeps = ruleset_deps(app);
    firc_ruleset_t *rs = firc_ruleset_new(app->cfg->groups[group_idx], &rdeps);
    err = rs != NULL ? rulesets_push(app, rs) : FIRC_ERR_NOMEM;
    if (err != FIRC_OK) {
        firc_ruleset_free(rs);
        end_sync_in_flight(app, group, "group removed");
        firc_config_remove_group_by_index(app->cfg, group_idx);
        return err;
    }

    if (app->running && activate) {
        err = activate_group_at(app, app->n_rulesets - 1, why, why_len);
        if (err != FIRC_OK) { return err; }
    }
    if (activate) { /* a batch republishes once and asks for missing lists once, in firc_app_replace_groups; a single add (POST /groups) does both here */
        republish_or_log(app);
        if (group->list != NULL) { firc_app_request_sync_missing_unlocked(app); }
    }
    return FIRC_OK;
}

firc_err_t firc_app_add_group_why(firc_app_t *app, firc_group_t *group, char *why, size_t why_len) {
    app_nf_enter(app);
    firc_err_t r = firc_app_add_group_unlocked(app, group, true, why, why_len);
    app_nf_leave(app);
    return r;
}

firc_err_t firc_app_add_group(firc_app_t *app, firc_group_t *group) {
    return firc_app_add_group_why(app, group, NULL, 0);
}

/* asked of the kernel each call, on the loop that owns app->rtnl, so it is never stale; blackhole needs no link */
static bool iface_link_up(const firc_app_t *app, const char *iface) {
    if (iface != NULL && strcmp(iface, FIRC_IPSET_TO_LINK_BLACKHOLE) == 0) { return true; }
    if (app->rtnl == NULL || iface == NULL) { return false; }
    firc_link_info_t li;
    bool found = false;
    if (firc_rtnl_link_by_name(app->rtnl, iface, &li, &found) != FIRC_OK) { return false; }
    return found && li.up;
}

bool firc_app_group_live(const firc_app_t *app, firc_id_t id, const char **reason) {
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, id);
    const char *why = NULL;
    if (rs != NULL && !firc_ruleset_group(rs)->enable) {
        why = "disabled";
    } else if (rs == NULL || !firc_ruleset_runtime_enabled(rs)) {
        why = "not-enabled";
    } else if (!firc_ruleset_routed(rs) || !iface_link_up(app, firc_ruleset_group(rs)->iface)) {
        why = "no-interface"; /* routing itself does not read the link; the table's blackhole default routes nowhere either way */
    } else {
        /* no false live: before the first pass, or after 5s of failures, the chain may not be in the kernel */
        firc_nfcommit_health_t h;
        firc_app_netfilter_health(app, &h);
        if (h.failing || h.first_pending) { why = "not-written"; }
    }
    if (reason != NULL) { *reason = why; }
    return why == NULL;
}

static bool retry_due(const firc_app_t *app, firc_ruleset_t *rs, const char *iface, uint64_t now) {
    const firc_group_t *g = firc_ruleset_group(rs);
    if (!app->running || !retry_pending(rs) || now < firc_ruleset_retry(rs)->at_ms) { return false; }
    return iface == NULL || (g->iface != NULL && strcmp(g->iface, iface) == 0);
}

bool firc_app_retry_timer_for_test(const firc_app_t *app, uint64_t *delay_ms) {
    if (delay_ms != NULL) { *delay_ms = app->retry_timer != 0 ? app->retry_timer_delay : 0; }
    return app->retry_timer != 0;
}

/* the due check runs first, without the lock, so nothing-due does not interrupt a pass in flight */
bool firc_app_retry_groups(firc_app_t *app, const char *iface) {
    if (app == NULL) { return false; }
    uint64_t now = app->mono_ms();
    bool any = false;
    for (size_t i = 0; i < app->n_rulesets && !any; i++) { any = retry_due(app, app->rulesets[i], iface, now); }
    if (!any) {
        retry_rearm(app); /* a timer that fired early is armed again for when it is due */
        return false;
    }
    app_nf_enter(app);
    bool came_up = false;
    for (size_t i = 0; i < app->n_rulesets; i++) {
        firc_ruleset_t *rs = app->rulesets[i];
        if (!retry_due(app, rs, iface, now)) { continue; }
        char why[FIRC_APP_WHY_MAX];
        why[0] = '\0';
        if (app_group_up_ex(app, rs, why, sizeof(why), true) == FIRC_OK) {
            hold_if_newly_routed(app, rs, false);
            came_up = true;
            const char *name = firc_ruleset_group(rs)->name;
            FIRC_INFO("group \"%s\" came up on a retry", name != NULL ? name : "");
            continue;
        }
        firc_ruleset_retry_t *r = firc_ruleset_retry(rs);
        if (!r->warned) {
            FIRC_WARN("%s; trying again, spaced up to every %u s, until it comes up", why,
                      (unsigned)(FIRC_APP_RETRY_MAX_MS / 1000u));
            r->warned = true;
        } else {
            FIRC_DEBUG("%s (retry)", why);
        }
    }
    if (came_up) { republish_or_log(app); }
    app_nf_leave(app);
    return came_up;
}

void firc_app_netfilter_health(const firc_app_t *app, firc_nfcommit_health_t *out) {
    firc_nfcommit_health(app != NULL ? app->committer : NULL, out);
}

/* without the lock: firc_app_sync_group is this plus the lock, for a caller not already inside it */
static firc_err_t sync_group_ruleset_locked(firc_app_t *app, firc_ruleset_t *rs) {
    bool chain_changed = false;
    firc_err_t r = firc_ruleset_sync(rs, &chain_changed);
    /* asked for even on error: a failed devices render already handed the link new prefixes the next sync would miss */
    if (chain_changed) {
        if (app->committer) {
            app_request_more_locked(app);
        } else {
            firc_err_t w = firc_ruleset_rewrite_chains(rs);
            if (r == FIRC_OK) { r = w; }
        }
    }
    if (firc_ruleset_devices_narrowed(rs)) { note_narrowed(app, rs); } /* a render that narrowed resets chunk flows exactly as a narrowing edit does */
    return r;
}

firc_err_t firc_app_sync_group(firc_app_t *app, firc_ruleset_t *rs) {
    app_nf_enter(app);
    firc_err_t r = sync_group_ruleset_locked(app, rs);
    app_nf_leave(app);
    return r;
}

static bool id_among(firc_id_t id, firc_group_t *const *keep, size_t n_keep) {
    for (size_t i = 0; i < n_keep; i++) {
        if (keep[i] != NULL && firc_id_equal(keep[i]->id, id)) { return true; }
    }
    return false;
}

/* true only when the group is among keep AND comes back out of the same interface */
static bool keeps_its_routing(const firc_group_t *g, firc_group_t *const *keep, size_t n_keep) {
    for (size_t i = 0; i < n_keep; i++) {
        if (keep[i] == NULL || !firc_id_equal(keep[i]->id, g->id)) { continue; }
        const char *was = g->iface != NULL ? g->iface : "";
        const char *will = keep[i]->iface != NULL ? keep[i]->iface : "";
        return keep[i]->enable && strcmp(was, will) == 0; /* a group turned off routes nothing, so its flows must stop too */
    }
    return false;
}

/* keep: groups about to be re-added under the same ids, whose mappings must survive the replace */
static void clear_groups_keeping(firc_app_t *app, firc_group_t *const *keep, size_t n_keep) {
    release_dns_snapshot(app); /* the snapshot borrows the lists freed below */
    /* forgetting a group may rebuild tables on the spot, walking the ruleset list, so the list is emptied first */
    size_t n_gone = 0;
    firc_id_t *gone = app->n_rulesets ? calloc(app->n_rulesets, sizeof(*gone)) : NULL;
    for (size_t i = 0; i < app->n_rulesets; i++) {
        const firc_group_t *g = firc_ruleset_group(app->rulesets[i]);
        (void)app_group_down(app, app->rulesets[i],
                             keeps_its_routing(g, keep, n_keep) ? FIRC_FLOWS_KEEP : FIRC_FLOWS_DROP);
        if (!id_among(g->id, keep, n_keep)) {
            if (g->list != NULL) {
                sync_end_for_removed_list(app, g->id, g->list, "group removed");
            }
            if (gone != NULL) { gone[n_gone++] = g->id; }
        }
        firc_ruleset_free(app->rulesets[i]);
    }
    app->n_rulesets = 0;
    firc_config_clear_groups(app->cfg);
    for (size_t i = 0; i < n_gone; i++) { pool_forget_group_id(app, gone[i]); }
    free(gone);
    republish_or_log(app);
    retry_rearm(app);
}

static void firc_app_clear_groups_unlocked(firc_app_t *app) {
    clear_groups_keeping(app, NULL, 0);
}


void firc_app_clear_groups(firc_app_t *app) {
    app_nf_enter(app);
    firc_app_clear_groups_unlocked(app);
    app_nf_leave(app);
}

/* the same list under new metadata: moving the arena across avoids a refetch */
static void carry_list(firc_group_list_t *nw, firc_group_list_t *old) {
    /* sync_seq is carried for every same-url arrival, or a Save mid-sync strands the stream at "fetching" */
    nw->sync_state = old->sync_state;
    nw->sync_seq = old->sync_seq;
    nw->sync_progress = old->sync_progress;
    memcpy(nw->sync_error, old->sync_error, sizeof(nw->sync_error));

    firc_sub_rules_free(&nw->rules);
    firc_sub_rules_move(&nw->rules, &old->rules);
    memcpy(nw->body_hash, old->body_hash, sizeof(nw->body_hash));
    nw->has_body_hash = old->has_body_hash;
    nw->last_check = old->last_check;
    nw->last_update = old->last_update; /* the daemon's, never a body's */
    firc_sub_apply_overrides(nw, &nw->rules);

    old->has_body_hash = false;
    memset(old->body_hash, 0, sizeof(old->body_hash));
    old->sync_state = FIRC_SUB_SYNC_IDLE;
    old->last_check = 0;
}

static bool same_url(const firc_group_list_t *a, const firc_group_list_t *b) {
    return strcmp(a->url != NULL ? a->url : "", b->url != NULL ? b->url : "") == 0;
}

/* carried into arrival's list if the url is the same; otherwise the stream watching live's list ends */
static void hand_over_list(firc_app_t *app, firc_group_t *live, firc_group_t *arrival) {
    if (live->list == NULL) { return; }
    if (arrival->list == NULL) {
        sync_end_for_removed_list(app, live->id, live->list, "list removed");
    } else if (same_url(arrival->list, live->list)) {
        carry_list(arrival->list, live->list);
    } else {
        end_sync_in_flight(app, live, "list url changed");
    }
}

firc_err_t firc_app_replace_groups(firc_app_t *app, firc_group_t **groups, size_t n) {
    /* one acquisition for the whole swap, or a committer pass could land between clear() and add() */
    app_nf_enter(app);
    size_t n_was = 0; /* who was routed before the swap; taken before anything moves, so an OOM here applies nothing */
    firc_id_t *was = app->n_rulesets != 0 ? calloc(app->n_rulesets, sizeof(*was)) : NULL;
    if (app->n_rulesets != 0 && was == NULL) {
        app_nf_leave(app);
        for (size_t i = 0; i < n; i++) { firc_group_free(groups[i]); }
        free(groups);
        return FIRC_ERR_NOMEM;
    }
    for (size_t i = 0; i < app->n_rulesets; i++) {
        if (firc_ruleset_routed(app->rulesets[i])) { was[n_was++] = firc_ruleset_group(app->rulesets[i])->id; }
    }
    size_t n_narrowed = 0; /* groups the swap keeps with a narrower selector, read by id before it moves old selectors out */
    firc_id_t *narrowed = n != 0 ? calloc(n, sizeof(*narrowed)) : NULL;
    /* each routed group's devices copy, to compare the Save's render with, by the same index as was */
    devices_before_t *was_dev = n_was != 0 ? calloc(n_was, sizeof(*was_dev)) : NULL;
    if ((n != 0 && narrowed == NULL) || (n_was != 0 && was_dev == NULL)) {
        free(narrowed);
        free(was_dev);
        free(was);
        app_nf_leave(app);
        for (size_t i = 0; i < n; i++) { firc_group_free(groups[i]); }
        free(groups);
        return FIRC_ERR_NOMEM;
    }
    for (size_t i = 0; i < n; i++) {
        firc_ruleset_t *old = firc_app_find_group_by_id(app, groups[i]->id);
        if (old != NULL && firc_ruleset_routed(old) &&
            firc_devsel_spec_narrows(&firc_ruleset_group(old)->devices, &groups[i]->devices)) {
            narrowed[n_narrowed++] = groups[i]->id;
        }
    }
    for (size_t w = 0; w < n_was; w++) { was_dev[w] = devices_before(firc_app_find_group_by_id(app, was[w])); }
    release_dns_snapshot(app); /* before the gate moves any arena or anything is freed: the snapshot borrows the lists */
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < app->cfg->n_groups; j++) {
            if (firc_id_equal(app->cfg->groups[j]->id, groups[i]->id)) {
                hand_over_list(app, app->cfg->groups[j], groups[i]);
                break;
            }
        }
    }
    clear_groups_keeping(app, groups, n);
    firc_err_t err = FIRC_OK;
    size_t i = 0;
    for (; i < n; i++) {
        err = firc_app_add_group_unlocked(app, groups[i], false, NULL, 0); /* takes ownership, even on failure */
        if (err != FIRC_OK) { break; }
    }
    /* every added group is activated regardless of the one before it; one that fails stays config-only, not-enabled */
    if (app->running) {
        for (size_t k = 0; k < app->n_rulesets; k++) {
            firc_ruleset_t *rs = app->rulesets[k];
            bool was_routed = false;
            size_t at = 0;
            for (size_t w = 0; w < n_was && !was_routed; w++) {
                was_routed = firc_id_equal(was[w], firc_ruleset_group(rs)->id);
                at = w;
            }
            if (app_group_up(app, rs, NULL, 0) == FIRC_OK) {
                hold_if_newly_routed(app, rs, was_routed);
                bool narrows = was_routed && devices_narrowed_since(rs, &was_dev[at]);
                for (size_t w = 0; w < n_narrowed && !narrows; w++) {
                    narrows = firc_id_equal(narrowed[w], firc_ruleset_group(rs)->id);
                }
                if (narrows) { note_narrowed(app, rs); }
            }
        }
    }
    for (size_t w = 0; w < n_was; w++) { firc_nf_devices_clear(&was_dev[w].dev); }
    free(was_dev);
    free(was);
    free(narrowed);
    for (size_t j = i + 1; j < n; j++) {
        end_sync_in_flight(app, groups[j], "group removed");
        firc_group_free(groups[j]);
    }
    republish_or_log(app);
    /* a failed replace does not restore the old set: a group it could not add is gone with its list */
    firc_app_request_sync_missing_unlocked(app);
    app_nf_leave(app);
    free(groups);
    return err;
}

/* moves fields from from into into in place, preserving into's address and id; frees the emptied from shell */
static void group_move_into(firc_app_t *app, firc_group_t *into, firc_group_t *from) {
    free(into->name);
    into->name = from->name;
    free(into->iface);
    into->iface = from->iface;
    into->enable = from->enable;
    for (size_t i = 0; i < into->n_rules; i++) { firc_rule_free(into->rules[i]); }
    free(into->rules);
    into->rules = from->rules;
    into->n_rules = from->n_rules;
    firc_devsel_spec_clear(&into->devices);
    into->devices = from->devices;
    free(into->resolve.server);
    into->resolve = from->resolve;
    if (into->list != NULL) { /* hand_over_list: after it, into's list is either carried into from's (blank) or finished with */
        hand_over_list(app, into, from);
        firc_group_list_free(into->list);
    }
    into->list = from->list;
    free(from); /* the shell: everything it held has moved */
}

firc_err_t firc_app_update_group(firc_app_t *app, firc_id_t id, firc_group_t *built) {
    app_nf_enter(app);
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, id);
    if (rs == NULL) {
        app_nf_leave(app);
        firc_group_free(built);
        return FIRC_ERR_NOENT;
    }
    firc_group_t *live = firc_ruleset_group_mut(rs);
    bool was_routed = firc_ruleset_routed(rs);
    bool narrowed = was_routed && firc_devsel_spec_narrows(&live->devices, &built->devices); /* read before the move takes the old selector away */
    devices_before_t before = devices_before(rs);
    if (firc_ruleset_runtime_enabled(rs)) {
        const char *was = live->iface != NULL ? live->iface : "";
        const char *will = built->iface != NULL ? built->iface : "";
        /* flows are only wrong if the update changed where packets go, not a rename or rule edit */
        firc_flows_t flows =
            (built->enable && strcmp(was, will) == 0) ? FIRC_FLOWS_KEEP : FIRC_FLOWS_DROP;
        (void)app_group_down(app, rs, flows); /* an rtnetlink error does not stop the update; the enable below deletes a stale rule before adding its own */
    }
    release_dns_snapshot(app); /* it borrows the list freed by the move */
    group_move_into(app, live, built);
    firc_app_request_sync_missing_unlocked(app); /* a new list, or a new url */
    /* runs whenever the daemon runs, not only when it was before; the move stands whether this enable fails or not */
    if (app->running && app_group_up(app, rs, NULL, 0) == FIRC_OK) {
        hold_if_newly_routed(app, rs, was_routed);
        if (narrowed || (was_routed && devices_narrowed_since(rs, &before))) { note_narrowed(app, rs); }
    }
    firc_nf_devices_clear(&before.dev);
    firc_err_t snap_err = republish_dns_matching_only(app); /* after the enable: before it this group was not in the view */
    if (snap_err != FIRC_OK) {
        FIRC_ERROR("failed to republish DNS-matching snapshot: %s", firc_err_str(snap_err));
    }
    firc_app_republish_resolve_routes(app); /* after the enable: the mark is the kernel's now */
    app_nf_leave(app);
    return FIRC_OK;
}

/* a subnet rule is part of the chain, so its enable/type needs the kernel told; a name rule needs only the snapshot */
static bool is_subnet_type(const char *type) {
    return strcmp(type, FIRC_RULE_SUBNET) == 0 || strcmp(type, FIRC_RULE_SUBNET6) == 0;
}

/* "" and NULL are the same spec everywhere a proto/ports pair is compared */
static bool spec_eq(const char *a, const char *b) { return strcmp(a != NULL ? a : "", b != NULL ? b : "") == 0; }

/* whether some OTHER rule shares idx's text/proto/ports, the only case an override needs list_type to tell apart */
static bool rule_has_twin(const firc_sub_rules_t *rs, size_t idx) {
    const char *text = firc_sub_rules_text(rs, idx);
    const char *proto = firc_sub_rules_proto(rs, idx), *ports = firc_sub_rules_ports(rs, idx);
    for (size_t j = 0; j < rs->n; j++) {
        if (j != idx && strcmp(firc_sub_rules_text(rs, j), text) == 0 &&
            spec_eq(firc_sub_rules_proto(rs, j), proto) && spec_eq(firc_sub_rules_ports(rs, j), ports)) {
            return true;
        }
    }
    return false;
}

/* a later PATCH finding no twin must still land on this entry, or the edit silently reverts at the next sync */
static bool has_typed_override(const firc_group_list_t *l, const char *text, const char *given,
                               const char *proto, const char *ports) {
    for (size_t i = 0; i < l->n_overrides; i++) {
        const firc_sub_override_t *o = l->overrides[i];
        if (strcmp(o->rule, text) == 0 && spec_eq(o->list_type, given) && spec_eq(o->proto, proto) &&
            spec_eq(o->ports, ports)) {
            return true;
        }
    }
    return false;
}

firc_err_t firc_app_patch_list_rules(firc_app_t *app, firc_id_t id, const firc_list_rule_edit_t *edits,
                                     size_t n, char *msg, size_t msg_len) {
    app_nf_enter(app);
    firc_ruleset_t *rs = firc_app_find_group_by_id(app, id);
    firc_group_list_t *l = rs != NULL ? firc_ruleset_group_mut(rs)->list : NULL;
    if (l == NULL) {
        app_nf_leave(app);
        return FIRC_ERR_NOENT;
    }
    if (n == 0) {
        app_nf_leave(app);
        return FIRC_OK;
    }
    /* pass one resolves every edit before any is applied: the rule's index and, for a type edit, the override to store */
    size_t *at = calloc(n, sizeof(*at));
    const char **override = calloc(n, sizeof(*override));
    if (at == NULL || override == NULL) {
        free(at);
        free(override);
        app_nf_leave(app);
        return FIRC_ERR_NOMEM;
    }
    firc_err_t err = FIRC_OK;
    for (size_t i = 0; err == FIRC_OK && i < n; i++) {
        if (!firc_sub_rules_find_id(&l->rules, edits[i].rule, &at[i])) {
            err = FIRC_ERR_NOENT;
            break;
        }
        if (edits[i].type == NULL) { continue; }
        const char *text = firc_sub_rules_text(&l->rules, at[i]);
        const char *proto = firc_sub_rules_proto(&l->rules, at[i]),
                   *ports = firc_sub_rules_ports(&l->rules, at[i]);
        const char *why = NULL;
        if (!firc_rule_spec_is_usable(edits[i].type, text, proto, ports, &why)) {
            snprintf(msg, msg_len, "rule \"%.*s\" (type \"%.*s\"): %.90s",
                     firc_api_utf8_clamp(text, 120), text, firc_api_utf8_clamp(edits[i].type, 20),
                     edits[i].type, why != NULL ? why : "unusable");
            err = FIRC_ERR_INVAL;
            break;
        }
        /* an override exists to disagree with the list: a type equal to the one the list gave is stored as "", clearing it */
        const char *given = firc_sub_rules_list_type(&l->rules, at[i]);
        override[i] = strcmp(given, edits[i].type) == 0 ? "" : edits[i].type;
    }
    if (err != FIRC_OK) { /* refused before anything changed */
        free(at);
        free(override);
        app_nf_leave(app);
        return err;
    }

    bool chain_touched = false; /* pass two can only fail for memory; whatever it applied before that is published below like a whole edit */
    for (size_t i = 0; i < n; i++) {
        const char *text = firc_sub_rules_text(&l->rules, at[i]);
        const char *given = firc_sub_rules_list_type(&l->rules, at[i]);
        const char *proto = firc_sub_rules_proto(&l->rules, at[i]),
                   *ports = firc_sub_rules_ports(&l->rules, at[i]);
        /* keyed by text+spec alone, except a twin of a different type: then the list's own type joins the key too */
        if (edits[i].has_enable || override[i] != NULL) {
            bool keyed_by_type =
                rule_has_twin(&l->rules, at[i]) || has_typed_override(l, text, given, proto, ports);
            firc_sub_rule_key_t key = {text, keyed_by_type ? given : NULL, proto, ports};
            err = firc_group_list_set_override(l, &key, override[i],
                                               edits[i].has_enable ? &edits[i].enable : NULL);
            if (err != FIRC_OK) { break; }
        }
        if (is_subnet_type(firc_sub_rules_type(&l->rules, at[i]))) { chain_touched = true; }
        if (edits[i].has_enable) { l->rules.v[at[i]].enable = edits[i].enable; }
        if (edits[i].type != NULL) { firc_sub_rules_set_type(&l->rules, at[i], edits[i].type); }
        if (is_subnet_type(firc_sub_rules_type(&l->rules, at[i]))) { chain_touched = true; }
    }
    free(at);
    free(override);
    /* the arena's text did not move, so borrowed text stays valid; the matcher rebuilds since it was built by type */
    release_dns_snapshot(app);
    republish_or_log(app);
    if (chain_touched && firc_ruleset_runtime_enabled(rs)) {
        firc_err_t serr = sync_group_ruleset_locked(app, rs);
        if (err == FIRC_OK) { err = serr; }
    }
    app_nf_leave(app);
    return err;
}

uint64_t firc_app_nf_enters_for_test(const firc_app_t *app) { return app->nf_enters; }
uint64_t firc_app_nf_passes_for_test(const firc_app_t *app) {
    return app->committer ? firc_nfcommit_passes(app->committer) : 0;
}

uint64_t firc_app_nf_last_completed_pass_for_test(const firc_app_t *app) {
    return app->committer ? firc_nfcommit_last_completed_pass(app->committer) : 0;
}

uint64_t firc_app_nf_change_for_test(const firc_app_t *app) { return app->nf_change; }
void firc_app_pay_flushes_for_test(firc_app_t *app, uint64_t ticket) { pay_flushes(app, ticket); }
size_t firc_app_tombstones_for_test(const firc_app_t *app) { return app->n_tombs; }

/* forgets a group that is gone: its mappings, its chunks (parked for the quarantine window) */
static void pool_forget_group_id(firc_app_t *app, firc_id_t gid) {
    char id[FIRC_ID_STR_LEN];
    firc_id_format(gid, id);
    /* the mark field goes back too, but not while a flush of its flows is still queued: pay_flushes forgets it then */
    if (!flush_queued_for(app, gid)) { firc_rtnl_forget_mark_field(app->rtnl, id); }
    if (app->pool == NULL) { return; }
    firc_fakeip_drop_group(app->pool, id, (int64_t)time(NULL));
    firc_app_pool_changed(app);
}


static void firc_app_remove_group_by_index_unlocked(firc_app_t *app, size_t idx) {
    if (idx >= app->n_rulesets) { return; }
    /* out of the kernel before the config: ip rules/routes now, chain by tombstone next pass */
    if (firc_ruleset_runtime_enabled(app->rulesets[idx])) {
        (void)app_group_down(app, app->rulesets[idx], FIRC_FLOWS_DROP);
    }
    firc_group_t *g = app->cfg->groups[idx];
    firc_id_t gid = g->id;
    firc_ruleset_free(app->rulesets[idx]);
    rulesets_remove_at(app, idx);
    release_dns_snapshot(app); /* it borrows the list freed next */
    if (g->list != NULL) { sync_end_for_removed_list(app, gid, g->list, "group removed"); }
    firc_config_remove_group_by_index(app->cfg, idx);
    pool_forget_group_id(app, gid); /* after the list is consistent: see clear_groups_keeping */
    republish_or_log(app);
    retry_rearm(app); /* a failed group gone takes its timer with it */
}

void firc_app_remove_group_by_index(firc_app_t *app, size_t idx) {
    app_nf_enter(app);
    firc_app_remove_group_by_index_unlocked(app, idx);
    app_nf_leave(app);
}

static bool firc_app_remove_group_by_id_unlocked(firc_app_t *app, firc_id_t id) {
    for (size_t i = 0; i < app->n_rulesets; i++) {
        if (firc_id_equal(firc_ruleset_group(app->rulesets[i])->id, id)) {
            firc_app_remove_group_by_index_unlocked(app, i);
            return true;
        }
    }
    return false;
}

bool firc_app_remove_group_by_id(firc_app_t *app, firc_id_t id) {
    app_nf_enter(app);
    bool r = firc_app_remove_group_by_id_unlocked(app, id);
    app_nf_leave(app);
    return r;
}

static uint64_t sync_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

/* the seq answers three questions (exists, url unchanged, no newer request); checked here and nowhere else */
static bool sync_seq_is_current(const firc_group_list_t *list, const firc_sub_event_t *ev) {
    return ev->seq == list->sync_seq;
}

/* unflattened: a server refusal names its HTTP status, the four reasons call for four operator actions */
static void sync_set_error(firc_group_list_t *list, firc_err_t err, long http_status, const char *why) {
    list->sync_state = FIRC_SUB_SYNC_ERROR;
    if (why != NULL) {
        snprintf(list->sync_error, sizeof(list->sync_error), "%s", why);
    } else if (http_status != 0) {
        snprintf(list->sync_error, sizeof(list->sync_error), "%s: HTTP %ld", firc_err_str(err),
                 http_status);
    } else {
        snprintf(list->sync_error, sizeof(list->sync_error), "%s", firc_err_str(err));
    }
}

static void sync_set_idle(firc_group_list_t *list) {
    list->sync_state = FIRC_SUB_SYNC_IDLE;
    list->sync_error[0] = '\0';
}

/* runs once at the apply of a changed list, not on every rebuild: this is the only place that sees every line */
static void warn_unusable_list_lines(const char *owner_name, const firc_sub_rules_t *rules) {
    size_t unusable = 0;
    const char *first_why = "", *first_type = "", *first_rule = "";
    for (size_t i = 0; i < rules->n; i++) {
        if (!firc_sub_rules_enable(rules, i)) { continue; }
        const char *type = firc_sub_rules_type(rules, i);
        const char *text = firc_sub_rules_text(rules, i);
        const char *proto = firc_sub_rules_proto(rules, i), *ports = firc_sub_rules_ports(rules, i);
        const char *why = NULL;
        if (!firc_rule_spec_is_usable(type, text, proto, ports, &why)) {
            if (unusable == 0) {
                first_why = why ? why : "unusable";
                first_type = type;
                first_rule = text;
            }
            unusable++;
        }
    }
    if (unusable > 0) {
        FIRC_WARN("group \"%s\": %zu line(s) give a rule the daemon cannot use and that "
                  "routes nothing, the first being %s (type \"%s\", rule \"%s\")",
                  owner_name, unusable, first_why, first_type, first_rule);
    }
}

static firc_err_t firc_app_request_sync_unlocked(firc_app_t *app, firc_id_t id); /* for "ask again" on a stale UNCHANGED */
static firc_group_list_t *find_list(firc_app_t *app, firc_id_t id, const char **name); /* defined below */

/* provisional flips false->true only at the next republish; without this call it would never clear */
static void republish_if_first_list(firc_app_t *app, bool first_list) {
    if (!first_list) { return; }
    release_dns_snapshot(app); /* before the new one is built, as on the path that actually moved rules */
    republish_or_log(app);
}

/* the app-touching half of a sync; ev is not freed here, its rules may be moved out; the lock is the caller's */
static firc_err_t firc_app_apply_sync_result_unlocked(firc_app_t *app, firc_sub_event_t *ev,
                                                      int64_t now_unix, bool *out_changed) {
    *out_changed = false;

    const char *name = NULL;
    firc_group_list_t *list = find_list(app, ev->group_id, &name);
    if (list == NULL) { return FIRC_ERR_NOENT; }
    if (!sync_seq_is_current(list, ev)) {
        FIRC_DEBUG("\"%s\": a superseded result (seq %llu, latest %llu) is dropped", name,
                   (unsigned long long)ev->seq, (unsigned long long)list->sync_seq);
        return FIRC_OK;
    }

    /* told BEFORE the work runs: what follows is the seconds somebody watches a progress bar for */
    list->sync_progress.applying = true;
    if (app->sync_listener != NULL && !app->sync_listener_muted) {
        app->sync_listener(app->sync_listener_ud, ev->group_id, list, false);
    }

    uint64_t refresh_ms = 0, compare_ms = 0, rebuild_ms = 0, snapshot_ms = 0, save_ms = 0;
    firc_err_t ret = FIRC_OK;

    switch (ev->result) {
    case FIRC_SUB_RESULT_ERROR:
        /* set even on failure: firc_sub_is_due reads it, so a broken url is retried once per interval */
        sync_set_error(list, ev->err, ev->http_status, ev->why);
        list->last_check = (uint32_t)now_unix;
        FIRC_WARN("group \"%s\": its list was not synced: %s", name, list->sync_error);
        ret = ev->err;
        break;

    case FIRC_SUB_RESULT_UNCHANGED:
        /* refused with no body hash: storing it would wrongly claim hand-given rules came from bytes */
        if (!list->has_body_hash) {
            FIRC_DEBUG("\"%s\": unchanged against a hash this list no longer holds; "
                       "re-requesting",
                       name);
            list->last_check = (uint32_t)now_unix;
            sync_set_idle(list);
            firc_err_t qerr = firc_app_request_sync_unlocked(app, ev->group_id);
            if (qerr != FIRC_OK) { /* not this sync's failure to report; firc_sub_is_due comes back to it at the interval */
                FIRC_WARN("\"%s\": could not ask for the parse it needs: %s", name,
                          firc_err_str(qerr));
            }
            break;
        }
        FIRC_DEBUG("\"%s\": the list is the same bytes as last time, not parsed", name);
        memcpy(list->body_hash, ev->hash, sizeof(list->body_hash));
        list->has_body_hash = true;
        list->last_check = (uint32_t)now_unix;
        sync_set_idle(list);
        break;

    case FIRC_SUB_RESULT_PARSED: {
        if (ev->dropped > 0) {
            FIRC_WARN("group \"%s\": %zu entr(y/ies) of its list are neither a name, an address nor "
                      "a regex as written, and were dropped",
                      name, ev->dropped);
        }
        if (ev->unconstrained > 0) {
            FIRC_WARN("group \"%s\": %zu name(s) of its list came with a protocol or port that a name "
                      "rule cannot keep, and route every protocol and port",
                      name, ev->unconstrained);
        }
        uint64_t t0 = sync_mono_ms();
        /* carries the old arena's ids/types/enables across by rule text; the parser allocated fresh ids for everything */
        firc_err_t rerr = firc_sub_rules_inherit(&ev->rules, &list->rules);
        uint64_t t1 = sync_mono_ms();
        refresh_ms = t1 - t0;

        bool same = false;
        firc_err_t cerr = rerr;
        if (rerr == FIRC_OK) {
            firc_sub_apply_overrides(list, &ev->rules); /* before the comparison, or a changed override reads as "the list has not moved" */
            cerr = firc_sub_same_rules_checked(&list->rules, &ev->rules, &same); /* could not tell is not a change: don't replace rules on an allocation failure */
        }
        compare_ms = sync_mono_ms() - t1;
        if (cerr != FIRC_OK) {
            sync_set_error(list, cerr, 0, NULL);
            ret = cerr;
            break;
        }
        if (same) {
            bool first_list = !list->has_body_hash;
            firc_sub_rules_free(&ev->rules);
            memcpy(list->body_hash, ev->hash, sizeof(list->body_hash));
            list->has_body_hash = true;
            list->last_check = (uint32_t)now_unix;
            sync_set_idle(list);
            republish_if_first_list(app, first_list);
            break;
        }

        firc_sub_rules_t prev_rules = list->rules; /* kept aside for the rollback below; the list holds the new ones from here */
        uint32_t prev_last_check = list->last_check;
        uint32_t prev_last_update = list->last_update;
        list->rules = ev->rules; /* moved: the event owns nothing now */
        firc_sub_rules_init(&ev->rules);
        list->last_check = (uint32_t)now_unix;
        list->last_update = (uint32_t)now_unix;

        warn_unusable_list_lines(name, &list->rules); /* once per changed list, the one place that sees every line */

        release_dns_snapshot(app); /* before anything new is built: holding both was the transition the router could not survive. Old rules stay until the resync succeeds, for the rollback. */
        uint64_t t2 = sync_mono_ms();
        firc_ruleset_t *group_rs = firc_app_find_group_by_id(app, ev->group_id);
        firc_err_t err = group_rs != NULL ? sync_group_ruleset_locked(app, group_rs) : FIRC_ERR_NOENT;
        uint64_t t3 = sync_mono_ms();
        rebuild_ms = t3 - t2;
        if (err != FIRC_OK) {
            firc_sub_rules_free(&list->rules);
            list->rules = prev_rules;
            list->last_check = prev_last_check;
            list->last_update = prev_last_update;
            firc_err_t rollback_err = group_rs != NULL ? sync_group_ruleset_locked(app, group_rs) : FIRC_ERR_NOENT;
            if (rollback_err != FIRC_OK) {
                FIRC_ERROR("failed to rollback the group's ruleset: %s", firc_err_str(rollback_err));
            }
            republish_or_log(app); /* the rule-set released above, from the rules kept */
            snapshot_ms = sync_mono_ms() - t3;
            sync_set_error(list, err, 0, NULL);
            *out_changed = true; /* a change was attempted, even though rolled back */
            ret = err;
            break;
        }
        firc_sub_rules_free(&prev_rules);

        /* set BEFORE the republish: snapshot.c reads has_body_hash on the live group at build time */
        memcpy(list->body_hash, ev->hash, sizeof(list->body_hash));
        list->has_body_hash = true;
        republish_or_log(app);
        uint64_t t4 = sync_mono_ms();
        snapshot_ms = t4 - t3;

        sync_set_idle(list);
        *out_changed = true;

        /* written here and nowhere else now: the sync route has no save parameter to gate it on */
        if (app->config_path != NULL) {
            firc_err_t serr = firc_app_save_groups(app, app->config_path,
                                                   app->config_version != NULL ? app->config_version
                                                                               : "");
            if (serr != FIRC_OK) {
                FIRC_ERROR("failed to save the groups file: %s", firc_err_str(serr));
            }
            save_ms = sync_mono_ms() - t4;
        }
        break;
    }
    }

    list->sync_progress.applying = false;
    if (ev->result == FIRC_SUB_RESULT_PARSED) { /* tools/bench/run_sub_cost.sh sums this format */
        FIRC_DEBUG("%s: sync applied: refresh %llu ms, compare %llu ms, "
                   "rebuild %llu ms, snapshot %llu ms, save %llu ms, rules %zu",
                   name, (unsigned long long)refresh_ms, (unsigned long long)compare_ms,
                   (unsigned long long)rebuild_ms, (unsigned long long)snapshot_ms,
                   (unsigned long long)save_ms, list->rules.n);
    }
    return ret;
}

firc_err_t firc_app_apply_sync_result(firc_app_t *app, firc_sub_event_t *ev, int64_t now_unix,
                                      bool *out_changed) {
    app_nf_enter(app);
    firc_err_t r = firc_app_apply_sync_result_unlocked(app, ev, now_unix, out_changed);
    app_nf_leave(app);
    return r;
}

/* no lock but for a RESULT: STARTED/PROGRESS write only the list's own sync fields, which no pass reads */
void firc_app_on_sync_event(firc_app_t *app, firc_sub_event_t *ev, int64_t now_unix) {
    if (ev == NULL) { return; }
    if (app == NULL) {
        firc_sub_event_free(ev);
        return;
    }
    const char *name = NULL;
    firc_group_list_t *list = find_list(app, ev->group_id, &name);
    if (list == NULL) { /* deleted while the job ran; the worker could not have known */
        char idbuf[FIRC_ID_STR_LEN];
        firc_id_format(ev->group_id, idbuf);
        FIRC_DEBUG("sync event for %s, which is gone: dropped", idbuf);
        firc_sub_event_free(ev);
        return;
    }
    if (!sync_seq_is_current(list, ev)) {
        FIRC_DEBUG("\"%s\": a superseded sync event (seq %llu, latest %llu) is dropped", name,
                   (unsigned long long)ev->seq, (unsigned long long)list->sync_seq);
        firc_sub_event_free(ev);
        return;
    }

    switch (ev->kind) {
    case FIRC_SUB_EV_STARTED:
        list->sync_state = FIRC_SUB_SYNC_FETCHING;
        memset(&list->sync_progress, 0, sizeof(list->sync_progress));
        break;
    case FIRC_SUB_EV_PROGRESS:
        list->sync_progress.stage = ev->stage;
        list->sync_progress.bytes = ev->bytes;
        list->sync_progress.total = ev->total;
        list->sync_progress.lines = ev->lines;
        list->sync_progress.applying = false;
        break;
    case FIRC_SUB_EV_RESULT: {
        bool changed = false;
        app_nf_enter(app);
        firc_err_t err = firc_app_apply_sync_result_unlocked(app, ev, now_unix, &changed);
        app_nf_leave(app);
        if (err != FIRC_OK) { FIRC_WARN("\"%s\": sync failed: %s", name, firc_err_str(err)); }
        break;
    }
    }

    if (app->sync_listener != NULL) {
        app->sync_listener(app->sync_listener_ud, ev->group_id, list, ev->kind == FIRC_SUB_EV_RESULT);
    }
    firc_sub_event_free(ev);
}

void firc_app_set_sync_listener(firc_app_t *app, firc_app_sync_listener_fn fn, void *ud) {
    app->sync_listener = fn;
    app->sync_listener_ud = ud;
}

/* NULL when no group has id, or it holds no list */
static firc_group_list_t *find_list(firc_app_t *app, firc_id_t id, const char **name) {
    for (size_t i = 0; i < app->cfg->n_groups; i++) {
        firc_group_t *g = app->cfg->groups[i];
        if (!firc_id_equal(g->id, id)) { continue; }
        if (name != NULL) { *name = g->name != NULL ? g->name : ""; }
        return g->list;
    }
    return NULL;
}

static firc_err_t firc_app_request_sync_unlocked(firc_app_t *app, firc_id_t id) {
    if (app->sub_worker == NULL) { return FIRC_ERR_STATE; }
    firc_group_list_t *l = find_list(app, id, NULL);
    if (l == NULL) { return FIRC_ERR_NOENT; }
    if (l->url == NULL || l->url[0] == '\0') { return FIRC_ERR_INVAL; }

    firc_sub_job_t job;
    memset(&job, 0, sizeof(job));
    job.group_id = id;
    if (firc_strset(&job.url, l->url) != FIRC_OK) { return FIRC_ERR_NOMEM; }
    job.has_hash = l->has_body_hash;
    memcpy(job.expected_hash, l->body_hash, sizeof(job.expected_hash));
    job.seq = ++app->sync_seq_counter;

    firc_err_t err = firc_sub_worker_enqueue(app->sub_worker, &job); /* takes job.url on every return, error ones included */
    if (err != FIRC_OK) { return err; } /* FIRC_ERR_LIMIT: FIRC_SUB_WORKER_CAPACITY distinct ids already waiting; the list is left exactly as it was */

    l->sync_seq = job.seq;
    l->sync_state = FIRC_SUB_SYNC_QUEUED;
    l->sync_error[0] = '\0';
    memset(&l->sync_progress, 0, sizeof(l->sync_progress));
    return FIRC_OK;
}

/* this, the url change and the two sweeps below take no lock: they write only a list's own fields, no pass reads */
firc_err_t firc_app_request_sync(firc_app_t *app, firc_id_t id) {
    return firc_app_request_sync_unlocked(app, id);
}

firc_err_t firc_app_set_list_url(firc_app_t *app, firc_id_t id, const char *url) {
    /* id checked first: 400 "cannot take this url" would be a lie when there is no such list at all */
    firc_group_list_t *l = find_list(app, id, NULL);
    if (l == NULL) {
        return FIRC_ERR_NOENT;
    }
    if (url == NULL || !firc_sub_url_is_supported(url)) {
        return FIRC_ERR_INVAL;
    }
    if (strcmp(l->url != NULL ? l->url : "", url) == 0) {
        return FIRC_OK;
    }
    if (firc_strset(&l->url, url) != FIRC_OK) {
        return FIRC_ERR_NOMEM;
    }
    /* the body hash is kept deliberately: it hashes the list, not the address */
    if (app->config_path != NULL) {
        firc_err_t serr = firc_app_save_groups(app, app->config_path,
                                               app->config_version != NULL ? app->config_version
                                                                           : "");
        if (serr != FIRC_OK) {
            FIRC_ERROR("failed to save the groups file: %s", firc_err_str(serr));
        }
    }
    return FIRC_OK;
}

static void log_request_failure(firc_id_t id, const char *name, firc_err_t err) {
    char idbuf[FIRC_ID_STR_LEN];
    firc_id_format(id, idbuf);
    FIRC_WARN("list of %s (\"%s\") was not queued for a sync: %s", idbuf, name,
              firc_err_str(err));
}

/* has_body_hash is the filter, not last_check; skips QUEUED/FETCHING, unlike the due sweep, which must not */
static void request_if_missing(firc_app_t *app, firc_id_t id, const char *name, bool enable,
                               const firc_group_list_t *l) {
    if (!enable || l->url == NULL || l->url[0] == '\0' || l->has_body_hash) { return; }
    if (l->sync_state == FIRC_SUB_SYNC_QUEUED || l->sync_state == FIRC_SUB_SYNC_FETCHING) { return; }
    firc_err_t err = firc_app_request_sync_unlocked(app, id);
    if (err != FIRC_OK) { log_request_failure(id, name, err); }
}

static void firc_app_request_sync_missing_unlocked(firc_app_t *app) {
    for (size_t i = 0; i < app->cfg->n_groups; i++) {
        firc_group_t *g = app->cfg->groups[i];
        if (g->list == NULL) { continue; }
        request_if_missing(app, g->id, g->name != NULL ? g->name : "", g->enable, g->list);
    }
}

void firc_app_request_sync_missing(firc_app_t *app) {
    firc_app_request_sync_missing_unlocked(app);
}

void firc_app_request_sync_due(firc_app_t *app, int64_t now_unix) {
    for (size_t i = 0; i < app->cfg->n_groups; i++) {
        firc_group_t *g = app->cfg->groups[i];
        if (g->list == NULL || !firc_sub_is_due(g->enable, g->list, now_unix)) { continue; } /* not skipped when QUEUED/FETCHING */
        firc_err_t err = firc_app_request_sync_unlocked(app, g->id);
        if (err != FIRC_OK) { log_request_failure(g->id, g->name != NULL ? g->name : "", err); }
    }
}

typedef struct sync_capture {
    firc_sub_event_t *result; /* the last RESULT the job emitted, owned */
} sync_capture_t;

static void sync_capture_emit(void *ud, firc_sub_event_t *ev) {
    sync_capture_t *cap = ud;
    if (ev->kind != FIRC_SUB_EV_RESULT) {
        firc_sub_event_free(ev); /* nobody is watching a synchronous job */
        return;
    }
    firc_sub_event_free(cap->result);
    cap->result = ev;
}

static firc_err_t firc_app_sync_list_now_unlocked(firc_app_t *app, firc_id_t id,
                                                  int64_t now_unix,
                                                  const char *url_override,
                                                  bool *out_changed) {
    *out_changed = false;

    firc_group_list_t *list = find_list(app, id, NULL);
    if (list == NULL) { return FIRC_ERR_NOENT; }
    const char *fetch_url = (url_override != NULL && url_override[0] != '\0') ? url_override
                                                                             : list->url;
    if (fetch_url == NULL || fetch_url[0] == '\0') { return FIRC_ERR_INVAL; }

    firc_sub_job_t job;
    memset(&job, 0, sizeof(job));
    job.group_id = id;
    if (firc_strset(&job.url, fetch_url) != FIRC_OK) { return FIRC_ERR_NOMEM; }
    job.has_hash = list->has_body_hash;
    memcpy(job.expected_hash, list->body_hash, sizeof(job.expected_hash));
    job.seq = ++app->sync_seq_counter;

    sync_capture_t cap = {.result = NULL};
    firc_sub_job_run(&job, NULL, sync_capture_emit, &cap);
    free(job.url);
    if (cap.result == NULL) { return FIRC_ERR_NOMEM; } /* a job that could not allocate its result says nothing, rather than a start with no end */

    bool was_fetch_error = cap.result->result == FIRC_SUB_RESULT_ERROR;
    firc_err_t result_err = cap.result->err;

    /* the url the fetch used becomes the list's before the apply, so the rollback below can restore it */
    bool url_changed = strcmp(list->url != NULL ? list->url : "", fetch_url) != 0;
    char *prev_url = NULL;
    if (url_changed && !was_fetch_error) {
        char *new_url = NULL;
        if (firc_strset(&new_url, fetch_url) != FIRC_OK) {
            firc_sub_event_free(cap.result);
            return FIRC_ERR_NOMEM;
        }
        prev_url = list->url;
        list->url = new_url;
    }

    list->sync_seq = job.seq; /* the latest thing asked of this list, so its answer is the one to take */
    bool changed = false;
    /* listener-silent deliberately: this path hands the answer back as a return value, not an event */
    app->sync_listener_muted = true;
    firc_err_t err = firc_app_apply_sync_result_unlocked(app, cap.result, now_unix, &changed);
    app->sync_listener_muted = false;
    firc_sub_event_free(cap.result);

    if (err != FIRC_OK) {
        if (prev_url != NULL) {
            free(list->url);
            list->url = prev_url;
        }
        *out_changed = changed;
        if (was_fetch_error) { /* one code for "could not be fetched", whatever stopped it; the list's own state says which, unflattened */
            return result_err == FIRC_ERR_NOMEM ? FIRC_ERR_NOMEM : FIRC_ERR_UPSTREAM;
        }
        return err;
    }
    free(prev_url);
    *out_changed = changed || url_changed;
    return FIRC_OK;
}

firc_err_t firc_app_sync_list_now(firc_app_t *app, firc_id_t id, int64_t now_unix,
                                  const char *url_override, bool *out_changed) {
    app_nf_enter(app);
    firc_err_t r = firc_app_sync_list_now_unlocked(app, id, now_unix, url_override,
                                                           out_changed);
    app_nf_leave(app);
    return r;
}

typedef struct posted_sync_event {
    firc_app_t *app;
    firc_sub_event_t *ev;
} posted_sync_event_t;

static void on_posted_sync_event(firc_loop_t *loop, void *ud) {
    (void)loop;
    posted_sync_event_t *p = ud;
    firc_app_on_sync_event(p->app, p->ev, (int64_t)time(NULL));
    free(p);
}

/* file-scope, not app fields: the drop runs at firc_loop_destroy, after firc_app_destroy, with no app left */
static _Atomic size_t g_sync_events_posted;
static _Atomic size_t g_sync_results_posted;
static _Atomic size_t g_sync_events_dropped;

void firc_app_sync_event_counts_for_test(size_t *out_posted, size_t *out_results,
                                         size_t *out_dropped) {
    if (out_posted != NULL) { *out_posted = atomic_load(&g_sync_events_posted); }
    if (out_results != NULL) { *out_results = atomic_load(&g_sync_results_posted); }
    if (out_dropped != NULL) { *out_dropped = atomic_load(&g_sync_events_dropped); }
}

/* a result the loop never read carries a rules arena, freed here rather than left to the wrapper's own free */
static void drop_posted_sync_event(void *ud) {
    posted_sync_event_t *p = ud;
    firc_sub_event_free(p->ev);
    free(p);
    atomic_fetch_add(&g_sync_events_dropped, 1);
}

/* worker thread; reads nothing of the app's but the loop it was created with */
static void sync_worker_emit(void *ud, firc_sub_event_t *ev) {
    firc_app_t *app = ud;
    posted_sync_event_t *p = malloc(sizeof(*p));
    if (p == NULL || app->loop == NULL) {
        free(p);
        firc_sub_event_free(ev);
        return;
    }
    p->app = app;
    p->ev = ev;
    bool is_result = ev->kind == FIRC_SUB_EV_RESULT; /* read before the post: a successful post may free ev before this call returns */
    if (firc_loop_post_with_drop(app->loop, on_posted_sync_event, p, drop_posted_sync_event) ==
        FIRC_OK) {
        if (is_result) { atomic_fetch_add(&g_sync_results_posted, 1); }
        atomic_fetch_add(&g_sync_events_posted, 1);
    } else { /* a failed post leaves the list QUEUED/FETCHING; the due sweep asks again */
        firc_sub_event_free(ev);
        free(p);
    }
}

firc_err_t firc_app_start_list_worker(firc_app_t *app) {
    if (app->sub_worker != NULL) { return FIRC_ERR_STATE; }
    if (app->loop == NULL) { return FIRC_ERR_STATE; } /* a worker that can fetch but not report is worse than none */

    app->sub_worker = firc_sub_worker_new(FIRC_SUB_WORKER_CAPACITY, sync_worker_emit, app);
    if (app->sub_worker == NULL) { return FIRC_ERR_NOMEM; }

    firc_err_t err = firc_sub_worker_start(app->sub_worker);
    if (err != FIRC_OK) {
        firc_sub_worker_free(app->sub_worker);
        app->sub_worker = NULL;
        return err;
    }
    FIRC_INFO("list worker started");
    return FIRC_OK;
}

void firc_app_stop_list_worker(firc_app_t *app) {
    if (app == NULL || app->sub_worker == NULL) { return; }
    firc_sub_worker_free(app->sub_worker); /* raises the cancel token, ends the transfer in flight, and joins */
    app->sub_worker = NULL;
}

/* a fixed Keenetic virtual-interface list under entware_kn, applied only when !show_all_interfaces */
#ifdef FIRC_ENTWARE_KN
static const char *const FIRC_IGNORED_INTERFACES[] = {
    "ezcfg0",
    "ra0", "ra1", "ra2", "ra3", "ra4", "ra5", "ra6", "ra7",
    "ra8", "ra9", "ra10", "ra11", "ra12", "ra13", "ra14", "ra15",
};
#define FIRC_IGNORED_INTERFACES_N (sizeof(FIRC_IGNORED_INTERFACES) / sizeof(FIRC_IGNORED_INTERFACES[0]))

static bool iface_is_ignored(const char *name) {
    for (size_t i = 0; i < FIRC_IGNORED_INTERFACES_N; i++) {
        if (strcmp(FIRC_IGNORED_INTERFACES[i], name) == 0) { return true; }
    }
    return false;
}
#else
static bool iface_is_ignored(const char *name) {
    (void)name;
    return false;
}
#endif

bool firc_iface_is_ignored_for_test(const char *name) { return iface_is_ignored(name); }

firc_err_t firc_app_list_interfaces(const firc_app_t *app, firc_iface_info_t **out, size_t *out_n) {
    *out = NULL;
    *out_n = 0;

    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) != 0) { return firc_err_from_errno(errno); }

    bool show_all = app->cfg->app.show_all_interfaces;
    size_t cap = 0;
    size_t n = 0;
    firc_iface_info_t *arr = NULL;

    for (struct ifaddrs *p = ifap; p != NULL; p = p->ifa_next) {
        bool already = false;
        for (size_t i = 0; i < n; i++) {
            if (strcmp(arr[i].id, p->ifa_name) == 0) {
                already = true;
                break;
            }
        }
        if (already) { continue; }

        if (!show_all && ((p->ifa_flags & IFF_POINTOPOINT) == 0 || iface_is_ignored(p->ifa_name))) { continue; }

        if (n == cap) {
            size_t new_cap = cap ? cap * 2 : 8;
            firc_iface_info_t *na = realloc(arr, new_cap * sizeof(*na));
            if (!na) {
                free(arr);
                freeifaddrs(ifap);
                return FIRC_ERR_NOMEM;
            }
            arr = na;
            cap = new_cap;
        }
        memset(&arr[n], 0, sizeof(arr[n]));
        snprintf(arr[n].id, sizeof(arr[n].id), "%s", p->ifa_name);
        n++;
    }
    freeifaddrs(ifap);

    /* friendly names where the platform supplies them; an unreachable RCI must never fail the interface list itself */
    firc_kn_aliases_t aliases = {0};
    firc_err_t alias_err = firc_kn_get_iface_aliases(&aliases);
    if (alias_err != FIRC_OK) {
        FIRC_DEBUG("failed to load interface aliases: %s", firc_err_str(alias_err));
    } else {
        for (size_t i = 0; i < n; i++) {
            const char *alias = firc_kn_aliases_lookup(&aliases, arr[i].id);
            if (alias) { snprintf(arr[i].name, sizeof(arr[i].name), "%s", alias); }
        }
    }
    firc_kn_aliases_free(&aliases);

    *out = arr;
    *out_n = n;
    return FIRC_OK;
}

firc_err_t firc_app_save_groups(firc_app_t *app, const char *conf_path, const char *version) {
    /* derived here rather than carried alongside conf_path, so the two paths cannot drift apart */
    char groups_path[4096];
    firc_err_t err = firc_config_groups_path(conf_path, groups_path, sizeof(groups_path));
    if (err != FIRC_OK) { return err; }
    return firc_config_save_part_file(app->cfg, version, FIRC_CFG_GROUPS, groups_path);
}

firc_err_t firc_app_save_config(firc_app_t *app, const char *conf_path, const char *version) {
    /* settings first, groups second, each its own atomic write; writes the SAVED copy, not cfg->app */
    firc_config_t shell;
    memset(&shell, 0, sizeof(shell));
    shell.app = app->saved; /* shallow: never cleared */
    firc_err_t err = firc_config_save_part_file(&shell, version, FIRC_CFG_SETTINGS, conf_path);
    if (err != FIRC_OK) { return err; }
    return firc_app_save_groups(app, conf_path, version);
}

const firc_app_config_t *firc_app_saved_settings(const firc_app_t *app) { return &app->saved; }

const firc_app_config_t *firc_app_running_settings(const firc_app_t *app) { return &app->cfg->app; }

size_t firc_app_pending_restart(const firc_app_t *app, bool pending[FIRC_SETTINGS_COUNT]) {
    size_t n = 0;
    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
        const firc_setting_t *s = &firc_settings[i];
        pending[i] = s->cls == FIRC_SETTING_RESTART && !firc_setting_equal(s, &app->saved, &app->cfg->app);
        if (pending[i]) { n++; }
    }
    return n;
}

/* the proxy and log level are told first: the running copy's old string is about to be freed by the copy */
static firc_err_t apply_live(firc_app_t *app, bool applied[FIRC_SETTINGS_COUNT]) {
    firc_err_t first = FIRC_OK;
    firc_app_config_t *run = &app->cfg->app;
    const firc_app_config_t *sav = &app->saved;
    bool differ[FIRC_SETTINGS_COUNT];
    bool upstream = false, flags = false;
    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
        const firc_setting_t *s = &firc_settings[i];
        differ[i] = s->cls == FIRC_SETTING_LIVE && !firc_setting_equal(s, sav, run);
        if (!differ[i]) { continue; }
        if (s->apply == FIRC_APPLY_UPSTREAM) { upstream = true; }
        if (s->apply == FIRC_APPLY_PROXY_FLAGS) { flags = true; }
    }
    if (upstream && app->proxy != NULL) {
        firc_err_t err = firc_dnsproxy_set_upstream(app->proxy, sav->dns_proxy.upstream.address,
                                                    sav->dns_proxy.upstream.port);
        if (err != FIRC_OK) {
            FIRC_ERROR("settings: the DNS proxy stays on %s:%u: %s", run->dns_proxy.upstream.address,
                       run->dns_proxy.upstream.port, firc_err_str(err));
            first = err;
            for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
                if (firc_settings[i].apply == FIRC_APPLY_UPSTREAM) { differ[i] = false; }
            }
        }
    }
    if (flags && app->proxy != NULL) {
        firc_dnsproxy_set_disable_drop_aaaa(app->proxy, sav->dns_proxy.disable_drop_aaaa);
    }
    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
        if (applied != NULL) { applied[i] = false; }
        if (!differ[i]) { continue; }
        const firc_setting_t *s = &firc_settings[i];
        if (firc_setting_copy(s, run, sav) != FIRC_OK) {
            FIRC_ERROR("settings: %s not applied: out of memory", s->path);
            if (first == FIRC_OK) { first = FIRC_ERR_NOMEM; }
            continue;
        }
        if (s->apply == FIRC_APPLY_LOG_LEVEL) {
            firc_log_set_level(firc_log_level_from_str(run->log_level));
        }
        if (s->apply == FIRC_APPLY_UNMATCHED_TTL && app->pipeline != NULL) {
            firc_dns_pipeline_set_unmatched_ttl(
                app->pipeline, (uint32_t)(run->dns_proxy.unmatched_ttl / FIRC_DURATION_SEC));
        }
        if (applied != NULL) { applied[i] = true; }
        FIRC_INFO("settings: %s applied", s->path);
    }
    return first;
}

/* next becomes the saved copy (taken: zeroed on return); returns apply_live's first failure */
static firc_err_t adopt_saved(firc_app_t *app, firc_app_config_t *next,
                              bool applied[FIRC_SETTINGS_COUNT]) {
    firc_app_config_clear(&app->saved);
    app->saved = *next;
    memset(next, 0, sizeof(*next));
    return apply_live(app, applied);
}

firc_err_t firc_app_put_settings(firc_app_t *app, firc_app_config_t *next, const char *conf_path,
                                 const char *version, bool applied[FIRC_SETTINGS_COUNT],
                                 firc_err_t *live_err) {
    if (applied != NULL) { memset(applied, 0, FIRC_SETTINGS_COUNT * sizeof(bool)); }
    if (live_err != NULL) { *live_err = FIRC_OK; }
    bool changed = false;
    for (size_t i = 0; i < FIRC_SETTINGS_COUNT && !changed; i++) {
        changed = !firc_setting_equal(&firc_settings[i], next, &app->saved);
    }
    if (!changed) {
        firc_app_config_clear(next);
        return FIRC_OK;
    }
    if (conf_path != NULL) {
        firc_config_t shell;
        memset(&shell, 0, sizeof(shell));
        shell.app = *next; /* shallow: never cleared */
        firc_err_t err = firc_config_save_part_file(&shell, version, FIRC_CFG_SETTINGS, conf_path);
        if (err != FIRC_OK) { return err; }
    }
    firc_err_t lerr = adopt_saved(app, next, applied);
    if (live_err != NULL) { *live_err = lerr; }
    return FIRC_OK;
}

firc_err_t firc_app_move_web_port(firc_app_t *app, uint16_t port, const char *conf_path,
                                  const char *version) {
    app->cfg->app.http_web.host.port = port;
    firc_app_config_t next;
    memset(&next, 0, sizeof(next));
    firc_err_t err = firc_app_config_copy(&next, &app->saved);
    if (err == FIRC_OK) {
        next.http_web.host.port = port;
        err = firc_app_put_settings(app, &next, conf_path, version, NULL, NULL);
    }
    if (err != FIRC_OK) {
        firc_app_config_clear(&next);
        app->saved.http_web.host.port = port;
    }
    return err;
}

firc_err_t firc_app_reload_settings(firc_app_t *app, const firc_app_config_t *from_file,
                                    bool applied[FIRC_SETTINGS_COUNT]) {
    firc_app_config_t next;
    memset(&next, 0, sizeof(next));
    firc_err_t err = firc_app_config_copy(&next, from_file);
    if (err != FIRC_OK) {
        firc_app_config_clear(&next);
        return err;
    }
    return adopt_saved(app, &next, applied);
}

void firc_app_set_port_remap(firc_app_t *app, firc_port_remap_t *remap) {
    app->port_remap = remap;
}

/* collected by the pass under nf_mu while it walks the registry: DNAT follows "routed" */
typedef struct routed_ids {
    char (*ids)[FIRC_ID_STR_LEN];
    size_t n;
} routed_ids_t;

static int routed_id_cmp(const void *a, const void *b) { return strcmp(a, b); }

static bool routed_has(const char *group_id, void *ud) {
    const routed_ids_t *r = ud;
    return r->n != 0 && bsearch(group_id, r->ids, r->n, sizeof(*r->ids), routed_id_cmp) != NULL;
}

static firc_err_t rebuild_netfilter_locked(firc_app_t *app, firc_cancel_t *cancel, bool full) {
    firc_err_t err = FIRC_OK;
    if (full) {
        /* everything of ours out first, so the result depends only on the current group set, not on what was left behind */
        err = firc_netfilter_clean_iptables(app->ipt4, app->ipt6,
                                            app->cfg->app.netfilter.iptables.chain_prefix);
        if (err != FIRC_OK) { return err; }
        if (firc_cancel_raised(cancel)) { return FIRC_ERR_CANCELED; }
    } /* otherwise every chain is an override, replaced whole inside one iptables-restore transaction */

    err = firc_netfilter_register_base_chains(app->ipt4, app->ipt6);
    if (err != FIRC_OK) { return err; }

    err = firc_port_remap_prepare_iptables(app->port_remap);
    if (err != FIRC_OK) { return err; }
    err = firc_app_stage_pool_reject(app);
    if (err != FIRC_OK) { return err; }

    err = firc_app_stage_tap(app); /* every pass while a capture runs: the pass after a rewrite puts its rules back */
    if (err != FIRC_OK) { return err; }

    /* tombstones before the groups: staged first, a delete can never replace a chain registration being written */
    for (size_t i = 0; i < app->n_tombs; i++) {
        err = stage_tombstone(app->ipt4, &app->tombs[i]);
        if (err == FIRC_OK) { err = stage_tombstone(app->ipt6, &app->tombs[i]); }
        if (err != FIRC_OK) { return err; }
    }

    for (size_t i = 0; i < app->n_rulesets; i++) {
        err = firc_ruleset_prepare_iptables(app->rulesets[i]);
        if (err != FIRC_OK) { return err; }
    }

    /* every mapping from this pass's snapshot, routed groups only; a non-routed group dies on the unreachable route */
    const char *prefix = app->cfg->app.netfilter.iptables.chain_prefix;
    routed_ids_t routed = {NULL, 0};
    if (app->n_rulesets != 0) {
        routed.ids = calloc(app->n_rulesets, sizeof(*routed.ids));
        if (routed.ids == NULL) { return FIRC_ERR_NOMEM; }
    }
    for (size_t i = 0; i < app->n_rulesets; i++) {
        if (firc_ruleset_routed(app->rulesets[i])) {
            firc_id_format(firc_ruleset_group(app->rulesets[i])->id, routed.ids[routed.n++]);
        }
    }
    if (routed.n > 1) { qsort(routed.ids, routed.n, sizeof(*routed.ids), routed_id_cmp); }
    if (app->ipt4 && app->pass_snap) {
        err = firc_dnat_build_rules(app->ipt4, prefix, app->pass_snap, routed_has, &routed);
    }
    if (err == FIRC_OK && app->ipt6 && app->pass_snap) {
        err = firc_dnat_build_rules(app->ipt6, prefix, app->pass_snap, routed_has, &routed);
    }
    free(routed.ids);
    if (err != FIRC_OK) { return err; }

    if (firc_cancel_raised(cancel)) { return FIRC_ERR_CANCELED; }

    if (app->ipt4) {
        err = firc_ipt_commit(app->ipt4);
        if (err != FIRC_OK) { return err; }
    }
    if (app->ipt6) {
        err = firc_ipt_commit(app->ipt6);
        if (err != FIRC_OK) { return err; }
    }
    return FIRC_OK;
}

firc_err_t firc_app_stage_tap(firc_app_t *app) {
    if (app == NULL || !app->tap_open) { return FIRC_OK; }
    const char *prefix = app->cfg->app.netfilter.iptables.chain_prefix;
    firc_ipt_t *engines[] = {app->ipt4, app->ipt6};
    for (unsigned fam = 0; fam < 2; fam++) {
        if (engines[fam] == NULL) { continue; }
        firc_err_t err = firc_tap_rules_install(engines[fam], prefix, app->pool,
                                                (const char *const *)app->tap_lan,
                                                app->n_tap_lan);
        if (err != FIRC_OK) { return err; }
    }
    return FIRC_OK;
}

/* dedup table has no eviction; once full, every further bypass becomes its own event. 1024 is an estimate. */
#define TAP_MAX_FLOWS 1024

static int64_t tap_wall_secs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec;
}

/* the capture's own lines go to the journal at INFO whatever the log level, so they are never silently hidden */
__attribute__((format(printf, 1, 2))) static void capture_say(const char *fmt, ...) {
    char buf[FIRC_EVENT_TEXT];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) { return; }
    FIRC_INFO("%s", buf);
    if (firc_log_level() > FIRC_LOG_INFO) {
        firc_event_put_log(FIRC_LOG_INFO, tap_wall_secs(), buf);
    }
}

/* unprefixed: a prefix would cut the sentence's end off, already at most one log event's text */
_Static_assert(FIRC_TAP_SENTENCE_MAX < FIRC_EVENT_TEXT, "a summary sentence fits a log event");
static void say_sentence(const char *sentence, void *ud) {
    (void)ud;
    capture_say("%s", sentence);
}

static void tap_lan_free(char **lan, size_t n) {
    for (size_t i = 0; i < n; i++) { free(lan[i]); }
    free(lan);
}

/* built before the rules are staged: a reader not yet bound is packets the kernel drops */
static firc_err_t tap_reader_up(firc_app_t *app) {
    static const uint16_t groups[2] = {FIRC_TAP_GROUP_NEW, FIRC_TAP_GROUP_HELLO};
    static const uint16_t ranges[2] = {FIRC_TAP_HEAD_RANGE, FIRC_TAP_COPY_RANGE};
    firc_tap_pool_t pool;
    if (!firc_tap_pool_from_fakeip(app->pool, &pool)) { return FIRC_ERR_STATE; }
    firc_tap_report_t *report = firc_tap_report_new(TAP_MAX_FLOWS);
    if (report == NULL) { return FIRC_ERR_NOMEM; }

    firc_nflog_t *socks[2] = {NULL, NULL};
    bool on_loop[2] = {false, false};
    firc_err_t err = FIRC_OK;
    for (int w = 0; w < 2 && err == FIRC_OK; w++) {
        socks[w] = app->tap_nflog_open(groups[w], ranges[w]);
        if (socks[w] == NULL) {
            FIRC_ERROR("capture refused: could not bind NFLOG group %u", (unsigned)groups[w]);
            err = FIRC_ERR_SYS;
            break;
        }
        app->tap_reader[w].app = app;
        app->tap_reader[w].which = w;
        /* without a loop the group is bound but nothing drains it; the kernel still copies in rather than drop it */
        if (app->loop != NULL) {
            firc_err_t watched = firc_loop_add_fd(app->loop, firc_nflog_fd(socks[w]), EPOLLIN,
                                                  on_tap_readable, &app->tap_reader[w]);
            if (watched != FIRC_OK) { /* same FIRC_ERR_SYS as a failed bind; this log line is what tells them apart */
                FIRC_ERROR("capture refused: NFLOG group %u bound, but the event loop would not "
                           "watch its socket (%s)",
                           (unsigned)groups[w], firc_err_str(watched));
                err = FIRC_ERR_SYS;
                break;
            }
            on_loop[w] = true;
        }
    }
    if (err != FIRC_OK) {
        for (int w = 0; w < 2; w++) {
            if (on_loop[w]) { (void)firc_loop_del_fd(app->loop, firc_nflog_fd(socks[w])); }
            if (socks[w] != NULL) { firc_nflog_close(socks[w]); }
        }
        firc_tap_report_free(report);
        return err;
    }
    for (int w = 0; w < 2; w++) { app->tap_reader[w].sock = socks[w]; }
    app->tap_report = report;
    app->tap_pool = pool;
    return FIRC_OK;
}

/* nothing is kept after a capture: its events are its result; safe on one that never had readers */
static void tap_reader_down(firc_app_t *app) {
    for (int w = 0; w < 2; w++) {
        firc_nflog_t *sock = app->tap_reader[w].sock;
        if (sock == NULL) { continue; }
        if (app->loop != NULL) { (void)firc_loop_del_fd(app->loop, firc_nflog_fd(sock)); }
        firc_nflog_close(sock);
        app->tap_reader[w].sock = NULL;
    }
    firc_tap_report_free(app->tap_report);
    app->tap_report = NULL;
    memset(&app->tap_pool, 0, sizeof(app->tap_pool));
}

/* The kernel has something on one of the two sockets. */
static void on_tap_readable(firc_loop_t *loop, int fd, uint32_t events, void *ud) {
    (void)loop;
    (void)fd;
    (void)events;
    struct tap_reader *r = ud;
    firc_app_t *app = r->app;
    if (r->sock == NULL) { return; }

    /* read fresh on every wakeup, not kept: the judge's covers() reads the pipeline's own snapshot too */
    firc_tap_drain_t d;
    memset(&d, 0, sizeof(d));
    d.ctx.snap = app->pipeline != NULL ? firc_dns_pipeline_snapshot(app->pipeline) : NULL;
    d.ctx.pool = &app->tap_pool;
    d.ctx.pipeline = app->pipeline;
    d.ctx.recall = app->pipeline != NULL ? firc_dns_pipeline_recall(app->pipeline) : NULL;
    d.ctx.policy = app->tap_policy;
    d.ctx.device = app->tap_device;
    d.ctx.ud = app->tap_resolver_ud;
    d.report = app->tap_report;
    d.which = r->which;

    /* bounded, not "until empty": draining a flood here would stop the daemon answering DNS while it did */
    for (int i = 0; i < 64; i++) {
        firc_err_t e = firc_tap_drain(&d, r->sock, NULL);
        if (e == FIRC_ERR_AGAIN) { return; }
        if (e != FIRC_OK) { /* the reader is broken; carrying on would report a false clean five minutes */
            FIRC_ERROR("capture: its %s reader failed (%s), so the capture ends here",
                       r->which == 0 ? "new-connection" : "ClientHello", firc_err_str(e));
            (void)firc_app_capture_stop(app, NULL);
            return;
        }
    }
}

void firc_app_set_policy_resolver(firc_app_t *app, firc_devsel_policy_fn policy,
                                  firc_devsel_device_fn device, void *ud) {
    if (app == NULL) { return; }
    app->tap_policy = policy;
    app->tap_device = device;
    app->tap_resolver_ud = ud;
}

void firc_app_set_device_lookup(firc_app_t *app, firc_devsel_mark_fn mark, firc_devsel_hosts_fn hosts,
                                firc_devsel_policy_hosts_fn policy_hosts, firc_devsel_policy_nets_fn policy_nets,
                                void *ud) {
    if (app == NULL) { return; }
    app->lookup.policy_mark = mark;
    app->lookup.host_addrs = hosts;
    app->lookup.policy_hosts = policy_hosts;
    app->lookup.policy_nets = policy_nets;
    app->lookup.ud = ud;
}

void firc_app_devices_changed(firc_app_t *app) {
    if (app == NULL || !app->running) { return; }
    /* compared before taking nf_mu, so a table that moved no chain costs the committer nothing */
    bool any = false;
    for (size_t i = 0; i < app->n_rulesets && !any; i++) {
        bool moved = false;
        any = firc_ruleset_devices_would_move(app->rulesets[i], &moved) != FIRC_OK || moved;
    }
    if (!any) { return; }
    app_nf_enter(app);
    bool moved = false;
    for (size_t i = 0; i < app->n_rulesets; i++) {
        firc_ruleset_t *rs = app->rulesets[i];
        bool changed = false;
        firc_err_t err = firc_ruleset_refresh_devices(rs, &changed);
        if (err != FIRC_OK) {
            const char *name = firc_ruleset_group(rs)->name;
            FIRC_WARN("group \"%s\": its devices chain could not follow the firmware's host table (%s); it keeps "
                      "the one it had", name != NULL ? name : "", firc_err_str(err));
            continue;
        }
        if (!changed) { continue; }
        moved = true;
        if (app->committer == NULL) { (void)firc_ruleset_rewrite_chains(rs); }
        /* a device no longer matched by a narrowed chain keeps its flows unless flushed */
        if (firc_ruleset_devices_narrowed(rs)) { note_narrowed(app, rs); }
    }
    if (moved && app->committer != NULL) { app_request_more_locked(app); }
    app_nf_leave(app);
}

/* any missing LAN interface is "one went away": iptables accepts a rule naming one that does not exist */
static void tap_note_iface(firc_app_t *app) {
    if (app->tap_report == NULL || app->n_tap_lan == 0) { return; }
    bool gone = false;
    for (size_t i = 0; i < app->n_tap_lan && !gone; i++) {
        gone = app->tap_iface_index(app->tap_lan[i]) == 0;
    }
    if (gone) {
        firc_tap_report_saw_iface_gone(app->tap_report);
    } else {
        firc_tap_report_saw_iface_there(app->tap_report);
    }
}

/* folds what the committer counted since last asked; called by the stop and the start, so nothing is owed twice */
static void tap_fold_failed_passes(firc_app_t *app) {
    uint32_t failed = atomic_load_explicit(&app->tap_failed_passes, memory_order_relaxed);
    for (; app->tap_failed_passes_seen < failed; app->tap_failed_passes_seen++) {
        firc_tap_report_saw_rules_gone(app->tap_report);
    }
}

static int64_t mono_secs(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec;
}

firc_err_t firc_app_capture_start(firc_app_t *app, int64_t now_unix,
                                  char token_out[FIRC_TAP_TOKEN_CHARS + 1]) {
    if (app == NULL) { return FIRC_ERR_INVAL; }
    /* checked first: a running capture is the answer regardless of a cleared link/pool since it started */
    if (app->tap_open) { return FIRC_ERR_EXIST; }
    /* syntax only: this is written verbatim into an iptables-restore transcript, where a newline is a line of its own */
    const firc_app_config_t *ac = &app->cfg->app;
    if (ac->n_link == 0) { return FIRC_ERR_INVAL; }
    for (size_t i = 0; i < ac->n_link; i++) {
        if (!firc_is_interface_name(ac->link[i])) { return FIRC_ERR_INVAL; }
    }
    if (app->pool == NULL) { return FIRC_ERR_STATE; }

    /* generated before the lock: it reads /dev/urandom, and nf_mu is not a thing to hold across a file */
    char token[FIRC_TAP_TOKEN_CHARS + 1];
    {
        uint8_t raw[FIRC_TAP_TOKEN_CHARS / 2];
        if (firc_random_bytes(raw, sizeof(raw)) != FIRC_OK) { /* FIRC_ERR_IO, deliberately distinct from the NFLOG bind's FIRC_ERR_SYS */
            FIRC_ERROR("capture refused: no random bytes for its token");
            return FIRC_ERR_IO;
        }
        for (size_t i = 0; i < sizeof(raw); i++) { snprintf(token + i * 2, 3, "%02x", raw[i]); }
    }

    /* readers come up outside the mutex below: binding an NFLOG group is a kernel round trip with a two-second ceiling */
    char **lan = calloc(ac->n_link, sizeof(*lan));
    if (lan == NULL) { return FIRC_ERR_NOMEM; }
    for (size_t i = 0; i < ac->n_link; i++) {
        lan[i] = strdup(ac->link[i]);
        if (lan[i] == NULL) {
            tap_lan_free(lan, i);
            return FIRC_ERR_NOMEM;
        }
    }
    size_t n_lan = ac->n_link;

    /* readers first, rules only if they came up: rules with nothing bound to their groups are packets the kernel drops */
    firc_err_t err = tap_reader_up(app);
    if (err != FIRC_OK) {
        tap_lan_free(lan, n_lan);
        FIRC_ERROR("capture refused: its readers could not be started (%s)", firc_err_str(err));
        return err;
    }
    app->tap_failed_passes_seen = /* the last capture's failed passes are its own; it has stopped */
        atomic_load_explicit(&app->tap_failed_passes, memory_order_relaxed);

    app_nf_enter(app); /* driving an iptables engine the committer may be mid-pass on is the race this mutex exists for */
    if (app->tap_open) {
        app_nf_leave(app);
        tap_reader_down(app);
        tap_lan_free(lan, n_lan);
        return FIRC_ERR_EXIST;
    }

    /* probed under the lock: it forks iptables-restore, whose cancel token the committer attaches under this same mutex */
    const char *prefix = ac->netfilter.iptables.chain_prefix;
    /* firmware ships xt_NFLOG/xt_string but may not load them after a reboot; root-only so tests avoid the host's modules */
    if ((app->ipt4 != NULL || app->ipt6 != NULL) && geteuid() == 0) {
        (void)firc_tap_load_modules(NULL);
    }
    for (unsigned fam = 0; fam < 2; fam++) {
        firc_ipt_t *engine = fam == 0 ? app->ipt4 : app->ipt6;
        if (engine == NULL) { continue; }
        firc_err_t asked = firc_tap_rules_supported(engine, prefix, app->pool,
                                                    (const char *const *)lan, n_lan);
        if (asked == FIRC_ERR_NOSYS) {
            app_nf_leave(app);
            tap_reader_down(app);
            tap_lan_free(lan, n_lan);
            FIRC_ERROR("capture refused: this kernel will not take the capture rules. They need "
                       FIRC_TAP_LAN_MODULES "; the line it refused is in the log above");
            return FIRC_ERR_NOSYS;
        }
        if (asked != FIRC_OK) {
            FIRC_WARN("could not ask whether this kernel takes the capture rules (%s): starting "
                      "the capture anyway",
                      firc_err_str(asked));
        }
    }

    memcpy(app->tap_token, token, sizeof(token));
    app->tap_lan = lan;
    app->n_tap_lan = n_lan;
    app->tap_ends_at = now_unix + app->tap_seconds;
    app->tap_ends_mono = mono_secs() + app->tap_seconds;
    app->tap_open = true;

    err = firc_app_stage_tap(app);
    if (err != FIRC_OK) {
        /* unregister, not merely unstage: an uncleared registration is written again by the next commit */
        app->tap_open = false;
        (void)firc_tap_rules_remove_all(app);
        memset(app->tap_token, 0, sizeof(app->tap_token));
        app->tap_lan = NULL;
        app->n_tap_lan = 0;
        app_nf_leave(app);
        tap_reader_down(app);
        tap_lan_free(lan, n_lan);
        FIRC_ERROR("capture could not be staged, and is not running: %s", firc_err_str(err));
        return err;
    }
    app_nf_leave(app);

    /* one-shot deadline; without a loop (tests, the pre-loop window) a capture has no deadline and runs until stopped */
    if (app->loop != NULL) {
        uint64_t ms = (uint64_t)app->tap_seconds * 1000u;
        if (firc_loop_add_timer(app->loop, ms, 0, on_tap_deadline, app, &app->tap_timer) !=
            FIRC_OK) {
            /* reachable only when out of file descriptors, untested; a quiet teardown since the start was never said */
            app->tap_timer = 0;
            app_nf_enter(app);
            app->tap_open = false;
            memset(app->tap_token, 0, sizeof(app->tap_token));
            app->tap_lan = NULL;
            app->n_tap_lan = 0;
            (void)firc_tap_rules_remove_all(app);
            app_nf_leave(app);
            tap_reader_down(app);
            tap_lan_free(lan, n_lan);
            /* only unregisters; a pass may already have written the rules for real, so ask for one now */
            if (app->committer != NULL) { firc_nfcommit_request(app->committer); }
            FIRC_ERROR("capture refused: its deadline could not be armed");
            return FIRC_ERR_NOMEM;
        }
    }

    /* a recall with no real address yet recognises nothing by address; noted now, said at the capture's end */
    firc_recall_t *recall = app->pipeline != NULL ? firc_dns_pipeline_recall(app->pipeline) : NULL;
    if (firc_recall_real_count(recall) == 0) { firc_tap_report_saw_cold_recall(app->tap_report); }
    tap_note_iface(app);

    /* said after it is actually running, so the log cannot say the capability is on when it is not */
    char names[FIRC_EVENT_TEXT];
    size_t at = 0;
    names[0] = '\0';
    for (size_t i = 0; i < n_lan && at < sizeof(names); i++) {
        int n = snprintf(names + at, sizeof(names) - at, "%s%s", i ? ", " : "", lan[i]);
        if (n < 0) { break; }
        at += (size_t)n;
    }
    capture_say("capture started: %llds on the LAN side, on %s", (long long)app->tap_seconds,
                names);
    if (app->committer != NULL) { firc_nfcommit_request(app->committer); }
    if (token_out != NULL) { memcpy(token_out, token, sizeof(token)); }
    return FIRC_OK;
}

/* takes the capture's chain out of both engines; caller holds nf_mu */
static firc_err_t firc_tap_rules_remove_all(firc_app_t *app) {
    const char *prefix = app->cfg->app.netfilter.iptables.chain_prefix;
    firc_ipt_t *engines[] = {app->ipt4, app->ipt6};
    firc_err_t first = FIRC_OK;
    for (unsigned fam = 0; fam < 2; fam++) {
        if (engines[fam] == NULL) { continue; }
        firc_err_t err = firc_tap_rules_remove(engines[fam], prefix); /* both families attempted whatever the first does */
        if (err != FIRC_OK && first == FIRC_OK) { first = err; }
    }
    return first;
}

static void on_tap_deadline(firc_loop_t *loop, void *ud) {
    (void)loop;
    firc_app_t *app = ud;
    app->tap_timer = 0; /* the timer has fired and is dead; saying so first keeps the stop from deleting an id that names nothing */
    capture_say("capture reached its end");
    (void)firc_app_capture_stop(app, NULL);
}

firc_err_t firc_app_capture_stop(firc_app_t *app, const char *token) {
    if (app == NULL) { return FIRC_ERR_INVAL; }

    app_nf_enter(app);
    if (!app->tap_open) {
        app_nf_leave(app);
        return FIRC_OK;
    }
    if (token != NULL && strcmp(token, app->tap_token) != 0) { /* decided under the same lock that decides whether a capture exists at all */
        app_nf_leave(app);
        return FIRC_ERR_NOENT;
    }
    tap_note_iface(app); /* the last reading taken while still running; after this the summary is what it is */
    tap_fold_failed_passes(app);
    app->tap_open = false;
    memset(app->tap_token, 0, sizeof(app->tap_token));
    tap_lan_free(app->tap_lan, app->n_tap_lan);
    app->tap_lan = NULL;
    app->n_tap_lan = 0;
    int timer = app->tap_timer; /* noted here, cancelled below the unlock; safe since every caller is the loop thread */
    app->tap_timer = 0;
    firc_err_t first = firc_tap_rules_remove_all(app);
    app_nf_leave(app);

    if (timer != 0 && app->loop != NULL) { (void)firc_loop_del_timer(app->loop, timer); }

    if (first != FIRC_OK) { /* the capture is over either way; what is left is a chain only the next full pass's cleaner removes */
        FIRC_ERROR("capture stopped, but its chain could not be unstaged: %s",
                   firc_err_str(first));
    }
    capture_say("capture stopped");
    firc_tap_report_sentences(app->tap_report, true, say_sentence, NULL); /* one sentence per line; nothing of the capture is kept after this */
    tap_reader_down(app);
    if (app->committer != NULL) { firc_nfcommit_request(app->committer); }
    return first;
}

void firc_app_capture_status(const firc_app_t *app, firc_capture_status_t *out) {
    if (out == NULL) { return; }
    memset(out, 0, sizeof(*out));
    if (app == NULL) { return; }
    /* the mutex directly, not app_nf_enter, which would wrongly interrupt a running commit for a status read */
    firc_app_t *mut = (firc_app_t *)app;
    if (mut->nf_mu_ready) { pthread_mutex_lock(&mut->nf_mu); }
    out->running = app->tap_open;
    if (out->running) {
        out->ends_at = app->tap_ends_at;
        int64_t left = app->tap_ends_mono - mono_secs();
        out->seconds_left = left > 0 ? left : 0;
    }
    if (mut->nf_mu_ready) { pthread_mutex_unlock(&mut->nf_mu); }
}

firc_err_t firc_app_stage_pool_reject(firc_app_t *app) {
    const char *prefix = app->cfg->app.netfilter.iptables.chain_prefix;
    firc_ipt_t *engines[] = {app->ipt4, app->ipt6};
    for (unsigned fam = 0; fam < 2; fam++) {
        if (engines[fam] == NULL || !app->reject_has[fam]) { continue; }
        firc_err_t err = firc_pool_reject_build_rules(engines[fam], prefix, &app->reject_base[fam], app->reject_len[fam]);
        if (err != FIRC_OK) { return err; }
    }
    return FIRC_OK;
}

firc_err_t firc_app_rebuild_netfilter(firc_app_t *app, firc_cancel_t *cancel) {
    return firc_app_rebuild_netfilter_kind(app, cancel, true);
}

static firc_err_t firc_app_rebuild_netfilter_locked(firc_app_t *app, firc_cancel_t *cancel,
                                                    bool full);

firc_err_t firc_app_rebuild_netfilter_kind(firc_app_t *app, firc_cancel_t *cancel, bool full) {
    firc_err_t err = firc_app_rebuild_netfilter_locked(app, cancel, full);
    /* a cancelled/raced pass leaves no unwritten window; anything else does, so a capture's rules may be missing */
    if (err != FIRC_OK && err != FIRC_ERR_CANCELED && err != FIRC_ERR_AGAIN && app->tap_open) {
        atomic_fetch_add_explicit(&app->tap_failed_passes, 1u, memory_order_relaxed);
    }
    return err;
}

static firc_err_t firc_app_rebuild_netfilter_locked(firc_app_t *app, firc_cancel_t *cancel,
                                                    bool full) {
    if (app->nf_mu_ready) { pthread_mutex_lock(&app->nf_mu); }
    uint64_t ticket = app->nf_change; /* every mutation made before this pass took the lock */

    /* attached for exactly this pass: leaving it on would also abort a synchronous API commit on the loop thread */
    if (app->ipt4) { firc_ipt_set_cancel(app->ipt4, cancel); }
    if (app->ipt6) { firc_ipt_set_cancel(app->ipt6, cancel); }

    uint64_t gen = pass_snapshot_begin(app);
    firc_err_t err = rebuild_netfilter_locked(app, cancel, full);
    pass_snapshot_end(app);

    if (err != FIRC_OK) { /* discard, or the next commit on this engine (a loop-thread group enable) would carry out what was only staged */
        firc_ipt_discard(app->ipt4);
        firc_ipt_discard(app->ipt6);
        (void)firc_netfilter_register_base_chains(app->ipt4, app->ipt6); /* the discard took base-chain registrations with it */
    } else {
        app->n_tombs = 0; /* all carried: the loop writes the list only under nf_mu, held since before this pass staged them */
    }

    if (app->ipt4) { firc_ipt_set_cancel(app->ipt4, NULL); }
    if (app->ipt6) { firc_ipt_set_cancel(app->ipt6, NULL); }

    if (app->nf_mu_ready) { pthread_mutex_unlock(&app->nf_mu); }
    if (err == FIRC_OK) { report_committed(app, gen, full, ticket); }
    return err;
}

static firc_err_t rebuild_netfilter_cb(void *ud, firc_cancel_t *cancel, bool full) {
    return firc_app_rebuild_netfilter_kind(ud, cancel, full);
}

/* only after a full pass: an incremental one leaves the kernel with our rules, so sweeping it would drop live flows */
/* ponytail: a whole-table dump on the DNS loop thread, cost unmeasured */
static void sweep_fail_open_flows(firc_app_t *app) {
    if (app == NULL || app->ct == NULL || app->pool == NULL) { return; }
    firc_ip_t b4, b6;
    uint8_t l4 = 0, l6 = 0;
    bool has4 = firc_fakeip_pool_prefix(app->pool, FIRC_FAM_V4, &b4, &l4);
    bool has6 = firc_fakeip_pool_prefix(app->pool, FIRC_FAM_V6, &b6, &l6);
    size_t dropped = 0;
    firc_err_t err = firc_ct_flush_pool_replies(app->ct, has4 ? b4.b : NULL, has4 ? l4 : 0,
                                                has6 ? b6.b : NULL, has6 ? l6 : 0, &dropped);
    if (dropped > 0) { /* the count regardless: a sweep that failed halfway has still deleted what it deleted */
        FIRC_INFO("cleared %zu flow(s) answered with a fake address while the pool was "
                  "unprotected",
                  dropped);
    }
    if (err != FIRC_OK) { /* a flow the sweep missed recovers on the client's next connection anyway, and the next full pass sweeps again */
        FIRC_WARN("could not clear the flows of the fail-open window: %s -- any left are swept "
                  "at the next full rebuild",
                  firc_err_str(err));
    }
}

/* reported on the loop thread: the pool, the proxy and the conntrack handle are all loop-thread objects */
typedef struct committed_report {
    firc_app_t *app;
    uint64_t gen;
    bool full;
    uint64_t ticket;
} committed_report_t;

static void on_committed_posted(firc_loop_t *loop, void *ud) {
    (void)loop;
    committed_report_t *r = ud;
    r->app->owed_full_sweep = false; /* a report landed, so whatever was owed is paid; the next failure is a new one */
    /* answers first, sweep second: the sweep is blocking netlink I/O, and the held answers have a deadline */
    firc_app_pass_committed(r->app, r->gen);
    if (r->full) { sweep_fail_open_flows(r->app); }
    pay_flushes(r->app, r->ticket); /* the flushes this pass carried */
    firc_app_retry_groups(r->app, NULL); /* a group whose enable failed is tried again when due */
    free(r);
}

static void report_committed(firc_app_t *app, uint64_t gen, bool full, uint64_t ticket) {
    if (app->loop == NULL) {
        /* no loop: the committer thread itself writes loop objects (pool, conntrack handle), all under nf_mu */
        if (app->nf_mu_ready) { pthread_mutex_lock(&app->nf_mu); }
        firc_app_pass_committed(app, gen);
        if (full) { sweep_fail_open_flows(app); }
        pay_flushes(app, ticket);
        if (app->nf_mu_ready) { pthread_mutex_unlock(&app->nf_mu); }
        return;
    }
    committed_report_t *r = malloc(sizeof(*r));
    if (r != NULL) {
        r->app = app;
        r->gen = gen;
        r->full = full;
        r->ticket = ticket;
    }
    if (r == NULL ||
        firc_loop_post_with_drop(app->loop, on_committed_posted, r, free) != FIRC_OK) {
        /* nothing would report or schedule another pass, leaving every answer waiting out its deadline */
        free(r);
        if (full) {
            /* the sweep's report could not post; an incremental follow-up would not sweep, so a full one is asked, once */
            if (app->owed_full_sweep) {
                FIRC_WARN("could not report a completed rebuild again; the flows of its fail-open "
                          "window are left unswept rather than asking for a third pass that would "
                          "open another");
            } else {
                app->owed_full_sweep = true;
                FIRC_WARN("could not report a completed rebuild; asking for another so the flows "
                          "of its fail-open window are swept");
                firc_nfcommit_request(app->committer);
            }
        } else {
            firc_nfcommit_request_more(app->committer);
        }
    }
}

static bool answer_ready(const firc_dns_msg_t *msg, void *ud) {
    return firc_app_answer_ready(ud, msg);
}

bool firc_app_answer_ready(firc_app_t *app, const firc_dns_msg_t *msg) {
    char qname[FIRC_DNS_MAX_NAME * 4 + 2];
    if (!firc_dns_msg_queried_name(msg, qname, sizeof(qname))) { return true; }
    /* only the families the held answer actually carries: an A answer is not kept waiting on a later AAAA's v6 pair */
    for (size_t i = 0; i < msg->n_answers; i++) {
        uint16_t t = msg->answers[i].rtype;
        if (t == FIRC_DNS_TYPE_A && firc_fakeip_needs_commit(app->pool, qname, FIRC_FAM_V4)) {
            return false;
        }
        if (t == FIRC_DNS_TYPE_AAAA && firc_fakeip_needs_commit(app->pool, qname, FIRC_FAM_V6)) {
            return false;
        }
    }
    return true;
}

void firc_app_pass_committed(firc_app_t *app, uint64_t gen) {
    if (app == NULL) { return; }
    firc_fakeip_mark_committed(app->pool, gen);
    if (app->proxy) { firc_dnsproxy_release(app->proxy, answer_ready, app); }
}

void firc_app_pool_changed(firc_app_t *app) {
    if (app == NULL) { return; }
    firc_err_t err = firc_app_refresh_pool_snapshot(app);
    if (err != FIRC_OK) { /* the old snapshot stays current; the next change retries the refresh */
        FIRC_ERROR("failed to snapshot the address pool: %s", firc_err_str(err));
    }
    if (app->committer) {
        firc_nfcommit_request_more(app->committer);
    } else {
        err = firc_app_rebuild_netfilter_kind(app, NULL, false);
        if (err != FIRC_OK) { FIRC_ERROR("netfilter rebuild failed: %s", firc_err_str(err)); }
    }
}

firc_nfcommit_t *firc_app_committer_for_test(firc_app_t *app) {
    return app != NULL ? app->committer : NULL;
}

firc_err_t firc_app_start_netfilter_committer(firc_app_t *app) {
    if (app->committer) { return FIRC_ERR_STATE; }

    pthread_mutexattr_t attr;
    if (pthread_mutexattr_init(&attr) != 0) { return FIRC_ERR_SYS; }
    bool mu_ok = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0 &&
                 pthread_mutex_init(&app->nf_mu, &attr) == 0;
    pthread_mutexattr_destroy(&attr);
    if (!mu_ok) { return FIRC_ERR_SYS; }

    app->committer = firc_nfcommit_new(rebuild_netfilter_cb, app);
    if (!app->committer) {
        pthread_mutex_destroy(&app->nf_mu);
        return FIRC_ERR_NOMEM;
    }

    app->nf_mu_ready = true; /* published before the thread starts, so the first webhook request already takes the lock */

    firc_err_t err = firc_nfcommit_start(app->committer);
    if (err != FIRC_OK) {
        app->nf_mu_ready = false;
        firc_nfcommit_free(app->committer);
        app->committer = NULL;
        pthread_mutex_destroy(&app->nf_mu);
        return err;
    }
    FIRC_INFO("netfilter table committer started");
    return FIRC_OK;
}

void firc_app_stop_netfilter_committer(firc_app_t *app) {
    if (!app || !app->committer) { return; }

    firc_nfcommit_free(app->committer); /* joins the thread, so no pass can still have the token attached to an engine by the time this returns */
    app->committer = NULL;

    app->nf_mu_ready = false;
    pthread_mutex_destroy(&app->nf_mu);
}

firc_err_t firc_app_force_commit_iptables(firc_app_t *app) {
    if (app->committer) { /* nothing to wait for or report: the committer aborts whatever it is writing and rebuilds from scratch */
        firc_nfcommit_request(app->committer);
        return FIRC_OK;
    }

    /* only before the committer has started, or after it failed; commits on the caller's thread, blocking what it serves */
    app_nf_enter(app);
    firc_err_t err = FIRC_OK;
    if (app->ipt4) { err = firc_ipt_commit(app->ipt4); }
    if (err == FIRC_OK && app->ipt6) { err = firc_ipt_commit(app->ipt6); }
    app_nf_leave(app);
    return err;
}
