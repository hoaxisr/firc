#include "firc/tunrun.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "firc/events.h"
#include "firc/mark.h"
#include "firc/tunnet.h"
#include "firc/tunnodes.h"

#define TUNVLESS_STDIN_MAX ((size_t)1 << 20)

typedef struct {
    char id[16];
    char device[16];
    firc_tunnet_uplink_t u;
} drain_t;

typedef struct {
    firc_tun_src_t *src;
    size_t *row_of;
    size_t n;
    bool have;
    firc_tun_nodes_t rows;
} sent_t;

typedef struct {
    char key[FIRC_TUN_KEY_MAX + 1];
    int64_t since;
} down_t;

typedef struct {
    down_t *v;
    size_t n;
} keys_t;

typedef struct {
    firc_tun_status_t syn;
    int64_t syn_since;
    keys_t downs;
    keys_t acts;
} ext_t;

struct firc_tunrun {
    firc_loop_t *loop;
    firc_rtnl_t *r;
    uint32_t start;
    firc_tunsup_t *sup;
    firc_tunnels_t cur;
    firc_tunnet_uplink_t *up;
    bool *ok;
    sent_t *sent;
    bool *waiting;
    ext_t *ext;
    drain_t *drains;
    size_t n_drains;
    firc_tunsubs_t *subs;
    size_t list_max;
    bool stopped;
};

bool firc_tun_journal_line(const firc_tun_state_t *st, const firc_tev_t *ev, char *buf, size_t cap,
                           firc_log_level_t *level)
{
    if (ev == NULL) {
        if (st->status != FIRC_TUN_ST_BACKOFF) {
            return false;
        }
        *level = FIRC_LOG_WARN;
        snprintf(buf, cap, "tunnel %s: exited (%d), restart in %d s", st->device, st->last_exit, st->backoff_s);
        return true;
    }
    switch (ev->kind) {
    case FIRC_TEV_ACTIVE: {
        if (ev->n_active == 0) {
            return false;
        }
        *level = FIRC_LOG_INFO;
        int off = snprintf(buf, cap, "tunnel %s: active ", st->device);
        for (size_t i = 0; i < ev->n_active && off >= 0 && (size_t)off < cap; i++) {
            off += snprintf(buf + off, cap - (size_t)off, "%s%s", i > 0 ? ", " : "", ev->active[i]);
        }
        return true;
    }
    case FIRC_TEV_NODE_DOWN:
        *level = FIRC_LOG_WARN;
        if (ev->why[0] != 0) {
            snprintf(buf, cap, "tunnel %s: %s does not answer (%s)", st->device, ev->node, ev->why);
        } else {
            snprintf(buf, cap, "tunnel %s: %s does not answer", st->device, ev->node);
        }
        return true;
    case FIRC_TEV_NODE_UP:
        *level = FIRC_LOG_INFO;
        snprintf(buf, cap, "tunnel %s: %s answers again", st->device, ev->node);
        return true;
    case FIRC_TEV_NO_NODE:
        *level = FIRC_LOG_WARN;
        if (ev->retry_s > 0) {
            snprintf(buf, cap, "tunnel %s: no node answers, retry in %d s", st->device, ev->retry_s);
        } else {
            snprintf(buf, cap, "tunnel %s: no node answers", st->device);
        }
        return true;
    case FIRC_TEV_READY:
    case FIRC_TEV_BAD:
    default:
        return false;
    }
}

static int64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int64_t wall_secs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec;
}

static void say(firc_log_level_t level, bool logged, const char *line)
{
    if (!logged) {
        firc_log(level, "%s", line);
    }
    if (firc_log_level() > level) {
        firc_event_put_log(level, wall_secs(), line);
    }
}

static bool needs_uplink(const firc_tunnel_t *tun)
{
    return tun->enable && tun->uplink != FIRC_UPLINK_AUTO;
}

static void show_uplink(firc_tunrun_t *t, size_t i)
{
    firc_tunsup_set_uplink_ok(t->sup, t->cur.t[i].id, !needs_uplink(&t->cur.t[i]) || t->up[i].routed);
}

static void refresh(firc_tunrun_t *t, size_t i)
{
    firc_err_t err = firc_tunnet_uplink_refresh(t->r, &t->cur.t[i], &t->cur, &t->up[i]);
    if (err != FIRC_OK) {
        FIRC_WARN("tunnel %s: uplink route not rewritten: %s", t->cur.t[i].device, firc_err_str(err));
    }
    show_uplink(t, i);
}

static ssize_t find(const firc_tunnels_t *all, const char *id);

static const down_t *key_find(const keys_t *k, const char *key)
{
    for (size_t i = 0; i < k->n; i++) {
        if (strcmp(k->v[i].key, key) == 0) {
            return &k->v[i];
        }
    }
    return NULL;
}

static void key_add(keys_t *k, const char *key)
{
    if (key_find(k, key) != NULL || k->n >= FIRC_TUN_MAX_NODES) {
        return;
    }
    down_t *g = realloc(k->v, (k->n + 1) * sizeof *g);
    if (g == NULL) {
        return;
    }
    k->v = g;
    snprintf(g[k->n].key, sizeof g[k->n].key, "%s", key);
    g[k->n].since = mono_ms();
    k->n++;
}

static void key_del_at(keys_t *k, size_t i)
{
    memmove(&k->v[i], &k->v[i + 1], (k->n - i - 1) * sizeof *k->v);
    k->n--;
}

static void key_del(keys_t *k, const char *key)
{
    for (size_t i = 0; i < k->n; i++) {
        if (strcmp(k->v[i].key, key) == 0) {
            key_del_at(k, i);
            return;
        }
    }
}

static void each_key(const sent_t *x, int pos, const char *name, keys_t *k, void (*fn)(keys_t *, const char *))
{
    if (pos >= 0 && (size_t)pos < x->n && x->row_of != NULL) {
        const firc_tun_node_t *row = &x->rows.v[x->row_of[pos]];
        if (strncmp(row->name, name, strlen(name)) == 0) {
            fn(k, row->key);
            return;
        }
    }
    for (size_t r = 0; r < x->rows.n; r++) {
        if (strcmp(x->rows.v[r].name, name) == 0) {
            fn(k, x->rows.v[r].key);
        }
    }
}

static bool sent_key(const sent_t *x, const char *key)
{
    for (size_t p = 0; p < x->n && x->row_of != NULL; p++) {
        if (strcmp(x->rows.v[x->row_of[p]].key, key) == 0) {
            return true;
        }
    }
    return false;
}

static void prune(keys_t *k, const sent_t *x)
{
    for (size_t i = 0; i < k->n;) {
        if (sent_key(x, k->v[i].key)) {
            i++;
        } else {
            key_del_at(k, i);
        }
    }
}

static void track_nodes(firc_tunrun_t *t, const firc_tun_state_t *st, const firc_tev_t *ev)
{
    ssize_t i = find(&t->cur, st->id);
    if (i < 0 || t->ext == NULL) {
        return;
    }
    ext_t *x = &t->ext[i];
    const sent_t *sent = &t->sent[i];
    if (ev == NULL) {
        x->acts.n = 0;
        if (st->status == FIRC_TUN_ST_STARTING || st->status == FIRC_TUN_ST_OFF) {
            x->downs.n = 0;
        }
        return;
    }
    switch (ev->kind) {
    case FIRC_TEV_NODE_DOWN:
        each_key(sent, ev->pos, ev->node, &x->downs, key_add);
        break;
    case FIRC_TEV_NODE_UP:
        each_key(sent, ev->pos, ev->node, &x->downs, key_del);
        break;
    case FIRC_TEV_ACTIVE:
        x->acts.n = 0;
        for (size_t k = 0; k < ev->n_active && k < 8; k++) {
            each_key(sent, ev->active_pos[k], ev->active[k], &x->acts, key_add);
        }
        break;
    case FIRC_TEV_NO_NODE:
        x->acts.n = 0;
        break;
    default:
        break;
    }
}

static void on_event(const firc_tun_state_t *st, const firc_tev_t *ev, void *ud)
{
    firc_tunrun_t *t = ud;
    track_nodes(t, st, ev);
    char line[FIRC_EVENT_TEXT];
    firc_log_level_t level = FIRC_LOG_INFO;
    if (firc_tun_journal_line(st, ev, line, sizeof line, &level)) {
        say(level, ev == NULL, line);
    }
    if (ev == NULL || ev->kind != FIRC_TEV_READY) {
        return;
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        if (t->cur.t[i].uplink == FIRC_UPLINK_TUNNEL && strcmp(t->cur.t[i].uplink_ref, st->id) == 0) {
            refresh(t, i);
        }
    }
}

static void forget(firc_tunrun_t *t, const char *id)
{
    char owner[24];
    snprintf(owner, sizeof owner, FIRC_MARK_TUNNEL_OWNER "%s", id);
    firc_rtnl_forget_mark_field(t->r, owner);
}

static void remove_uplink(firc_tunrun_t *t, const char *device, firc_tunnet_uplink_t *u)
{
    firc_err_t err = firc_tunnet_uplink_remove(t->r, u);
    if (err != FIRC_OK) {
        FIRC_WARN("tunnel %s: uplink not fully removed: %s", device, firc_err_str(err));
    }
    memset(u, 0, sizeof *u);
}

static ssize_t find_drain(const firc_tunrun_t *t, const char *id)
{
    for (size_t i = 0; i < t->n_drains; i++) {
        if (strcmp(t->drains[i].id, id) == 0) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static void drop_drain(firc_tunrun_t *t, size_t i)
{
    memmove(&t->drains[i], &t->drains[i + 1], (t->n_drains - i - 1) * sizeof *t->drains);
    t->n_drains--;
}

static void release(firc_tunrun_t *t, size_t i)
{
    remove_uplink(t, t->drains[i].device, &t->drains[i].u);
    forget(t, t->drains[i].id);
    drop_drain(t, i);
}

static void drain(firc_tunrun_t *t, const firc_tunnel_t *tun, firc_tunnet_uplink_t *u)
{
    if (!firc_tunsup_holds(t->sup, tun->id, u->mark)) {
        remove_uplink(t, tun->device, u);
        forget(t, tun->id);
        return;
    }
    drain_t *grown = realloc(t->drains, (t->n_drains + 1) * sizeof *grown);
    if (grown == NULL) {
        FIRC_ERROR("tunnel %s: out of memory, its uplink rule stays until the next start", tun->device);
        memset(u, 0, sizeof *u);
        return;
    }
    t->drains = grown;
    drain_t *d = &t->drains[t->n_drains++];
    snprintf(d->id, sizeof d->id, "%s", tun->id);
    snprintf(d->device, sizeof d->device, "%s", tun->device);
    d->u = *u;
    memset(u, 0, sizeof *u);
}

static void on_reap(const char *id, pid_t pid, void *ud)
{
    (void)pid;
    firc_tunrun_t *t = ud;
    ssize_t d = find_drain(t, id);
    if (d >= 0 && !firc_tunsup_holds(t->sup, id, t->drains[d].u.mark)) {
        release(t, (size_t)d);
    }
}

firc_tunrun_t *firc_tunrun_new(firc_loop_t *loop, firc_rtnl_t *r, uint32_t start_table, const char *binary)
{
    firc_tunrun_t *t = calloc(1, sizeof *t);
    if (t == NULL) {
        return NULL;
    }
    t->loop = loop;
    t->r = r;
    t->list_max = TUNVLESS_STDIN_MAX;
    t->start = start_table;
    t->sup = firc_tunsup_new(loop, binary, on_event, t);
    if (t->sup == NULL) {
        free(t);
        return NULL;
    }
    firc_tunsup_set_on_reap(t->sup, on_reap, t);
    return t;
}

typedef struct {
    char id[FIRC_MARK_MAX_GROUPS][16];
    size_t n;
} tun_owners_t;

static void collect_tun_owners(void *ud, const firc_rtnl_field_t *v, size_t n)
{
    tun_owners_t *o = ud;
    size_t pl = sizeof(FIRC_MARK_TUNNEL_OWNER) - 1;
    for (size_t i = 0; i < n && o->n < FIRC_MARK_MAX_GROUPS; i++) {
        if (strncmp(v[i].owner, FIRC_MARK_TUNNEL_OWNER, pl) == 0 && strlen(v[i].owner + pl) < sizeof o->id[0]) {
            snprintf(o->id[o->n++], sizeof o->id[0], "%s", v[i].owner + pl);
        }
    }
}

static bool holds_field(const firc_tunrun_t *t, const char *id)
{
    for (size_t i = 0; i < t->cur.n; i++) {
        if (t->up[i].mark != 0 && strcmp(t->cur.t[i].id, id) == 0) {
            return true;
        }
    }
    return find_drain(t, id) >= 0;
}

static void free_unheld_fields(firc_tunrun_t *t)
{
    tun_owners_t *o = calloc(1, sizeof *o);
    if (o == NULL) {
        return;
    }
    firc_rtnl_fields_now(t->r, collect_tun_owners, o);
    for (size_t i = 0; i < o->n; i++) {
        if (!holds_field(t, o->id[i])) {
            forget(t, o->id[i]);
        }
    }
    free(o);
}

static ssize_t find(const firc_tunnels_t *all, const char *id)
{
    for (size_t i = 0; i < all->n; i++) {
        if (strcmp(all->t[i].id, id) == 0) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static void keep(firc_tunrun_t *t, const firc_tunnel_t *nt, const firc_tunnels_t *want, firc_tunnet_uplink_t *u)
{
    firc_err_t err = firc_tunnet_uplink_refresh(t->r, nt, want, u);
    if (err != FIRC_OK) {
        FIRC_WARN("tunnel %s: uplink route not rewritten: %s", nt->device, firc_err_str(err));
    }
}

static void free_sendable(firc_tun_src_t *v, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        free(v[i].link);
    }
    free(v);
}

static void free_one_sent(sent_t *x)
{
    free_sendable(x->src, x->n);
    free(x->row_of);
    firc_tun_nodes_free(&x->rows);
    memset(x, 0, sizeof *x);
}

static size_t fit_stdin(const firc_tunnel_t *tun, firc_tun_src_t *v, size_t k, firc_tun_nodes_t *nodes,
                        const size_t *row_of, size_t max)
{
    size_t total = 1;
    size_t keep = 0;
    while (keep < k && total + strlen(v[keep].link) + 1 <= max) {
        total += strlen(v[keep].link) + 1;
        keep++;
    }
    if (keep == k) {
        return k;
    }
    for (size_t p = keep; p < k; p++) {
        free(v[p].link);
        v[p].link = NULL;
        snprintf(nodes->v[row_of[p]].skip_reason, sizeof nodes->v[row_of[p]].skip_reason, "%s",
                 "over tunvless's 1 MiB node list");
    }
    FIRC_WARN("tunnel %s: node list over %zu bytes, %zu nodes kept, %zu left out", tun->device, max, keep, k - keep);
    return keep;
}

static firc_err_t sendable(const firc_tunnel_t *tun, uint32_t mark, const firc_tun_body_t *bodies, size_t n_bodies,
                           size_t max, sent_t *out)
{
    firc_tun_nodes_t nodes;
    firc_err_t err = firc_tun_nodes_build(tun, mark, bodies, n_bodies, &nodes);
    if (err != FIRC_OK) {
        return err;
    }
    firc_tun_src_t *v = calloc(nodes.n + 1, sizeof *v);
    size_t *row_of = calloc(nodes.n + 1, sizeof *row_of);
    if (v == NULL || row_of == NULL) {
        free(v);
        free(row_of);
        firc_tun_nodes_free(&nodes);
        return FIRC_ERR_NOMEM;
    }
    size_t k = 0;
    for (size_t i = 0; i < nodes.n; i++) {
        if (nodes.v[i].link != NULL) {
            v[k].kind = FIRC_TUN_SRC_LINK;
            v[k].link = nodes.v[i].link;
            nodes.v[i].link = NULL;
            row_of[k] = i;
            k++;
        }
    }
    k = fit_stdin(tun, v, k, &nodes, row_of, max);
    out->src = v;
    out->row_of = row_of;
    out->n = k;
    out->have = true;
    out->rows = nodes;
    return FIRC_OK;
}

static void want_subs(firc_tunrun_t *t)
{
    size_t n = t->cur.n;
    firc_tunnel_t *view = calloc(n + 1, sizeof *view);
    uint32_t *marks = calloc(n + 1, sizeof *marks);
    if (view == NULL || marks == NULL) {
        free(view);
        free(marks);
        FIRC_ERROR("tunnels: out of memory, the subscriptions to fetch are not updated");
        return;
    }
    for (size_t i = 0; i < n; i++) {
        view[i] = t->cur.t[i];
        view[i].enable = view[i].enable && t->ok[i];
        marks[i] = t->ok[i] ? t->up[i].mark : 0;
    }
    firc_tunnels_t sel = {.t = view, .n = n};
    firc_tunsubs_want(t->subs, &sel, marks);
    free(view);
    free(marks);
}

static void mark_syn(firc_tunrun_t *t)
{
    for (size_t i = 0; i < t->cur.n; i++) {
        const firc_tunnel_t *tun = &t->cur.t[i];
        firc_tun_status_t cls = !tun->enable ? FIRC_TUN_ST_OFF
                                : !t->ok[i]  ? FIRC_TUN_ST_UPLINK_DOWN
                                : t->waiting[i] ? FIRC_TUN_ST_WAITING
                                                : FIRC_TUN_ST_STARTING;
        if (cls != t->ext[i].syn || t->ext[i].syn_since == 0) {
            t->ext[i].syn = cls;
            t->ext[i].syn_since = mono_ms();
        }
    }
}

static firc_err_t push(firc_tunrun_t *t, bool want)
{
    size_t n = t->cur.n;
    firc_tunnel_t *run = calloc(n + 1, sizeof *run);
    uint32_t *marks = calloc(n + 1, sizeof *marks);
    if (run == NULL || marks == NULL) {
        free(run);
        free(marks);
        return FIRC_ERR_NOMEM;
    }
    if (want && t->subs != NULL) {
        want_subs(t);
    }
    size_t n_bodies = 0;
    const firc_tun_body_t *bodies = firc_tunsubs_bodies(t->subs, &n_bodies);
    size_t k = 0;
    for (size_t i = 0; i < n; i++) {
        if (!t->ok[i]) {
            continue;
        }
        const firc_tunnel_t *tun = &t->cur.t[i];
        uint32_t mark = t->up[i].mark;
        sent_t fresh = {0};
        firc_err_t err = sendable(tun, mark, bodies, n_bodies, t->list_max, &fresh);
        if (err != FIRC_OK) {
            FIRC_ERROR("tunnel %s: node list not built: %s", tun->device, firc_err_str(err));
        } else {
            free_one_sent(&t->sent[i]);
            t->sent[i] = fresh;
            prune(&t->ext[i].downs, &t->sent[i]);
            prune(&t->ext[i].acts, &t->sent[i]);
        }
        if (tun->enable && t->sent[i].n == 0) {
            if (!t->waiting[i]) {
                char line[FIRC_EVENT_TEXT];
                snprintf(line, sizeof line, "tunnel %s: no nodes to use yet", tun->device);
                say(FIRC_LOG_INFO, false, line);
                t->waiting[i] = true;
            }
            continue;
        }
        t->waiting[i] = false;
        run[k] = *tun;
        run[k].src = t->sent[i].src;
        run[k].n_src = t->sent[i].n;
        marks[k] = mark;
        k++;
    }
    firc_tunnels_t sel = {.t = run, .n = k};
    firc_err_t rc = firc_tunsup_apply(t->sup, &sel, marks);
    if (rc != FIRC_OK) {
        FIRC_ERROR("tunnels: not every tunnel could be started: %s", firc_err_str(rc));
    }
    free(run);
    free(marks);
    mark_syn(t);
    return rc;
}

static void free_sent(sent_t *v, size_t n)
{
    for (size_t i = 0; v != NULL && i < n; i++) {
        free_one_sent(&v[i]);
    }
    free(v);
}

static void free_ext(ext_t *v, size_t n)
{
    for (size_t i = 0; v != NULL && i < n; i++) {
        free(v[i].downs.v);
        free(v[i].acts.v);
    }
    free(v);
}

firc_err_t firc_tunrun_apply(firc_tunrun_t *t, firc_tunnels_t *want)
{
    if (t->stopped) {
        return FIRC_ERR_STATE;
    }
    size_t n = want->n;
    firc_tunnet_uplink_t *up = calloc(n + 1, sizeof *up);
    bool *ok = calloc(n + 1, sizeof *ok);
    bool *kept = calloc(t->cur.n + 1, sizeof *kept);
    sent_t *sent = calloc(n + 1, sizeof *sent);
    bool *waiting = calloc(n + 1, sizeof *waiting);
    ext_t *ext = calloc(n + 1, sizeof *ext);
    if (up == NULL || ok == NULL || kept == NULL || sent == NULL || waiting == NULL || ext == NULL) {
        free(up);
        free(ok);
        free(kept);
        free(sent);
        free(waiting);
        free(ext);
        return FIRC_ERR_NOMEM;
    }
    for (size_t i = 0; i < n; i++) {
        const firc_tunnel_t *nt = &want->t[i];
        ssize_t j = find(&t->cur, nt->id);
        bool need = needs_uplink(nt);
        if (j >= 0) {
            kept[j] = true;
            sent[i] = t->sent[j];
            memset(&t->sent[j], 0, sizeof t->sent[j]);
            waiting[i] = t->waiting[j];
            ext[i] = t->ext[j];
            memset(&t->ext[j], 0, sizeof t->ext[j]);
            if (t->up[j].mark != 0) {
                if (need) {
                    up[i] = t->up[j];
                    memset(&t->up[j], 0, sizeof t->up[j]);
                    keep(t, nt, want, &up[i]);
                } else {
                    drain(t, nt, &t->up[j]);
                }
                ok[i] = true;
                continue;
            }
        }
        if (!need) {
            ok[i] = true;
            continue;
        }
        ssize_t d = find_drain(t, nt->id);
        if (d >= 0) {
            up[i] = t->drains[d].u;
            drop_drain(t, (size_t)d);
            keep(t, nt, want, &up[i]);
            ok[i] = true;
            continue;
        }
        firc_err_t err = firc_tunnet_uplink_apply(t->r, t->start, nt, want, &up[i]);
        if (err != FIRC_OK) {
            if (up[i].mark != 0) {
                remove_uplink(t, nt->device, &up[i]);
            }
            memset(&up[i], 0, sizeof up[i]);
            forget(t, nt->id);
            char line[FIRC_EVENT_TEXT];
            snprintf(line, sizeof line, "tunnel %s: not started, its uplink could not be set up (%s)", nt->device,
                     firc_err_str(err));
            say(FIRC_LOG_ERROR, false, line);
            continue;
        }
        ok[i] = true;
    }
    for (size_t j = 0; j < t->cur.n; j++) {
        if (!kept[j] && t->up[j].mark != 0) {
            drain(t, &t->cur.t[j], &t->up[j]);
        } else if (!kept[j] && find_drain(t, t->cur.t[j].id) < 0) {
            forget(t, t->cur.t[j].id);
        }
    }
    free_sent(t->sent, t->cur.n);
    free_ext(t->ext, t->cur.n);
    firc_tunnels_free(&t->cur);
    free(t->up);
    free(t->ok);
    free(t->waiting);
    t->cur = *want;
    t->up = up;
    t->ok = ok;
    t->sent = sent;
    t->waiting = waiting;
    t->ext = ext;
    want->t = NULL;
    want->n = 0;
    free_unheld_fields(t);
    firc_err_t rc = push(t, true);
    firc_tunsubs_sweep(t->subs, &t->cur);
    for (size_t i = 0; i < t->cur.n; i++) {
        show_uplink(t, i);
    }
    free(kept);
    return rc;
}

void firc_tunrun_set_subs(firc_tunrun_t *t, firc_tunsubs_t *subs)
{
    t->subs = subs;
}

void firc_tunrun_bodies_changed(void *ud)
{
    firc_tunrun_t *t = ud;
    if (t == NULL || t->stopped) {
        return;
    }
    (void)push(t, false);
}

size_t firc_tunrun_states(const firc_tunrun_t *t, firc_tun_state_t *out, size_t cap)
{
    firc_tun_state_t run[FIRC_TUN_MAX * 2];
    size_t n_run = firc_tunsup_states(t->sup, run, sizeof run / sizeof run[0]);
    if (n_run > sizeof run / sizeof run[0]) {
        n_run = sizeof run / sizeof run[0];
    }
    for (size_t i = 0; i < t->cur.n && i < cap; i++) {
        const firc_tunnel_t *tun = &t->cur.t[i];
        firc_tun_state_t *st = &out[i];
        memset(st, 0, sizeof *st);
        snprintf(st->id, sizeof st->id, "%s", tun->id);
        snprintf(st->device, sizeof st->device, "%s", tun->device);
        st->status = t->ext[i].syn;
        st->since_ms = t->ext[i].syn_since;
        st->uplink_ok = !needs_uplink(tun) || (t->ok[i] && t->up[i].routed);
        if (t->ext[i].syn == FIRC_TUN_ST_UPLINK_DOWN || t->ext[i].syn == FIRC_TUN_ST_WAITING) {
            continue;
        }
        st->status = FIRC_TUN_ST_OFF;
        for (size_t k = 0; k < n_run; k++) {
            if (strcmp(run[k].id, tun->id) == 0) {
                *st = run[k];
                break;
            }
        }
    }
    return t->cur.n;
}

const firc_tunnels_t *firc_tunrun_config(const firc_tunrun_t *t)
{
    return &t->cur;
}

firc_err_t firc_tunrun_restart(firc_tunrun_t *t, const char *id)
{
    if (t->stopped || find(&t->cur, id) < 0) {
        return FIRC_ERR_NOENT;
    }
    firc_err_t err = firc_tunsup_restart(t->sup, id);
    return err == FIRC_ERR_NOENT ? FIRC_ERR_STATE : err;
}

uint64_t firc_tunrun_start_seq(const firc_tunrun_t *t)
{
    return firc_tunsup_start_seq(t->sup);
}

uint64_t firc_tunrun_started(const firc_tunrun_t *t, const char *id)
{
    return firc_tunsup_started(t->sup, id);
}

uint64_t firc_tunrun_updated(const firc_tunrun_t *t, const char *id)
{
    return firc_tunsup_updated(t->sup, id);
}

const firc_tun_nodes_t *firc_tunrun_nodes(const firc_tunrun_t *t, const char *id)
{
    ssize_t i = find(&t->cur, id);
    if (i < 0 || !t->sent[i].have) {
        return NULL;
    }
    return &t->sent[i].rows;
}

bool firc_tunrun_node_down(const firc_tunrun_t *t, const char *id, const char *key, int64_t *since_ms)
{
    ssize_t i = find(&t->cur, id);
    const down_t *d = i < 0 ? NULL : key_find(&t->ext[i].downs, key);
    if (d == NULL) {
        return false;
    }
    *since_ms = d->since;
    return true;
}

bool firc_tunrun_node_active(const firc_tunrun_t *t, const char *id, const char *key)
{
    ssize_t i = find(&t->cur, id);
    return i >= 0 && key_find(&t->ext[i].acts, key) != NULL;
}

bool firc_tunrun_mark_of(const firc_tunrun_t *t, const char *id, uint32_t *mark, bool *held)
{
    *mark = 0;
    *held = false;
    ssize_t i = find(&t->cur, id);
    if (i < 0) {
        return false;
    }
    *mark = t->up[i].mark;
    *held = *mark != 0 && firc_tunsup_holds(t->sup, id, *mark);
    return true;
}

void firc_tunrun_link_up(firc_tunrun_t *t, const char *ifname)
{
    if (t == NULL || t->stopped || ifname == NULL) {
        return;
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        const char *dev = firc_tunnet_uplink_device(&t->cur.t[i], &t->cur);
        if (t->up[i].mark != 0 && dev != NULL && strcmp(dev, ifname) == 0) {
            refresh(t, i);
        }
    }
}

void firc_tunrun_stop(firc_tunrun_t *t, int grace_ms)
{
    if (t == NULL || t->stopped) {
        return;
    }
    firc_tunsup_stop(t->sup, grace_ms);
    while (t->n_drains > 0) {
        release(t, t->n_drains - 1);
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        remove_uplink(t, t->cur.t[i].device, &t->up[i]);
    }
    t->stopped = true;
}

void firc_tunrun_free(firc_tunrun_t *t)
{
    if (t == NULL) {
        return;
    }
    firc_tunrun_stop(t, 0);
    firc_tunsup_free(t->sup);
    free_sent(t->sent, t->cur.n);
    free_ext(t->ext, t->cur.n);
    firc_tunnels_free(&t->cur);
    free(t->up);
    free(t->ok);
    free(t->waiting);
    free(t->drains);
    free(t);
}

void firc_tunrun_set_list_max_for_test(firc_tunrun_t *t, size_t bytes)
{
    t->list_max = bytes;
}
