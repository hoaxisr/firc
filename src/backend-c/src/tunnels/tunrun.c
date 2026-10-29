#include "firc/tunrun.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include "firc/events.h"
#include "firc/logrep.h"
#include "firc/mark.h"
#include "firc/tunnet.h"
#include "firc/tunnodes.h"
#include "firc/tunvless_name.h"
#include "firc/tunwatch.h"

#define TUNVLESS_STDIN_MAX ((size_t)1 << 20)
#define WATCH_MS 15000

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

typedef enum { IB_OK, IB_GONE, IB_NOT_LAN, IB_NO_ADDR } ib_verdict_t;

typedef struct {
    char state[16];
    char why[96];
    uint64_t rx, tx;
    ib_verdict_t verdict;
    bool lined;
} ib_t;

typedef struct {
    firc_tun_status_t syn;
    int64_t syn_since;
    keys_t downs;
    keys_t acts;
    keys_t v6s;
    firc_tunwatch_t watch;
    firc_logrep_t no_node;
    ib_t ib[FIRC_TUN_MAX_INBOUNDS];
    char *sent_in;
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
    bool stopping;
    bool pushing;
    char **link;
    bool *wan;
    size_t n_link;
    bool has_k;
    firc_tunrun_ktcp_t k;
    uint16_t ports[FIRC_KTCP_DEVICES];
    uint8_t drifts[FIRC_KTCP_DEVICES];
    uint64_t kb_rx[FIRC_KTCP_DEVICES], kb_tx[FIRC_KTCP_DEVICES];
    bool ktcp_unusable;
    int watch_timer;
    int64_t (*now)(void);
};

bool firc_tun_journal_line(const firc_tev_t *ev, char *buf, size_t cap, firc_log_level_t *level)
{
    switch (ev->kind) {
    case FIRC_TEV_ACTIVE: {
        if (ev->n_active == 0) {
            return false;
        }
        *level = FIRC_LOG_INFO;
        int off = snprintf(buf, cap, "active ");
        for (size_t i = 0; i < ev->n_active && off >= 0 && (size_t)off < cap; i++) {
            off += snprintf(buf + off, cap - (size_t)off, "%s%s", i > 0 ? ", " : "", ev->active[i]);
        }
        return true;
    }
    case FIRC_TEV_NODE_DOWN:
        *level = FIRC_LOG_WARN;
        if (ev->why[0] != 0) {
            snprintf(buf, cap, "%s does not answer (%s)", ev->node, ev->why);
        } else {
            snprintf(buf, cap, "%s does not answer", ev->node);
        }
        return true;
    case FIRC_TEV_NODE_UP:
        *level = FIRC_LOG_INFO;
        snprintf(buf, cap, "%s answers again", ev->node);
        return true;
    case FIRC_TEV_NO_NODE:
        *level = FIRC_LOG_WARN;
        if (ev->retry_s > 0) {
            snprintf(buf, cap, "no node answers, retry in %d s", ev->retry_s);
        } else {
            snprintf(buf, cap, "no node answers");
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
        firc_log_from(FIRC_LOG_WARN, t->cur.t[i].device, "uplink route not rewritten: %s", firc_err_str(err));
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
        x->v6s.n = 0;
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
        x->v6s.n = 0;
        for (size_t k = 0; k < ev->n_active && k < 8; k++) {
            each_key(sent, ev->active_pos[k], ev->active[k], &x->acts, key_add);
            if (ev->active_v6[k]) {
                each_key(sent, ev->active_pos[k], ev->active[k], &x->v6s, key_add);
            }
        }
        break;
    case FIRC_TEV_NO_NODE:
        x->acts.n = 0;
        x->v6s.n = 0;
        break;
    default:
        break;
    }
}

static int ktcp_dev(const firc_tunnel_t *tun)
{
    uint16_t port = firc_tunnel_tcp_port(tun);
    return port == 0 ? -1 : port - FIRC_TUNNEL_TCP_PORT_BASE;
}

static void publish(const firc_tunrun_t *t)
{
    if (t->has_k && t->k.ports != NULL) {
        t->k.ports(t->ports, t->k.ud);
    }
}

static void set_port(firc_tunrun_t *t, int dev, uint16_t port)
{
    if (t->ports[dev] != port) {
        t->ports[dev] = port;
        publish(t);
    }
}

static int send_cmds(firc_tunrun_t *t, const firc_tunnel_t *tun, firc_tun_cmd_t kind, const firc_ktcp_cmds_t *c)
{
    if (c->n_cmds == 0) {
        return 0;
    }
    firc_err_t err = firc_tunsup_command(t->sup, tun->id, kind, c->text, c->len, c->counts, c->n_cmds);
    if (err != FIRC_OK) {
        firc_log_from(FIRC_LOG_WARN, tun->device, "command not sent: %s", firc_err_str(err));
        return 0;
    }
    return (int)c->n_cmds;
}

static void send_mapall(firc_tunrun_t *t, const firc_tunnel_t *tun, int dev, const firc_ktcp_image_t *im)
{
    static const firc_ktcp_image_t none = {0};
    firc_ktcp_cmds_t c = {0};
    if (firc_ktcp_map_cmds(im != NULL ? im : &none, (uint8_t)dev, true, &c) == FIRC_OK) {
        send_cmds(t, tun, FIRC_TUN_CMD_MAP, &c);
    } else {
        firc_log_from(FIRC_LOG_WARN, tun->device, "out of memory, the address map is not sent");
    }
    firc_ktcp_cmds_free(&c);
}

static const firc_ktcp_image_t *image_now(const firc_tunrun_t *t)
{
    return t->has_k && t->k.image != NULL ? t->k.image(t->k.ud) : NULL;
}

static void ready_port(firc_tunrun_t *t, const firc_tunnel_t *tun, int dev, uint16_t got)
{
    uint16_t want = firc_tunnel_tcp_port(tun);
    t->drifts[dev] = 0;
    if (want != 0 && got == 0) {
        firc_log_from(FIRC_LOG_WARN, tun->device, "port %u is taken, TCP stays on the TUN", (unsigned)want);
    } else if (want != 0 && got != want) {
        firc_log_from(FIRC_LOG_WARN, tun->device, "tunvless reported port %u, not %u; TCP stays on the TUN",
                      (unsigned)got, (unsigned)want);
    }
    set_port(t, dev, got == want ? want : 0);
    if (t->ports[dev] != 0) {
        send_mapall(t, tun, dev, image_now(t));
    }
}

static void map_drift(firc_tunrun_t *t, const firc_tunnel_t *tun, int dev, const firc_tev_t *ev)
{
    if (t->drifts[dev] >= 2) {
        return;
    }
    if (++t->drifts[dev] == 1) {
        send_mapall(t, tun, dev, image_now(t));
        return;
    }
    firc_log_from(FIRC_LOG_WARN, tun->device, "tunvless took %d of %d map lines, its map is no longer resent",
                  ev->count, ev->expect);
}

static void answer_miss(firc_tunrun_t *t, const firc_tunnel_t *tun, int dev, const uint8_t fake[4])
{
    uint8_t real[4];
    bool known = t->has_k && t->k.real_of != NULL && t->k.real_of((uint8_t)dev, fake, real, t->k.ud);
    firc_ktcp_cmds_t c = {0};
    if (firc_ktcp_line(&c, fake, known ? real : NULL) == FIRC_OK) {
        send_cmds(t, tun, FIRC_TUN_CMD_MAP, &c);
    }
    firc_ktcp_cmds_free(&c);
}

static void add_bytes(firc_tunrun_t *t, const char *device, uint32_t rx, uint32_t tx)
{
    int n = firc_tunvless_index(device);
    if (n < 0 || n >= FIRC_KTCP_DEVICES) {
        return;
    }
    t->kb_rx[n] += rx;
    t->kb_tx[n] += tx;
}

static void ktcp_event(firc_tunrun_t *t, const firc_tun_state_t *st, const firc_tev_t *ev)
{
    if (ev == NULL) {
        return;
    }
    ssize_t i = find(&t->cur, st->id);
    if (ev->kind == FIRC_TEV_BYTES) {
        if (i >= 0) {
            add_bytes(t, t->cur.t[i].device, ev->rx, ev->tx);
        }
        return;
    }
    int dev = i < 0 ? -1 : ktcp_dev(&t->cur.t[i]);
    if (dev < 0 || !firc_tunsup_ready(t->sup, st->id)) {
        return;
    }
    const firc_tunnel_t *tun = &t->cur.t[i];
    switch (ev->kind) {
    case FIRC_TEV_READY:
        if (t->k.ready != NULL) {
            t->k.ready((uint8_t)dev, t->k.ud);
        }
        ready_port(t, tun, dev, ev->tcp_port);
        break;
    case FIRC_TEV_MAP:
        if (ev->drift && t->ports[dev] != 0) {
            map_drift(t, tun, dev, ev);
        }
        break;
    case FIRC_TEV_MISS:
        if (t->ports[dev] != 0) {
            answer_miss(t, tun, dev, ev->fake);
        }
        break;
    case FIRC_TEV_CLOSE:
        firc_log_from(FIRC_LOG_DEBUG, tun->device, "tunvless closed %d connections", ev->count);
        if (t->k.closed != NULL) {
            t->k.closed((uint8_t)dev, t->k.ud);
        }
        break;
    default:
        break;
    }
}

static void watch(firc_tunrun_t *t)
{
    if (t->stopped || t->ext == NULL) {
        return;
    }
    firc_tun_state_t st[FIRC_TUN_MAX];
    size_t n = firc_tunrun_states(t, st, FIRC_TUN_MAX);
    for (size_t i = 0; i < n && i < FIRC_TUN_MAX; i++) {
        firc_tunwatch_see(&t->ext[i].watch, st[i].device, st[i].status, t->now());
    }
}

static void on_watch(firc_loop_t *loop, void *ud)
{
    (void)loop;
    watch(ud);
}

static void set_ib(ib_t *s, const char *state, const char *why)
{
    snprintf(s->state, sizeof s->state, "%.15s", state);
    snprintf(s->why, sizeof s->why, "%.95s", why);
}

static void judge(const firc_tunnel_t *tun, const firc_tun_inbound_t *b, ib_t *s, ib_verdict_t v)
{
    if (v == s->verdict) {
        return;
    }
    unsigned port = b->port;
    switch (v) {
    case IB_GONE:
        firc_log_from(FIRC_LOG_WARN, tun->device, "inbound :%u: node %s is gone", port, b->node);
        break;
    case IB_NOT_LAN:
        firc_log_from(FIRC_LOG_WARN, tun->device, "inbound :%u: %s is not a LAN interface of app.link", port, b->listen);
        break;
    case IB_NO_ADDR:
        firc_log_from(FIRC_LOG_WARN, tun->device, "inbound :%u: %s has no IPv4 address", port, b->listen);
        break;
    case IB_OK:
        if (s->verdict == IB_GONE) {
            firc_log_from(FIRC_LOG_INFO, tun->device, "inbound :%u: node %s is back", port, b->node);
        }
        break;
    }
    s->verdict = v;
}

static bool lan_ok(const firc_tunrun_t *t, const char *name)
{
    for (size_t i = 0; i < t->n_link; i++) {
        if (strcmp(t->link[i], name) == 0) {
            return !t->wan[i];
        }
    }
    return false;
}

bool firc_tunrun_lan_ok(const firc_tunrun_t *t, const char *name)
{
    return lan_ok(t, name);
}

static void put_field(FILE *fp, const char *s)
{
    if (s[0] == 0) {
        fputc('-', fp);
        return;
    }
    if (strcmp(s, "-") == 0) {
        fputs("%2D", fp);
        return;
    }
    for (const unsigned char *p = (const unsigned char *)s; *p != 0; p++) {
        if (*p <= 0x20 || *p == '%' || *p == 0x7f) {
            fprintf(fp, "%%%02X", *p);
        } else {
            fputc(*p, fp);
        }
    }
}

static bool put_line(firc_tunrun_t *t, size_t i, size_t k, const char *link, FILE *fp)
{
    const firc_tunnel_t *tun = &t->cur.t[i];
    const firc_tun_inbound_t *b = &tun->inb[k];
    ib_t *s = &t->ext[i].ib[k];
    char addr[INET_ADDRSTRLEN];
    if (!lan_ok(t, b->listen)) {
        judge(tun, b, s, IB_NOT_LAN);
        set_ib(s, "not-lan", "");
        return false;
    }
    if (firc_iface_ipv4(b->listen, addr, sizeof addr) != 0) {
        judge(tun, b, s, IB_NO_ADDR);
        set_ib(s, "no-address", "");
        return false;
    }
    if (strcmp(b->node, FIRC_TUN_NODE_POOL) == 0) {
        link = FIRC_TUN_NODE_POOL;
    }
    judge(tun, b, s, link != NULL ? IB_OK : IB_GONE);
    fprintf(fp, "%s:%u ", addr, (unsigned)b->port);
    put_field(fp, b->user);
    fputc(' ', fp);
    put_field(fp, b->password);
    fprintf(fp, " %s\n", link != NULL ? link : "-");
    if (link == NULL) {
        set_ib(s, "no-node", "");
        return false;
    }
    return true;
}

static void refresh_inbounds(firc_tunrun_t *t, size_t i)
{
    const firc_tunnel_t *tun = &t->cur.t[i];
    ext_t *x = &t->ext[i];
    if (t->stopping) {
        return;
    }
    if (!tun->enable) {
        for (size_t k = 0; k < tun->n_inb; k++) {
            set_ib(&x->ib[k], "off", "");
        }
        return;
    }
    if (tun->n_inb == 0 && x->sent_in == NULL) {
        return;
    }
    const char *keys[FIRC_TUN_MAX_INBOUNDS];
    char *links[FIRC_TUN_MAX_INBOUNDS] = {NULL};
    for (size_t k = 0; k < tun->n_inb; k++) {
        keys[k] = tun->inb[k].node;
    }
    size_t n_bodies = 0;
    const firc_tun_body_t *bodies = firc_tunsubs_bodies(t->subs, &n_bodies);
    if (tun->n_inb > 0 &&
        firc_tun_nodes_links_of(tun, t->up[i].mark, bodies, n_bodies, keys, tun->n_inb, links) != FIRC_OK) {
        return;
    }
    char *text = NULL;
    size_t len = 0;
    FILE *fp = open_memstream(&text, &len);
    bool live[FIRC_TUN_MAX_INBOUNDS] = {false};
    for (size_t k = 0; fp != NULL && k < tun->n_inb; k++) {
        live[k] = put_line(t, i, k, links[k], fp);
    }
    for (size_t k = 0; k < tun->n_inb; k++) {
        free(links[k]);
    }
    if (fp == NULL || fclose(fp) != 0 || text == NULL) {
        free(text);
        firc_log_from(FIRC_LOG_WARN, tun->device, "out of memory, inbounds not sent");
        return;
    }
    bool ready = firc_tunsup_ready(t->sup, tun->id);
    bool changed = x->sent_in == NULL ? len > 0 : strcmp(x->sent_in, text) != 0;
    bool due = changed;
    for (size_t k = 0; k < tun->n_inb && !due; k++) {
        due = x->ib[k].lined && strcmp(x->ib[k].state, "busy") == 0;
    }
    bool sent = false;
    if (ready && due) {
        firc_err_t err = firc_tunsup_command(t->sup, tun->id, FIRC_TUN_CMD_INBOUNDS, text, len, NULL, 0);
        if (err == FIRC_OK) {
            free(x->sent_in);
            x->sent_in = text;
            text = NULL;
            sent = true;
            for (size_t k = 0; k < tun->n_inb; k++) {
                x->ib[k].lined = live[k];
            }
        } else {
            firc_log_from(FIRC_LOG_WARN, tun->device, "inbounds not sent: %s", firc_err_str(err));
        }
    }
    free(text);
    for (size_t k = 0; k < tun->n_inb; k++) {
        if (live[k] && (sent || !ready) && (changed || strcmp(x->ib[k].state, "busy") != 0)) {
            set_ib(&x->ib[k], "starting", "");
        }
    }
}

static ssize_t ib_at(const firc_tunnel_t *tun, const ext_t *x, uint16_t port)
{
    for (size_t k = 0; k < tun->n_inb; k++) {
        if (x->ib[k].lined && tun->inb[k].port == port) {
            return (ssize_t)k;
        }
    }
    return -1;
}

static void inbound_event(firc_tunrun_t *t, const firc_tun_state_t *st, const firc_tev_t *ev)
{
    ssize_t i = find(&t->cur, st->id);
    if (i < 0 || t->ext == NULL) {
        return;
    }
    ext_t *x = &t->ext[i];
    const firc_tunnel_t *tun = &t->cur.t[i];
    if (ev == NULL) {
        if (!t->pushing) {
            refresh_inbounds(t, (size_t)i);
        }
        return;
    }
    if (ev->kind != FIRC_TEV_INBOUND && ev->kind != FIRC_TEV_IBYTES) {
        return;
    }
    ssize_t k = ib_at(tun, x, ev->ib_port);
    if (k < 0) {
        return;
    }
    ib_t *s = &x->ib[k];
    if (ev->kind == FIRC_TEV_IBYTES) {
        s->rx += ev->rx;
        s->tx += ev->tx;
        return;
    }
    if (strcmp(ev->istate, "busy") == 0 && strcmp(s->state, "busy") != 0) {
        firc_log_from(FIRC_LOG_ERROR, tun->device, "inbound :%u on %s: port is busy", (unsigned)ev->ib_port,
                      tun->inb[k].listen);
    }
    set_ib(s, ev->istate, ev->why);
}

static void on_event(const firc_tun_state_t *st, const firc_tev_t *ev, void *ud)
{
    firc_tunrun_t *t = ud;
    track_nodes(t, st, ev);
    ktcp_event(t, st, ev);
    ssize_t at = find(&t->cur, st->id);
    firc_logrep_t *no_node = at >= 0 && t->ext != NULL ? &t->ext[at].no_node : NULL;
    char line[FIRC_EVENT_TEXT];
    firc_log_level_t level = FIRC_LOG_INFO;
    if (ev != NULL && firc_tun_journal_line(ev, line, sizeof line, &level)) {
        if (ev->kind == FIRC_TEV_NO_NODE && no_node != NULL) {
            firc_logrep_fail(no_node, level, st->device, "%s", line);
        } else {
            firc_log_from(level, st->device, "%s", line);
        }
    }
    if (ev != NULL && ev->kind == FIRC_TEV_ACTIVE && ev->n_active > 0 && no_node != NULL) {
        (void)firc_logrep_ok(no_node, st->device, "nodes");
    }
    watch(t);
    inbound_event(t, st, ev);
    if (ev == NULL || ev->kind != FIRC_TEV_READY) {
        return;
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        if (t->cur.t[i].uplink == FIRC_UPLINK_TUNNEL && strcmp(t->cur.t[i].uplink_ref, st->id) == 0) {
            refresh(t, i);
        }
    }
    if (at >= 0 && t->ext != NULL) {
        free(t->ext[at].sent_in);
        t->ext[at].sent_in = NULL;
        refresh_inbounds(t, (size_t)at);
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
        firc_log_from(FIRC_LOG_WARN, device, "uplink not fully removed: %s", firc_err_str(err));
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
        firc_log_from(FIRC_LOG_WARN, tun->device, "out of memory, its uplink rule stays until the next start");
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

void firc_tunrun_refresh_inbounds(firc_tunrun_t *t)
{
    if (t == NULL || t->stopped) {
        return;
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        refresh_inbounds(t, i);
    }
}

static bool copy_lan(firc_tunrun_t *t, const firc_tunrun_lan_t *lan)
{
    if (lan == NULL) {
        return true;
    }
    t->link = calloc(lan->n_link + 1, sizeof *t->link);
    t->wan = calloc(lan->n_link + 1, sizeof *t->wan);
    if (t->link == NULL || t->wan == NULL) {
        return false;
    }
    for (size_t i = 0; i < lan->n_link; i++) {
        t->link[i] = strdup(lan->link[i]);
        if (t->link[i] == NULL) {
            return false;
        }
        t->wan[i] = lan->wan != NULL && lan->wan[i];
        t->n_link++;
    }
    return true;
}

static void free_lan(firc_tunrun_t *t)
{
    for (size_t i = 0; i < t->n_link; i++) {
        free(t->link[i]);
    }
    free(t->link);
    free(t->wan);
}

firc_tunrun_t *firc_tunrun_new(firc_loop_t *loop, firc_rtnl_t *r, uint32_t start_table, const char *binary,
                               const firc_tunrun_lan_t *lan)
{
    firc_tunrun_t *t = calloc(1, sizeof *t);
    if (t == NULL) {
        return NULL;
    }
    if (!copy_lan(t, lan)) {
        free_lan(t);
        free(t);
        return NULL;
    }
    t->loop = loop;
    t->r = r;
    t->list_max = TUNVLESS_STDIN_MAX;
    t->start = start_table;
    t->now = mono_ms;
    t->sup = firc_tunsup_new(loop, binary, on_event, t);
    if (t->sup == NULL) {
        free_lan(t);
        free(t);
        return NULL;
    }
    firc_tunsup_set_on_reap(t->sup, on_reap, t);
    if (firc_loop_add_timer(loop, WATCH_MS, WATCH_MS, on_watch, t, &t->watch_timer) != FIRC_OK) {
        t->watch_timer = 0;
        FIRC_WARN("tunnels: a tunnel with no working node will not be reported");
    }
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
        firc_log_from(FIRC_LOG_WARN, nt->device, "uplink route not rewritten: %s", firc_err_str(err));
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
    firc_log_from(FIRC_LOG_WARN, tun->device, "node list over %zu bytes, %zu nodes kept, %zu left out", max, keep, k - keep);
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
        FIRC_WARN("tunnels: out of memory, the subscriptions to fetch are not updated");
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
            firc_log_from(FIRC_LOG_ERROR, tun->device, "node list not built: %s", firc_err_str(err));
        } else {
            free_one_sent(&t->sent[i]);
            t->sent[i] = fresh;
            prune(&t->ext[i].downs, &t->sent[i]);
            prune(&t->ext[i].acts, &t->sent[i]);
            prune(&t->ext[i].v6s, &t->sent[i]);
        }
        if (tun->enable && t->sent[i].n == 0) {
            if (!t->waiting[i]) {
                firc_log_from(FIRC_LOG_INFO, tun->device, "no nodes to use yet");
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
    t->pushing = true;
    firc_err_t rc = firc_tunsup_apply(t->sup, &sel, marks);
    t->pushing = false;
    if (rc != FIRC_OK) {
        FIRC_ERROR("tunnels: not every tunnel could be started: %s", firc_err_str(rc));
    }
    free(run);
    free(marks);
    mark_syn(t);
    for (size_t i = 0; i < n; i++) {
        refresh_inbounds(t, i);
    }
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
        free(v[i].v6s.v);
        free(v[i].sent_in);
    }
    free(v);
}

static void drop_ports(firc_tunrun_t *t)
{
    bool changed = false;
    for (int dev = 0; dev < FIRC_KTCP_DEVICES; dev++) {
        bool kept = false;
        for (size_t i = 0; i < t->cur.n && t->ports[dev] != 0 && !kept; i++) {
            kept = firc_tunnel_tcp_port(&t->cur.t[i]) == t->ports[dev];
        }
        if (t->ports[dev] != 0 && !kept) {
            t->ports[dev] = 0;
            t->drifts[dev] = 0;
            changed = true;
        }
    }
    if (changed) {
        publish(t);
    }
}

static void remap_ib(ext_t *x, const firc_tunnel_t *was, const firc_tunnel_t *now)
{
    ib_t old[FIRC_TUN_MAX_INBOUNDS];
    memcpy(old, x->ib, sizeof old);
    memset(x->ib, 0, sizeof x->ib);
    for (size_t k = 0; k < now->n_inb; k++) {
        for (size_t j = 0; j < was->n_inb; j++) {
            const firc_tun_inbound_t *a = &was->inb[j];
            const firc_tun_inbound_t *b = &now->inb[k];
            if (a->port == b->port && strcmp(a->listen, b->listen) == 0) {
                x->ib[k] = old[j];
                if (strcmp(a->node, b->node) != 0) {
                    x->ib[k].verdict = IB_OK;
                }
                break;
            }
        }
    }
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
            remap_ib(&ext[i], &t->cur.t[j], nt);
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
            firc_log_from(FIRC_LOG_ERROR, nt->device, "not started, its uplink could not be set up (%s)",
                          firc_err_str(err));
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
    drop_ports(t);
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
        int dev = ktcp_dev(tun);
        uint16_t port = dev < 0 || t->ktcp_unusable ? 0 : t->ports[dev];
        st->tcp_port = port;
        if (t->ext[i].syn != FIRC_TUN_ST_UPLINK_DOWN && t->ext[i].syn != FIRC_TUN_ST_WAITING) {
            st->status = FIRC_TUN_ST_OFF;
            for (size_t k = 0; k < n_run; k++) {
                if (strcmp(run[k].id, tun->id) == 0) {
                    *st = run[k];
                    st->tcp_port = port;
                    break;
                }
            }
        }
        st->n_ib = tun->n_inb;
        for (size_t k = 0; k < tun->n_inb; k++) {
            const ib_t *s = &t->ext[i].ib[k];
            st->ib[k].port = tun->inb[k].port;
            memcpy(st->ib[k].state, s->state, sizeof st->ib[k].state);
            memcpy(st->ib[k].why, s->why, sizeof st->ib[k].why);
            st->ib[k].rx = s->rx;
            st->ib[k].tx = s->tx;
        }
    }
    return t->cur.n;
}

bool firc_tunrun_device_down(const firc_tunrun_t *t, const char *device)
{
    if (device == NULL) {
        return false;
    }
    firc_tun_state_t st[FIRC_TUN_MAX];
    size_t n = firc_tunrun_states(t, st, FIRC_TUN_MAX);
    for (size_t i = 0; i < n && i < FIRC_TUN_MAX; i++) {
        if (strcmp(st[i].device, device) == 0) {
            return st[i].status != FIRC_TUN_ST_UP;
        }
    }
    return false;
}

bool firc_tunrun_device_starting(const firc_tunrun_t *t, const char *device, int64_t *since_ms)
{
    if (device == NULL) {
        return false;
    }
    firc_tun_state_t st[FIRC_TUN_MAX];
    size_t n = firc_tunrun_states(t, st, FIRC_TUN_MAX);
    for (size_t i = 0; i < n && i < FIRC_TUN_MAX; i++) {
        if (strcmp(st[i].device, device) != 0) {
            continue;
        }
        if (st[i].status != FIRC_TUN_ST_STARTING && st[i].status != FIRC_TUN_ST_WAITING) {
            return false;
        }
        *since_ms = st[i].since_ms;
        return true;
    }
    return false;
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

void firc_tunrun_node_answered(firc_tunrun_t *t, const char *id, const char *key)
{
    ssize_t i = find(&t->cur, id);
    if (i >= 0) {
        key_del(&t->ext[i].downs, key);
    }
}

bool firc_tunrun_node_active(const firc_tunrun_t *t, const char *id, const char *key)
{
    ssize_t i = find(&t->cur, id);
    return i >= 0 && key_find(&t->ext[i].acts, key) != NULL;
}

bool firc_tunrun_node_v6(const firc_tunrun_t *t, const char *id, const char *key)
{
    ssize_t i = find(&t->cur, id);
    return i >= 0 && key_find(&t->ext[i].v6s, key) != NULL;
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

void firc_tunrun_refresh_uplinks(firc_tunrun_t *t, const char *ifname)
{
    if (t == NULL || t->stopped) {
        return;
    }
    for (size_t i = 0; i < t->cur.n; i++) {
        const char *dev = firc_tunnet_uplink_device(&t->cur.t[i], &t->cur);
        if (t->up[i].mark != 0 && dev != NULL && (ifname == NULL || strcmp(dev, ifname) == 0)) {
            refresh(t, i);
        }
    }
}

void firc_tunrun_stop(firc_tunrun_t *t, int grace_ms)
{
    if (t == NULL || t->stopped) {
        return;
    }
    t->stopping = true;
    if (t->watch_timer != 0) {
        (void)firc_loop_del_timer(t->loop, t->watch_timer);
        t->watch_timer = 0;
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
    free_lan(t);
    free(t);
}

void firc_tunrun_set_list_max_for_test(firc_tunrun_t *t, size_t bytes)
{
    t->list_max = bytes;
}

void firc_tunrun_set_ktcp(firc_tunrun_t *t, const firc_tunrun_ktcp_t *k)
{
    t->has_k = k != NULL;
    if (k != NULL) {
        t->k = *k;
        publish(t);
    }
}

typedef struct {
    firc_ktcp_cmds_t per[FIRC_KTCP_DEVICES];
    const firc_tunnel_t *to[FIRC_KTCP_DEVICES];
    bool failed[FIRC_KTCP_DEVICES];
} push_t;

static void delta_line(uint8_t dev, const uint8_t fake[4], const uint8_t *real, void *ud)
{
    push_t *p = ud;
    if (dev < FIRC_KTCP_DEVICES && p->to[dev] != NULL && !p->failed[dev] &&
        firc_ktcp_line(&p->per[dev], fake, real) != FIRC_OK) {
        p->failed[dev] = true;
    }
}

static const firc_tunnel_t *live_with_port(const firc_tunrun_t *t, int dev)
{
    for (size_t i = 0; i < t->cur.n && t->ports[dev] != 0; i++) {
        if (ktcp_dev(&t->cur.t[i]) == dev && firc_tunsup_ready(t->sup, t->cur.t[i].id)) {
            return &t->cur.t[i];
        }
    }
    return NULL;
}

void firc_tunrun_map_pushed(firc_tunrun_t *t, const firc_ktcp_image_t *prev, const firc_ktcp_image_t *next)
{
    if (t->stopped) {
        return;
    }
    push_t *p = calloc(1, sizeof *p);
    if (p == NULL) {
        FIRC_WARN("tunnels: out of memory, address map changes not sent");
        return;
    }
    bool any = false;
    for (int dev = 0; dev < FIRC_KTCP_DEVICES; dev++) {
        p->to[dev] = live_with_port(t, dev);
        any = any || p->to[dev] != NULL;
    }
    if (any) {
        firc_ktcp_image_diff(prev, next, delta_line, p);
    }
    for (int dev = 0; dev < FIRC_KTCP_DEVICES; dev++) {
        if (p->failed[dev]) {
            send_mapall(t, p->to[dev], dev, next);
        } else if (p->to[dev] != NULL) {
            send_cmds(t, p->to[dev], FIRC_TUN_CMD_MAP, &p->per[dev]);
        }
        firc_ktcp_cmds_free(&p->per[dev]);
    }
    free(p);
}

void firc_tunrun_set_ktcp_usable(firc_tunrun_t *t, bool usable)
{
    t->ktcp_unusable = !usable;
}

void firc_tunrun_set_tcp_pool(firc_tunrun_t *t, const uint8_t base[4], uint8_t len)
{
    firc_tunsup_set_tcp_pool(t->sup, base, len);
}

int firc_tunrun_close(firc_tunrun_t *t, uint8_t dev, const firc_nf_prefix_t *p, size_t n)
{
    const firc_tunnel_t *tun = t->stopped || dev >= FIRC_KTCP_DEVICES ? NULL : live_with_port(t, dev);
    if (tun == NULL) {
        return 0;
    }
    firc_ktcp_cmds_t c = {0};
    int sent = 0;
    if (firc_ktcp_close_cmd(p, n, &c) == FIRC_OK) {
        sent = send_cmds(t, tun, FIRC_TUN_CMD_CLOSE, &c);
    } else {
        firc_log_from(FIRC_LOG_WARN, tun->device, "out of memory, close not sent");
    }
    firc_ktcp_cmds_free(&c);
    return sent;
}

int firc_tunrun_set_watch_for_test(firc_tunrun_t *t, int64_t (*now_ms)(void), int period_ms)
{
    t->now = now_ms != NULL ? now_ms : mono_ms;
    if (t->watch_timer != 0) {
        (void)firc_loop_del_timer(t->loop, t->watch_timer);
    }
    if (firc_loop_add_timer(t->loop, (uint64_t)period_ms, (uint64_t)period_ms, on_watch, t, &t->watch_timer) != FIRC_OK) {
        t->watch_timer = 0;
    }
    return t->watch_timer;
}

bool firc_tunrun_ktcp_bytes(const firc_tunrun_t *t, const char *device, uint64_t *rx, uint64_t *tx)
{
    *rx = 0;
    *tx = 0;
    int n = t != NULL ? firc_tunvless_index(device) : -1;
    if (n < 0 || n >= FIRC_KTCP_DEVICES) {
        return false;
    }
    *rx = t->kb_rx[n];
    *tx = t->kb_tx[n];
    return true;
}

void firc_tunrun_ktcp_bytes_add_for_test(firc_tunrun_t *t, const char *device, uint32_t rx, uint32_t tx)
{
    add_bytes(t, device, rx, tx);
}
