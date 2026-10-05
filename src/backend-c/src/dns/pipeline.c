#include "firc/dnspipeline.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "firc/dnsrewrite.h"
#include "firc/events.h"
#include "firc/log.h"

#define FIRC_DNS_OUTAGE_RUN 8

struct firc_dns_pipeline {
    firc_fakeip_t *pool; /* borrowed, nullable */
    uint32_t clamp_secs;
    uint32_t unmatched_ttl_secs;
    bool v6_unroutable;
    firc_devsel_policy_fn policy_fn;
    firc_devsel_device_fn device_fn;
    void *policy_ud;
    firc_ruleset_snapshot_t *snapshot; /* owned */
    uint32_t failing_rcode;
    uint64_t failing_count;
    uint64_t healthy_count;
    bool outage_said;
    bool someone_covers_all;
    firc_recall_t *recall;
};

firc_dns_pipeline_t *firc_dns_pipeline_create(void)
{
    firc_dns_pipeline_t *p = calloc(1, sizeof(firc_dns_pipeline_t));
    if (p == NULL) { return NULL; }
    p->recall = firc_recall_new(FIRC_RECALL_ADDRS, FIRC_RECALL_PAIRS, FIRC_RECALL_HORIZON);
    return p;
}

void firc_dns_pipeline_destroy(firc_dns_pipeline_t *p)
{
    if (p == NULL) {
        return;
    }
    firc_ruleset_snapshot_free(p->snapshot);
    firc_recall_free(p->recall);
    free(p);
}

void firc_dns_pipeline_set_snapshot(firc_dns_pipeline_t *p,
                                  firc_ruleset_snapshot_t *snap)
{
    firc_ruleset_snapshot_t *old = p->snapshot;
    p->snapshot = snap;
    firc_ruleset_snapshot_free(old);
    p->someone_covers_all = false;
    for (size_t i = 0; snap != NULL && i < snap->n_groups; i++) {
        if (firc_devsel_is_empty(snap->groups[i]->devices)) { p->someone_covers_all = true; }
    }
}

firc_ruleset_snapshot_t *firc_dns_pipeline_snapshot(firc_dns_pipeline_t *p)
{
    return p != NULL ? p->snapshot : NULL;
}

void firc_dns_pipeline_set_pool(firc_dns_pipeline_t *p, firc_fakeip_t *pool, uint32_t clamp_secs)
{
    p->pool = pool;
    p->clamp_secs = clamp_secs;
}

void firc_dns_pipeline_set_v6_routable(firc_dns_pipeline_t *p, bool routable)
{
    p->v6_unroutable = !routable;
}

void firc_dns_pipeline_set_unmatched_ttl(firc_dns_pipeline_t *p, uint32_t secs)
{
    p->unmatched_ttl_secs = secs;
}

void firc_dns_pipeline_set_policy_resolver(firc_dns_pipeline_t *p, firc_devsel_policy_fn fn,
                                           firc_devsel_device_fn device, void *ud)
{
    p->policy_fn = fn;
    p->device_fn = device;
    p->policy_ud = ud;
}

static void fold_ascii(char *s)
{
    for (; *s != '\0'; s++) {
        if (*s >= 'A' && *s <= 'Z') { *s = (char)(*s - 'A' + 'a'); }
    }
}

static void trim_fqdn(char *name)
{
    size_t len = strlen(name);
    if (len > 0 && name[len - 1] == '.') {
        name[len - 1] = '\0';
    }
}

/* Only the queried name and its CNAME chain: other answer records are not trusted. */
#define CHAIN_MAX 12

typedef struct {
    char names[CHAIN_MAX][1100];
    size_t n;
} chain_t;

static bool chain_has(const chain_t *c, const char *name)
{
    for (size_t i = 0; i < c->n; i++) {
        if (strcmp(c->names[i], name) == 0) { return true; }
    }
    return false;
}

static void chain_add(chain_t *c, const char *name)
{
    if (c->n >= CHAIN_MAX || chain_has(c, name)) { return; }
    snprintf(c->names[c->n], sizeof(c->names[0]), "%s", name);
    c->n++;
}

static void chain_build(chain_t *c, const firc_dns_msg_t *msg, const char *qname)
{
    c->n = 0;
    if (qname == NULL || qname[0] == '\0') { return; }
    chain_add(c, qname);

    /* Repeated passes: the answer section need not be in chain order. */
    for (size_t pass = 0; pass < CHAIN_MAX; pass++) {
        size_t before = c->n;
        for (size_t i = 0; i < msg->n_answers; i++) {
            const firc_dns_rr_t *rr = &msg->answers[i];
            if (rr->rtype != FIRC_DNS_TYPE_CNAME) { continue; }
            char owner[1100], target[1100];
            if (firc_dns_name_to_string(rr->name, rr->name_len, owner, sizeof(owner), NULL) != FIRC_OK) {
                continue;
            }
            trim_fqdn(owner);
            fold_ascii(owner);
            if (!chain_has(c, owner)) { continue; }
            if (firc_dns_name_to_string(rr->rdata, rr->rdata_len, target, sizeof(target), NULL) !=
                FIRC_OK) {
                continue;
            }
            trim_fqdn(target);
            fold_ascii(target);
            chain_add(c, target);
        }
        if (c->n == before) { break; }
    }
}

static bool covered(const firc_dns_pipeline_t *p, const firc_ip_t *client)
{
    if (client == NULL || p->snapshot == NULL || p->snapshot->n_groups == 0) { return false; }
    if (p->someone_covers_all) { return true; }
    for (size_t i = 0; i < p->snapshot->n_groups; i++) {
        if (firc_devsel_allows(p->snapshot->groups[i]->devices, client, p->policy_fn, p->device_fn,
                               p->policy_ud)) {
            return true;
        }
    }
    return false;
}

static void journal_begin(firc_event_t *ev, int64_t now, const firc_ip_t *client, const char *qname,
                          const firc_dns_msg_t *msg, uint32_t rcode, firc_dns_resolver_t resolver)
{
    memset(ev, 0, sizeof(*ev));
    ev->kind = FIRC_EVENT_DNS;
    ev->at = now;
    ev->u.dns.client = *client;
    snprintf(ev->u.dns.name, sizeof(ev->u.dns.name), "%s", qname);
    ev->u.dns.qtype = msg->n_questions > 0 ? msg->questions[0].qtype : 0;
    ev->u.dns.rcode = (uint8_t)rcode;
    ev->u.dns.resolver = (uint8_t)resolver;
}

static void journal_group(firc_event_t *ev, const firc_group_snapshot_t *g)
{
    if (ev == NULL || g == NULL) { return; }
    firc_id_format(g->id, ev->u.dns.group_id);
    snprintf(ev->u.dns.group_name, sizeof(ev->u.dns.group_name), "%s", g->name ? g->name : "");
}

/* The recall gets only rcode-0 A/AAAA answers for owned names; others evict useful pairs. */
static void journal_put(firc_dns_pipeline_t *p, firc_event_t *ev, firc_dns_decision_t decision)
{
    if (ev == NULL) { return; }
    ev->u.dns.decision = (uint8_t)decision;
    firc_event_put(ev);
    const uint16_t qt = ev->u.dns.qtype;
    if (ev->u.dns.rcode != 0 || ev->u.dns.group_id[0] == '\0' ||
        (qt != FIRC_DNS_TYPE_A && qt != FIRC_DNS_TYPE_AAAA)) {
        return;
    }
    firc_recall_answer(p->recall, &ev->u.dns.client, ev->u.dns.name,
                       qt == FIRC_DNS_TYPE_A ? FIRC_RECALL_V4 : FIRC_RECALL_V6, (uint8_t)decision,
                       ev->u.dns.fake.len ? &ev->u.dns.fake : NULL, ev->at);
}

static firc_dns_verdict_t rewrite(firc_dns_pipeline_t *p, firc_dns_msg_t *msg, int64_t now,
                                  const firc_group_snapshot_t *owner, const char *qname,
                                  const chain_t *chain, bool *pool_changed, firc_event_t *ev)
{
    char group_id[FIRC_ID_STR_LEN];
    firc_id_format(owner->id, group_id);

    uint64_t gen_before = firc_fakeip_gen(p->pool);
    firc_ip_t fake4 = {{0}, 0}, fake6 = {{0}, 0};
    firc_err_t issue = firc_fakeip_get(p->pool, qname, group_id, now, &fake4, &fake6);
    if (issue == FIRC_ERR_INVAL) {
        FIRC_ERROR("pool refused to issue for %s: caller bug", qname);
        return FIRC_DNS_DROP; /* never the real answer in place of a rewrite */
    }
    /* LIMIT/NOMEM answer with the blackhole, never the real address. */

    firc_ip_t reals[64];
    size_t n_reals = 0;
    bool had4 = false, had6 = false;
    uint32_t ttl = p->clamp_secs;
    for (size_t i = 0; i < msg->n_answers; i++) {
        const firc_dns_rr_t *rr = &msg->answers[i];
        if (rr->rtype != FIRC_DNS_TYPE_A && rr->rtype != FIRC_DNS_TYPE_AAAA) { continue; }
        char rr_owner[1100];
        if (firc_dns_name_to_string(rr->name, rr->name_len, rr_owner, sizeof(rr_owner), NULL) != FIRC_OK) {
            continue;
        }
        trim_fqdn(rr_owner);
        fold_ascii(rr_owner);
        if (!chain_has(chain, rr_owner)) { continue; }
        uint8_t len = rr->rtype == FIRC_DNS_TYPE_A ? 4 : 16;
        if (rr->rdata_len != len) { continue; }
        if (len == 4) { had4 = true; } else { had6 = true; }
        if (rr->ttl < ttl) { ttl = rr->ttl; }
        if (n_reals < sizeof(reals) / sizeof(reals[0])) {
            memcpy(reals[n_reals].b, rr->rdata, len);
            reals[n_reals].len = len;
            n_reals++;
        }
    }
    if (ev != NULL) {
        size_t k = n_reals < FIRC_EVENT_REALS ? n_reals : FIRC_EVENT_REALS;
        memcpy(ev->u.dns.reals, reals, k * sizeof(reals[0]));
        ev->u.dns.n_reals = (uint8_t)k;
    }
    if (issue == FIRC_OK && n_reals > 0) {
        firc_err_t e = firc_fakeip_set_reals(p->pool, qname, reals, n_reals);
        if (e != FIRC_OK) { FIRC_ERROR("recording real addresses for %s: %s", qname, firc_err_str(e)); }
        /* Every real address, not only the event's four. */
        for (size_t i = 0; i < n_reals; i++) {
            firc_recall_real(p->recall, &reals[i], qname, group_id, now);
        }
    }

    /* Set whatever happens to the answer below: the pool has already changed. */
    if (pool_changed != NULL) { *pool_changed = firc_fakeip_gen(p->pool) != gen_before; }

    if (p->v6_unroutable) {
        had6 = false;
        (void)firc_dns_msg_strip_aaaa(msg);
    }
    firc_err_t e = firc_dns_msg_collapse(msg, had4 ? &fake4 : NULL, had6 ? &fake6 : NULL, ttl);
    if (e != FIRC_OK) {
        /* Neither the real answer nor a broken one may go out. */
        FIRC_ERROR("collapsing the answer for %s: %s", qname, firc_err_str(e));
        return FIRC_DNS_DROP;
    }
    if (ev != NULL) {
        uint16_t qt = msg->questions[0].qtype;
        if (qt == FIRC_DNS_TYPE_A && had4) { ev->u.dns.fake = fake4; }
        if (qt == FIRC_DNS_TYPE_AAAA && had6) { ev->u.dns.fake = fake6; }
    }
    journal_put(p, ev, issue == FIRC_OK ? FIRC_DNS_ISSUED : FIRC_DNS_POOL_REFUSED);

    bool waits = issue == FIRC_OK &&
                 ((had4 && firc_fakeip_needs_commit(p->pool, qname, FIRC_FAM_V4)) ||
                  (had6 && firc_fakeip_needs_commit(p->pool, qname, FIRC_FAM_V6)));
    return waits ? FIRC_DNS_HOLD : FIRC_DNS_REWRITTEN;
}

firc_dns_verdict_t firc_dns_pipeline_handle_message_from(firc_dns_pipeline_t *p, firc_dns_msg_t *msg,
                                                         int64_t now, const firc_ip_t *client,
                                                         firc_dns_resolver_t resolver, bool *pool_changed)
{
    if (pool_changed != NULL) { *pool_changed = false; }
    uint32_t rcode = msg->flags & 0x000fu;
    /* NXDOMAIN/NOTIMP stay at DEBUG: at WARN they wrap the firmware's syslog ring in minutes. */
    bool failing = rcode == 2u || rcode == 5u;
    if (failing) {
        if (p->failing_count == 0) { p->failing_rcode = rcode; }
        p->failing_count++;
        p->healthy_count = 0;
        if (!p->outage_said && p->failing_count >= FIRC_DNS_OUTAGE_RUN) {
            p->outage_said = true;
            FIRC_WARN("upstream is answering rcode=%u and has for %llu responses; names it "
                      "refuses are not routed",
                      p->failing_rcode, (unsigned long long)p->failing_count);
        }
    } else if (p->failing_count > 0) {
        p->healthy_count++;
        if (p->healthy_count >= FIRC_DNS_OUTAGE_RUN) {
            if (p->outage_said) {
                FIRC_WARN("upstream is answering again, after %llu failed response(s) starting "
                          "with rcode=%u",
                          (unsigned long long)p->failing_count, p->failing_rcode);
            }
            p->failing_count = 0;
            p->healthy_count = 0;
            p->failing_rcode = 0;
            p->outage_said = false;
        }
    }
    const bool journalled = covered(p, client);
    firc_event_t ev_store;
    firc_event_t *ev = journalled ? &ev_store : NULL;
    if (rcode != 0) {
        FIRC_DEBUG("response passed through (rcode=%u)", rcode);
        if (ev != NULL) {
            char nx[FIRC_DNS_MAX_NAME * 4 + 2];
            if (!firc_dns_msg_queried_name(msg, nx, sizeof(nx))) { nx[0] = '\0'; }
            journal_begin(ev, now, client, nx, msg, rcode, resolver);
            const firc_group_snapshot_t *g =
                nx[0] != '\0' ? firc_ruleset_snapshot_first_match(p->snapshot, nx) : NULL;
            if (g != NULL &&
                firc_devsel_allows(g->devices, client, p->policy_fn, p->device_fn, p->policy_ud)) {
                journal_group(ev, g);
            }
            journal_put(p, ev, FIRC_DNS_PASSED);
        }
        return FIRC_DNS_PASS;
    }

    /* First matching group only: firing per group alternates a name between groups. */
    char qname[FIRC_DNS_MAX_NAME * 4 + 2];
    const firc_group_snapshot_t *owner = NULL;
    if (firc_dns_msg_queried_name(msg, qname, sizeof(qname))) {
        owner = firc_ruleset_snapshot_first_match(p->snapshot, qname);
    } else {
        qname[0] = '\0';
    }

    if (ev != NULL) {
        journal_begin(ev, now, client, qname, msg, rcode, resolver);
        journal_group(ev, owner);
    }

    chain_t chain;
    chain_build(&chain, msg, qname);

    bool addr_question = msg->n_questions > 0 &&
        (msg->questions[0].qtype == FIRC_DNS_TYPE_A || msg->questions[0].qtype == FIRC_DNS_TYPE_AAAA);

    if (owner == NULL) {
        if (p->snapshot != NULL && p->snapshot->provisional && p->pool != NULL && addr_question) {
            /* RETIMED, not REWRITTEN: the address is real, so AAAA stripping must still apply. */
            uint32_t clamp = p->clamp_secs;
            if (p->unmatched_ttl_secs > 0 && p->unmatched_ttl_secs < clamp) {
                clamp = p->unmatched_ttl_secs;
            }
            journal_put(p, ev, FIRC_DNS_NO_MATCH);
            if (firc_dns_msg_clamp_ttl(msg, clamp)) { return FIRC_DNS_RETIMED; }
            return FIRC_DNS_PASS;
        }
        journal_put(p, ev, FIRC_DNS_NO_MATCH);
        if (p->unmatched_ttl_secs > 0 && addr_question) {
            if (firc_dns_msg_clamp_ttl(msg, p->unmatched_ttl_secs)) { return FIRC_DNS_RETIMED; }
        }
        return FIRC_DNS_PASS;
    }
    if (p->pool == NULL || msg->n_questions == 0) {
        journal_put(p, ev, FIRC_DNS_PASSED);
        return FIRC_DNS_PASS;
    }
    if (!firc_devsel_allows(owner->devices, client, p->policy_fn, p->device_fn, p->policy_ud)) {
        journal_put(p, ev, FIRC_DNS_NOT_COVERED);
        if (p->unmatched_ttl_secs > 0 && addr_question) {
            if (firc_dns_msg_clamp_ttl(msg, p->unmatched_ttl_secs)) { return FIRC_DNS_RETIMED; }
        }
        return FIRC_DNS_PASS;
    }
    switch (msg->questions[0].qtype) {
    case FIRC_DNS_TYPE_A:
    case FIRC_DNS_TYPE_AAAA:
        return rewrite(p, msg, now, owner, qname, &chain, pool_changed, ev);
    case 64: /* SVCB */
    case 65: /* HTTPS */
        if (firc_dns_msg_collapse(msg, NULL, NULL, 0) != FIRC_OK) { return FIRC_DNS_DROP; }
        journal_put(p, ev, FIRC_DNS_PASSED);
        return FIRC_DNS_REWRITTEN;
    default:
        journal_put(p, ev, FIRC_DNS_PASSED);
        return FIRC_DNS_PASS;
    }
}

firc_dns_verdict_t firc_dns_pipeline_handle_message(firc_dns_pipeline_t *p, firc_dns_msg_t *msg,
                                                    int64_t now, const firc_ip_t *client,
                                                    bool *pool_changed)
{
    return firc_dns_pipeline_handle_message_from(p, msg, now, client, FIRC_DNS_RESOLVER_UPSTREAM,
                                                 pool_changed);
}

firc_recall_t *firc_dns_pipeline_recall(firc_dns_pipeline_t *p)
{
    return p != NULL ? p->recall : NULL;
}

bool firc_dns_pipeline_covers(const firc_dns_pipeline_t *p, const firc_ip_t *client)
{
    return p != NULL && covered(p, client);
}

const firc_group_snapshot_t *firc_dns_pipeline_owner(firc_dns_pipeline_t *p, const firc_dns_msg_t *query,
                                                     const firc_ip_t *client, bool *covered)
{
    *covered = false;
    if (p == NULL || p->snapshot == NULL || query == NULL) { return NULL; }
    char qname[FIRC_DNS_MAX_NAME * 4 + 2];
    if (!firc_dns_msg_queried_name(query, qname, sizeof(qname))) { return NULL; }
    const firc_group_snapshot_t *owner = firc_ruleset_snapshot_first_match(p->snapshot, qname);
    if (owner != NULL) {
        *covered = firc_devsel_allows(owner->devices, client, p->policy_fn, p->device_fn, p->policy_ud);
    }
    return owner;
}
