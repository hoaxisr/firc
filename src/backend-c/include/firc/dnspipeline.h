#ifndef FIRC_DNSPIPELINE_H
#define FIRC_DNSPIPELINE_H

#include <stdbool.h>
#include <stdint.h>

#include "firc/dnswire.h"
#include "firc/events.h"
#include "firc/fakeip.h"
#include "firc/recall.h"
#include "firc/rulesnap.h"

typedef struct firc_dns_pipeline firc_dns_pipeline_t;

firc_dns_pipeline_t *firc_dns_pipeline_create(void);
void firc_dns_pipeline_destroy(firc_dns_pipeline_t *p);

/* Takes ownership of snap and frees the previous one. Loop thread only. */
void firc_dns_pipeline_set_snapshot(firc_dns_pipeline_t *p,
                                  firc_ruleset_snapshot_t *snap);
/* Borrowed or NULL; keep it only via firc_ruleset_snapshot_ref. Loop thread. */
firc_ruleset_snapshot_t *firc_dns_pipeline_snapshot(firc_dns_pipeline_t *p);

/* Borrowed; NULL turns the rewrite off. Loop thread only. */
void firc_dns_pipeline_set_pool(firc_dns_pipeline_t *p, firc_fakeip_t *pool, uint32_t clamp_secs);

/* False strips AAAA from matched answers (no ip6tables). Default true. */
void firc_dns_pipeline_set_v6_routable(firc_dns_pipeline_t *p, bool routable);

/* TTL ceiling for a real (unmatched) A/AAAA answer; 0 = off. Loop thread. */
void firc_dns_pipeline_set_unmatched_ttl(firc_dns_pipeline_t *p, uint32_t secs);

/* NULL client is admitted; *pool_changed (nullable) set means ask for a commit. */
firc_dns_verdict_t firc_dns_pipeline_handle_message(firc_dns_pipeline_t *p, firc_dns_msg_t *msg,
                                                    int64_t now, const firc_ip_t *client,
                                                    bool *pool_changed);

firc_dns_verdict_t firc_dns_pipeline_handle_message_from(firc_dns_pipeline_t *p, firc_dns_msg_t *msg,
                                                         int64_t now, const firc_ip_t *client,
                                                         firc_dns_resolver_t resolver, bool *pool_changed);

/* Without one a "policy:" selector entry matches no device. */
void firc_dns_pipeline_set_policy_resolver(firc_dns_pipeline_t *p, firc_devsel_policy_fn fn,
                                           firc_devsel_device_fn device, void *ud);

/* Owned by the pipeline; NULL when its allocation failed. Loop thread. */
firc_recall_t *firc_dns_pipeline_recall(firc_dns_pipeline_t *p);
/* Whether some group's selector admits `client`; NULL is not covered. */
bool firc_dns_pipeline_covers(const firc_dns_pipeline_t *p, const firc_ip_t *client);

/* First group matching the queried name, or NULL; valid until the next set_snapshot. */
const firc_group_snapshot_t *firc_dns_pipeline_owner(firc_dns_pipeline_t *p, const firc_dns_msg_t *query,
                                                     const firc_ip_t *client, bool *covered);

#endif /* FIRC_DNSPIPELINE_H */
