#ifndef FIRC_TEST_FAKE_IPTABLES_H
#define FIRC_TEST_FAKE_IPTABLES_H

#include <stdbool.h>
#include <stddef.h>

#include "firc/iptables.h"
#include "fake_xtables.h"

typedef struct firc_fake_ipt firc_fake_ipt_t;

firc_fake_ipt_t *firc_fake_ipt_new(firc_ipt_proto_t proto);
firc_ipt_executable_t *firc_fake_ipt_as_executable(firc_fake_ipt_t *f);
/* A handle over the fake's own nat table; one per engine. */
firc_xt_t *firc_fake_ipt_as_xt(firc_fake_ipt_t *f);
firc_fake_xt_t *firc_fake_ipt_xt(firc_fake_ipt_t *f);

/* `rules[i]` is an argv-style array of `rule_lens[i]` string parts */
firc_err_t firc_fake_ipt_set_initial_rules(firc_fake_ipt_t *f, const char *table, const char *chain,
                                       const char *const *const *rules, const size_t *rule_lens,
                                       size_t n_rules);

/* Borrowed view into current rules for `table`/`chain`; a nat view is a copy kept until reset or free */
bool firc_fake_ipt_get_rules(firc_fake_ipt_t *f, const char *table, const char *chain,
                          firc_ipt_rule_t *const **out_rules, size_t *out_n);
bool firc_fake_ipt_chain_exists(firc_fake_ipt_t *f, const char *table, const char *chain);

void firc_fake_ipt_reset(firc_fake_ipt_t *f);
/* Fails the next text restore or nat write; FIRC_ERR_CANCELED waits for a text restore. */
void firc_fake_ipt_fail_next_restore(firc_fake_ipt_t *f, firc_err_t err);
void firc_fake_ipt_fail_at_commit(firc_fake_ipt_t *f, size_t n, firc_err_t err);
bool firc_fake_ipt_failure_armed(firc_fake_ipt_t *f);
/* Refuses a transcript, or a nat table as printed, containing substr. */
void firc_fake_ipt_refuse_rules_containing(firc_fake_ipt_t *f, const char *substr);
/* Every transcript handed to restore, then every nat table written, printed. */
const char *firc_fake_ipt_restore_log(firc_fake_ipt_t *f);
const char *firc_fake_ipt_saved_log(firc_fake_ipt_t *f);
size_t firc_fake_ipt_restore_calls(firc_fake_ipt_t *f);
/* fn runs after each accepted text restore, outside the fake's lock; NULL stops it. */
void firc_fake_ipt_on_restore(firc_fake_ipt_t *f, void (*fn)(void *ud), void *ud);

#endif
