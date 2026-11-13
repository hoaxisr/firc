#ifndef FIRC_TEST_FAKE_IPTABLES_H
#define FIRC_TEST_FAKE_IPTABLES_H

#include <stdbool.h>
#include <stddef.h>

#include "firc/iptables.h"
#include "fake_xtables.h"

typedef struct firc_fake_ipt firc_fake_ipt_t;

firc_fake_ipt_t *firc_fake_ipt_new(firc_ipt_proto_t proto);
void firc_fake_ipt_free(firc_fake_ipt_t *f);
firc_xt_t *firc_fake_ipt_as_xt(firc_fake_ipt_t *f);
firc_fake_xt_t *firc_fake_ipt_xt(firc_fake_ipt_t *f);
firc_err_t firc_fake_ipt_set_initial_rules(firc_fake_ipt_t *f, const char *table, const char *chain,
                                           const char *const *const *rules, const size_t *rule_lens, size_t n_rules);
bool firc_fake_ipt_get_rules(firc_fake_ipt_t *f, const char *table, const char *chain, firc_ipt_rule_t *const **out_rules,
                             size_t *out_n);
bool firc_fake_ipt_chain_exists(firc_fake_ipt_t *f, const char *table, const char *chain);
char *firc_fake_ipt_print(firc_fake_ipt_t *f, const char *table);
void firc_fake_ipt_reset(firc_fake_ipt_t *f);
void firc_fake_ipt_fail_next_write(firc_fake_ipt_t *f, firc_err_t err);
void firc_fake_ipt_fail_at_commit(firc_fake_ipt_t *f, size_t n, firc_err_t err);
bool firc_fake_ipt_failure_armed(firc_fake_ipt_t *f);
void firc_fake_ipt_refuse_rules_containing(firc_fake_ipt_t *f, const char *substr);
void firc_fake_ipt_refuse_also_containing(firc_fake_ipt_t *f, const char *substr);
const char *firc_fake_ipt_writes_log(firc_fake_ipt_t *f);
const char *firc_fake_ipt_reads_log(firc_fake_ipt_t *f);
size_t firc_fake_ipt_writes(firc_fake_ipt_t *f);
size_t firc_fake_ipt_attempts(firc_fake_ipt_t *f);
void firc_fake_ipt_on_write(firc_fake_ipt_t *f, void (*fn)(void *ud), void *ud);

#endif
