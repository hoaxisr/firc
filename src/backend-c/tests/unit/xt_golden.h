#ifndef FIRC_TEST_XT_GOLDEN_H
#define FIRC_TEST_XT_GOLDEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "firc/iptables.h"
#include "firc/xtables.h"

extern const char *const firc_test_xt_fixtures[];
extern const size_t firc_test_xt_n_fixtures;

bool firc_test_xt_read(const char *name, firc_ipt_proto_t fam, firc_xt_info_t *info, uint8_t **blob);
uint8_t *firc_test_xt_raw(const char *name, firc_ipt_proto_t fam, size_t *len);
bool firc_test_xt_to_host(firc_ipt_proto_t fam, uint8_t *blob, uint32_t size);
char *firc_test_xt_read_text(const char *name, firc_ipt_proto_t fam);
char *firc_test_xt_print(firc_ipt_proto_t fam, const firc_xt_info_t *info, const uint8_t *blob);
void firc_test_xt_zero_kernel_fields(firc_ipt_proto_t fam, uint8_t *blob, uint32_t size);
bool firc_test_xt_same(firc_ipt_proto_t fam, const firc_xt_info_t *ai, const uint8_t *a,
                       const firc_xt_info_t *bi, const uint8_t *b);
firc_ipt_rule_t *firc_test_rule(const char *line);

typedef struct firc_test_stage {
    firc_xt_stage_t stage;
    firc_xt_stage_chain_t chains[8];
    firc_xt_patch_op_t ops[16];
    firc_ipt_rule_t *rules[2100];
    size_t n_chains, n_ops, n_rules;
} firc_test_stage_t;

firc_test_stage_t *firc_test_stage_new(void);
void firc_test_stage_override(firc_test_stage_t *s, const char *chain, const char *const *lines, size_t n);
void firc_test_stage_delete(firc_test_stage_t *s, const char *chain);
void firc_test_stage_patch(firc_test_stage_t *s, const char *chain, size_t n, const firc_ipt_option_t *opts,
                           const int *nums, const char *const *lines);
void firc_test_stage_fixture(firc_test_stage_t *s, const char *fixture, firc_ipt_proto_t fam);
void firc_test_stage_free(firc_test_stage_t *s);

#endif
