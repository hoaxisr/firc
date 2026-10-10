#include "greatest.h"

#include "fake_iptables.h"
#include "fake_xtables.h"
#include "firc/cancel.h"
#include "firc/iptables.h"

#include <string.h>

static bool rule_eq_strs(const firc_ipt_rule_t *r, const char *const *expected, size_t n_expected) {
    if (r->n_parts != n_expected) return false;
    for (size_t i = 0; i < n_expected; i++) {
        if (strcmp(r->parts[i], expected[i]) != 0) return false;
    }
    return true;
}

static bool rules_seq_eq(firc_ipt_rule_t *const *got, size_t n_got,
                         const char *const *const *expected, const size_t *expected_lens,
                         size_t n_expected) {
    if (n_got != n_expected) return false;
    for (size_t i = 0; i < n_expected; i++) {
        if (!rule_eq_strs(got[i], expected[i], expected_lens[i])) return false;
    }
    return true;
}

/* Catches: a chain patch replacing the rules already on the chain instead of merging with them. */
TEST chain_patch_appends_after_existing(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *r0[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *r1[] = {"-i", "eth1", "-j", "DROP"};
    const char *const *initial[] = {r0, r1};
    size_t initial_lens[] = {4, 4};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", initial, initial_lens, 2));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "FORWARD"));
    const char *newr[] = {"-i", "eth2", "-j", "ACCEPT"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "FORWARD", newr, 4));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "FORWARD", &got, &n_got));
    const char *const *expected[] = {r0, r1, newr};
    size_t expected_lens[] = {4, 4, 4};
    ASSERT(rules_seq_eq(got, n_got, expected, expected_lens, 3));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_patch_deletes_existing(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *r22[] = {"-p", "tcp", "--dport", "22", "-j", "ACCEPT"};
    const char *r80[] = {"-p", "tcp", "--dport", "80", "-j", "ACCEPT"};
    const char *r443[] = {"-p", "tcp", "--dport", "443", "-j", "ACCEPT"};
    const char *const *initial[] = {r22, r80, r443};
    size_t initial_lens[] = {6, 6, 6};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "filter", "INPUT", initial, initial_lens, 3));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "INPUT"));
    ASSERT_EQ(FIRC_OK, firc_ipt_delete(ipt, "filter", "INPUT", r80, 6));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "INPUT", &got, &n_got));
    const char *const *expected[] = {r22, r443};
    size_t expected_lens[] = {6, 6};
    ASSERT(rules_seq_eq(got, n_got, expected, expected_lens, 2));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_patch_inserts_at_front(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *r10[] = {"-d", "10.0.0.0/8", "-j", "ACCEPT"};
    const char *const *initial[] = {r10};
    size_t initial_lens[] = {4};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "filter", "OUTPUT", initial, initial_lens, 1));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "OUTPUT"));
    const char *r192[] = {"-d", "192.168.0.0/16", "-j", "ACCEPT"};
    ASSERT_EQ(FIRC_OK, firc_ipt_insert(ipt, "filter", "OUTPUT", 1, r192, 4));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "OUTPUT", &got, &n_got));
    const char *const *expected[] = {r192, r10};
    size_t expected_lens[] = {4, 4};
    ASSERT(rules_seq_eq(got, n_got, expected, expected_lens, 2));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_patch_no_duplicates(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *r0[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *initial[] = {r0};
    size_t initial_lens[] = {4};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", initial, initial_lens, 1));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "FORWARD"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "FORWARD", r0, 4));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "FORWARD", &got, &n_got));
    const char *const *expected[] = {r0};
    size_t expected_lens[] = {4};
    ASSERT(rules_seq_eq(got, n_got, expected, expected_lens, 1));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_override_replaces_all(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *r80[] = {"-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080"};
    const char *r443[] = {"-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-port", "8443"};
    const char *const *initial[] = {r80, r443};
    size_t initial_lens[] = {8, 8};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "mangle", "PREROUTING", initial, initial_lens, 2));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "PREROUTING"));
    const char *rudp[] = {"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "5353"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "mangle", "PREROUTING", rudp, 8));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", "PREROUTING", &got, &n_got));
    const char *const *expected[] = {rudp};
    size_t expected_lens[] = {8};
    ASSERT(rules_seq_eq(got, n_got, expected, expected_lens, 1));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_override_multiple_rules(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *rold[] = {"-j", "OLD_CHAIN"};
    const char *const *initial[] = {rold};
    size_t initial_lens[] = {2};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "mangle", "PREROUTING", initial, initial_lens, 1));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "PREROUTING"));
    const char *m1[] = {"-j", "MARK", "--set-mark", "1"};
    const char *m2[] = {"-j", "MARK", "--set-mark", "2"};
    const char *m3[] = {"-j", "CONNMARK", "--save-mark"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "mangle", "PREROUTING", m1, 4));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "mangle", "PREROUTING", m2, 4));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "mangle", "PREROUTING", m3, 3));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", "PREROUTING", &got, &n_got));
    const char *const *expected[] = {m1, m2, m3};
    size_t expected_lens[] = {4, 4, 3};
    ASSERT(rules_seq_eq(got, n_got, expected, expected_lens, 3));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_override_noop_if_unchanged(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *racc[] = {"-j", "ACCEPT"};
    const char *const *initial[] = {racc};
    size_t initial_lens[] = {2};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "filter", "TEST", initial, initial_lens, 1));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "TEST"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "TEST", racc, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "TEST", &got, &n_got));
    const char *const *expected[] = {racc};
    size_t expected_lens[] = {2};
    ASSERT(rules_seq_eq(got, n_got, expected, expected_lens, 1));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_delete_removes_chain(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *racc[] = {"-j", "ACCEPT"};
    const char *rdrop[] = {"-j", "DROP"};
    const char *const *initial[] = {racc, rdrop};
    size_t initial_lens[] = {2, 2};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "filter", "MY_CHAIN", initial, initial_lens, 2));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "MY_CHAIN"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "MY_CHAIN"));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_delete_removes_empty_chain(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "filter", "EMPTY_CHAIN", NULL, NULL, 0));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "EMPTY_CHAIN"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "EMPTY_CHAIN"));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_delete_nonexistent_is_noop(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "NON_EXISTENT"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "NON_EXISTENT"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a rule staged into a chain being deleted, or an insert into an override chain, accepted without a word. */
TEST a_rule_operation_a_chain_kind_does_not_take_is_refused(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *racc[] = {"-j", "ACCEPT"};
    const char *const *initial[] = {racc};
    size_t initial_lens[] = {2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "filter", "TO_DELETE", initial, initial_lens, 1));
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "TO_DELETE"));
    const char *rdrop[] = {"-j", "DROP"};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_ipt_append(ipt, "filter", "TO_DELETE", rdrop, 2));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_ipt_insert(ipt, "filter", "TO_DELETE", 1, rdrop, 2));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_ipt_delete(ipt, "filter", "TO_DELETE", racc, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "MINE"));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_ipt_insert(ipt, "filter", "MINE", 1, rdrop, 2));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_ipt_delete(ipt, "filter", "MINE", rdrop, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "MINE", rdrop, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "TO_DELETE"));
    firc_ipt_rule_t *const *got = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "MINE", &got, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    firc_ipt_free(ipt);
    PASS();
}

TEST mixed_chain_types_in_one_table(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *racc[] = {"-j", "ACCEPT"};
    const char *rold[] = {"-j", "OLD_RULE"};
    const char *rsomething[] = {"-j", "SOMETHING"};
    {
        const char *const *initial[] = {racc};
        size_t lens[] = {2};
        ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "filter", "INPUT", initial, lens, 1));
    }
    {
        const char *const *initial[] = {rold};
        size_t lens[] = {2};
        ASSERT_EQ(FIRC_OK,
                 firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", initial, lens, 1));
    }
    {
        const char *const *initial[] = {rsomething};
        size_t lens[] = {2};
        ASSERT_EQ(FIRC_OK,
                 firc_fake_ipt_set_initial_rules(fake, "filter", "TO_DELETE", initial, lens, 1));
    }

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));

    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "INPUT"));
    const char *rdrop[] = {"-j", "DROP"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "INPUT", rdrop, 2));

    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "FORWARD"));
    const char *rnew[] = {"-j", "NEW_RULE"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "FORWARD", rnew, 2));

    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "TO_DELETE"));

    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "INPUT", &got, &n_got));
    {
        const char *const *expected[] = {racc, rdrop};
        size_t lens[] = {2, 2};
        ASSERT(rules_seq_eq(got, n_got, expected, lens, 2));
    }

    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "FORWARD", &got, &n_got));
    {
        const char *const *expected[] = {rnew};
        size_t lens[] = {2};
        ASSERT(rules_seq_eq(got, n_got, expected, lens, 1));
    }

    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "TO_DELETE"));

    firc_ipt_free(ipt);
    PASS();
}

TEST multiple_commits_accumulate(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));

    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "MY_CHAIN"));
    const char *racc[] = {"-j", "ACCEPT"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "MY_CHAIN", racc, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "MY_CHAIN", &got, &n_got));
    ASSERT_EQ(1u, (unsigned)n_got);
    ASSERT(rule_eq_strs(got[0], (const char *const[]){"-j", "ACCEPT"}, 2));

    const char *rdrop[] = {"-j", "DROP"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "MY_CHAIN", rdrop, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "MY_CHAIN", &got, &n_got));
    const char *const *expected[] = {racc, rdrop};
    size_t lens[] = {2, 2};
    ASSERT(rules_seq_eq(got, n_got, expected, lens, 2));

    firc_ipt_free(ipt);
    PASS();
}

TEST ipv6_rules(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV6);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_IPT_PROTO_IPV6, firc_ipt_proto(ipt));

    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "INPUT"));
    const char *r[] = {"-s", "::1", "-j", "ACCEPT"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "INPUT", r, 4));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "INPUT", &got, &n_got));
    const char *const *expected[] = {r};
    size_t lens[] = {4};
    ASSERT(rules_seq_eq(got, n_got, expected, lens, 1));

    firc_ipt_free(ipt);
    PASS();
}

TEST error_on_uninitialized_chain(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));

    const char *r[] = {"-j", "ACCEPT"};
    firc_err_t err = firc_ipt_append(ipt, "filter", "NONEXISTENT", r, 2);
    ASSERT(firc_ipt_err_is_chain_not_initialized(err));

    err = firc_ipt_insert(ipt, "filter", "NONEXISTENT", 1, r, 2);
    ASSERT(firc_ipt_err_is_chain_not_initialized(err));

    err = firc_ipt_delete(ipt, "filter", "NONEXISTENT", r, 2);
    ASSERT(firc_ipt_err_is_chain_not_initialized(err));

    firc_ipt_free(ipt);
    PASS();
}

TEST patch_removes_duplicates(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *racc[] = {"-j", "ACCEPT"};
    const char *rdrop[] = {"-j", "DROP"};
    const char *const *initial[] = {racc, racc, rdrop};
    size_t lens[] = {2, 2, 2};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "filter", "FORWARD", initial, lens, 3));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "FORWARD"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "FORWARD", racc, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "filter", "FORWARD", &got, &n_got));
    const char *const *expected[] = {racc, rdrop};
    size_t explens[] = {2, 2};
    ASSERT(rules_seq_eq(got, n_got, expected, explens, 2));

    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a refused rule classified as a raced write, retried with no backoff and no line named. */
TEST a_rule_this_kernel_cannot_load_is_not_a_raced_write(void) {
    static const char refused[] =
        "iptables-restore v1.4.21: Couldn't load match `string':No such file or directory\n";
    ASSERT_FALSEm("a match the kernel has no module for is never worth retrying",
                  firc_ipt_stderr_is_retryable(refused, sizeof(refused) - 1));
    static const char no_target[] =
        "iptables-restore v1.4.21: Couldn't load target `NFLOG':No such file or directory\n";
    ASSERT_FALSEm("nor a target", firc_ipt_stderr_is_retryable(no_target, sizeof(no_target) - 1));

    static const char raced[] = "iptables-restore: Chain already exists\n";
    ASSERTm("a table replaced under us is started over",
            firc_ipt_stderr_is_retryable(raced, sizeof(raced) - 1));
    static const char locked[] = "Another app is currently holding the xtables lock\n";
    ASSERTm("so is the lock", firc_ipt_stderr_is_retryable(locked, sizeof(locked) - 1));
    static const char gone[] = "iptables-restore: No chain/target/match by that name\n";
    ASSERTm("so is a chain that went away", firc_ipt_stderr_is_retryable(gone, sizeof(gone) - 1));

    ASSERT_FALSE(firc_ipt_stderr_is_retryable("", 0));
    ASSERT_FALSE(firc_ipt_stderr_is_retryable(NULL, 0));
    ASSERT_FALSEm("only the bytes it was given",
                  firc_ipt_stderr_is_retryable("Chain already exists", 5));
    PASS();
}

TEST a_refused_line_is_quoted_back_from_the_transcript(void) {
    static const char transcript[] =
        "*mangle\n"
        ":FIRC_aaaa - [0:0]\n"
        "-A PREROUTING -j FIRC_aaaa\n"
        "-A FIRC_aaaa -m conntrack --ctdir REPLY -j RETURN\n"
        "COMMIT\n";
    const uint8_t *d = (const uint8_t *)transcript;
    size_t dl = sizeof(transcript) - 1;
    size_t n = 0;

    const char *l = firc_ipt_offending_line(d, dl, "iptables-restore: line 3 failed\n",
                                strlen("iptables-restore: line 3 failed\n"), &n);
    ASSERT(l != NULL);
    ASSERT_EQ_FMT((size_t)26, n, "%zu");
    ASSERT_MEM_EQ("-A PREROUTING -j FIRC_aaaa", l, 26);

    l = firc_ipt_offending_line(d, dl, "line 1 failed", strlen("line 1 failed"), &n);
    ASSERT(l != NULL);
    ASSERT_EQ_FMT((size_t)7, n, "%zu");
    ASSERT_MEM_EQ("*mangle", l, 7);

    l = firc_ipt_offending_line(d, dl, "iptables-restore v1.8.7 (nf_tables): line 5 failed",
                                strlen("iptables-restore v1.8.7 (nf_tables): line 5 failed"), &n);
    ASSERT(l != NULL);
    ASSERT_MEM_EQ("COMMIT", l, 6);

    ASSERT(firc_ipt_offending_line(d, dl, "Resource temporarily unavailable",
                                   strlen("Resource temporarily unavailable"), &n) == NULL);
    ASSERT(firc_ipt_offending_line(d, dl, "line 99 failed", strlen("line 99 failed"), &n) == NULL);
    ASSERT(firc_ipt_offending_line(d, dl, "line 0 failed", strlen("line 0 failed"), &n) == NULL);
    ASSERT(firc_ipt_offending_line(NULL, 0, "line 1 failed", strlen("line 1 failed"), &n) == NULL);
    PASS();
}

/* Catches: the fake's Nth-COMMIT failure keeping the wrong tables or staying armed. */
TEST a_failure_at_the_nth_commit_keeps_the_tables_before_it(void) {
    static const char t[] = "*filter\n:A - [0:0]\n-A A -j ACCEPT\nCOMMIT\n"
                            "*mangle\n:B - [0:0]\n-A B -j RETURN\nCOMMIT\n"
                            "*raw\n:C - [0:0]\n-A C -j RETURN\nCOMMIT\n";
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f), firc_fake_ipt_as_xt(f));
    ASSERT(ipt != NULL);

    firc_fake_ipt_fail_at_commit(f, 2, FIRC_ERR_IO);
    ASSERT(firc_fake_ipt_failure_armed(f));
    ASSERT_EQ(FIRC_ERR_IO, firc_ipt_write_transcript(ipt, (const uint8_t *)t, sizeof(t) - 1));
    ASSERTm("the table before the failing COMMIT landed", firc_fake_ipt_chain_exists(f, "filter", "A"));
    ASSERT_FALSEm("the failing table did not", firc_fake_ipt_chain_exists(f, "mangle", "B"));
    ASSERT_FALSEm("nor anything after it", firc_fake_ipt_chain_exists(f, "raw", "C"));
    ASSERT_FALSEm("it fired, once", firc_fake_ipt_failure_armed(f));

    ASSERT_EQ(FIRC_OK, firc_ipt_write_transcript(ipt, (const uint8_t *)t, sizeof(t) - 1));
    ASSERTm("the next call is whole", firc_fake_ipt_chain_exists(f, "mangle", "B") &&
                                      firc_fake_ipt_chain_exists(f, "raw", "C"));

    firc_fake_ipt_reset(f);
    firc_fake_ipt_fail_at_commit(f, 1, FIRC_ERR_IO);
    ASSERT_EQ(FIRC_ERR_IO, firc_ipt_write_transcript(ipt, (const uint8_t *)t, sizeof(t) - 1));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f, "filter", "A"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a bare "COMMIT failed" message classified as a retryable race. */
TEST a_bare_commit_failure_is_not_a_raced_write(void) {
    static const char bare[] = "iptables-restore: line 23 failed\n";
    ASSERT_EQ_FMT((size_t)33, sizeof(bare) - 1, "%zu");
    ASSERT_FALSEm("a bare COMMIT failure stays FIRC_ERR_IO",
                  firc_ipt_stderr_is_retryable(bare, sizeof(bare) - 1));
    PASS();
}

/* Catches: the fake not flushing a declared user chain at its declaration, as iptables-restore does. */
TEST a_declared_user_chain_is_flushed_before_the_block_runs(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *jump[] = {"-j", "D1"};
    const char *ret[] = {"-j", "RETURN"};
    const char *acc[] = {"-i", "eth0", "-j", "ACCEPT"};
    const char *const *g_rules[] = {jump}, *const *d_rules[] = {ret}, *const *p_rules[] = {acc};
    size_t g_lens[] = {2}, d_lens[] = {2}, p_lens[] = {4};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "mangle", "G1", g_rules, g_lens, 1));
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "mangle", "D1", d_rules, d_lens, 1));
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "mangle", "PREROUTING", p_rules, p_lens, 1));
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    static const char t[] = "*mangle\n:PREROUTING - [0:0]\n:D1 - [0:0]\n:G1 - [0:0]\n-X D1\n-X G1\nCOMMIT\n";
    ASSERT_EQ(FIRC_OK, firc_ipt_write_transcript(ipt, (const uint8_t *)t, sizeof(t) - 1));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", "D1"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", "G1"));
    firc_ipt_rule_t *const *got = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", "PREROUTING", &got, &n));
    ASSERT_EQ_FMTm("a built-in chain keeps its rules", (size_t)1, n, "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a commit saving every table when it writes one (a 168 KB dump on the bench for a mangle change). */
TEST a_commit_saves_only_the_tables_it_registered(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING"));
    const char *r[] = {"-j", "RETURN"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "mangle", "PREROUTING", r, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQ("mangle\n", firc_fake_ipt_saved_log(fake));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a nat registration still written as an iptables-restore transcript. */
TEST a_nat_registration_is_written_through_x_tables(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    const char *dnat[] = {"-d", "198.18.0.1/32", "-j", "DNAT", "--to-destination", "1.2.3.4"};
    const char *jump[] = {"-d", "198.18.0.0/15", "-j", "FIRC_DNAT"};
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "nat", "FIRC_DNAT", dnat, 6));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "nat", "PREROUTING", jump, 4));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_EQ_FMT((size_t)0, firc_fake_ipt_restore_calls(fake), "%zu");
    ASSERT_STR_EQ("", firc_fake_ipt_saved_log(fake));
    ASSERT_EQ_FMT((size_t)1, firc_fake_xt_replaces(firc_fake_ipt_xt(fake)), "%zu");
    firc_ipt_rule_t *const *got = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "nat", "FIRC_DNAT", &got, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT(rule_eq_strs(got[0], dnat, 6));
    ASSERT(firc_fake_ipt_get_rules(fake, "nat", "PREROUTING", &got, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT(rule_eq_strs(got[0], jump, 4));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a nat staging dropped without a word, or handed to iptables-restore, when the engine has no handle. */
TEST nat_without_a_handle_is_refused(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), NULL);
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_X"));
    ASSERT_EQ(FIRC_ERR_STATE, firc_ipt_commit(ipt));
    ASSERT_EQ_FMT((size_t)0, firc_fake_ipt_restore_calls(fake), "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a sweep accepted for a text table, or kept after its write so a later commit sweeps what it never meant to. */
TEST a_sweep_is_for_nat_and_happens_once(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *masq[] = {"-j", "MASQUERADE"};
    const char *jump[] = {"-j", "FIRC_old"};
    const char *const *chain_rules[] = {masq};
    const char *const *post_rules[] = {jump};
    size_t lens[] = {2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "nat", "FIRC_old", chain_rules, lens, 1));
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "nat", "POSTROUTING", post_rules, lens, 1));
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_ipt_register_sweep(ipt, "filter", "FIRC_"));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_sweep(ipt, "nat", "FIRC_"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    firc_ipt_rule_t *const *got = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "nat", "POSTROUTING", &got, &n));
    ASSERT_EQ_FMT((size_t)0, n, "%zu");
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "nat", "FIRC_new", chain_rules, lens, 1));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_other"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERTm("the sweep did not outlive its write", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_new"));
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_other"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a failure armed for the next write skipped when that write is an x_tables replace. */
TEST an_armed_failure_fails_a_nat_write(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    const char *ret[] = {"-j", "RETURN"};
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_X"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "nat", "FIRC_X", ret, 2));
    firc_fake_ipt_fail_next_restore(fake, FIRC_ERR_IO);
    ASSERT_EQ(FIRC_ERR_IO, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_X"));
    ASSERT_FALSE(firc_fake_ipt_failure_armed(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_X"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: nat written before the text tables, so a refused filter write leaves a half-applied pass. */
TEST a_refused_text_write_leaves_nat_unwritten(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    const char *acc[] = {"-j", "ACCEPT"};
    const char *ret[] = {"-j", "RETURN"};
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "FIRC_TEXT"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "filter", "FIRC_TEXT", acc, 2));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_X"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "nat", "FIRC_X", ret, 2));
    firc_fake_ipt_refuse_rules_containing(fake, "FIRC_TEXT");
    ASSERT_EQ(FIRC_ERR_IO, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_X"));
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_replaces(firc_fake_ipt_xt(fake)), "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: nat written or its table read when its only registrations are base patches with nothing staged. */
TEST base_patches_with_nothing_staged_write_no_nat(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), NULL);
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING"));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "nat", "POSTROUTING"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: the fake letting a refused nat table through, or leaving a written one out of its log. */
TEST the_fake_refuses_and_logs_nat_writes(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    const char *ret[] = {"-j", "RETURN"};
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_BAD"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "nat", "FIRC_BAD", ret, 2));
    firc_fake_ipt_refuse_rules_containing(fake, "FIRC_BAD");
    ASSERT_EQ(FIRC_ERR_IO, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_BAD"));
    firc_fake_ipt_refuse_rules_containing(fake, NULL);
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    const char *log = firc_fake_ipt_restore_log(fake);
    ASSERT(log != NULL && strstr(log, "*nat\n") != NULL);
    ASSERT(strstr(log, "\n-A FIRC_BAD -j RETURN\n") != NULL);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a fake reset that keeps the nat table or a failure armed against it. */
TEST a_reset_empties_nat_and_disarms_it(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *ret[] = {"-j", "RETURN"};
    const char *const *rules[] = {ret};
    size_t lens[] = {2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "nat", "FIRC_X", rules, lens, 1));
    firc_fake_xt_hold_lock(firc_fake_ipt_xt(fake), true);
    firc_fake_ipt_reset(fake);
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_X"));
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_Y"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_Y"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: the fake taking a nat table by iptables-restore, so a stray text writer of nat goes unnoticed. */
TEST a_transcript_naming_nat_is_refused(void) {
    static const char t[] = "*filter\n:A - [0:0]\nCOMMIT\n*nat\n:C - [0:0]\n-A C -j RETURN\nCOMMIT\n";
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    ASSERT_EQ(FIRC_ERR_STATE, firc_ipt_write_transcript(ipt, (const uint8_t *)t, sizeof(t) - 1));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "A"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "C"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a nat view freed by the next nat read while the caller still holds it. */
TEST a_nat_view_outlives_the_next_read(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *ret[] = {"-j", "RETURN"};
    const char *masq[] = {"-j", "MASQUERADE"};
    const char *const *a_rules[] = {ret};
    const char *const *b_rules[] = {masq};
    size_t lens[] = {2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "nat", "FIRC_A", a_rules, lens, 1));
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "nat", "FIRC_B", b_rules, lens, 1));
    firc_ipt_rule_t *const *a = NULL, *const *b = NULL;
    size_t na = 0, nb = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "nat", "FIRC_A", &a, &na));
    ASSERT(firc_fake_ipt_get_rules(fake, "nat", "FIRC_B", &b, &nb));
    ASSERT_EQ_FMT((size_t)1, na, "%zu");
    ASSERT(rule_eq_strs(a[0], ret, 2));
    ASSERT_EQ_FMT((size_t)1, nb, "%zu");
    ASSERT(rule_eq_strs(b[0], masq, 2));
    firc_ipt_executable_free(firc_fake_ipt_as_executable(fake));
    PASS();
}

static void stage_two(firc_ipt_t *ipt, const char *mangle_target, const char *nat_target) {
    const char *m[] = {"-j", mangle_target};
    const char *n[] = {"-j", nat_target};
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_m");
    (void)firc_ipt_append(ipt, "mangle", "FIRC_m", m, 2);
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_n");
    (void)firc_ipt_append(ipt, "nat", "FIRC_n", n, 2);
}

/* Catches: a table saved, read or written again when nothing staged for it changed since its last write. */
TEST an_unchanged_staging_costs_no_save_and_no_read(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQ("mangle\n", firc_fake_ipt_saved_log(fake));
    ASSERT_EQ_FMT((size_t)1, firc_fake_xt_reads(firc_fake_ipt_xt(fake)), "%zu");
    size_t restores = firc_fake_ipt_restore_calls(fake);
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQ("mangle\n", firc_fake_ipt_saved_log(fake));
    ASSERT_EQ_FMT((size_t)1, firc_fake_xt_reads(firc_fake_ipt_xt(fake)), "%zu");
    ASSERT_EQ_FMT(restores, firc_fake_ipt_restore_calls(fake), "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a change in one table making the other table's save or read happen too. */
TEST only_the_table_that_changed_is_touched(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    stage_two(ipt, "RETURN", "ACCEPT");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQ("mangle\n", firc_fake_ipt_saved_log(fake));
    ASSERT_EQ_FMT((size_t)2, firc_fake_xt_reads(firc_fake_ipt_xt(fake)), "%zu");
    stage_two(ipt, "ACCEPT", "ACCEPT");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQ("mangle\nmangle\n", firc_fake_ipt_saved_log(fake));
    ASSERT_EQ_FMT((size_t)2, firc_fake_xt_reads(firc_fake_ipt_xt(fake)), "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: two stagings of the same length taken as equal. */
TEST a_change_of_the_same_length_is_written(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    stage_two(ipt, "ACCEPT", "ACCEPT");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    static const char *const ret[] = {"-j", "RETURN"};
    ASSERT(firc_fake_ipt_get_rules(fake, "mangle", "FIRC_m", &rules, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT(rule_eq_strs(rules[0], ret, 2));
    ASSERT(firc_fake_ipt_get_rules(fake, "nat", "FIRC_n", &rules, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT(rule_eq_strs(rules[0], ret, 2));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: forgetting not making the next commit look at every table again, which a full pass needs. */
TEST forgetting_makes_the_next_commit_look_again(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    firc_ipt_forget_written(ipt);
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQ("mangle\nmangle\n", firc_fake_ipt_saved_log(fake));
    ASSERT_EQ_FMT((size_t)2, firc_fake_xt_reads(firc_fake_ipt_xt(fake)), "%zu");
    ASSERT_EQ_FMTm("read and found unchanged: no second replace", (size_t)1,
                   firc_fake_xt_replaces(firc_fake_ipt_xt(fake)), "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a discard dropping what was written, so the pass after a failed one rewrites unchanged tables. */
TEST a_discard_keeps_what_was_written(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    firc_ipt_discard(ipt);
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQ("mangle\n", firc_fake_ipt_saved_log(fake));
    ASSERT_EQ_FMT((size_t)1, firc_fake_xt_reads(firc_fake_ipt_xt(fake)), "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a failed write remembered as written, so the retry is skipped and the rule never lands. */
TEST a_failed_write_is_not_remembered(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    const char *n[] = {"-j", "RETURN"};
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_n"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "nat", "FIRC_n", n, 2));
    firc_fake_ipt_fail_next_restore(fake, FIRC_ERR_IO);
    ASSERT_EQ(FIRC_ERR_IO, firc_ipt_commit(ipt));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_n"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a failed text restore remembered as written, so the retry skips mangle. */
TEST a_failed_text_write_is_not_remembered(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    const char *m[] = {"-j", "RETURN"};
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_m"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "mangle", "FIRC_m", m, 2));
    firc_fake_ipt_fail_next_restore(fake, FIRC_ERR_IO);
    ASSERT_EQ(FIRC_ERR_IO, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "mangle", "FIRC_m"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "mangle", "FIRC_m"));
    firc_ipt_free(ipt);
    PASS();
}

static void raise_cancel(void *ud) { firc_cancel_raise(ud); }

/* Catches: nat remembered as written although a cancel stopped the commit after the text tables. */
TEST a_cancel_before_nat_leaves_nat_owed(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    firc_cancel_t *cancel = firc_cancel_new();
    firc_ipt_set_cancel(ipt, cancel);
    firc_fake_ipt_on_restore(fake, raise_cancel, cancel);
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_ERR_CANCELED, firc_ipt_commit(ipt));
    ASSERT(firc_fake_ipt_chain_exists(fake, "mangle", "FIRC_m"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_n"));
    ASSERT_EQ_FMT((size_t)0, firc_fake_xt_reads(firc_fake_ipt_xt(fake)), "%zu");
    firc_fake_ipt_on_restore(fake, NULL, NULL);
    firc_cancel_clear(cancel);
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQm("mangle was written and is not saved again", "mangle\n", firc_fake_ipt_saved_log(fake));
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_n"));
    firc_ipt_set_cancel(ipt, NULL);
    firc_cancel_free(cancel);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a sweep left out of the staging compared, so a commit that must sweep is skipped. */
TEST a_sweep_makes_an_unchanged_nat_due(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    static const char *const masq[] = {"-j", "MASQUERADE"};
    const char *const *rules[1] = {masq};
    size_t lens[1] = {2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "nat", "FIRC_old", rules, lens, 1));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_register_sweep(ipt, "nat", "FIRC_"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    ASSERT(firc_fake_ipt_chain_exists(fake, "nat", "FIRC_n"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a staging copy that joins parts with spaces, taking one part "a b" for the two parts "a" and "b". */
TEST parts_that_join_to_the_same_text_are_not_the_same_staging(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    const char *one[] = {"-m", "comment", "--comment", "a b", "-j", "RETURN"};
    const char *two[] = {"-m", "comment", "--comment", "a", "b", "-j", "RETURN"};
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_m"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "mangle", "FIRC_m", two, 7));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_m"));
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "mangle", "FIRC_m", one, 6));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_STR_EQ("mangle\nmangle\n", firc_fake_ipt_saved_log(fake));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a sweep left set when its commit skipped nat, so a later commit sweeps what nobody asked it to. */
TEST a_skipped_sweep_does_not_wait_for_the_next_commit(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake), firc_fake_ipt_as_xt(fake));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_register_sweep(ipt, "nat", "FIRC_"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    stage_two(ipt, "RETURN", "RETURN");
    ASSERT_EQ(FIRC_OK, firc_ipt_register_sweep(ipt, "nat", "FIRC_"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_EQ_FMTm("the second sweep was skipped", (size_t)1, firc_fake_xt_reads(firc_fake_ipt_xt(fake)), "%zu");
    static const char *const masq[] = {"-j", "MASQUERADE"};
    const char *const *rules[1] = {masq};
    size_t lens[1] = {2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "nat", "FIRC_old", rules, lens, 1));
    stage_two(ipt, "RETURN", "ACCEPT");
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    static const char *const acc[] = {"-j", "ACCEPT"};
    firc_ipt_rule_t *const *got = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(fake, "nat", "FIRC_n", &got, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT(rule_eq_strs(got[0], acc, 2));
    ASSERTm("no sweep was asked for", firc_fake_ipt_chain_exists(fake, "nat", "FIRC_old"));
    firc_ipt_free(ipt);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_commit_saves_only_the_tables_it_registered);
    RUN_TEST(chain_patch_appends_after_existing);
    RUN_TEST(chain_patch_deletes_existing);
    RUN_TEST(chain_patch_inserts_at_front);
    RUN_TEST(chain_patch_no_duplicates);
    RUN_TEST(chain_override_replaces_all);
    RUN_TEST(chain_override_multiple_rules);
    RUN_TEST(chain_override_noop_if_unchanged);
    RUN_TEST(chain_delete_removes_chain);
    RUN_TEST(chain_delete_removes_empty_chain);
    RUN_TEST(chain_delete_nonexistent_is_noop);
    RUN_TEST(a_rule_operation_a_chain_kind_does_not_take_is_refused);
    RUN_TEST(mixed_chain_types_in_one_table);
    RUN_TEST(multiple_commits_accumulate);
    RUN_TEST(ipv6_rules);
    RUN_TEST(error_on_uninitialized_chain);
    RUN_TEST(patch_removes_duplicates);
    RUN_TEST(a_rule_this_kernel_cannot_load_is_not_a_raced_write);
    RUN_TEST(a_failure_at_the_nth_commit_keeps_the_tables_before_it);
    RUN_TEST(a_bare_commit_failure_is_not_a_raced_write);
    RUN_TEST(a_refused_line_is_quoted_back_from_the_transcript);
    RUN_TEST(a_declared_user_chain_is_flushed_before_the_block_runs);
    RUN_TEST(a_nat_registration_is_written_through_x_tables);
    RUN_TEST(nat_without_a_handle_is_refused);
    RUN_TEST(a_sweep_is_for_nat_and_happens_once);
    RUN_TEST(an_armed_failure_fails_a_nat_write);
    RUN_TEST(a_refused_text_write_leaves_nat_unwritten);
    RUN_TEST(base_patches_with_nothing_staged_write_no_nat);
    RUN_TEST(the_fake_refuses_and_logs_nat_writes);
    RUN_TEST(a_reset_empties_nat_and_disarms_it);
    RUN_TEST(a_transcript_naming_nat_is_refused);
    RUN_TEST(a_nat_view_outlives_the_next_read);
    RUN_TEST(an_unchanged_staging_costs_no_save_and_no_read);
    RUN_TEST(only_the_table_that_changed_is_touched);
    RUN_TEST(a_change_of_the_same_length_is_written);
    RUN_TEST(forgetting_makes_the_next_commit_look_again);
    RUN_TEST(a_discard_keeps_what_was_written);
    RUN_TEST(a_failed_write_is_not_remembered);
    RUN_TEST(a_failed_text_write_is_not_remembered);
    RUN_TEST(a_cancel_before_nat_leaves_nat_owed);
    RUN_TEST(a_sweep_makes_an_unchanged_nat_due);
    RUN_TEST(parts_that_join_to_the_same_text_are_not_the_same_staging);
    RUN_TEST(a_skipped_sweep_does_not_wait_for_the_next_commit);
    GREATEST_MAIN_END();
}
