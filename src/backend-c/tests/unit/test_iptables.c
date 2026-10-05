#include "greatest.h"

#include "fake_iptables.h"
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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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
             firc_fake_ipt_set_initial_rules(fake, "nat", "PREROUTING", initial, initial_lens, 2));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "PREROUTING"));
    const char *rudp[] = {"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", "5353"};
    ASSERT_EQ(FIRC_OK, firc_ipt_append(ipt, "nat", "PREROUTING", rudp, 8));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    firc_ipt_rule_t *const *got;
    size_t n_got;
    ASSERT(firc_fake_ipt_get_rules(fake, "nat", "PREROUTING", &got, &n_got));
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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "MY_CHAIN"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "MY_CHAIN"));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_delete_removes_empty_chain(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(fake, "filter", "EMPTY_CHAIN", NULL, NULL, 0));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "EMPTY_CHAIN"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));

    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "EMPTY_CHAIN"));

    firc_ipt_free(ipt);
    PASS();
}

TEST chain_delete_nonexistent_is_noop(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "NON_EXISTENT"));
    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "NON_EXISTENT"));
    firc_ipt_free(ipt);
    PASS();
}

TEST chain_delete_ignores_mutations(void) {
    firc_fake_ipt_t *fake = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    const char *racc[] = {"-j", "ACCEPT"};
    const char *const *initial[] = {racc};
    size_t initial_lens[] = {2};
    ASSERT_EQ(FIRC_OK,
             firc_fake_ipt_set_initial_rules(fake, "filter", "TO_DELETE", initial, initial_lens, 1));

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_delete(ipt, "filter", "TO_DELETE"));

    const char *rdrop[] = {"-j", "DROP"};
    const char *rlog[] = {"-j", "LOG"};
    (void)firc_ipt_append(ipt, "filter", "TO_DELETE", rdrop, 2);
    (void)firc_ipt_insert(ipt, "filter", "TO_DELETE", 1, rlog, 2);
    (void)firc_ipt_delete(ipt, "filter", "TO_DELETE", racc, 2);

    ASSERT_EQ(FIRC_OK, firc_ipt_commit(ipt));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(fake, "filter", "TO_DELETE"));

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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));

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
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));

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
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));

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

    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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
                            "*nat\n:C - [0:0]\n-A C -j RETURN\nCOMMIT\n";
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(f));
    ASSERT(ipt != NULL);

    firc_fake_ipt_fail_at_commit(f, 2, FIRC_ERR_IO);
    ASSERT(firc_fake_ipt_failure_armed(f));
    ASSERT_EQ(FIRC_ERR_IO, firc_ipt_write_transcript(ipt, (const uint8_t *)t, sizeof(t) - 1));
    ASSERTm("the table before the failing COMMIT landed", firc_fake_ipt_chain_exists(f, "filter", "A"));
    ASSERT_FALSEm("the failing table did not", firc_fake_ipt_chain_exists(f, "mangle", "B"));
    ASSERT_FALSEm("nor anything after it", firc_fake_ipt_chain_exists(f, "nat", "C"));
    ASSERT_FALSEm("it fired, once", firc_fake_ipt_failure_armed(f));

    ASSERT_EQ(FIRC_OK, firc_ipt_write_transcript(ipt, (const uint8_t *)t, sizeof(t) - 1));
    ASSERTm("the next call is whole", firc_fake_ipt_chain_exists(f, "mangle", "B") &&
                                      firc_fake_ipt_chain_exists(f, "nat", "C"));

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
    firc_ipt_t *ipt = firc_ipt_new(firc_fake_ipt_as_executable(fake));
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

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
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
    RUN_TEST(chain_delete_ignores_mutations);
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
    GREATEST_MAIN_END();
}
