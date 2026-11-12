#include "greatest.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "fake_iptables.h"
#include "fake_xtables.h"
#include "firc/cancel.h"
#include "firc/iptables.h"
#include "firc/log.h"
#include "firc/xtables.h"
#include "xt_golden.h"

static FILE *g_log;

static void log_start(firc_log_level_t level) {
    g_log = tmpfile();
    firc_log_set_fd(fileno(g_log));
    firc_log_set_output_floor(level);
}

static char *log_stop(void) {
    firc_log_set_fd(STDOUT_FILENO);
    firc_log_set_output_floor(FIRC_LOG_INFO);
    long n = ftell(g_log);
    char *text = calloc(1, (size_t)(n > 0 ? n : 0) + 1);
    rewind(g_log);
    if (n > 0 && fread(text, 1, (size_t)n, g_log) != (size_t)n) { text[0] = '\0'; }
    fclose(g_log);
    return text;
}

static size_t count(const char *hay, const char *needle) {
    size_t n = 0;
    for (const char *p = strstr(hay, needle); p != NULL; p = strstr(p + 1, needle)) { n++; }
    return n;
}

static firc_ipt_t *engine(firc_fake_ipt_t **f) {
    *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    return *f != NULL ? firc_ipt_new(firc_fake_ipt_as_xt(*f), "FIRC_") : NULL;
}

static firc_err_t add(firc_ipt_t *ipt, const char *table, const char *chain, const char *line) {
    firc_ipt_rule_t *r = firc_test_rule(line);
    firc_err_t err = firc_ipt_append(ipt, table, chain, (const char *const *)r->parts, r->n_parts);
    firc_ipt_rule_free(r);
    return err;
}

static firc_err_t ins1(firc_ipt_t *ipt, const char *table, const char *chain, const char *line) {
    firc_ipt_rule_t *r = firc_test_rule(line);
    firc_err_t err = firc_ipt_insert(ipt, table, chain, 1, (const char *const *)r->parts, r->n_parts);
    firc_ipt_rule_free(r);
    return err;
}

static bool has(firc_fake_ipt_t *f, const char *table, const char *line) {
    char *text = firc_fake_ipt_print(f, table);
    char want[512];
    snprintf(want, sizeof(want), "%s\n", line);
    bool found = text != NULL && strstr(text, want) != NULL;
    free(text);
    return found;
}

static void first_rule(firc_fake_ipt_t *f, const char *table, const char *chain, char *out, size_t cap) {
    char *text = firc_fake_ipt_print(f, table);
    char head[64];
    snprintf(head, sizeof(head), "-A %s ", chain);
    out[0] = '\0';
    const char *at = text != NULL ? strstr(text, head) : NULL;
    if (at != NULL) {
        const char *nl = strchr(at, '\n');
        size_t n = nl != NULL ? (size_t)(nl - at) : strlen(at);
        if (n >= cap) { n = cap - 1; }
        memcpy(out, at, n);
        out[n] = '\0';
    }
    free(text);
}

static void stage_mangle(firc_ipt_t *ipt, const char *chain, const char *mark) {
    char jump[64], line[128];
    snprintf(jump, sizeof(jump), "-j %s", chain);
    snprintf(line, sizeof(line), "-d 198.18.0.0/24 -j MARK --set-xmark %s/0x40ff0000", mark);
    (void)firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING");
    (void)add(ipt, "mangle", "PREROUTING", jump);
    (void)firc_ipt_register_chain_override(ipt, "mangle", chain);
    (void)add(ipt, "mangle", chain, line);
}

/* Catches: an override that would replace a firmware chain whole, or a patch of a chain of ours, slipping through. */
TEST registrations_keep_to_their_kind(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_register_chain_override(ipt, "mangle", "_NDM_QOS"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_register_chain_override(ipt, "mangle", "PREROUTING"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_register_chain_patch(ipt, "mangle", "FIRC_g"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_register_chain_patch(ipt, "raw", "PREROUTING"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, ins1(ipt, "mangle", "FIRC_g", "-j RETURN"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_STATE, add(ipt, "mangle", "FIRC_other", "-j RETURN"), "%d");
    const uint8_t fake[4] = {198, 18, 0, 5}, real[4] = {1, 1, 1, 1};
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_append_dnat(ipt, "nat", "PREROUTING", fake, real), "%d");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a rule outside what firc writes reaching the kernel, or quoted at every pass instead of once. */
TEST a_rule_outside_the_vocabulary_is_refused_at_append_and_said_once(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    log_start(FIRC_LOG_INFO);
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_FMT(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g"), "%d");
        ASSERT_EQ_FMT(FIRC_ERR_INVAL, add(ipt, "mangle", "FIRC_g", "-j MARK --set-mark 7"), "%d");
        firc_ipt_discard(ipt);
    }
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, "the rule \"-j MARK --set-mark 7\" in FIRC_g is outside what firc writes"), "%zu");
    free(text);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a table left on another writer, or a registration not reaching the kernel. */
TEST every_table_is_written_through_x_tables(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "FORWARD"));
    ASSERT_EQ(FIRC_OK, ins1(ipt, "filter", "FORWARD", "-j FIRC_f"));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "FIRC_f"));
    ASSERT_EQ(FIRC_OK, add(ipt, "filter", "FIRC_f", "-d 198.18.0.0/15 -p tcp -j REJECT --reject-with tcp-reset"));
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING"));
    ASSERT_EQ(FIRC_OK, add(ipt, "nat", "PREROUTING", "-d 198.18.0.0/15 -j FIRC_DNAT"));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT"));
    const uint8_t fake[4] = {198, 18, 0, 5}, real[4] = {93, 184, 216, 34};
    ASSERT_EQ(FIRC_OK, firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", fake, real));
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT(has(f, "filter", "-A FIRC_f -d 198.18.0.0/15 -p tcp -j REJECT --reject-with tcp-reset"));
    ASSERT(has(f, "filter", "-A FORWARD -j FIRC_f"));
    ASSERT(has(f, "mangle", "-A FIRC_g -d 198.18.0.0/24 -j MARK --set-xmark 0x40010000/0x40ff0000"));
    ASSERT(has(f, "nat", "-A FIRC_DNAT -d 198.18.0.5/32 -m mark --mark 0x40000000/0x40000000 -j DNAT --to-destination 93.184.216.34"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a chain of ours a pass no longer stages surviving it, or a foreign rule taken with it. */
TEST an_unstaged_chain_of_ours_is_gone_after_the_next_commit(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    static const char *foreign[] = {"-i", "eth0", "-j", "RETURN"};
    const char *const *rules[1] = {foreign};
    size_t lens[1] = {4};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(f, "mangle", "PREROUTING", rules, lens, 1));
    stage_mangle(ipt, "FIRC_a", "0x40010000");
    ASSERT_EQ(FIRC_OK, add(ipt, "mangle", "PREROUTING", "-j FIRC_b"));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_b"));
    ASSERT_EQ(FIRC_OK, add(ipt, "mangle", "FIRC_b", "-j RETURN"));
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_b"));
    stage_mangle(ipt, "FIRC_a", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_b"));
    ASSERT_FALSE(has(f, "mangle", "-A PREROUTING -j FIRC_b"));
    ASSERT(has(f, "mangle", "-A PREROUTING -i eth0 -j RETURN"));
    ASSERT(has(f, "mangle", "-A PREROUTING -j FIRC_a"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a commit reading or writing a table nothing registered (a DNS-only pass costing mangle and filter). */
TEST a_table_not_registered_is_not_touched(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    size_t reads = firc_fake_xt_reads(firc_fake_ipt_xt(f));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING"));
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMT(reads + 1, firc_fake_xt_reads(firc_fake_ipt_xt(f)), "%zu");
    ASSERT(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_g"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a registration outliving its commit, so a chain a later pass no longer stages comes back. */
TEST registrations_do_not_outlive_their_commit(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    stage_mangle(ipt, "FIRC_x", "0x40010000");
    firc_fake_ipt_fail_next_write(f, FIRC_ERR_IO);
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_ipt_commit(ipt), "%d");
    size_t writes = firc_fake_ipt_writes(f);
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMT(writes, firc_fake_ipt_writes(f), "%zu");
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_x"));
    stage_mangle(ipt, "FIRC_x", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    size_t reads = firc_fake_xt_reads(firc_fake_ipt_xt(f));
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMT(reads, firc_fake_xt_reads(firc_fake_ipt_xt(f)), "%zu");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a table staged as last written read or written again, or a changed one skipped. */
TEST an_unchanged_staging_costs_no_read(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    size_t reads = firc_fake_xt_reads(firc_fake_ipt_xt(f));
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMT(reads, firc_fake_xt_reads(firc_fake_ipt_xt(f)), "%zu");
    stage_mangle(ipt, "FIRC_g", "0x40020000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMT(reads + 1, firc_fake_xt_reads(firc_fake_ipt_xt(f)), "%zu");
    ASSERT(has(f, "mangle", "-A FIRC_g -d 198.18.0.0/24 -j MARK --set-xmark 0x40020000/0x40ff0000"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a commit trusting the skip, so a chain the firmware's rewrite took away unheard is not put back. */
TEST a_commit_puts_back_what_a_rewrite_took(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    firc_fake_xt_reset(firc_fake_ipt_xt(f));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_g"));
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_g"));
    ASSERT(has(f, "mangle", "-A PREROUTING -j FIRC_g"));
    firc_ipt_free(ipt);
    PASS();
}

static void stage_dnsor(firc_ipt_t *ipt, const char *addr) {
    char line[128];
    snprintf(line, sizeof(line), "-p udp -d %s --dport 53 -j DNAT --to-destination :3553", addr);
    (void)firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING");
    (void)ins1(ipt, "nat", "PREROUTING", "-j FIRC_DNSOR");
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNSOR");
    (void)add(ipt, "nat", "FIRC_DNSOR", line);
}

/* Catches: an incremental commit moving a jump someone put a rule above, or a full commit leaving it below. */
TEST a_full_commit_puts_our_jumps_back_in_place(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    stage_dnsor(ipt, "192.168.1.1");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    static const char *other[] = {"-i", "eth0", "-j", "ACCEPT"};
    static const char *ours[] = {"-j", "FIRC_DNSOR"};
    const char *const *rules[2] = {other, ours};
    size_t lens[2] = {4, 2};
    ASSERT_EQ(FIRC_OK, firc_fake_ipt_set_initial_rules(f, "nat", "PREROUTING", rules, lens, 2));
    char first[160];
    stage_dnsor(ipt, "192.168.1.2");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    first_rule(f, "nat", "PREROUTING", first, sizeof(first));
    ASSERT_STR_EQm("an incremental commit keeps it where it is", "-A PREROUTING -i eth0 -j ACCEPT", first);
    stage_dnsor(ipt, "192.168.1.2");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit_full(ipt), "%d");
    first_rule(f, "nat", "PREROUTING", first, sizeof(first));
    ASSERT_STR_EQm("a full commit puts it first", "-A PREROUTING -j FIRC_DNSOR", first);
    ASSERT(has(f, "nat", "-A PREROUTING -i eth0 -j ACCEPT"));
    firc_ipt_free(ipt);
    PASS();
}

static void raise_cancel(void *ud) { firc_cancel_raise(ud); }

/* Catches: a cancel between two tables remembered as a completed write, so the second table is never written. */
TEST a_cancel_between_tables_leaves_the_rest_owed(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    firc_cancel_t *cancel = firc_cancel_new();
    firc_ipt_set_cancel(ipt, cancel);
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "FORWARD"));
    ASSERT_EQ(FIRC_OK, add(ipt, "filter", "FORWARD", "-j FIRC_f"));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "FIRC_f"));
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    firc_fake_ipt_on_write(f, raise_cancel, cancel);
    ASSERT_EQ_FMT(FIRC_ERR_CANCELED, firc_ipt_commit(ipt), "%d");
    firc_fake_ipt_on_write(f, NULL, NULL);
    ASSERT(firc_fake_ipt_chain_exists(f, "filter", "FIRC_f"));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_g"));
    firc_cancel_clear(cancel);
    size_t reads = firc_fake_xt_reads(firc_fake_ipt_xt(f));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "filter", "FORWARD"));
    ASSERT_EQ(FIRC_OK, add(ipt, "filter", "FORWARD", "-j FIRC_f"));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "filter", "FIRC_f"));
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMTm("filter was written and is skipped", reads + 1, firc_fake_xt_reads(firc_fake_ipt_xt(f)), "%zu");
    ASSERT(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_g"));
    firc_ipt_set_cancel(ipt, NULL);
    firc_cancel_free(cancel);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: the capture's probe left in the table, written into a registration, or forgetting the skip copies. */
TEST the_probe_chain_is_written_and_taken_away(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    firc_ipt_rule_t *rules[2] = {firc_test_rule("-i br0 -m conntrack --ctstate NEW -j NFLOG --nflog-group 5"),
                                 firc_test_rule("-i br0 -j RETURN")};
    char *before = firc_fake_xt_write_order(firc_fake_ipt_xt(f));
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_probe_chain(ipt, "mangle", "FIRC_TAPPROBE", rules, 2), "%d");
    char *after = firc_fake_xt_write_order(firc_fake_ipt_xt(f));
    ASSERT_STR_EQ("mangle\nmangle\n", after + strlen(before));
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_TAPPROBE"));
    ASSERT(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_g"));
    size_t reads = firc_fake_xt_reads(firc_fake_ipt_xt(f));
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMT(reads, firc_fake_xt_reads(firc_fake_ipt_xt(f)), "%zu");
    firc_fake_ipt_refuse_rules_containing(f, "NFLOG");
    ASSERT_EQ_FMT(FIRC_ERR_IO, firc_ipt_probe_chain(ipt, "mangle", "FIRC_TAPPROBE", rules, 2), "%d");
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_TAPPROBE"));
    free(before);
    free(after);
    firc_ipt_rule_free(rules[0]);
    firc_ipt_rule_free(rules[1]);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a patch registered on a chain its table lacks, written as a user chain named like a built-in. */
TEST a_patch_names_a_chain_its_table_has(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_register_chain_patch(ipt, "filter", "PREROUTING"), "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_register_chain_patch(ipt, "nat", "FORWARD"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_register_chain_patch(ipt, "mangle", "FORWARD"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_register_chain_patch(ipt, "nat", "OUTPUT"), "%d");
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a refusal after a landed commit kept at DEBUG, so the next bad rule goes unsaid. */
TEST a_refusal_is_said_again_after_a_commit_lands(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    log_start(FIRC_LOG_INFO);
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g"));
    ASSERT_EQ(FIRC_ERR_INVAL, add(ipt, "mangle", "FIRC_g", "-j MARK --set-mark 7"));
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_g"));
    ASSERT_EQ(FIRC_ERR_INVAL, add(ipt, "mangle", "FIRC_g", "-j MARK --set-mark 7"));
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)2, count(text, "outside what firc writes"), "%zu");
    free(text);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: an override written under mac revision 0 on a kernel the probe found revision 1 in (Keenetic). */
TEST an_override_is_encoded_for_the_mac_revision_the_kernel_has(void) {
    firc_fake_ipt_t *f = firc_fake_ipt_new(FIRC_IPT_PROTO_IPV4);
    firc_xt_t *xt = firc_fake_ipt_as_xt(f);
    ASSERT_EQ(FIRC_OK, firc_xt_probe(xt));
    ASSERT_EQ(1, firc_xt_mac_rev(xt));
    firc_ipt_t *ipt = firc_ipt_new(xt, "FIRC_");
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING"));
    ASSERT_EQ(FIRC_OK, add(ipt, "mangle", "PREROUTING", "-j FIRC_gD"));
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_override(ipt, "mangle", "FIRC_gD"));
    ASSERT_EQ(FIRC_OK, add(ipt, "mangle", "FIRC_gD", "-m mac --mac-source AA:BB:CC:DD:EE:01 -j MARK --set-xmark 0x40010000/0x40ff0000"));
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_gD"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a probe chain whose take-away failed left behind by commits that skip mangle as last written. */
TEST a_probe_chain_left_behind_is_dropped_by_the_next_commit(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    firc_ipt_rule_t *rules[1] = {firc_test_rule("-i br0 -j RETURN")};
    firc_fake_ipt_fail_at_commit(f, 2, FIRC_ERR_IO);
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_probe_chain(ipt, "mangle", "FIRC_TAPPROBE", rules, 1), "%d");
    ASSERT(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_TAPPROBE"));
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_FALSE(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_TAPPROBE"));
    ASSERT(firc_fake_ipt_chain_exists(f, "mangle", "FIRC_g"));
    firc_ipt_rule_free(rules[0]);
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: a later stager registering a base chain again and wiping the jumps an earlier one staged in it. */
TEST registering_a_patch_again_keeps_what_it_staged(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "mangle", "PREROUTING"));
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT(has(f, "mangle", "-A PREROUTING -j FIRC_g"));
    firc_ipt_free(ipt);
    PASS();
}

/* Catches: an address rewrite staged in a built-in chain, where the coverage check never reads it. */
TEST a_patch_refuses_an_address_rewrite(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    ASSERT_EQ(FIRC_OK, firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING"));
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, add(ipt, "nat", "PREROUTING", "-d 198.18.0.5/32 -j DNAT --to-destination 93.184.216.34"),
                  "%d");
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, add(ipt, "nat", "PREROUTING", "-j DNAT --to-destination 93.184.216.34"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, add(ipt, "nat", "PREROUTING", "-p udp -d 192.168.1.1/32 --dport 53 -j DNAT --to-destination :3553"),
                  "%d");
    firc_ipt_free(ipt);
    PASS();
}

static void stage_uncovered(firc_ipt_t *ipt) {
    (void)firc_ipt_register_chain_patch(ipt, "nat", "PREROUTING");
    (void)add(ipt, "nat", "PREROUTING", "-d 198.18.0.0/15 -j FIRC_DNAT");
    (void)firc_ipt_register_chain_override(ipt, "nat", "FIRC_DNAT");
    const uint8_t fake[4] = {198, 18, 1, 5}, real[4] = {93, 184, 216, 34};
    (void)firc_ipt_append_dnat(ipt, "nat", "FIRC_DNAT", fake, real);
}

/* Catches: an uncovered rewrite warned about on every pass, not warned about again after a pass that landed, or the landing pass not saying it recovered. */
TEST an_uncovered_rewrite_is_warned_about_once_per_run_of_refusals(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    log_start(FIRC_LOG_INFO);
    for (int i = 0; i < 3; i++) {
        stage_uncovered(ipt);
        ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_commit(ipt), "%d");
    }
    stage_mangle(ipt, "FIRC_g", "0x40010000");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    stage_uncovered(ipt);
    ASSERT_EQ_FMT(FIRC_ERR_INVAL, firc_ipt_commit(ipt), "%d");
    char *text = log_stop();
    ASSERT_EQ_FMTm(text, (size_t)2, count(text, "without their mark"), "%zu");
    ASSERT_EQ_FMTm(text, (size_t)1, count(text, " INF x_tables ipv4 nat rewrites: recovered after 3 failures over "),
                   "%zu");
    free(text);
    firc_ipt_free(ipt);
    PASS();
}

TEST restaging_the_same_set_rule_writes_nothing(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    firc_fake_xt_set(firc_fake_ipt_xt(f), "fircA", 7);
    firc_fake_xt_set(firc_fake_ipt_xt(f), "fircB", 8);
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_s");
    ASSERT_EQ_FMT(FIRC_OK, add(ipt, "mangle", "FIRC_s", "-m set --match-set fircA dst -j RETURN"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    size_t reads = firc_fake_xt_reads(firc_fake_ipt_xt(f)), replaces = firc_fake_xt_replaces(firc_fake_ipt_xt(f));
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_s");
    ASSERT_EQ_FMT(FIRC_OK, add(ipt, "mangle", "FIRC_s", "-m set --match-set fircA dst -j RETURN"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMT(reads, firc_fake_xt_reads(firc_fake_ipt_xt(f)), "%zu");
    ASSERT_EQ_FMT(replaces, firc_fake_xt_replaces(firc_fake_ipt_xt(f)), "%zu");
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_s");
    ASSERT_EQ_FMT(FIRC_OK, add(ipt, "mangle", "FIRC_s", "-m set --match-set fircB dst -j RETURN"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT_EQ_FMT(replaces + 1, firc_fake_xt_replaces(firc_fake_ipt_xt(f)), "%zu");
    ASSERT(has(f, "mangle", "-A FIRC_s -m set --match-set fircB dst -j RETURN"));
    firc_ipt_free(ipt);
    PASS();
}

TEST the_printer_names_the_set(void) {
    firc_fake_ipt_t *f;
    firc_ipt_t *ipt = engine(&f);
    firc_fake_xt_set(firc_fake_ipt_xt(f), "fircAS4", 7);
    (void)firc_ipt_register_chain_override(ipt, "mangle", "FIRC_s");
    ASSERT_EQ_FMT(FIRC_OK, add(ipt, "mangle", "FIRC_s", "-p tcp --dport 53 -m set --match-set fircAS4 dst -j RETURN"), "%d");
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_commit(ipt), "%d");
    ASSERT(has(f, "mangle", "-A FIRC_s -p tcp -m tcp --dport 53 -m set --match-set fircAS4 dst -j RETURN"));
    firc_ipt_rule_t *const *rules = NULL;
    size_t n = 0;
    ASSERT(firc_fake_ipt_get_rules(f, "mangle", "FIRC_s", &rules, &n));
    ASSERT_EQ_FMT((size_t)1, n, "%zu");
    ASSERT(firc_test_rule_contains(rules[0], "--match-set fircAS4 dst"));
    firc_ipt_free(ipt);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(registrations_keep_to_their_kind);
    RUN_TEST(a_rule_outside_the_vocabulary_is_refused_at_append_and_said_once);
    RUN_TEST(every_table_is_written_through_x_tables);
    RUN_TEST(an_unstaged_chain_of_ours_is_gone_after_the_next_commit);
    RUN_TEST(a_table_not_registered_is_not_touched);
    RUN_TEST(registrations_do_not_outlive_their_commit);
    RUN_TEST(an_unchanged_staging_costs_no_read);
    RUN_TEST(a_commit_puts_back_what_a_rewrite_took);
    RUN_TEST(a_full_commit_puts_our_jumps_back_in_place);
    RUN_TEST(a_cancel_between_tables_leaves_the_rest_owed);
    RUN_TEST(the_probe_chain_is_written_and_taken_away);
    RUN_TEST(a_patch_names_a_chain_its_table_has);
    RUN_TEST(a_refusal_is_said_again_after_a_commit_lands);
    RUN_TEST(an_override_is_encoded_for_the_mac_revision_the_kernel_has);
    RUN_TEST(a_probe_chain_left_behind_is_dropped_by_the_next_commit);
    RUN_TEST(registering_a_patch_again_keeps_what_it_staged);
    RUN_TEST(a_patch_refuses_an_address_rewrite);
    RUN_TEST(an_uncovered_rewrite_is_warned_about_once_per_run_of_refusals);
    RUN_TEST(restaging_the_same_set_rule_writes_nothing);
    RUN_TEST(the_printer_names_the_set);
    GREATEST_MAIN_END();
}
