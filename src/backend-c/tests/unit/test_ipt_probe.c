#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "firc/iptables.h"
#include "firc/log.h"
#include "firc/taprules.h"

#define PREFIX "FIRC_"

static char g_dir[64];
static char g_log[96];
static char *g_old_path;

static firc_fakeip_t *make_pool(void) {
    firc_fakeip_cfg_t c = {0};
    c.v4.base.len = 4; c.v4.base.b[0] = 198; c.v4.base.b[1] = 18;
    c.v4.pool_cidr = 15; c.v4.chunk_cidr = 24;
    c.v6.base.len = 16; c.v6.base.b[0] = 0xfd; c.v6.base.b[1] = 0x37;
    c.v6.pool_cidr = 48; c.v6.chunk_cidr = 64;
    c.max_names = 64; c.idle_secs = 86400; c.clamp_secs = 300;
    firc_fakeip_t *f = NULL;
    return firc_fakeip_new(&c, &f) == FIRC_OK ? f : NULL;
}

/* Installs a stand-in iptables logging each call; `refuse_nflog` makes a real NFLOG write fail. */
static void stand_in(int refuse_nflog) {
    char path[128];
    snprintf(path, sizeof(path), "%s/iptables-restore", g_dir);
    FILE *f = fopen(path, "w");
    fprintf(f,
            "#!/bin/sh\n"
            "in=$(cat)\n"
            "printf '== %%s\\n%%s\\n' \"$*\" \"$in\" >> '%s'\n"
            "case \"$*\" in *--test*) exit 0 ;; esac\n"
            "if [ %d = 1 ] && printf '%%s' \"$in\" | grep -q -- '-j NFLOG'; then\n"
            "  echo 'iptables-restore: line 4 failed' >&2; exit 1\n"
            "fi\n"
            "exit 0\n",
            g_log, refuse_nflog);
    fclose(f);
    chmod(path, 0755);
    unlink(g_log);
}

static char *read_log(void) {
    FILE *f = fopen(g_log, "r");
    if (f == NULL) { return strdup(""); }
    char *buf = calloc(1, 65536);
    size_t n = fread(buf, 1, 65535, f);
    buf[n] = '\0';
    fclose(f);
    return buf;
}

static void setup(void *ud) {
    (void)ud;
    snprintf(g_dir, sizeof(g_dir), "/tmp/firc-probe-XXXXXX");
    if (mkdtemp(g_dir) == NULL) { abort(); }
    snprintf(g_log, sizeof(g_log), "%s/calls.log", g_dir);
    const char *old = getenv("PATH");
    g_old_path = strdup(old ? old : "");
    char path[4096];
    snprintf(path, sizeof(path), "%s:%s", g_dir, g_old_path);
    setenv("PATH", path, 1);
}

static void teardown(void *ud) {
    (void)ud;
    setenv("PATH", g_old_path, 1);
    free(g_old_path);
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) {  }
}

/* Catches: the preflight asking `iptables-restore --test`, which 1.4.21 always passes. */
TEST a_kernel_that_refuses_the_write_refuses_the_capture(void) {
    stand_in(1);
    firc_fakeip_t *pool = make_pool();
    firc_ipt_t *ipt = firc_ipt_new(firc_ipt_executable_real_new(FIRC_IPT_PROTO_IPV4), NULL);
    ASSERT(pool != NULL && ipt != NULL);
    const char *lan[] = {"br0"};
    ASSERT_EQ_FMT(FIRC_ERR_NOSYS, firc_tap_rules_supported(ipt, PREFIX, pool, lan, 1), "%d");
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the probe reusing the capture's chain or jump, or leaving its chain behind. */
TEST an_accepted_probe_writes_nothing_that_stays(void) {
    stand_in(0);
    firc_fakeip_t *pool = make_pool();
    firc_ipt_t *ipt = firc_ipt_new(firc_ipt_executable_real_new(FIRC_IPT_PROTO_IPV4), NULL);
    ASSERT(pool != NULL && ipt != NULL);
    const char *lan[] = {"br0"};
    ASSERT_EQ_FMT(FIRC_OK, firc_tap_rules_supported(ipt, PREFIX, pool, lan, 1), "%d");

    char *log = read_log();
    const char *probe = PREFIX FIRC_TAP_CHAIN_SUFFIX FIRC_TAP_PROBE_SUFFIX;
    char want[160];
    ASSERTm("no call asks --test", strstr(log, "--test") == NULL);
    ASSERTm("no call touches FORWARD", strstr(log, "FORWARD") == NULL);
    snprintf(want, sizeof(want), "-A %s -i br0", probe);
    ASSERTm("the rules are written into the probe chain", strstr(log, want) != NULL);
    snprintf(want, sizeof(want), "-A %s -i br0 -m conntrack --ctstate NEW", probe);
    ASSERTm("including the new-connection rule", strstr(log, want) != NULL);
    snprintf(want, sizeof(want), "-X %s", probe);
    const char *del = strstr(log, want);
    ASSERTm("and the chain is deleted again", del != NULL);
    snprintf(want, sizeof(want), "-A %s", probe);
    ASSERTm("after it was written", strstr(log, want) < del);
    free(log);
    firc_ipt_free(ipt);
    firc_fakeip_free(pool);
    PASS();
}

/* Catches: the loader stopping at its first refused module, or not logging one. */
TEST the_loader_names_each_module_the_kernel_refuses(void) {
    const char *names[] = {"nfnetlink_log.ko", "xt_string.ko"};
    for (size_t i = 0; i < 2; i++) {
        char path[128];
        snprintf(path, sizeof(path), "%s/%s", g_dir, names[i]);
        FILE *f = fopen(path, "w");
        ASSERT(f != NULL);
        fputs("not a module", f);
        fclose(f);
    }
    int fd = open(g_log, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT(fd >= 0);
    firc_log_set_fd(fd);
    size_t loaded = firc_tap_load_modules(g_dir);
    firc_log_set_fd(2);
    close(fd);

    ASSERT_EQ_FMT((size_t)0, loaded, "%zu");
    char *log = read_log();
    ASSERTm("the first refusal is named", strstr(log, "nfnetlink_log") != NULL);
    ASSERTm("and the loader went on to the next", strstr(log, "xt_string") != NULL);
    ASSERTm("a module with no file is not mentioned", strstr(log, "xt_NFLOG") == NULL);
    free(log);
    PASS();
}

static firc_err_t restore_logged(const char *transcript, char *log, size_t cap) {
    firc_ipt_executable_t *exe = firc_ipt_executable_real_new(FIRC_IPT_PROTO_IPV4);
    if (exe == NULL) { return FIRC_ERR_NOMEM; }
    char out[128];
    snprintf(out, sizeof(out), "%s/daemon.log", g_dir);
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        firc_ipt_executable_free(exe);
        return FIRC_ERR_SYS;
    }
    firc_log_level_t kept = firc_log_level();
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fd);
    firc_err_t err = exe->ops->restore(exe, (const uint8_t *)transcript, strlen(transcript));
    firc_log_set_fd(2);
    firc_log_set_level(kept);
    close(fd);
    firc_ipt_executable_free(exe);
    log[0] = '\0';
    FILE *f = fopen(out, "r");
    if (f != NULL) {
        size_t n = fread(log, 1, cap - 1, f);
        log[n] = '\0';
        fclose(f);
    }
    return err;
}

/* Catches: a refused restore said at ERR, losing the quoted line, or not FIRC_ERR_IO. */
TEST a_refused_restore_is_a_warning_that_quotes_the_line(void) {
    stand_in(1);
    char log[4096];
    firc_err_t err = restore_logged("*filter\n"
                                    ":X - [0:0]\n"
                                    "-A X -j ACCEPT\n"
                                    "-A X -j NFLOG\n"
                                    "COMMIT\n",
                                    log, sizeof(log));
    ASSERT_EQ_FMT(FIRC_ERR_IO, err, "%d");
    ASSERTm("the refusal is said, at WARN",
            strstr(log, " WRN iptables-restore failed (status=256): iptables-restore: line 4 failed") != NULL);
    ASSERTm("with the line it refused", strstr(log, "the line it refused was: -A X -j NFLOG") != NULL);
    ASSERTm("and nothing at ERR", strstr(log, " ERR ") == NULL);
    PASS();
}

/* Catches: a refusal at COMMIT, the firmware's usual race, said at WARN on its first time. */
TEST a_refusal_at_commit_is_not_a_warning(void) {
    stand_in(1);
    char log[4096];
    firc_err_t err = restore_logged("*filter\n"
                                    ":X - [0:0]\n"
                                    "-A X -j NFLOG\n"
                                    "COMMIT\n",
                                    log, sizeof(log));
    ASSERT_EQ_FMT(FIRC_ERR_IO, err, "%d");
    ASSERT_STR_EQ("", log);
    PASS();
}

/* Catches: a refused save said at ERR, or not at all. */
TEST a_refused_save_is_a_warning_too(void) {
    char path[128];
    snprintf(path, sizeof(path), "%s/iptables-save", g_dir);
    FILE *sf = fopen(path, "w");
    ASSERT(sf != NULL);
    fputs("#!/bin/sh\necho \"iptables-save: can't initialize iptables table\" >&2\nexit 1\n", sf);
    fclose(sf);
    chmod(path, 0755);
    firc_ipt_executable_t *exe = firc_ipt_executable_real_new(FIRC_IPT_PROTO_IPV4);
    ASSERT(exe != NULL);
    char out[128];
    snprintf(out, sizeof(out), "%s/daemon.log", g_dir);
    int fd = open(out, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT(fd >= 0);
    firc_log_level_t kept = firc_log_level();
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fd);
    uint8_t *data = NULL;
    size_t len = 0;
    firc_err_t err = exe->ops->save(exe, "filter", &data, &len);
    firc_log_set_fd(2);
    firc_log_set_level(kept);
    close(fd);
    free(data);
    firc_ipt_executable_free(exe);

    ASSERT_EQ_FMT(FIRC_ERR_IO, err, "%d");
    FILE *f = fopen(out, "r");
    ASSERT(f != NULL);
    char log[4096];
    size_t n = fread(log, 1, sizeof(log) - 1, f);
    log[n] = '\0';
    fclose(f);
    ASSERTm("the refusal is said, at WARN",
            strstr(log, " WRN iptables-save failed (status=256): iptables-save: can't initialize iptables table") != NULL);
    ASSERTm("and nothing at ERR", strstr(log, " ERR ") == NULL);
    PASS();
}

/* Catches: the real save asking for every table when one was asked for. */
TEST the_real_save_asks_for_the_one_table(void) {
    char path[128];
    snprintf(path, sizeof(path), "%s/iptables-save", g_dir);
    FILE *sf = fopen(path, "w");
    ASSERT(sf != NULL);
    fprintf(sf, "#!/bin/sh\necho \"$*\" >> '%s'\nprintf '*mangle\\n:PREROUTING ACCEPT [0:0]\\nCOMMIT\\n'\n", g_log);
    fclose(sf);
    chmod(path, 0755);
    unlink(g_log);
    firc_ipt_t *ipt = firc_ipt_new(firc_ipt_executable_real_new(FIRC_IPT_PROTO_IPV4), NULL);
    ASSERT(ipt != NULL);
    firc_ipt_rules_snapshot_t *snap = NULL;
    const char *tables[] = {"mangle"};
    ASSERT_EQ_FMT(FIRC_OK, firc_ipt_get_current_rules(ipt, tables, 1, &snap), "%d");
    char *log = read_log();
    ASSERT_STR_EQ("-t mangle\n", log);
    ASSERT(firc_ipt_rules_snapshot_find_table(snap, "mangle") != NULL);
    free(log);
    firc_ipt_rules_snapshot_free(snap);
    firc_ipt_free(ipt);
    PASS();
}

SUITE(probe) {
    SET_SETUP(setup, NULL);
    SET_TEARDOWN(teardown, NULL);
    RUN_TEST(a_kernel_that_refuses_the_write_refuses_the_capture);
    RUN_TEST(an_accepted_probe_writes_nothing_that_stays);
    RUN_TEST(the_loader_names_each_module_the_kernel_refuses);
    RUN_TEST(a_refused_restore_is_a_warning_that_quotes_the_line);
    RUN_TEST(a_refusal_at_commit_is_not_a_warning);
    RUN_TEST(a_refused_save_is_a_warning_too);
    RUN_TEST(the_real_save_asks_for_the_one_table);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(probe);
    GREATEST_MAIN_END();
}
