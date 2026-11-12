#include "greatest.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "firc/kmod.h"
#include "firc/log.h"

static bool read_log_after_netfilter_load(const char *const *files, size_t n, char *log, size_t cap, size_t *loaded) {
    char dir[64];
    snprintf(dir, sizeof(dir), "/tmp/firc-kmod-XXXXXX");
    if (mkdtemp(dir) == NULL) { return false; }
    for (size_t i = 0; i < n; i++) {
        char path[128];
        snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
        FILE *f = fopen(path, "w");
        if (f == NULL) { return false; }
        fputs("not a module", f);
        fclose(f);
    }
    char logpath[96];
    snprintf(logpath, sizeof(logpath), "%s/log", dir);
    int fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { return false; }
    firc_log_set_fd(fd);
    *loaded = firc_kmod_load_netfilter(dir);
    firc_log_set_fd(2);
    close(fd);
    FILE *f = fopen(logpath, "r");
    if (f == NULL) { return false; }
    size_t got = fread(log, 1, cap - 1, f);
    log[got] = '\0';
    fclose(f);
    unlink(logpath);
    for (size_t i = 0; i < n; i++) {
        char path[128];
        snprintf(path, sizeof(path), "%s/%s", dir, files[i]);
        unlink(path);
    }
    rmdir(dir);
    return true;
}

/* Catches: the pass's modular matches (multiport for port lists, addrtype for kernel TCP) never loaded at start, so the probe calls them missing. */
TEST the_netfilter_loader_tries_multiport_and_addrtype(void) {
    const char *files[] = {"xt_multiport.ko", "xt_addrtype.ko"};
    char log[8192];
    size_t loaded = 99;
    ASSERT(read_log_after_netfilter_load(files, 2, log, sizeof(log), &loaded));
    ASSERT_EQ_FMT((size_t)0, loaded, "%zu");
    ASSERTm("multiport attempted", strstr(log, "kernel module xt_multiport would not load") != NULL);
    ASSERTm("addrtype attempted", strstr(log, "kernel module xt_addrtype would not load") != NULL);
    ASSERTm("said what needs it", strstr(log, "firc's rules may need it") != NULL);
    PASS();
}

/* Catches: a module the firmware builds in (no file) reported as a failure. */
TEST a_module_without_a_file_is_not_mentioned(void) {
    const char *files[] = {"xt_multiport.ko"};
    char log[8192];
    size_t loaded = 99;
    ASSERT(read_log_after_netfilter_load(files, 1, log, sizeof(log), &loaded));
    ASSERT(strstr(log, "xt_multiport") != NULL);
    ASSERT(strstr(log, "xt_addrtype") == NULL);
    PASS();
}

TEST the_netfilter_loader_tries_the_set_modules_in_order(void) {
    const char *files[] = {"xt_set.ko", "ip_set_hash_net.ko", "ip_set.ko"};
    char log[8192];
    size_t loaded = 99;
    ASSERT(read_log_after_netfilter_load(files, 3, log, sizeof(log), &loaded));
    ASSERT_EQ_FMT((size_t)0, loaded, "%zu");
    const char *core = strstr(log, "kernel module ip_set would not load");
    const char *hash = strstr(log, "kernel module ip_set_hash_net would not load");
    const char *match = strstr(log, "kernel module xt_set would not load");
    ASSERT(core != NULL && hash != NULL && match != NULL);
    ASSERT(core < hash && hash < match);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_netfilter_loader_tries_multiport_and_addrtype);
    RUN_TEST(a_module_without_a_file_is_not_mentioned);
    RUN_TEST(the_netfilter_loader_tries_the_set_modules_in_order);
    GREATEST_MAIN_END();
}
