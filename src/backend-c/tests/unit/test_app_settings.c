#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "firc/app.h"
#include "firc/dnsproxy.h"
#include "firc/log.h"
#include "firc/settings.h"
#include "firc/yamlio.h"

typedef struct {
    firc_config_t cfg;
    firc_loop_t *loop;
    firc_dnsproxy_t *proxy;
    firc_app_t *app;
} rig_t;

static firc_dns_verdict_t pass_hook(firc_dns_msg_t *msg, const firc_ip_t *client,
                                    const char *network, firc_dns_resolver_t resolver, void *ud) {
    (void)msg;
    (void)client;
    (void)network;
    (void)resolver;
    (void)ud;
    return FIRC_DNS_PASS;
}

static bool rig_up(rig_t *r) {
    memset(r, 0, sizeof(*r));
    firc_log_set_level(FIRC_LOG_INFO);
    if (firc_config_init_defaults(&r->cfg) != FIRC_OK) { return false; }
    if (firc_loop_create(&r->loop) != FIRC_OK) { return false; }
    firc_dnsproxy_config_t pcfg = {.listen_addr = "127.0.0.1", .listen_port = 1,
                                   .upstream_addr = "127.0.0.1", .upstream_port = 53,
                                   .timeout_ms = 1000, .max_concurrent = 4, .max_idle_conns = 2};
    if (firc_dnsproxy_create(&pcfg, r->loop, pass_hook, NULL, &r->proxy) != FIRC_OK) { return false; }
    firc_app_deps_t deps = {.cfg = &r->cfg, .proxy = r->proxy};
    r->app = firc_app_create(&deps);
    return r->app != NULL;
}

static void rig_down(rig_t *r) {
    firc_app_destroy(r->app);
    firc_dnsproxy_destroy(r->proxy);
    firc_loop_destroy(r->loop);
    firc_config_clear(&r->cfg);
    firc_log_set_level(FIRC_LOG_INFO);
}

static size_t row(const char *path) {
    const firc_setting_t *s = firc_setting_find(path);
    return s != NULL ? (size_t)(s - firc_settings) : FIRC_SETTINGS_COUNT;
}

/* The saved block with four live settings and one restart setting changed, as from the page. */
static firc_err_t edited(const firc_app_t *app, firc_app_config_t *next) {
    memset(next, 0, sizeof(*next));
    firc_err_t err = firc_app_config_copy(next, firc_app_saved_settings(app));
    if (err == FIRC_OK) { err = firc_strset(&next->dns_proxy.upstream.address, "9.9.9.9"); }
    if (err == FIRC_OK) { err = firc_strset(&next->log_level, "debug"); }
    next->dns_proxy.disable_drop_aaaa = true;
    next->show_all_interfaces = true;
    next->fakeip.max_names = 4096;
    return err;
}

static char *emit(const firc_app_config_t *a) {
    firc_config_t shell;
    memset(&shell, 0, sizeof(shell));
    shell.app = *a;
    char *out = NULL;
    size_t len = 0;
    return firc_config_save_buffer_part(&shell, "0.7.0", FIRC_CFG_SETTINGS, &out, &len) == FIRC_OK
               ? out
               : NULL;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) { return NULL; }
    char *buf = calloc(1, 65536);
    size_t n = buf != NULL ? fread(buf, 1, 65535, f) : 0;
    (void)n;
    fclose(f);
    return buf;
}

/* Catches: a live setting not applied, a restart setting applied, or pending-restart wrong. */
TEST a_put_applies_the_live_settings_and_holds_the_rest(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_app_config_t next;
    ASSERT_EQ(FIRC_OK, edited(r.app, &next));
    bool applied[FIRC_SETTINGS_COUNT];
    ASSERT_EQ(FIRC_OK, firc_app_put_settings(r.app, &next, NULL, "0.7.0", applied, NULL));
    firc_app_config_clear(&next);

    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
        bool want = i == row("app.dnsProxy.upstream.address") ||
                    i == row("app.dnsProxy.disableDropAAAA") || i == row("app.showAllInterfaces") ||
                    i == row("app.logLevel");
        ASSERT_EQm(firc_settings[i].path, want, applied[i]);
    }
    uint16_t port = 0;
    ASSERT_STR_EQ("9.9.9.9", firc_dnsproxy_upstream(r.proxy, &port));
    ASSERT_EQ(53, port);
    ASSERT_EQ(FIRC_LOG_DEBUG, firc_log_level());
    const firc_app_config_t *run = firc_app_running_settings(r.app);
    ASSERT(run->show_all_interfaces);
    ASSERT(run->dns_proxy.disable_drop_aaaa);
    ASSERT_STR_EQ("9.9.9.9", run->dns_proxy.upstream.address);
    ASSERT_EQm("a restart setting does not reach the running copy", 65536u, run->fakeip.max_names);
    ASSERT_EQ(4096u, firc_app_saved_settings(r.app)->fakeip.max_names);

    bool pending[FIRC_SETTINGS_COUNT];
    ASSERT_EQ((size_t)1, firc_app_pending_restart(r.app, pending));
    ASSERT(pending[row("app.addressPool.maxNames")]);
    rig_down(&r);
    PASS();
}

TEST a_put_writes_firc_conf_and_not_groups_yaml(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char dir[] = "/tmp/firc_app_settings_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char conf[128], groups[128];
    snprintf(conf, sizeof(conf), "%s/firc.conf", dir);
    snprintf(groups, sizeof(groups), "%s/groups.yaml", dir);

    firc_app_config_t next;
    ASSERT_EQ(FIRC_OK, edited(r.app, &next));
    ASSERT_EQ(FIRC_OK, firc_app_put_settings(r.app, &next, conf, "0.7.0", NULL, NULL));
    firc_app_config_clear(&next);

    char *text = slurp(conf);
    ASSERT(text != NULL);
    ASSERT(strstr(text, "maxNames: 4096\n") != NULL);
    ASSERT(strstr(text, "address: 9.9.9.9\n") != NULL);
    ASSERT_FALSE(strstr(text, "groups:") != NULL);
    ASSERTm("groups.yaml is not written", access(groups, F_OK) != 0);
    free(text);
    unlink(conf);
    rmdir(dir);
    rig_down(&r);
    PASS();
}

/* Catches: firc.conf written on a PUT that changes nothing. */
TEST a_put_that_changes_nothing_writes_nothing(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char dir[] = "/tmp/firc_app_settings_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char conf[128];
    snprintf(conf, sizeof(conf), "%s/firc.conf", dir);
    firc_app_config_t next;
    memset(&next, 0, sizeof(next));
    ASSERT_EQ(FIRC_OK, firc_app_config_copy(&next, firc_app_saved_settings(r.app)));
    bool applied[FIRC_SETTINGS_COUNT];
    ASSERT_EQ(FIRC_OK, firc_app_put_settings(r.app, &next, conf, "0.7.0", applied, NULL));
    firc_app_config_clear(&next);
    ASSERT(access(conf, F_OK) != 0);
    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) { ASSERT_FALSE(applied[i]); }
    rmdir(dir);
    rig_down(&r);
    PASS();
}

/* Catches: the new settings adopted before the file write succeeded. */
TEST a_put_whose_file_cannot_be_written_changes_nothing(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    firc_app_config_t next;
    ASSERT_EQ(FIRC_OK, edited(r.app, &next));
    ASSERT(firc_app_put_settings(r.app, &next, "/nonexistent-firc-dir/firc.conf", "0.7.0", NULL, NULL) !=
           FIRC_OK);
    firc_app_config_clear(&next);
    ASSERT_EQ(65536u, firc_app_saved_settings(r.app)->fakeip.max_names);
    ASSERT_EQ(FIRC_LOG_INFO, firc_log_level());
    ASSERT_STR_EQ("127.0.0.1", firc_dnsproxy_upstream(r.proxy, NULL));
    ASSERT_FALSE(firc_app_running_settings(r.app)->show_all_interfaces);
    rig_down(&r);
    PASS();
}

/* Catches: a reload copying or applying the settings differently from a PUT. */
TEST a_reload_leaves_the_daemon_as_a_put_does(void) {
    rig_t a, b;
    ASSERT(rig_up(&a));
    ASSERT(rig_up(&b));
    firc_app_config_t na, nb;
    ASSERT_EQ(FIRC_OK, edited(a.app, &na));
    ASSERT_EQ(FIRC_OK, edited(b.app, &nb));
    bool by_put[FIRC_SETTINGS_COUNT], by_reload[FIRC_SETTINGS_COUNT];
    ASSERT_EQ(FIRC_OK, firc_app_put_settings(a.app, &na, NULL, "0.7.0", by_put, NULL));
    ASSERT_EQ(FIRC_OK, firc_app_reload_settings(b.app, &nb, by_reload));
    firc_app_config_clear(&na);
    firc_app_config_clear(&nb);

    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
        ASSERT_EQm(firc_settings[i].path, by_put[i], by_reload[i]);
    }
    char *sa = emit(firc_app_saved_settings(a.app)), *sb = emit(firc_app_saved_settings(b.app));
    char *ra = emit(firc_app_running_settings(a.app)), *rb = emit(firc_app_running_settings(b.app));
    ASSERT(sa && sb && ra && rb);
    ASSERT_STR_EQ(sa, sb);
    ASSERT_STR_EQ(ra, rb);
    ASSERT_STR_EQ(firc_dnsproxy_upstream(a.proxy, NULL), firc_dnsproxy_upstream(b.proxy, NULL));
    free(sa);
    free(sb);
    free(ra);
    free(rb);
    rig_down(&b);
    rig_down(&a);
    PASS();
}

/* Catches: a config save writing the running settings over the saved ones. */
TEST save_config_writes_the_saved_settings(void) {
    rig_t r;
    ASSERT(rig_up(&r));
    char dir[] = "/tmp/firc_app_settings_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    char conf[128], groups[128];
    snprintf(conf, sizeof(conf), "%s/firc.conf", dir);
    snprintf(groups, sizeof(groups), "%s/groups.yaml", dir);
    firc_app_config_t next;
    ASSERT_EQ(FIRC_OK, edited(r.app, &next));
    ASSERT_EQ(FIRC_OK, firc_app_put_settings(r.app, &next, NULL, "0.7.0", NULL, NULL));
    firc_app_config_clear(&next);

    ASSERT_EQ(FIRC_OK, firc_app_save_config(r.app, conf, "0.7.0"));
    char *text = slurp(conf);
    ASSERT(text != NULL);
    ASSERT(strstr(text, "maxNames: 4096\n") != NULL);
    free(text);
    unlink(conf);
    unlink(groups);
    rmdir(dir);
    rig_down(&r);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_put_applies_the_live_settings_and_holds_the_rest);
    RUN_TEST(a_put_writes_firc_conf_and_not_groups_yaml);
    RUN_TEST(a_put_that_changes_nothing_writes_nothing);
    RUN_TEST(a_put_whose_file_cannot_be_written_changes_nothing);
    RUN_TEST(a_reload_leaves_the_daemon_as_a_put_does);
    RUN_TEST(save_config_writes_the_saved_settings);
    GREATEST_MAIN_END();
}
