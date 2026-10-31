#include "greatest.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "firc/settings.h"
#include "firc/yamlio.h"

static const char EVERY_FIELD[] =
    "configVersion: 0.7.0\n"
    "app:\n"
    "  httpWeb:\n"
    "    enabled: false\n"
    "    host: {address: 192.168.1.1, port: 8081}\n"
    "  dnsProxy:\n"
    "    host: {address: 127.0.0.1, port: 5353}\n"
    "    upstream: {address: 1.1.1.1, port: 5300}\n"
    "    disableRemap53: true\n"
    "    disableDropAAAA: true\n"
    "    disableStats: true\n"
    "    unmatchedTtl: 90s\n"
    "    maxIdleConns: 3\n"
    "    maxConcurrent: 7\n"
    "    timeout: 2500ms\n"
    "  netfilter:\n"
    "    iptables: {chainPrefix: XX_}\n"
    "    disableIPv4: true\n"
    "    disableIPv6: true\n"
    "    startMarkTableIndex: 1000\n"
    "  addressPool:\n"
    "    v4: {pool: 100.64.0.0/10, chunk: 26}\n"
    "    v6: {pool: 'fd7a:115c:a1e0::/48', chunk: 60}\n"
    "    ttlClamp: 2m\n"
    "    maxNames: 4096\n"
    "  link: [br0, br1]\n"
    "  update: {check: true}\n"
    "  check: {url: 'https://check.example/204', wanUrl: 'http://wan.example/204', interval: 45s, timeout: 3s}\n"
    "  autolist: {enabled: true, group: 0a0b0c0d, failThreshold: 5, failTime: 2m, retransThreshold: 4,\n"
    "             exclude: [example.com], recheck: true, recheckInterval: 2h,\n"
    "             checkInterface: ppp0, mode: add}\n";

static char *emit_settings(const firc_app_config_t *app) {
    firc_config_t shell;
    memset(&shell, 0, sizeof(shell));
    shell.app = *app;
    char *out = NULL;
    size_t len = 0;
    if (firc_config_save_buffer_part(&shell, "0.7.0", FIRC_CFG_SETTINGS, &out, &len) != FIRC_OK) {
        return NULL;
    }
    return out;
}

/* Catches: a setting missing from the table, a wrong copy or compare, or httpWeb.enabled in the table. */
TEST the_table_covers_every_field_but_enabled(void) {
    firc_config_t all, defaults;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&all));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&all, EVERY_FIELD, strlen(EVERY_FIELD)));
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&defaults));

    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
        ASSERT(firc_settings[i].path != NULL);
        ASSERT_FALSEm(firc_settings[i].path,
                      firc_setting_equal(&firc_settings[i], &all.app, &defaults.app));
        ASSERT_EQ(&firc_settings[i], firc_setting_find(firc_settings[i].path));
    }
    ASSERT_EQ(NULL, firc_setting_find("app.httpWeb.enabled"));
    ASSERT_EQ(NULL, firc_setting_find("app.nope"));

    firc_app_config_t copy;
    memset(&copy, 0, sizeof(copy));
    ASSERT_EQ(FIRC_OK, firc_app_config_copy(&copy, &all.app));
    char *want = emit_settings(&all.app);
    char *got = emit_settings(&copy);
    ASSERT(want != NULL && got != NULL);
    ASSERT_STR_EQ(want, got);

    free(want);
    free(got);
    firc_app_config_clear(&copy);
    firc_config_clear(&all);
    firc_config_clear(&defaults);
    PASS();
}

static void upstream_is_a_name(firc_app_config_t *c) { firc_strset(&c->dns_proxy.upstream.address, "dns.example"); }
static void upstream_is_empty(firc_app_config_t *c) { firc_strset(&c->dns_proxy.upstream.address, ""); }
static void upstream_port_zero(firc_app_config_t *c) { c->dns_proxy.upstream.port = 0; }
static void proxy_host_bad(firc_app_config_t *c) { firc_strset(&c->dns_proxy.host.address, "0.0.0.0.0"); }
static void proxy_port_zero(firc_app_config_t *c) { c->dns_proxy.host.port = 0; }
static void web_host_unbalanced(firc_app_config_t *c) { firc_strset(&c->http_web.host.address, "[::1"); }
/* An empty DNS proxy host, which the proxy's parser refuses (the WebUI's allows it). */
static void proxy_host_empty(firc_app_config_t *c) { firc_strset(&c->dns_proxy.host.address, ""); }
static void web_port_zero(firc_app_config_t *c) { c->http_web.host.port = 0; }
static void timeout_negative(firc_app_config_t *c) { c->dns_proxy.timeout = -5 * FIRC_DURATION_SEC; }
static void timeout_past_32_bits(firc_app_config_t *c) {
    c->dns_proxy.timeout = ((firc_duration_t)UINT32_MAX + 1) * FIRC_DURATION_MS;
}
static void concurrent_past_32_bits(firc_app_config_t *c) { c->dns_proxy.max_concurrent = (uint64_t)UINT32_MAX + 1; }
static void idle_past_32_bits(firc_app_config_t *c) { c->dns_proxy.max_idle_conns = (uint64_t)UINT32_MAX + 1; }
static void prefix_empty(firc_app_config_t *c) { firc_strset(&c->netfilter.iptables.chain_prefix, ""); }
static void prefix_with_space(firc_app_config_t *c) { firc_strset(&c->netfilter.iptables.chain_prefix, "FI RC"); }
static void prefix_with_newline(firc_app_config_t *c) { firc_strset(&c->netfilter.iptables.chain_prefix, "FIRC\n-A"); }
static void prefix_leading_dash(firc_app_config_t *c) { firc_strset(&c->netfilter.iptables.chain_prefix, "-FIRC_"); }
static void prefix_too_long(firc_app_config_t *c) {
    firc_strset(&c->netfilter.iptables.chain_prefix, "ABCDEFGHIJKLMNOPQRS");
}
static void v4_pool_is_v6(firc_app_config_t *c) { firc_strset(&c->fakeip.v4.pool, "fd00::/48"); }
static void v4_chunk_wider(firc_app_config_t *c) { c->fakeip.v4.chunk = 12; }
static void v6_pool_is_v4(firc_app_config_t *c) { firc_strset(&c->fakeip.v6.pool, "10.0.0.0/8"); }
static void v6_chunk_wider(firc_app_config_t *c) { c->fakeip.v6.chunk = 40; }
static void clamp_zero(firc_app_config_t *c) { c->fakeip.ttl_clamp = 0; }
static void clamp_past_a_year(firc_app_config_t *c) { c->fakeip.ttl_clamp = INT64_C(366) * 24 * 3600 * FIRC_DURATION_SEC; }
static void clamp_past_half_a_year(firc_app_config_t *c) { c->fakeip.ttl_clamp = INT64_C(183) * 24 * 3600 * FIRC_DURATION_SEC; }
/* An unmatchedTtl past a day; 0 means off and is allowed. */
static void unmatched_ttl_past_a_day(firc_app_config_t *c) { c->dns_proxy.unmatched_ttl = 86401 * FIRC_DURATION_SEC; }
static void unmatched_ttl_negative(firc_app_config_t *c) { c->dns_proxy.unmatched_ttl = -5 * FIRC_DURATION_SEC; }
static void names_zero(firc_app_config_t *c) { c->fakeip.max_names = 0; }
static void link_empty_name(firc_app_config_t *c) { firc_strset(&c->link[0], ""); }
static void link_long_name(firc_app_config_t *c) { firc_strset(&c->link[0], "abcdefghijklmnop"); }
static void link_with_newline(firc_app_config_t *c) { firc_strset(&c->link[0], "br0\n-A"); }
static void link_twice(firc_app_config_t *c) {
    char **list = realloc(c->link, 2 * sizeof(char *));
    if (list == NULL) { return; }
    c->link = list;
    c->link[1] = strdup("br0");
    c->n_link = 2;
}
/* A chain prefix with a quote, which opens a word iptables-restore never sees closed. */
static void prefix_with_double_quote(firc_app_config_t *c) { firc_strset(&c->netfilter.iptables.chain_prefix, "FI\"RC"); }
static void prefix_with_single_quote(firc_app_config_t *c) { firc_strset(&c->netfilter.iptables.chain_prefix, "FI'RC"); }
/* The WebUI on the DNS proxy's port: both take TCP on [::] by default, so the second bind fails. */
static void web_port_is_proxy_port(firc_app_config_t *c) { c->http_web.host.port = c->dns_proxy.host.port; }
/* The WebUI on one address under the proxy's [::] wildcard on the same port. */
static void web_address_under_proxy_wildcard(firc_app_config_t *c) {
    firc_strset(&c->http_web.host.address, "192.168.1.1");
    c->http_web.host.port = c->dns_proxy.host.port;
}
static void web_and_proxy_same_socket(firc_app_config_t *c) {
    firc_strset(&c->http_web.host.address, "127.0.0.1");
    firc_strset(&c->dns_proxy.host.address, "127.0.0.1");
    c->http_web.host.port = 5353;
    c->dns_proxy.host.port = 5353;
}
/* A mark table start with fewer than 255 ids before 0x7ffffffe. */
static void mark_index_short_of_255(firc_app_config_t *c) { c->netfilter.start_mark_table_index = UINT32_C(0x7fffff00); }
static void mark_index_past_the_loop(firc_app_config_t *c) { c->netfilter.start_mark_table_index = UINT32_C(0xffffffff); }

static void check_url_ftp(firc_app_config_t *c) { firc_strset(&c->check.url, "ftp://check.example/"); }
static void check_url_no_host(firc_app_config_t *c) { firc_strset(&c->check.url, "http:///generate_204"); }
static void check_url_space(firc_app_config_t *c) { firc_strset(&c->check.url, "http://a b/"); }
static void check_url_v6_literal(firc_app_config_t *c) { firc_strset(&c->check.url, "https://[2606:4700::1111]/generate_204"); }
static void check_url_v6_behind_userinfo(firc_app_config_t *c) { firc_strset(&c->check.url, "http://u@[::1]:8080/204"); }
static void check_interval_9s(firc_app_config_t *c) { c->check.interval = 9 * FIRC_DURATION_SEC; }
static void check_interval_3601s(firc_app_config_t *c) { c->check.interval = 3601 * FIRC_DURATION_SEC; }
static void check_timeout_0(firc_app_config_t *c) { c->check.timeout = 0; }
static void check_timeout_31s(firc_app_config_t *c) { c->check.timeout = 31 * FIRC_DURATION_SEC; }

static const struct {
    void (*spoil)(firc_app_config_t *c);
    const char *field;
} CASES[] = {
    {check_url_ftp, "app.check.url"},
    {check_url_no_host, "app.check.url"},
    {check_url_space, "app.check.url"},
    {check_url_v6_literal, "app.check.url"},
    {check_url_v6_behind_userinfo, "app.check.url"},
    {check_interval_9s, "app.check.interval"},
    {check_interval_3601s, "app.check.interval"},
    {check_timeout_0, "app.check.timeout"},
    {check_timeout_31s, "app.check.timeout"},
    {upstream_is_a_name, "app.dnsProxy.upstream.address"},
    {upstream_is_empty, "app.dnsProxy.upstream.address"},
    {upstream_port_zero, "app.dnsProxy.upstream.port"},
    {proxy_host_bad, "app.dnsProxy.host.address"},
    {proxy_port_zero, "app.dnsProxy.host.port"},
    {web_host_unbalanced, "app.httpWeb.host.address"},
    {proxy_host_empty, "app.dnsProxy.host.address"},
    {web_port_zero, "app.httpWeb.host.port"},
    {timeout_negative, "app.dnsProxy.timeout"},
    {timeout_past_32_bits, "app.dnsProxy.timeout"},
    {concurrent_past_32_bits, "app.dnsProxy.maxConcurrent"},
    {idle_past_32_bits, "app.dnsProxy.maxIdleConns"},
    {prefix_empty, "app.netfilter.iptables.chainPrefix"},
    {prefix_with_space, "app.netfilter.iptables.chainPrefix"},
    {prefix_with_newline, "app.netfilter.iptables.chainPrefix"},
    {prefix_leading_dash, "app.netfilter.iptables.chainPrefix"},
    {prefix_too_long, "app.netfilter.iptables.chainPrefix"},
    {v4_pool_is_v6, "app.addressPool.v4.pool"},
    {v4_chunk_wider, "app.addressPool.v4.chunk"},
    {v6_pool_is_v4, "app.addressPool.v6.pool"},
    {v6_chunk_wider, "app.addressPool.v6.chunk"},
    {clamp_zero, "app.addressPool.ttlClamp"},
    {clamp_past_a_year, "app.addressPool.ttlClamp"},
    {unmatched_ttl_past_a_day, "app.dnsProxy.unmatchedTtl"},
    {unmatched_ttl_negative, "app.dnsProxy.unmatchedTtl"},
    {clamp_past_half_a_year, "app.addressPool.ttlClamp"},
    {names_zero, "app.addressPool.maxNames"},
    {link_empty_name, "app.link"},
    {link_long_name, "app.link"},
    {link_with_newline, "app.link"},
    {link_twice, "app.link"},
    {prefix_with_double_quote, "app.netfilter.iptables.chainPrefix"},
    {prefix_with_single_quote, "app.netfilter.iptables.chainPrefix"},
    {web_port_is_proxy_port, "app.httpWeb.host.port"},
    {web_address_under_proxy_wildcard, "app.httpWeb.host.port"},
    {web_and_proxy_same_socket, "app.httpWeb.host.port"},
    {mark_index_short_of_255, "app.netfilter.startMarkTableIndex"},
    {mark_index_past_the_loop, "app.netfilter.startMarkTableIndex"},
};

/* Catches: a rule deleted from the check, or one that blames the wrong key. */
TEST the_check_names_the_field_that_broke(void) {
    for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) {
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        CASES[i].spoil(&cfg.app);
        const char *field = NULL, *why = NULL;
        firc_err_t err = firc_app_config_check(&cfg.app, &field, &why);
        firc_config_clear(&cfg);
        ASSERT_EQm(CASES[i].field, FIRC_ERR_INVAL, err);
        ASSERT_STR_EQm(CASES[i].field, CASES[i].field, field);
        ASSERTm(CASES[i].field, why != NULL && why[0] != '\0');
    }
    PASS();
}

/* Catches: a default that is not empty, or a key the saved file drops. */
TEST wan_url_defaults_empty(void) {
    firc_config_t d, back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&d));
    ASSERT_STR_EQ("", d.app.check.wan_url);
    char *y = emit_settings(&d.app);
    ASSERT(y != NULL);
    ASSERT(strstr(y, "wanUrl: ''") != NULL || strstr(y, "wanUrl: \"\"") != NULL);
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, y, strlen(y)));
    ASSERT_STR_EQ("", back.app.check.wan_url);
    free(y);
    firc_config_clear(&d);
    firc_config_clear(&back);
    PASS();
}

/* Catches: a WAN URL checked less than the URL, an empty one refused, or the wrong key blamed. */
TEST wan_url_takes_a_url_or_empty(void) {
    firc_app_config_t c;
    ASSERT_EQ(FIRC_OK, firc_app_config_init_defaults(&c));
    const char *field = NULL, *why = NULL;
    ASSERT_EQ(FIRC_OK, firc_strset(&c.check.wan_url, "http://api.browser.yandex.ru/generate_204"));
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&c, &field, &why));
    ASSERT_EQ(FIRC_OK, firc_strset(&c.check.wan_url, ""));
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&c, &field, &why));
    free(c.check.wan_url);
    c.check.wan_url = NULL;
    ASSERT_EQm("a key absent from the file leaves NULL-safe", FIRC_OK, firc_app_config_check(&c, &field, &why));
    ASSERT_EQ(FIRC_OK, firc_strset(&c.check.wan_url, "ftp://x"));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&c, &field, &why));
    ASSERT_STR_EQ("app.check.wanUrl", field);
    firc_app_config_clear(&c);
    PASS();
}

TEST the_check_settings_default_to_the_spec_and_are_live(void) {
    firc_app_config_t c;
    ASSERT_EQ(FIRC_OK, firc_app_config_init_defaults(&c));
    ASSERT_STR_EQ("http://cp.cloudflare.com/generate_204", c.check.url);
    ASSERT_EQ(30 * FIRC_DURATION_SEC, c.check.interval);
    ASSERT_EQ(5 * FIRC_DURATION_SEC, c.check.timeout);
    const char *field = NULL, *why = NULL;
    c.check.interval = 10 * FIRC_DURATION_SEC;
    c.check.timeout = 30 * FIRC_DURATION_SEC;
    ASSERT_EQm("the edges are in range", FIRC_OK, firc_app_config_check(&c, &field, &why));
    c.check.interval = 3600 * FIRC_DURATION_SEC;
    c.check.timeout = 1 * FIRC_DURATION_SEC;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&c, &field, &why));
    static const char *const live[] = {"app.check.url", "app.check.interval", "app.check.timeout"};
    for (size_t i = 0; i < 3; i++) {
        const firc_setting_t *s = firc_setting_find(live[i]);
        ASSERT(s != NULL);
        ASSERT_EQ(FIRC_SETTING_LIVE, s->cls);
        ASSERT_EQ(FIRC_APPLY_CHECK, s->apply);
    }
    firc_app_config_clear(&c);
    PASS();
}

/* Catches: a rule too strict for a value the daemon ships or reads. */
TEST the_check_passes_what_the_daemon_accepts(void) {
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *field = NULL, *why = NULL;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));

    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.dns_proxy.upstream.address, "[::1]"));
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.http_web.host.address, "[127.0.0.1]"));
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.link[0], "abcdefghijklmno"));
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.http_web.host.address, ""));
    cfg.app.dns_proxy.timeout = 0;
    cfg.app.dns_proxy.max_concurrent = 0;
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.netfilter.iptables.chain_prefix, "fi-rc.v2_"));
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.netfilter.iptables.chain_prefix, "ABCDEFGHIJKLMNOPQR"));
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    cfg.app.netfilter.start_mark_table_index = UINT32_C(0x7ffffeff);
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    cfg.app.netfilter.start_mark_table_index = 0;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.http_web.host.address, "192.168.1.1"));
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.dns_proxy.host.address, "127.0.0.1"));
    cfg.app.http_web.host.port = cfg.app.dns_proxy.host.port;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    cfg.app.dns_proxy.unmatched_ttl = 0;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    cfg.app.dns_proxy.unmatched_ttl = 86400 * FIRC_DURATION_SEC;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: the WebUI host checked while the WebUI is off. */
TEST a_disabled_webui_host_is_not_checked(void) {
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    cfg.app.http_web.enabled = false;
    cfg.app.http_web.host.port = 0;
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.http_web.host.address, "[::1"));
    const char *field = NULL, *why = NULL;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    cfg.app.http_web.host.port = cfg.app.dns_proxy.host.port;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    firc_config_clear(&cfg);
    PASS();
}

TEST mode_defaults_to_candidates(void) {
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_STR_EQ("candidates", cfg.app.autolist.mode);
    firc_config_clear(&cfg);
    PASS();
}

TEST mode_other_than_two_refused(void) {
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *field = NULL, *why = NULL;
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.autolist.mode, "auto"));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_STR_EQ("app.autolist.mode", field);
    ASSERT_STR_EQ("candidates or add", why);
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.autolist.mode, "add"));
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    firc_config_clear(&cfg);
    PASS();
}

TEST enabled_without_group_refused(void) {
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *field = NULL, *why = NULL;
    cfg.app.autolist.enabled = true;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_STR_EQ("app.autolist.group", field);
    ASSERT_STR_EQ("a group is needed while the automatic list is on", why);
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.autolist.group, "0a0b0c0d"));
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    firc_config_clear(&cfg);
    PASS();
}

TEST enabled_with_unmatched_ttl_zero_refused(void) {
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *field = NULL, *why = NULL;
    cfg.app.autolist.enabled = true;
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.autolist.group, "0a0b0c0d"));
    cfg.app.dns_proxy.unmatched_ttl = 0;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_STR_EQ("app.autolist.enabled", field);
    ASSERT_STR_EQ("needs app.dnsProxy.unmatchedTtl above 0: without it devices keep the old address", why);
    cfg.app.autolist.enabled = false;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    firc_config_clear(&cfg);
    PASS();
}

TEST the_autolist_values_are_checked(void) {
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *field = NULL, *why = NULL;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));

    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.autolist.group, "not-an-id"));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_STR_EQ("app.autolist.group", field);
    ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.autolist.group, "0a0b0c0d"));

    cfg.app.autolist.fail_threshold = 0;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_STR_EQ("app.autolist.failThreshold", field);
    cfg.app.autolist.fail_threshold = 3;

    cfg.app.autolist.fail_time = 5 * FIRC_DURATION_SEC;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_STR_EQ("app.autolist.failTime", field);
    cfg.app.autolist.fail_time = 60 * FIRC_DURATION_SEC;

    cfg.app.autolist.retrans_threshold = 9;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_STR_EQ("app.autolist.retransThreshold", field);
    cfg.app.autolist.retrans_threshold = 3;

    static const char *const dup[] = {"example.com", "example.com"};
    cfg.app.autolist.exclude = (char **)dup;
    cfg.app.autolist.n_exclude = 2;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    ASSERT_STR_EQ("app.autolist.exclude", field);
    static const char *const bad[] = {"*.example.com"};
    cfg.app.autolist.exclude = (char **)bad;
    cfg.app.autolist.n_exclude = 1;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_app_config_check(&cfg.app, &field, &why));
    cfg.app.autolist.exclude = NULL;
    cfg.app.autolist.n_exclude = 0;

    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a row's live or restart class flipped, or a live row losing its apply kind. */
TEST each_row_has_the_specs_class_and_apply(void) {
    static const struct {
        const char *path;
        firc_setting_apply_t apply;
    } live[] = {
        {"app.dnsProxy.upstream.address", FIRC_APPLY_UPSTREAM},
        {"app.dnsProxy.upstream.port", FIRC_APPLY_UPSTREAM},
        {"app.dnsProxy.disableDropAAAA", FIRC_APPLY_PROXY_FLAGS},
        {"app.dnsProxy.disableStats", FIRC_APPLY_DNS_STATS},
        {"app.dnsProxy.unmatchedTtl", FIRC_APPLY_UNMATCHED_TTL},
        {"app.update.check", FIRC_APPLY_NONE},
        {"app.check.url", FIRC_APPLY_CHECK},
        {"app.check.wanUrl", FIRC_APPLY_CHECK},
        {"app.check.interval", FIRC_APPLY_CHECK},
        {"app.check.timeout", FIRC_APPLY_CHECK},
        {"app.autolist.enabled", FIRC_APPLY_AUTOLIST},
        {"app.autolist.group", FIRC_APPLY_AUTOLIST},
        {"app.autolist.failThreshold", FIRC_APPLY_AUTOLIST},
        {"app.autolist.exclude", FIRC_APPLY_AUTOLIST},
        {"app.autolist.recheck", FIRC_APPLY_AUTOLIST},
        {"app.autolist.recheckInterval", FIRC_APPLY_AUTOLIST},
        {"app.autolist.checkInterface", FIRC_APPLY_AUTOLIST},
        {"app.autolist.mode", FIRC_APPLY_AUTOLIST},
        {"app.autolist.failTime", FIRC_APPLY_AUTOLIST},
        {"app.autolist.retransThreshold", FIRC_APPLY_AUTOLIST},
    };
    size_t n_live = 0;
    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) {
        const firc_setting_t *s = &firc_settings[i];
        size_t k = 0;
        while (k < sizeof(live) / sizeof(live[0]) && strcmp(live[k].path, s->path) != 0) { k++; }
        if (k < sizeof(live) / sizeof(live[0])) {
            n_live++;
            ASSERT_EQm(s->path, FIRC_SETTING_LIVE, s->cls);
            ASSERT_EQm(s->path, live[k].apply, s->apply);
        } else {
            ASSERT_EQm(s->path, FIRC_SETTING_RESTART, s->cls);
            ASSERT_EQm(s->path, FIRC_APPLY_NONE, s->apply);
        }
    }
    ASSERT_EQ(sizeof(live) / sizeof(live[0]), n_live);
    PASS();
}

/* Catches: a missing row, the restart class, or a default of true (a router phoning GitHub unasked). */
TEST the_update_check_is_live_off_by_default_and_applies_nothing(void) {
    const firc_setting_t *s = firc_setting_find("app.update.check");
    ASSERT(s != NULL);
    ASSERT_EQ(FIRC_SK_BOOL, s->kind);
    ASSERT_EQ(FIRC_SETTING_LIVE, s->cls);
    ASSERT_EQ(FIRC_APPLY_NONE, s->apply);
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_FALSE(cfg.app.update.check);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: the stats off by default, the key read or written under another name, or a save dropping it. */
TEST disable_stats_is_off_by_default_and_round_trips(void) {
    const firc_setting_t *s = firc_setting_find("app.dnsProxy.disableStats");
    ASSERT(s != NULL);
    ASSERT_EQ(FIRC_SK_BOOL, s->kind);
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_FALSE(cfg.app.dns_proxy.disable_stats);
    static const char text[] = "configVersion: 0.7.0\napp:\n  dnsProxy:\n    disableStats: true\n";
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&cfg, text, strlen(text)));
    ASSERT(cfg.app.dns_proxy.disable_stats);
    ASSERT_FALSE(cfg.app.dns_proxy.disable_drop_aaaa);
    char *out = emit_settings(&cfg.app);
    ASSERT(out != NULL);
    ASSERT(strstr(out, "    disableStats: true\n") != NULL);
    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, out, strlen(out)));
    ASSERT(back.app.dns_proxy.disable_stats);
    free(out);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

typedef struct {
    const char *path;
    size_t off;
    size_t size;
} field_t;

#define FIELD(p, f) {p, offsetof(firc_app_config_t, f), sizeof(((firc_app_config_t *)0)->f)}

static const field_t NUMERIC[] = {
    FIELD("app.dnsProxy.upstream.port", dns_proxy.upstream.port),
    FIELD("app.dnsProxy.disableDropAAAA", dns_proxy.disable_drop_aaaa),
    FIELD("app.dnsProxy.disableStats", dns_proxy.disable_stats),
    FIELD("app.dnsProxy.unmatchedTtl", dns_proxy.unmatched_ttl),
    FIELD("app.dnsProxy.timeout", dns_proxy.timeout),
    FIELD("app.dnsProxy.maxConcurrent", dns_proxy.max_concurrent),
    FIELD("app.dnsProxy.maxIdleConns", dns_proxy.max_idle_conns),
    FIELD("app.dnsProxy.host.port", dns_proxy.host.port),
    FIELD("app.dnsProxy.disableRemap53", dns_proxy.disable_remap53),
    FIELD("app.addressPool.ttlClamp", fakeip.ttl_clamp),
    FIELD("app.addressPool.maxNames", fakeip.max_names),
    FIELD("app.addressPool.v4.chunk", fakeip.v4.chunk),
    FIELD("app.addressPool.v6.chunk", fakeip.v6.chunk),
    FIELD("app.netfilter.disableIPv4", netfilter.disable_ipv4),
    FIELD("app.netfilter.disableIPv6", netfilter.disable_ipv6),
    FIELD("app.netfilter.startMarkTableIndex", netfilter.start_mark_table_index),
    FIELD("app.update.check", update.check),
    FIELD("app.check.interval", check.interval),
    FIELD("app.check.timeout", check.timeout),
    FIELD("app.httpWeb.host.port", http_web.host.port),
    FIELD("app.autolist.enabled", autolist.enabled),
    FIELD("app.autolist.failThreshold", autolist.fail_threshold),
    FIELD("app.autolist.failTime", autolist.fail_time),
    FIELD("app.autolist.retransThreshold", autolist.retrans_threshold),
    FIELD("app.autolist.recheck", autolist.recheck),
    FIELD("app.autolist.recheckInterval", autolist.recheck_interval),
};

static bool is_numeric(firc_setting_kind_t k) {
    return k != FIRC_SK_ADDR && k != FIRC_SK_STRING && k != FIRC_SK_LIST;
}

TEST every_numeric_setting_copies_exactly_the_bytes_of_its_field(void) {
    size_t numeric_rows = 0;
    for (size_t i = 0; i < FIRC_SETTINGS_COUNT; i++) { numeric_rows += is_numeric(firc_settings[i].kind); }
    ASSERT_EQ_FMT(sizeof(NUMERIC) / sizeof(NUMERIC[0]), numeric_rows, "%zu");

    for (size_t i = 0; i < sizeof(NUMERIC) / sizeof(NUMERIC[0]); i++) {
        const field_t *f = &NUMERIC[i];
        const firc_setting_t *row = firc_setting_find(f->path);
        ASSERT(row != NULL);
        ASSERT(is_numeric(row->kind));
        ASSERT_EQ_FMTm(f->path, f->off, row->off, "%zu");

        static firc_app_config_t src, dst, want;
        memset(&src, 0xa5, sizeof(src));
        unsigned char *field = (unsigned char *)&src + f->off;
        if (row->kind == FIRC_SK_BOOL) {
            field[0] = 1;
        } else {
            for (size_t b = 0; b < f->size; b++) { field[b] = (unsigned char)(0x11u * (b + 1)); }
        }
        memset(&dst, 0, sizeof(dst));
        memset(&want, 0, sizeof(want));
        memcpy((unsigned char *)&want + f->off, field, f->size);

        ASSERT_EQ(FIRC_OK, firc_setting_copy(row, &dst, &src));
        ASSERTm(f->path, memcmp(&want, &dst, sizeof(dst)) == 0);
        ASSERTm(f->path, firc_setting_equal(row, &dst, &src));
        field[f->size - 1] ^= 0x01;
        ASSERTm(f->path, !firc_setting_equal(row, &dst, &src));
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_table_covers_every_field_but_enabled);
    RUN_TEST(disable_stats_is_off_by_default_and_round_trips);
    RUN_TEST(the_check_names_the_field_that_broke);
    RUN_TEST(the_check_passes_what_the_daemon_accepts);
    RUN_TEST(wan_url_defaults_empty);
    RUN_TEST(wan_url_takes_a_url_or_empty);
    RUN_TEST(the_check_settings_default_to_the_spec_and_are_live);
    RUN_TEST(a_disabled_webui_host_is_not_checked);
    RUN_TEST(mode_defaults_to_candidates);
    RUN_TEST(mode_other_than_two_refused);
    RUN_TEST(enabled_without_group_refused);
    RUN_TEST(enabled_with_unmatched_ttl_zero_refused);
    RUN_TEST(the_autolist_values_are_checked);
    RUN_TEST(each_row_has_the_specs_class_and_apply);
    RUN_TEST(the_update_check_is_live_off_by_default_and_applies_nothing);
    RUN_TEST(every_numeric_setting_copies_exactly_the_bytes_of_its_field);
    GREATEST_MAIN_END();
}
