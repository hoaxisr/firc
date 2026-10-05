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
    "    idleWindow: 36h\n"
    "    maxNames: 4096\n"
    "  link: [br0, br1]\n"
    "  showAllInterfaces: true\n"
    "  logLevel: debug\n";

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
static void idle_sub_second(firc_app_config_t *c) { c->fakeip.idle_window = 500 * FIRC_DURATION_MS; }
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
static void level_unknown(firc_app_config_t *c) { firc_strset(&c->log_level, "loud"); }
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

static const struct {
    void (*spoil)(firc_app_config_t *c);
    const char *field;
} CASES[] = {
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
    {idle_sub_second, "app.addressPool.idleWindow"},
    {names_zero, "app.addressPool.maxNames"},
    {link_empty_name, "app.link"},
    {link_long_name, "app.link"},
    {link_with_newline, "app.link"},
    {link_twice, "app.link"},
    {level_unknown, "app.logLevel"},
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

/* Catches: a rule too strict for a value the daemon ships or reads. */
TEST the_check_passes_what_the_daemon_accepts(void) {
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *field = NULL, *why = NULL;
    ASSERT_EQ(FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));

    static const char *const levels[] = {"trace", "debug", "info",    "warn",    "error",
                                         "fatal", "panic", "nolevel", "disabled"};
    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++) {
        ASSERT_EQ(FIRC_OK, firc_strset(&cfg.app.log_level, levels[i]));
        ASSERT_EQm(levels[i], FIRC_OK, firc_app_config_check(&cfg.app, &field, &why));
    }
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

/* Catches: a row's live or restart class flipped, or a live row losing its apply kind. */
TEST each_row_has_the_specs_class_and_apply(void) {
    static const struct {
        const char *path;
        firc_setting_apply_t apply;
    } live[] = {
        {"app.dnsProxy.upstream.address", FIRC_APPLY_UPSTREAM},
        {"app.dnsProxy.upstream.port", FIRC_APPLY_UPSTREAM},
        {"app.dnsProxy.disableDropAAAA", FIRC_APPLY_PROXY_FLAGS},
        {"app.dnsProxy.unmatchedTtl", FIRC_APPLY_UNMATCHED_TTL},
        {"app.logLevel", FIRC_APPLY_LOG_LEVEL},
        {"app.showAllInterfaces", FIRC_APPLY_NONE},
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

typedef struct {
    const char *path;
    size_t off;
    size_t size;
} field_t;

#define FIELD(p, f) {p, offsetof(firc_app_config_t, f), sizeof(((firc_app_config_t *)0)->f)}

static const field_t NUMERIC[] = {
    FIELD("app.dnsProxy.upstream.port", dns_proxy.upstream.port),
    FIELD("app.dnsProxy.disableDropAAAA", dns_proxy.disable_drop_aaaa),
    FIELD("app.dnsProxy.unmatchedTtl", dns_proxy.unmatched_ttl),
    FIELD("app.dnsProxy.timeout", dns_proxy.timeout),
    FIELD("app.dnsProxy.maxConcurrent", dns_proxy.max_concurrent),
    FIELD("app.dnsProxy.maxIdleConns", dns_proxy.max_idle_conns),
    FIELD("app.dnsProxy.host.port", dns_proxy.host.port),
    FIELD("app.dnsProxy.disableRemap53", dns_proxy.disable_remap53),
    FIELD("app.addressPool.ttlClamp", fakeip.ttl_clamp),
    FIELD("app.addressPool.idleWindow", fakeip.idle_window),
    FIELD("app.addressPool.maxNames", fakeip.max_names),
    FIELD("app.addressPool.v4.chunk", fakeip.v4.chunk),
    FIELD("app.addressPool.v6.chunk", fakeip.v6.chunk),
    FIELD("app.netfilter.disableIPv4", netfilter.disable_ipv4),
    FIELD("app.netfilter.disableIPv6", netfilter.disable_ipv6),
    FIELD("app.netfilter.startMarkTableIndex", netfilter.start_mark_table_index),
    FIELD("app.showAllInterfaces", show_all_interfaces),
    FIELD("app.httpWeb.host.port", http_web.host.port),
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
    RUN_TEST(the_check_names_the_field_that_broke);
    RUN_TEST(the_check_passes_what_the_daemon_accepts);
    RUN_TEST(a_disabled_webui_host_is_not_checked);
    RUN_TEST(each_row_has_the_specs_class_and_apply);
    RUN_TEST(every_numeric_setting_copies_exactly_the_bytes_of_its_field);
    GREATEST_MAIN_END();
}
