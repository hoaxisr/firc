#include "greatest.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#include "firc/yamlio.h"
#include <unistd.h>
#include "firc/log.h"

static firc_err_t load_str(firc_config_t *cfg, const char *doc)
{
    return firc_config_load_buffer(cfg, doc, strlen(doc));
}

TEST any_config_version_loads(void)
{
    static const char *const docs[] = {
        "configVersion: 1.2.3\n",
        "configVersion: 1~git20261005154241.a39456ba\n",
        "configVersion: \"\"\n",
        "app: {}\n",
        "configVersion: 0.7.0\n",
    };
    for (size_t i = 0; i < sizeof(docs) / sizeof(docs[0]); i++) {
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        ASSERT_EQ(FIRC_OK, load_str(&cfg, docs[i]));
        firc_config_clear(&cfg);
    }
    PASS();
}

TEST an_empty_document_is_refused(void)
{
    static const char *const docs[] = {"", "\n", "   \n\n", "# only a comment\n"};
    for (size_t i = 0; i < sizeof(docs) / sizeof(docs[0]); i++) {
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        ASSERT_EQ(FIRC_ERR_STATE, load_str(&cfg, docs[i]));
        firc_config_clear(&cfg);
    }
    PASS();
}

TEST a_saved_non_zero_version_loads_back(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    char *out = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer(&cfg, "1~git20261005154241.a39456ba", &out, &len));
    ASSERT(strstr(out, "configVersion: 1~git20261005154241.a39456ba") != NULL);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, out, len));
    free(out);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

TEST overlay_and_defaults(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "app:\n"
        "  dnsProxy:\n"
        "    host:\n"
        "      port: 5353\n"
        "  logLevel: debug\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_EQ(5353, cfg.app.dns_proxy.host.port);
    ASSERT_STR_EQ("[::]", cfg.app.dns_proxy.host.address);
    ASSERT_STR_EQ("127.0.0.1", cfg.app.dns_proxy.upstream.address);
    ASSERT_EQ(53, cfg.app.dns_proxy.upstream.port);
    ASSERT_STR_EQ("debug", cfg.app.log_level);
    ASSERT_EQ(5000 * FIRC_DURATION_MS, cfg.app.dns_proxy.timeout);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a device selector lost on a round trip, or an empty one written. */
TEST device_selector_round_trips_and_an_empty_one_is_not_written(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: kids\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    devices:\n"
        "      allow: [192.168.1.0/24, 'policy:Kids']\n"
        "      deny: [192.168.1.5]\n"
        "    rules: []\n"
        "  - id: 0a1b2c3e\n"
        "    name: all\n"
        "    interface: nwg1\n"
        "    enable: true\n"
        "    rules: []\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_EQ_FMT((size_t)2, cfg.groups[0]->devices.n_allow, "%zu");
    ASSERT_STR_EQ("policy:Kids", cfg.groups[0]->devices.allow[1]);
    ASSERT_EQ_FMT((size_t)1, cfg.groups[0]->devices.n_deny, "%zu");
    ASSERT_EQ_FMT((size_t)0, cfg.groups[1]->devices.n_allow, "%zu");

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer(&cfg, "0.99.0", &out, &out_len));
    ASSERT(strstr(out, "policy:Kids") != NULL);
    ASSERT(strstr(out, "192.168.1.5") != NULL);
    ASSERTm("one devices key: the group without a selector gets none",
            strstr(out, "devices") != NULL && strstr(strstr(out, "devices") + 7, "devices") == NULL);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, load_str(&back, out));
    ASSERT_EQ_FMT((size_t)2, back.groups[0]->devices.n_allow, "%zu");
    ASSERT_STR_EQ("192.168.1.0/24", back.groups[0]->devices.allow[0]);
    ASSERT_EQ_FMT((size_t)1, back.groups[0]->devices.n_deny, "%zu");
    free(out);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: an empty device entry accepted at load. */
TEST a_device_entry_that_is_nothing_fails_the_load(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: kids\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    devices:\n"
        "      allow: [the-tv]\n"
        "    rules: []\n";
    ASSERT(load_str(&cfg, doc) != FIRC_OK);
    firc_config_clear(&cfg);
    PASS();
}

TEST legacy_duration_normalization(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "app:\n"
        "  dnsProxy:\n"
        "    timeout: 5000\n"
        "  netfilter:\n"
        "    ipset:\n"
        "      additionalTTL: 3600\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_EQ(5000 * FIRC_DURATION_MS, cfg.app.dns_proxy.timeout);
    firc_config_clear(&cfg);
    PASS();
}

TEST absent_enable_is_false(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: d663876a\n"
        "    name: G\n"
        "    color: '#AABBCC'\n"
        "    rules:\n"
        "      - id: 6f34ee91\n"
        "        type: domain\n"
        "        rule: example.com\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_EQ(1u, (unsigned)cfg.n_groups);
    ASSERT_FALSE(cfg.groups[0]->enable);
    ASSERT_FALSE(cfg.groups[0]->rules[0]->enable);
    firc_config_clear(&cfg);
    PASS();
}

TEST duplicate_ids_fail(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: d663876a\n"
        "  - id: d663876a\n";
    ASSERT_EQ(FIRC_ERR_EXIST, load_str(&cfg, doc));
    firc_config_clear(&cfg);
    PASS();
}

TEST type_mismatch_fails(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_ERR_INVAL,
              load_str(&cfg, "configVersion: 0.7.0\napp:\n  httpWeb:\n"
                             "    enabled: 1\n"));
    firc_config_clear(&cfg);

    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_ERR_INVAL,
              load_str(&cfg, "configVersion: 0.7.0\napp:\n  httpWeb:\n"
                             "    host:\n      port: \"8080\"\n"));
    firc_config_clear(&cfg);

    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_ERR_INVAL,
              load_str(&cfg, "configVersion: 0.7.0\napp:\n  httpWeb:\n"
                             "    host:\n      port: 70000\n"));
    firc_config_clear(&cfg);
    PASS();
}

TEST corrupt_yaml_fails(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_ERR_PROTO, load_str(&cfg, "a: [unclosed\n  b: }{"));
    firc_config_clear(&cfg);
    PASS();
}

TEST a_subnet_rule_keeps_its_proto_and_ports(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: d663876a\n"
        "    name: g\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    rules:\n"
        "      - id: 6f34ee91\n"
        "        type: subnet\n"
        "        rule: 10.0.0.0/8\n"
        "        enable: true\n"
        "        proto: udp\n"
        "        ports: 53,1000-2000\n"
        "      - id: 6f34ee92\n"
        "        type: subnet\n"
        "        rule: 10.1.0.0/16\n"
        "        enable: true\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_EQ(2, (int)cfg.groups[0]->n_rules);
    ASSERT_STR_EQ("udp", cfg.groups[0]->rules[0]->proto);
    ASSERT_STR_EQ("53,1000-2000", cfg.groups[0]->rules[0]->ports);
    ASSERT(cfg.groups[0]->rules[1]->proto == NULL);
    ASSERT(cfg.groups[0]->rules[1]->ports == NULL);

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&cfg, "0.99.0", FIRC_CFG_GROUPS, &out, &out_len));
    ASSERT(strstr(out, "proto: udp\n") != NULL);
    ASSERT(strstr(out, "ports: 53,1000-2000\n") != NULL);
    ASSERTm("written once, for the rule that has them",
            strstr(strstr(out, "proto:") + 1, "proto:") == NULL && strstr(strstr(out, "ports:") + 1, "ports:") == NULL);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, load_str(&back, out));
    ASSERT_STR_EQ("53,1000-2000", back.groups[0]->rules[0]->ports);
    ASSERT(back.groups[0]->rules[1]->ports == NULL);
    free(out);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a key written to the wrong file, or the two files not loading back to the tree that was split. */
TEST the_two_halves_hold_the_whole_config(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "app:\n"
        "  httpWeb:\n"
        "    enabled: false\n"
        "    host:\n"
        "      address: 127.0.0.1\n"
        "      port: 9999\n"
        "  logLevel: debug\n"
        "  link: [br0, eth3]\n"
        "groups:\n"
        "  - id: d663876a\n"
        "    name: Example\n"
        "    color: '#ffffff'\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    rules:\n"
        "      - id: 6f34ee91\n"
        "        name: Wildcard Example\n"
        "        type: wildcard\n"
        "        rule: '*wildcard.example.com'\n"
        "        enable: true\n"
        "  - id: aa11bb22\n"
        "    name: A list\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    list:\n"
        "      url: https://example.com/list.txt\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));

    char *whole = NULL, *settings = NULL, *groups = NULL;
    size_t whole_len = 0, settings_len = 0, groups_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer(&cfg, "0.99.0", &whole, &whole_len));
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&cfg, "0.99.0", FIRC_CFG_SETTINGS, &settings,
                                                    &settings_len));
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.99.0", FIRC_CFG_GROUPS, &groups, &groups_len));

    ASSERTm("settings carry the app block", strstr(settings, "\napp:\n") != NULL);
    ASSERT_FALSEm("and not the groups", strstr(settings, "\ngroups:") != NULL);
    ASSERT_FALSEm("nor a list", strstr(settings, "list:") != NULL);
    ASSERTm("groups carry the groups", strstr(groups, "\ngroups:\n") != NULL);
    ASSERTm("and their lists with them", strstr(groups, "\n  list:\n") != NULL);
    ASSERT_FALSEm("and not the app block", strstr(groups, "\napp:") != NULL);
    ASSERTm("each says its version", strstr(settings, "configVersion: 0.99.0") != NULL);
    ASSERTm("each says its version", strstr(groups, "configVersion: 0.99.0") != NULL);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, settings, settings_len));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, groups, groups_len));

    char *again = NULL;
    size_t again_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer(&back, "0.99.0", &again, &again_len));
    ASSERT_EQ_FMT(whole_len, again_len, "%zu");
    ASSERT_STR_EQ(whole, again);

    free(whole);
    free(settings);
    free(groups);
    free(again);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: groups.yaml looked for anywhere but beside the settings file. */
TEST the_groups_file_sits_next_to_the_settings_file(void)
{
    char out[64];
    ASSERT_EQ(FIRC_OK, firc_config_groups_path("/opt/etc/firc/firc.conf", out, sizeof(out)));
    ASSERT_STR_EQ("/opt/etc/firc/groups.yaml", out);

    ASSERT_EQ(FIRC_OK, firc_config_groups_path("firc.conf", out, sizeof(out)));
    ASSERT_STR_EQ("groups.yaml", out);

    ASSERT_EQ(FIRC_OK, firc_config_groups_path("/tmp/x/anything.yaml", out, sizeof(out)));
    ASSERT_STR_EQm("the name of the settings file does not matter", "/tmp/x/groups.yaml", out);

    char exact[sizeof("/opt/etc/firc/groups.yaml")];
    ASSERT_EQ(FIRC_OK, firc_config_groups_path("/opt/etc/firc/firc.conf", exact, sizeof(exact)));
    ASSERT_STR_EQ("/opt/etc/firc/groups.yaml", exact);
    ASSERT_EQ_FMTm("and one byte less is refused", FIRC_ERR_INVAL,
                   firc_config_groups_path("/opt/etc/firc/firc.conf", exact, sizeof(exact) - 1),
                   "%d");

    char tiny[8];
    ASSERT_EQ(FIRC_ERR_INVAL,
              firc_config_groups_path("/opt/etc/firc/firc.conf", tiny, sizeof(tiny)));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_config_groups_path(NULL, out, sizeof(out)));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_config_groups_path("firc.conf", out, 0));
    PASS();
}

TEST save_shape_matches_committed_fixture(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: d663876a\n"
        "    name: Example\n"
        "    color: '#ffffff'\n"
        "    interface: nwg0\n"
        "    enable: false\n"
        "    rules:\n"
        "      - id: 6f34ee91\n"
        "        name: Wildcard Example\n"
        "        type: wildcard\n"
        "        rule: '*wildcard.example.com'\n"
        "        enable: true\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer(&cfg, "0.99.0", &out, &out_len));

    const char *want =
        "configVersion: 0.99.0\n"
        "app:\n"
        "  httpWeb:\n"
        "    enabled: true\n"
        "    host:\n"
        "      address: '[::]'\n"
        "      port: 666\n"
        "  dnsProxy:\n"
        "    host:\n"
        "      address: '[::]'\n"
        "      port: 3553\n"
        "    upstream:\n"
        "      address: 127.0.0.1\n"
        "      port: 53\n"
        "    disableRemap53: false\n"
        "    disableDropAAAA: false\n"
        "    unmatchedTtl: 1m0s\n"
        "    maxIdleConns: 10\n"
        "    maxConcurrent: 100\n"
        "    timeout: 5s\n"
        "  netfilter:\n"
        "    iptables:\n"
        "      chainPrefix: FIRC_\n"
        "    disableIPv4: false\n"
        "    disableIPv6: false\n"
        "    startMarkTableIndex: 1718186595\n"
        "  addressPool:\n"
        "    v4:\n"
        "      pool: 198.18.0.0/15\n"
        "      chunk: 24\n"
        "    v6:\n"
        "      pool: \"\"\n"
        "      chunk: 64\n"
        "    ttlClamp: 5m0s\n"
        "    maxNames: 65536\n"
        "  link:\n"
        "  - br0\n"
        "  showAllInterfaces: false\n"
        "  logLevel: info\n"
        "groups:\n"
        "- id: d663876a\n"
        "  name: Example\n"
        "  interface: nwg0\n"
        "  enable: false\n"
        "  rules:\n"
        "  - id: 6f34ee91\n"
        "    type: wildcard\n"
        "    rule: '*wildcard.example.com'\n"
        "    enable: true\n";
    ASSERT_STR_EQ(want, out);
    free(out);
    firc_config_clear(&cfg);
    PASS();
}

TEST quoted_id_shapes(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: \"12345678\"\n"
        "  - id: 666e0000\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer(&cfg, "0.99.0", &out, &out_len));
    ASSERT(strstr(out, "- id: \"12345678\"\n") != NULL);
    ASSERT(strstr(out, "- id: \"666e0000\"\n") != NULL);
    free(out);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: an addressPool field written but not read back, or read into the wrong field. */
TEST fakeip_block_is_read_back(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg,
                                "configVersion: 0.1.0\n"
                                "app:\n"
                                "  addressPool:\n"
                                "    v4:\n"
                                "      pool: 203.0.113.0/26\n"
                                "      chunk: 30\n"
                                "    v6:\n"
                                "      pool: fd00:dead:beef::/48\n"
                                "      chunk: 60\n"
                                "    ttlClamp: 90s\n"
                                "    maxNames: 1234\n"));

    ASSERT_STR_EQ("203.0.113.0/26", cfg.app.fakeip.v4.pool);
    ASSERT_EQ_FMT(30u, (unsigned)cfg.app.fakeip.v4.chunk, "%u");
    ASSERT_STR_EQ("fd00:dead:beef::/48", cfg.app.fakeip.v6.pool);
    ASSERT_EQ_FMT(60u, (unsigned)cfg.app.fakeip.v6.chunk, "%u");
    ASSERT_EQ_FMT((uint64_t)(90 * FIRC_DURATION_SEC), (uint64_t)cfg.app.fakeip.ttl_clamp, "%" PRIu64);
    ASSERT_EQ_FMT(1234u, cfg.app.fakeip.max_names, "%u");

    firc_config_clear(&cfg);

    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, "configVersion: 0.1.0\napp:\n  logLevel: info\n"));
    ASSERT_STR_EQ("198.18.0.0/15", cfg.app.fakeip.v4.pool);
    ASSERT_EQ_FMT(64u, (unsigned)cfg.app.fakeip.v6.chunk, "%u");
    ASSERT_EQ_FMT((uint64_t)(300 * FIRC_DURATION_SEC), (uint64_t)cfg.app.fakeip.ttl_clamp, "%" PRIu64);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a pool geometry the pool would refuse accepted at load, for either family. */
TEST fakeip_bad_geometry_is_refused(void)
{
    static const struct {
        const char *why;
        const char *block;
    } bad[] = {
        {"chunk wider than the pool leaves nothing to slice",
         "    v4:\n      pool: 198.18.0.0/15\n      chunk: 8\n"},
        {"chunk equal to the pool is a single chunk, not a slicing",
         "    v4:\n      pool: 198.18.0.0/15\n      chunk: 15\n"},
        {"a chunk past the address width does not exist",
         "    v4:\n      pool: 198.18.0.0/15\n      chunk: 100\n"},
        {"a /31 chunk holds two addresses, both of them reserved",
         "    v4:\n      pool: 198.18.0.0/15\n      chunk: 31\n"},
        {"not an address at all",
         "    v4:\n      pool: not-an-address\n      chunk: 24\n"},
        {"an address with no prefix is not a pool",
         "    v4:\n      pool: 198.18.0.0\n      chunk: 24\n"},
        {"a base with bits below the prefix is not a CIDR block",
         "    v4:\n      pool: 198.18.0.1/15\n      chunk: 24\n"},
        {"the family comes from the text, so this is not a v4 pool",
         "    v4:\n      pool: fd00::/48\n      chunk: 64\n"},
        {"and the reverse, in the v6 slot",
         "    v6:\n      pool: 198.18.0.0/15\n      chunk: 24\n"},
        {"2^48 chunks cannot be counted in 32 bits",
         "    v6:\n      pool: fd00::/16\n      chunk: 64\n"},
        {"the v6 pool is generated as a /48, so a /40 chunk is wider than it",
         "    v6:\n      chunk: 40\n"},
        {"a family is a mapping; a scalar here is a typo, not a pool",
         "    v4: 198.18.0.0/15\n"},
        {"a chunk wider than any address, past the getter's own ceiling — it is "
         "truncated to a byte on the way in, so 280 would become 24 and pass",
         "    v4:\n      pool: 198.18.0.0/15\n      chunk: 280\n"},
        {"and the v6 equivalent, where 320 would become 64",
         "    v6:\n      pool: fd00:dead:beef::/48\n      chunk: 320\n"},
        {"a /0 pool is the whole address space, which is not ours to claim",
         "    v4:\n      pool: 0.0.0.0/0\n      chunk: 24\n"},
        {"and the v6 equivalent",
         "    v6:\n      pool: ::/0\n      chunk: 64\n"},
        {"exactly 2^32 chunks is one too many for the uint32_t counting them",
         "    v6:\n      pool: fd00::/32\n      chunk: 64\n"},
        {"there is no generated v4 pool, so an empty one names nothing",
         "    v4:\n      pool: \"\"\n      chunk: 24\n"},
    };

    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char doc[512];
        snprintf(doc, sizeof(doc),
                 "configVersion: 0.1.0\napp:\n  addressPool:\n%s", bad[i].block);
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        firc_err_t got = load_str(&cfg, doc);
        firc_config_clear(&cfg);
        if (got != FIRC_ERR_INVAL) {
            FAILm(bad[i].why);
        }
    }
    PASS();
}

/* Catches: a valid pool geometry refused at load. */
TEST fakeip_good_geometry_is_accepted(void)
{
    static const char *good[] = {
        "    v4:\n      pool: 198.18.0.0/15\n      chunk: 24\n",
        "    v4:\n      pool: 203.0.113.0/26\n      chunk: 30\n",
        "    v6:\n      pool: fd00:dead:beef:1::/96\n      chunk: 126\n",
        "    v6:\n      pool: fd12:3456:789a:b000::/52\n      chunk: 64\n",
        "    v6:\n      chunk: 64\n",
        "    ttlClamp: 60s\n",
    };

    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
        char doc[512];
        snprintf(doc, sizeof(doc),
                 "configVersion: 0.1.0\napp:\n  addressPool:\n%s", good[i]);
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        firc_err_t got = load_str(&cfg, doc);
        firc_config_clear(&cfg);
        if (got != FIRC_OK) {
            FAILm(good[i]);
        }
    }
    PASS();
}

/* Catches: maxNames 0 accepted, which the pool reads as the default bound. */
TEST fakeip_zero_max_names_is_refused(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_ERR_INVAL,
              load_str(&cfg, "configVersion: 0.1.0\napp:\n  addressPool:\n    maxNames: 0\n"));
    firc_config_clear(&cfg);

    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK,
              load_str(&cfg, "configVersion: 0.1.0\napp:\n  addressPool:\n    maxNames: 1\n"));
    ASSERT_EQ_FMT(1u, cfg.app.fakeip.max_names, "%u");
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a scalar or list addressPool accepted and silently replaced by the defaults. */
TEST an_address_pool_that_is_not_a_mapping_is_refused(void)
{
    static const char *bad[] = {
        "configVersion: 0.1.0\napp:\n  addressPool: 100.64.0.0/10\n",
        "configVersion: 0.1.0\napp:\n  addressPool: 42\n",
        "configVersion: 0.1.0\napp:\n  addressPool:\n    - v4\n    - v6\n",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        firc_err_t got = load_str(&cfg, bad[i]);
        firc_config_clear(&cfg);
        if (got != FIRC_ERR_INVAL) { FAILm(bad[i]); }
    }

    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, "configVersion: 0.1.0\napp:\n  addressPool:\n"));
    ASSERT_STR_EQ("198.18.0.0/15", cfg.app.fakeip.v4.pool);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a clamp whose derived window passes the one-year ceiling accepted at load. */
TEST windows_past_the_ceiling_are_refused(void)
{
    static const char *bad[] = {
        "configVersion: 0.1.0\napp:\n  addressPool:\n    ttlClamp: 87600h\n",
        "configVersion: 0.1.0\napp:\n  addressPool:\n    ttlClamp: 4392h\n",
        "configVersion: 0.1.0\napp:\n  addressPool:\n    ttlClamp: 15724801s\n",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        firc_err_t got = load_str(&cfg, bad[i]);
        firc_config_clear(&cfg);
        if (got != FIRC_ERR_INVAL) { FAILm(bad[i]); }
    }

    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK,
              load_str(&cfg, "configVersion: 0.1.0\napp:\n  addressPool:\n    ttlClamp: 4368h\n"));
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a refused clamp not naming its key, or the cap off by a second either way. */
TEST a_clamp_past_182_days_is_refused_naming_its_key(void)
{
    char path[] = "/tmp/firc_clamp_log_XXXXXX";
    int fd = mkstemp(path);
    ASSERT(fd >= 0);
    firc_log_set_fd(fd);
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    firc_err_t got = load_str(&cfg, "configVersion: 0.1.0\napp:\n  addressPool:\n    ttlClamp: 15724801s\n");
    firc_config_clear(&cfg);
    firc_log_set_fd(2);
    char buf[512] = {0};
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
    close(fd);
    unlink(path);
    ASSERT_EQ(FIRC_ERR_INVAL, got);
    ASSERT(n > 0);
    ASSERT(strstr(buf, "app.addressPool.ttlClamp") != NULL);

    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, "configVersion: 0.1.0\napp:\n  addressPool:\n    ttlClamp: 15724800s\n"));
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: an idleWindow from an old file surviving into the saved file. */
TEST an_old_idle_window_is_dropped_by_the_next_save(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, "configVersion: 0.1.0\napp:\n  addressPool:\n    ttlClamp: 90s\n    idleWindow: 12h\n"));
    char *out = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer(&cfg, "0.7.0", &out, &len));
    ASSERT(strstr(out, "idleWindow") == NULL);
    ASSERT(strstr(out, "ttlClamp: 1m30s") != NULL);
    free(out);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a second overlay without the block clearing a refusal from an earlier one. */
TEST a_later_load_cannot_launder_a_refused_geometry(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_ERR_INVAL,
              load_str(&cfg, "configVersion: 0.1.0\napp:\n  addressPool:\n"
                             "    v4:\n      pool: 198.18.0.0/15\n      chunk: 8\n"));
    ASSERT_EQ_FMT(8u, (unsigned)cfg.app.fakeip.v4.chunk, "%u");

    ASSERT_EQ_FMTm("the geometry is still the refused one, so this must refuse too",
                   (int)FIRC_ERR_INVAL,
                   (int)load_str(&cfg, "configVersion: 0.1.0\napp:\n  logLevel: info\n"), "%d");
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: the loader not asking firc_app_config_check, so an unknown log level loads. */
TEST a_log_level_the_daemon_does_not_have_is_refused(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_ERR_INVAL, load_str(&cfg, "configVersion: 0.7.0\napp:\n  logLevel: loud\n"));
    firc_config_clear(&cfg);
    PASS();
}

TEST an_upstream_that_is_not_an_address_is_refused(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_ERR_INVAL, load_str(&cfg, "configVersion: 0.7.0\napp:\n  dnsProxy:\n"
                                             "    upstream: {address: dns.example}\n"));
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: the loader still reading `skin`, or the saver still writing it. */
TEST a_conf_that_still_names_a_skin_loads_and_drops_it(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, "configVersion: 0.7.0\napp:\n  httpWeb:\n    skin: custom\n"));
    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_SETTINGS, &out, &out_len));
    ASSERT_FALSE(strstr(out, "skin") != NULL);
    free(out);
    firc_config_clear(&cfg);
    PASS();
}

TEST a_conf_that_still_names_the_fake_ptr_switch_loads_and_drops_it(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, "configVersion: 0.7.0\napp:\n  dnsProxy:\n    disableFakePTR: true\n"
                                      "    disableDropAAAA: true\n"));
    ASSERTm("control: the keys around it are still read", cfg.app.dns_proxy.disable_drop_aaaa);
    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_SETTINGS, &out, &out_len));
    ASSERT_EQ(NULL, strstr(out, "FakePTR"));
    free(out);
    firc_config_clear(&cfg);
    PASS();
}

#define LIST_GROUP_DOC                                                                             \
    "configVersion: 0.7.0\n"                                                                       \
    "groups:\n"                                                                                    \
    "  - id: 5eba1111\n"                                                                           \
    "    name: ads\n"                                                                              \
    "    interface: nwg0\n"                                                                        \
    "    enable: true\n"                                                                           \
    "    list:\n"                                                                                  \
    "      url: 'https://example.invalid/l.txt'\n"                                                 \
    "      interval: 86400\n"

/* Adds a group with a list to `cfg`; NULL on OOM. */
static firc_group_list_t *add_list_group(firc_config_t *cfg, const char *name)
{
    firc_group_t *g = firc_group_new();
    if (g == NULL) { return NULL; }
    g->id = firc_id_random();
    g->list = firc_group_list_new();
    if (g->list == NULL || firc_strset(&g->name, name) != FIRC_OK ||
        firc_strset(&g->iface, "nwg0") != FIRC_OK ||
        firc_strset(&g->list->url, "https://example.invalid/l.txt") != FIRC_OK ||
        firc_config_add_group(cfg, g) != FIRC_OK) {
        firc_group_free(g);
        return NULL;
    }
    g->enable = true;
    return g->list;
}

/* Catches: a group's list logging a line at every load. */
TEST a_group_list_in_the_new_shape_loads_quietly(void)
{
    int fds[2];
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    firc_err_t err = load_str(&cfg, LIST_GROUP_DOC
                              "      overrides:\n"
                              "        - rule: edited.example.com\n"
                              "          enable: false\n");
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    char out[1024];
    ssize_t got = read(fds[0], out, sizeof(out) - 1);
    close(fds[0]);
    if (got < 0) { got = 0; }
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMTm("nothing to say", (size_t)0, (size_t)got, "%zu");
    ASSERT_EQ(1, (int)cfg.n_groups);
    ASSERT(firc_group_list_find_override(cfg.groups[0]->list,
                                         &(firc_sub_rule_key_t){.text = "edited.example.com"}) != NULL);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a saved list writing its fetched rules instead of only the overrides. */
TEST a_saved_group_list_carries_edits_not_rules(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    firc_group_list_t *l = add_list_group(&cfg, "ads");
    ASSERT(l != NULL);
    l->interval = 86400;
    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&l->rules, "fetched.example.com", "namespace", true,
                                           firc_id_random()));
    bool off = false;
    ASSERT_EQ(FIRC_OK,
             firc_group_list_set_override(
                 l, &(firc_sub_rule_key_t){.text = "edited.example.com"}, "domain", &off));

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));

    ASSERTm("the file has an overrides list", strstr(out, "overrides:") != NULL);
    ASSERTm("naming the edited rule by its text", strstr(out, "edited.example.com") != NULL);
    ASSERTm("with the type it was given", strstr(out, "domain") != NULL);
    ASSERT_FALSEm("and the fetched rule is not in the file at all",
                  strstr(out, "fetched.example.com") != NULL);
    ASSERT_FALSEm("nor is a rules key under the list",
                  strstr(strstr(out, "list:"), "rules:") != NULL);

    free(out);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: an untouched list writing anything but an empty overrides list. */
TEST a_group_list_with_no_edits_writes_an_empty_list(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    firc_group_list_t *l = add_list_group(&cfg, "ads");
    ASSERT(l != NULL);
    for (int i = 0; i < 100; i++) {
        char text[64];
        snprintf(text, sizeof(text), "n%d.example.com", i);
        ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&l->rules, text, "namespace", true, firc_id_random()));
    }

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));
    ASSERT(strstr(out, "overrides: []") != NULL);
    ASSERT_FALSEm("a hundred rules add nothing to the file",
                  strstr(out, "n99.example.com") != NULL);
    ASSERT_FALSEm("nor the first of them", strstr(out, "n0.example.com") != NULL);

    free(out);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a list's overrides lost on a save and load. */
TEST overrides_round_trip(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: 'ads.example.com'\n"
                                "          type: domain\n"
                                "          enable: false\n"
                                "        - rule: 'other.example.com'\n"
                                "          type: wildcard\n"));
    ASSERT_EQ(1, (int)cfg.n_groups);
    const firc_sub_override_t *o =
        firc_group_list_find_override(cfg.groups[0]->list,
                                      &(firc_sub_rule_key_t){.text = "ads.example.com"});
    ASSERT(o != NULL);
    ASSERT_STR_EQ("domain", o->type);
    ASSERTm("an enable key means an opinion about enable", o->has_enable);
    ASSERT_FALSE(o->enable);

    const firc_sub_override_t *o2 =
        firc_group_list_find_override(cfg.groups[0]->list,
                                      &(firc_sub_rule_key_t){.text = "other.example.com"});
    ASSERT(o2 != NULL);
    ASSERT_STR_EQ("wildcard", o2->type);
    ASSERT_FALSEm("and no enable key means none", o2->has_enable);

    firc_config_clear(&cfg);
    PASS();
}

/* Catches: an override's list_type, proto or ports dropped on save or load, so its key stops matching. */
TEST an_override_with_a_full_key_round_trips(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: '10.0.0.0/8'\n"
                                "          list_type: subnet\n"
                                "          proto: udp\n"
                                "          ports: \"53\"\n"
                                "          enable: false\n"));
    firc_sub_rule_key_t key = {
        .text = "10.0.0.0/8", .list_type = "subnet", .proto = "udp", .ports = "53"};
    const firc_sub_override_t *o = firc_group_list_find_override(cfg.groups[0]->list, &key);
    ASSERTm("the full key is found right after loading", o != NULL);
    ASSERT_FALSE(o->enable);

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));
    ASSERTm("list_type is saved", strstr(out, "list_type: subnet") != NULL);
    ASSERTm("proto is saved", strstr(out, "proto: udp") != NULL);
    ASSERTm("ports is saved", strstr(out, "ports: \"53\"") != NULL);
    firc_config_clear(&cfg);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, out, out_len));
    const firc_sub_override_t *o2 = firc_group_list_find_override(back.groups[0]->list, &key);
    ASSERTm("the same full key finds it again after the reload", o2 != NULL);
    ASSERT_FALSE(o2->enable);
    free(out);
    firc_config_clear(&back);
    PASS();
}

/* Catches: an override key not folded at load, so it misses the folded rule it names. */
TEST an_override_key_is_folded_like_the_rule_it_names(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: 'Ads.Example.COM.'\n"
                                "          enable: false\n"
                                "        - rule: '\\A(?:^Ads\\.example\\.com$)\\z'\n"
                                "          enable: false\n"));
    ASSERT_EQ(1, (int)cfg.n_groups);
    ASSERT(firc_group_list_find_override(cfg.groups[0]->list,
                                         &(firc_sub_rule_key_t){.text = "ads.example.com"}) != NULL);
    ASSERT(firc_group_list_find_override(cfg.groups[0]->list,
                                         &(firc_sub_rule_key_t){.text = "Ads.Example.COM."}) == NULL);
    ASSERT(firc_group_list_find_override(cfg.groups[0]->list,
                                         &(firc_sub_rule_key_t){.text = "\\A(?:^Ads\\.example\\.com$)\\z"}) != NULL);
    firc_config_clear(&cfg);
    PASS();
}

TEST a_hand_typed_regex_override_key_is_not_folded(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: '^A\\D+\\.com$'\n"
                                "          enable: false\n"));
    ASSERT_EQ(1, (int)cfg.n_groups);
    ASSERT(firc_group_list_find_override(cfg.groups[0]->list,
                                         &(firc_sub_rule_key_t){.text = "^A\\D+\\.com$"}) != NULL);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a list-typed regex key with no metacharacter folded at load. */
TEST a_list_typed_regex_override_key_is_not_folded_without_a_metacharacter(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: 'ABC'\n"
                                "          list_type: regex\n"
                                "          enable: false\n"));
    ASSERT_EQ(1, (int)cfg.n_groups);
    ASSERTm("the mixed-case key is kept as written",
            firc_group_list_find_override(
                cfg.groups[0]->list, &(firc_sub_rule_key_t){.text = "ABC", .list_type = "regex"}) !=
                NULL);
    ASSERTm("it was not folded to lower case",
            firc_group_list_find_override(
                cfg.groups[0]->list, &(firc_sub_rule_key_t){.text = "abc", .list_type = "regex"}) ==
                NULL);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: an override with an unusable type dropped whole, switching its rule back on. */
TEST an_unusable_override_type_does_not_take_the_enable_with_it(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: 'ads.example.com'\n"
                                "          type: subnet\n"
                                "          enable: false\n"));
    const firc_sub_override_t *o =
        firc_group_list_find_override(cfg.groups[0]->list,
                                      &(firc_sub_rule_key_t){.text = "ads.example.com"});
    ASSERTm("the entry survives", o != NULL);
    ASSERT_EQm("without the type nobody can use", NULL, o->type);
    ASSERTm("and with the switch the operator threw", o->has_enable);
    ASSERT_FALSE(o->enable);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: an override type checked without the rule's proto, keeping a type that cannot carry it. */
TEST an_override_type_unusable_with_its_own_proto_is_dropped(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: 'a.com'\n"
                                "          proto: udp\n"
                                "          type: domain\n"
                                "          enable: false\n"));
    const firc_sub_override_t *o = firc_group_list_find_override(
        cfg.groups[0]->list, &(firc_sub_rule_key_t){.text = "a.com", .proto = "udp"});
    ASSERTm("the entry survives", o != NULL);
    ASSERT_EQm("domain cannot carry a proto, so the type is dropped", NULL, o->type);
    ASSERTm("and the switch the operator threw is kept", o->has_enable);
    ASSERT_FALSE(o->enable);
    firc_config_clear(&cfg);
    PASS();
}

TEST an_override_that_was_only_a_bad_type_is_dropped(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: 'ads.example.com'\n"
                                "          type: subnet\n"));
    ASSERT_EQ_FMTm("nothing left to say", 0, (int)cfg.groups[0]->list->n_overrides, "%d");
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a `type:` key written for an override that set no type. */
TEST an_override_with_no_type_writes_no_type_key(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    firc_group_list_t *l = add_list_group(&cfg, "ads");
    ASSERT(l != NULL);
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           l, &(firc_sub_rule_key_t){.text = "ads.example.com"}, NULL, &off));

    char *out = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &len));
    ASSERTm("the entry is there", strstr(out, "ads.example.com") != NULL);
    ASSERTm("with its enable", strstr(strstr(out, "ads.example.com"), "enable: false") != NULL);
    ASSERT_FALSEm("and no type key at all", strstr(out, "type:") != NULL);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, out, len));
    const firc_sub_override_t *o =
        firc_group_list_find_override(back.groups[0]->list,
                                      &(firc_sub_rule_key_t){.text = "ads.example.com"});
    ASSERT(o != NULL);
    ASSERT_EQ(NULL, o->type);
    ASSERT(o->has_enable);
    ASSERT_FALSE(o->enable);

    free(out);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: proto or ports keys written for an override that set neither. */
TEST an_override_with_no_spec_writes_no_spec_keys(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    firc_group_list_t *l = add_list_group(&cfg, "ads");
    ASSERT(l != NULL);
    bool off = false;
    ASSERT_EQ(FIRC_OK, firc_group_list_set_override(
                           l, &(firc_sub_rule_key_t){.text = "ads.example.com"}, "domain", &off));

    char *out = NULL;
    size_t len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &len));
    ASSERTm("the entry is there", strstr(out, "ads.example.com") != NULL);
    ASSERT_FALSEm("no list_type key", strstr(out, "list_type:") != NULL);
    ASSERT_FALSEm("no proto key", strstr(out, "proto:") != NULL);
    ASSERT_FALSEm("no ports key", strstr(out, "ports:") != NULL);
    free(out);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a full-key edit missing a legacy entry, so the rule reads as off again after a reload. */
TEST enabling_a_legacy_override_by_its_full_key_survives_a_reload(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: 'ads.example.com'\n"
                                "          enable: false\n"));
    firc_group_list_t *l = cfg.groups[0]->list;
    bool on = true;
    ASSERT_EQ(FIRC_OK,
              firc_group_list_set_override(
                  l, &(firc_sub_rule_key_t){.text = "ads.example.com", .list_type = "domain"}, NULL,
                  &on));

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));
    ASSERT_FALSEm("nothing left to disagree about -- the legacy entry is adopted and cleared",
                  strstr(out, "ads.example.com") != NULL);
    firc_config_clear(&cfg);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, out, out_len));
    free(out);

    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK,
              firc_sub_rules_push(&rules, "ads.example.com", "domain", true, firc_id_random()));
    firc_sub_apply_overrides(back.groups[0]->list, &rules);
    ASSERTm("the rule reads enabled after the reload", firc_sub_rules_enable(&rules, 0));

    firc_sub_rules_free(&rules);
    firc_config_clear(&back);
    PASS();
}

/* Catches: an older legacy entry shadowing a typed one after a reload, losing the chosen type. */
TEST a_type_edit_on_a_legacy_overridden_rule_survives_a_reload(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str(&cfg, LIST_GROUP_DOC
                                "      overrides:\n"
                                "        - rule: 'ads.example.com'\n"
                                "          enable: false\n"));
    firc_group_list_t *l = cfg.groups[0]->list;
    ASSERT_EQ(FIRC_OK,
              firc_group_list_set_override(
                  l, &(firc_sub_rule_key_t){.text = "ads.example.com", .list_type = "domain"},
                  "wildcard", NULL));
    ASSERT_EQ_FMTm("the legacy entry is adopted, not duplicated", 1, (int)l->n_overrides, "%d");

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));
    firc_config_clear(&cfg);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, firc_config_load_buffer(&back, out, out_len));
    free(out);

    firc_sub_rules_t rules;
    firc_sub_rules_init(&rules);
    ASSERT_EQ(FIRC_OK,
              firc_sub_rules_push(&rules, "ads.example.com", "domain", true, firc_id_random()));
    firc_sub_apply_overrides(back.groups[0]->list, &rules);
    ASSERT_STR_EQm("the type survived the reload", "wildcard", firc_sub_rules_type(&rules, 0));
    ASSERT_FALSEm("and so did the old enable opinion", firc_sub_rules_enable(&rules, 0));

    firc_sub_rules_free(&rules);
    firc_config_clear(&back);
    PASS();
}

/* Loads a YAML document into `cfg` and copies what was logged at INFO and above into `out`. */
static firc_err_t load_str_logged(firc_config_t *cfg, const char *doc, char *out, size_t cap)
{
    int fds[2];
    if (pipe(fds) != 0) { return FIRC_ERR_IO; }
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    firc_err_t err = load_str(cfg, doc);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    ssize_t n = read(fds[0], out, cap - 1);
    close(fds[0]);
    if (n < 0) { n = 0; }
    out[n] = '\0';
    return err;
}

TEST a_mac_entry_is_loaded_and_saved_canonical(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: kids\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    devices:\n"
        "      allow: ['mac:AA-BB-CC-DD-EE-0F', '192.168.1.0/24']\n"
        "      deny: ['mac:AA-BB-CC-DD-EE-10']\n"
        "    rules: []\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_STR_EQm("held canonical", "mac:aa:bb:cc:dd:ee:0f", cfg.groups[0]->devices.allow[0]);
    ASSERT_STR_EQm("an address entry untouched", "192.168.1.0/24", cfg.groups[0]->devices.allow[1]);
    ASSERT_STR_EQm("deny is canonicalised too", "mac:aa:bb:cc:dd:ee:10", cfg.groups[0]->devices.deny[0]);

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer(&cfg, "0.99.0", &out, &out_len));
    ASSERT(strstr(out, "mac:aa:bb:cc:dd:ee:0f") != NULL);
    ASSERT(strstr(out, "mac:aa:bb:cc:dd:ee:10") != NULL);
    ASSERT_FALSEm("no trace of the form it was written in", strstr(out, "AA-BB") != NULL);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, load_str(&back, out));
    ASSERT_STR_EQ("mac:aa:bb:cc:dd:ee:0f", back.groups[0]->devices.allow[0]);
    free(out);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a bad device entry refused in silence, or naming the wrong list. */
TEST a_bad_device_entry_fails_the_load_naming_the_group_and_the_key(void)
{
    struct {
        const char *devices, *key, *entry, *word;
    } bad[] = {
        {"allow: ['mac:aa:bb:cc:dd:ee']", "devices.allow", "mac:aa:bb:cc:dd:ee", "MAC"},
        {"deny: [the-tv]", "devices.deny", "the-tv", "neither"},
        {"deny: ['policy:']", "devices.deny", "policy:", "no policy"},
        {"allow: not-a-list", "devices.allow", "is not a list of device names", "names"},
        {"deny: [{a: b}]", "devices.deny", "is not a list of device names", "names"},
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        char doc[512];
        snprintf(doc, sizeof(doc),
                 "configVersion: 0.7.0\n"
                 "groups:\n"
                 "  - id: 0a1b2c3d\n"
                 "    name: kids\n"
                 "    interface: nwg0\n"
                 "    enable: true\n"
                 "    devices: {%s}\n"
                 "    rules: []\n",
                 bad[i].devices);
        char log[2048];
        ASSERT_FALSEm(bad[i].entry, load_str_logged(&cfg, doc, log, sizeof(log)) == FIRC_OK);
        ASSERTm(log, strstr(log, "\"kids\"") != NULL);
        ASSERTm(log, strstr(log, bad[i].key) != NULL);
        ASSERTm(log, strstr(log, bad[i].entry) != NULL);
        ASSERTm(log, strstr(log, bad[i].word) != NULL);
        firc_config_clear(&cfg);
    }
    PASS();
}

/* Catches: a group without `resolve` not tunnelling, or a default `resolve` block written. */
TEST a_group_without_resolve_tunnels_and_writes_no_resolve_key(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: nl\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    rules: []\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT(cfg.groups[0]->resolve.tunnel);
    ASSERT(cfg.groups[0]->resolve.server == NULL || cfg.groups[0]->resolve.server[0] == '\0');
    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));
    ASSERT_FALSEm("no resolve key for the default", strstr(out, "resolve") != NULL);
    free(out);
    firc_config_clear(&cfg);
    PASS();
}

TEST a_group_resolve_round_trips(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: off\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    resolve: {tunnel: false}\n"
        "    rules: []\n"
        "  - id: 0a1b2c3e\n"
        "    name: own\n"
        "    interface: nwg1\n"
        "    enable: true\n"
        "    resolve:\n"
        "      server: '[2620:fe::fe]:853'\n"
        "    rules: []\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_FALSE(cfg.groups[0]->resolve.tunnel);
    ASSERT(cfg.groups[1]->resolve.tunnel);
    ASSERT_STR_EQ("[2620:fe::fe]:853", cfg.groups[1]->resolve.server);

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK, firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));
    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, load_str(&back, out));
    free(out);
    ASSERT_FALSE(back.groups[0]->resolve.tunnel);
    ASSERT(back.groups[0]->resolve.server == NULL || back.groups[0]->resolve.server[0] == '\0');
    ASSERT(back.groups[1]->resolve.tunnel);
    ASSERT_STR_EQ("[2620:fe::fe]:853", back.groups[1]->resolve.server);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a sink resolve server accepted, or refused without naming the group and key. */
TEST a_sink_resolve_server_fails_the_load_and_names_the_key(void)
{
    const char *bad[] = {"127.0.0.1", "0.0.0.0:53", "::1", "dns.google", "9.9.9.9:0"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        char doc[512];
        snprintf(doc, sizeof(doc),
                 "configVersion: 0.7.0\n"
                 "groups:\n"
                 "  - id: 0a1b2c3d\n"
                 "    name: nl\n"
                 "    interface: nwg0\n"
                 "    enable: true\n"
                 "    resolve: {server: '%s'}\n"
                 "    rules: []\n",
                 bad[i]);
        char log[2048];
        ASSERT_FALSEm(bad[i], load_str_logged(&cfg, doc, log, sizeof(log)) == FIRC_OK);
        ASSERTm(log, strstr(log, "resolve.server") != NULL);
        ASSERTm(log, strstr(log, "\"nl\"") != NULL);
        firc_config_clear(&cfg);
    }
    PASS();
}

/* Catches: a non-mapping `resolve` or a non-bool `tunnel` loading. */
TEST a_resolve_of_the_wrong_shape_fails_the_load(void)
{
    const char *bad[] = {"resolve: 9.9.9.9", "resolve: {tunnel: maybe}", "resolve: [9.9.9.9]"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        firc_config_t cfg;
        ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
        char doc[512];
        snprintf(doc, sizeof(doc),
                 "configVersion: 0.7.0\ngroups:\n  - id: 0a1b2c3d\n    name: nl\n"
                 "    interface: nwg0\n    enable: true\n    %s\n    rules: []\n",
                 bad[i]);
        ASSERT_FALSEm(bad[i], load_str(&cfg, doc) == FIRC_OK);
        firc_config_clear(&cfg);
    }
    PASS();
}

/* Catches: an old `subscriptions:` key dropped silently, or warned once per entry. */
TEST a_file_with_subscriptions_warns_once(void)
{
    char out[4096];
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    firc_err_t err = load_str_logged(&cfg,
                                     "configVersion: 0.7.0\n"
                                     "groups:\n"
                                     "  - id: 0a1b2c3d\n"
                                     "    name: kids\n"
                                     "    interface: nwg0\n"
                                     "    enable: true\n"
                                     "    rules: []\n"
                                     "subscriptions:\n"
                                     "  - id: 5eba1111\n"
                                     "    name: ads\n"
                                     "    url: 'https://example.invalid/a.txt'\n"
                                     "  - id: 5eba2222\n"
                                     "    name: more\n"
                                     "    url: 'https://example.invalid/b.txt'\n",
                                     out, sizeof(out));
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQ_FMTm("the groups are loaded", (size_t)1, cfg.n_groups, "%zu");
    int lines = 0;
    for (const char *p = out; (p = strstr(p, "\"subscriptions\" key is no longer read")) != NULL; p++) {
        lines++;
    }
    ASSERT_EQ_FMTm("said once, not per entry", 1, lines, "%d");
    ASSERTm("as a warning", strstr(out, "WRN") != NULL);
    ASSERTm("the count", strstr(out, "2 entries are ignored") != NULL);
    ASSERTm("the first url", strstr(out, "https://example.invalid/a.txt") != NULL);
    ASSERTm("the second url", strstr(out, "https://example.invalid/b.txt") != NULL);
    ASSERTm("no tail for two", strstr(out, "more") == NULL);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: every subscription url printed, or those past three dropped without a count. */
TEST a_long_subscriptions_key_names_three_urls_and_counts_the_rest(void)
{
    char out[4096];
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str_logged(&cfg,
                                       "configVersion: 0.7.0\n"
                                       "subscriptions:\n"
                                       "  - url: 'https://example.invalid/1.txt'\n"
                                       "  - url: 'https://example.invalid/2.txt'\n"
                                       "  - url: 'https://example.invalid/3.txt'\n"
                                       "  - url: 'https://example.invalid/4.txt'\n"
                                       "  - url: 'https://example.invalid/5.txt'\n",
                                       out, sizeof(out)));
    ASSERTm("the count", strstr(out, "5 entries are ignored") != NULL);
    ASSERTm("the third url", strstr(out, "https://example.invalid/3.txt") != NULL);
    ASSERTm("not the fourth", strstr(out, "https://example.invalid/4.txt") == NULL);
    ASSERTm("the rest counted", strstr(out, "and 2 more") != NULL);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: `subscriptions: []` reported as ignored entries, or not at all. */
TEST an_empty_subscriptions_key_says_nothing_is_lost(void)
{
    char out[4096];
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(FIRC_OK, load_str_logged(&cfg, "configVersion: 0.7.0\nsubscriptions: []\n", out, sizeof(out)));
    ASSERTm("said", strstr(out, "\"subscriptions\" key is no longer read") != NULL);
    ASSERTm("nothing lost", strstr(out, "it holds no entries, nothing is lost") != NULL);
    ASSERTm("no entries counted", strstr(out, "entries are ignored") == NULL);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a group's list block not read, read at the wrong nesting, or saved with rules. */
TEST a_group_list_round_trips(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: ads\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    rules: []\n"
        "    list:\n"
        "      url: 'https://example.invalid/l.txt'\n"
        "      interval: 86400\n"
        "      last_update: 1700000000\n"
        "      overrides:\n"
        "        - rule: 'Ads.Example.COM'\n"
        "          type: domain\n"
        "          enable: false\n"
        "        - rule: '\\A(?:^Weird\\.Example\\.com$)\\z'\n"
        "          enable: false\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_EQ(1, (int)cfg.n_groups);
    ASSERT(cfg.groups[0]->list != NULL);
    ASSERT_STR_EQ("https://example.invalid/l.txt", cfg.groups[0]->list->url);
    ASSERT_EQ_FMT((uint32_t)86400, cfg.groups[0]->list->interval, "%u");
    ASSERT_EQ_FMT((uint32_t)1700000000, cfg.groups[0]->list->last_update, "%u");
    const firc_sub_override_t *o =
        firc_group_list_find_override(cfg.groups[0]->list,
                                      &(firc_sub_rule_key_t){.text = "ads.example.com"});
    ASSERTm("a mixed-case key is folded", o != NULL);
    ASSERT_STR_EQ("domain", o->type);
    ASSERT_FALSE(o->enable);
    ASSERT_FALSEm("the unfolded original key is gone",
                  firc_group_list_find_override(cfg.groups[0]->list,
                                                &(firc_sub_rule_key_t){.text = "Ads.Example.COM"}) != NULL);
    const firc_sub_override_t *o2 = firc_group_list_find_override(
        cfg.groups[0]->list, &(firc_sub_rule_key_t){.text = "\\A(?:^Weird\\.Example\\.com$)\\z"});
    ASSERTm("a regex key is not folded", o2 != NULL);
    ASSERT_FALSE(o2->enable);

    ASSERT_EQ(FIRC_OK, firc_sub_rules_push(&cfg.groups[0]->list->rules,
                                           "must-not-be-written.example.com", FIRC_RULE_DOMAIN,
                                           true, (firc_id_t){{9, 9, 0, 0}}));

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));
    const char *rules_pos = strstr(out, "rules:");
    const char *list_pos = strstr(out, "list:");
    ASSERT(rules_pos != NULL);
    ASSERTm("list: is written", list_pos != NULL);
    ASSERTm("list: comes after the group's own rules:", list_pos > rules_pos);
    ASSERT_FALSEm("the list's own rule is not written",
                  strstr(out, "must-not-be-written.example.com") != NULL);
    ASSERT_FALSEm("no list rules key is written", strstr(list_pos, "rules:") != NULL);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, load_str(&back, out));
    free(out);
    ASSERT(back.groups[0]->list != NULL);
    ASSERT_STR_EQ("https://example.invalid/l.txt", back.groups[0]->list->url);
    ASSERT_EQ_FMT((uint32_t)86400, back.groups[0]->list->interval, "%u");
    ASSERT_EQ_FMT((uint32_t)1700000000, back.groups[0]->list->last_update, "%u");
    ASSERT(firc_group_list_find_override(back.groups[0]->list,
                                         &(firc_sub_rule_key_t){.text = "ads.example.com"}) != NULL);
    ASSERT(firc_group_list_find_override(back.groups[0]->list,
                                         &(firc_sub_rule_key_t){.text = "\\A(?:^Weird\\.Example\\.com$)\\z"}) != NULL);

    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a list without a url accepted at load. */
TEST a_group_list_without_a_url_fails_the_load(void)
{
    firc_config_t cfg;
    char buf[4096];
    int fds[2];

    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_level(FIRC_LOG_INFO);
    firc_log_set_fd(fds[1]);
    const char *missing =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: ads\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    rules: []\n"
        "    list:\n"
        "      interval: 86400\n";
    firc_err_t err = load_str(&cfg, missing);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    ssize_t n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    ASSERT(err != FIRC_OK);
    if (n < 0) { n = 0; }
    buf[n] = '\0';
    ASSERTm("a missing url names the group in the error", strstr(buf, "ads") != NULL);
    firc_config_clear(&cfg);

    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    ASSERT_EQ(0, pipe(fds));
    firc_log_set_fd(fds[1]);
    const char *empty =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: ads\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    rules: []\n"
        "    list:\n"
        "      url: ''\n";
    err = load_str(&cfg, empty);
    firc_log_set_fd(STDOUT_FILENO);
    close(fds[1]);
    n = read(fds[0], buf, sizeof(buf) - 1);
    close(fds[0]);
    ASSERT(err != FIRC_OK);
    if (n < 0) { n = 0; }
    buf[n] = '\0';
    ASSERTm("an empty url names the group in the error", strstr(buf, "ads") != NULL);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: `list: null` refused instead of read as no list. */
TEST a_null_list_is_no_list(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: ads\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    rules: []\n"
        "    list: null\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT_EQ(1, (int)cfg.n_groups);
    ASSERT(cfg.groups[0]->list == NULL);
    firc_config_clear(&cfg);
    PASS();
}

/* Catches: a `list` key written for a group without a list. */
TEST a_group_without_a_list_writes_no_list_key(void)
{
    firc_config_t cfg;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&cfg));
    const char *doc =
        "configVersion: 0.7.0\n"
        "groups:\n"
        "  - id: 0a1b2c3d\n"
        "    name: kids\n"
        "    interface: nwg0\n"
        "    enable: true\n"
        "    rules: []\n";
    ASSERT_EQ(FIRC_OK, load_str(&cfg, doc));
    ASSERT(cfg.groups[0]->list == NULL);

    char *out = NULL;
    size_t out_len = 0;
    ASSERT_EQ(FIRC_OK,
              firc_config_save_buffer_part(&cfg, "0.7.0", FIRC_CFG_GROUPS, &out, &out_len));
    ASSERT_FALSEm("no list key for a manual group", strstr(out, "list:") != NULL);

    firc_config_t back;
    ASSERT_EQ(FIRC_OK, firc_config_init_defaults(&back));
    ASSERT_EQ(FIRC_OK, load_str(&back, out));
    free(out);
    ASSERT(back.groups[0]->list == NULL);
    firc_config_clear(&back);
    firc_config_clear(&cfg);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_group_list_in_the_new_shape_loads_quietly);
    RUN_TEST(a_saved_group_list_carries_edits_not_rules);
    RUN_TEST(a_group_list_with_no_edits_writes_an_empty_list);
    RUN_TEST(overrides_round_trip);
    RUN_TEST(an_override_with_a_full_key_round_trips);
    RUN_TEST(an_override_key_is_folded_like_the_rule_it_names);
    RUN_TEST(a_hand_typed_regex_override_key_is_not_folded);
    RUN_TEST(a_list_typed_regex_override_key_is_not_folded_without_a_metacharacter);
    RUN_TEST(an_unusable_override_type_does_not_take_the_enable_with_it);
    RUN_TEST(an_override_type_unusable_with_its_own_proto_is_dropped);
    RUN_TEST(an_override_that_was_only_a_bad_type_is_dropped);
    RUN_TEST(an_override_with_no_type_writes_no_type_key);
    RUN_TEST(an_override_with_no_spec_writes_no_spec_keys);
    RUN_TEST(enabling_a_legacy_override_by_its_full_key_survives_a_reload);
    RUN_TEST(a_type_edit_on_a_legacy_overridden_rule_survives_a_reload);
    RUN_TEST(a_mac_entry_is_loaded_and_saved_canonical);
    RUN_TEST(a_bad_device_entry_fails_the_load_naming_the_group_and_the_key);
    RUN_TEST(a_group_without_resolve_tunnels_and_writes_no_resolve_key);
    RUN_TEST(a_group_resolve_round_trips);
    RUN_TEST(a_sink_resolve_server_fails_the_load_and_names_the_key);
    RUN_TEST(a_resolve_of_the_wrong_shape_fails_the_load);
    RUN_TEST(a_file_with_subscriptions_warns_once);
    RUN_TEST(a_long_subscriptions_key_names_three_urls_and_counts_the_rest);
    RUN_TEST(an_empty_subscriptions_key_says_nothing_is_lost);
    RUN_TEST(a_group_list_round_trips);
    RUN_TEST(a_group_list_without_a_url_fails_the_load);
    RUN_TEST(a_null_list_is_no_list);
    RUN_TEST(a_group_without_a_list_writes_no_list_key);
    RUN_TEST(any_config_version_loads);
    RUN_TEST(an_empty_document_is_refused);
    RUN_TEST(a_saved_non_zero_version_loads_back);
    RUN_TEST(overlay_and_defaults);
    RUN_TEST(device_selector_round_trips_and_an_empty_one_is_not_written);
    RUN_TEST(a_device_entry_that_is_nothing_fails_the_load);
    RUN_TEST(legacy_duration_normalization);
    RUN_TEST(absent_enable_is_false);
    RUN_TEST(duplicate_ids_fail);
    RUN_TEST(type_mismatch_fails);
    RUN_TEST(corrupt_yaml_fails);
    RUN_TEST(the_two_halves_hold_the_whole_config);
    RUN_TEST(a_subnet_rule_keeps_its_proto_and_ports);
    RUN_TEST(the_groups_file_sits_next_to_the_settings_file);
    RUN_TEST(save_shape_matches_committed_fixture);
    RUN_TEST(quoted_id_shapes);
    RUN_TEST(fakeip_block_is_read_back);
    RUN_TEST(fakeip_bad_geometry_is_refused);
    RUN_TEST(fakeip_good_geometry_is_accepted);
    RUN_TEST(fakeip_zero_max_names_is_refused);
    RUN_TEST(an_address_pool_that_is_not_a_mapping_is_refused);
    RUN_TEST(windows_past_the_ceiling_are_refused);
    RUN_TEST(a_clamp_past_182_days_is_refused_naming_its_key);
    RUN_TEST(an_old_idle_window_is_dropped_by_the_next_save);
    RUN_TEST(a_later_load_cannot_launder_a_refused_geometry);
    RUN_TEST(a_log_level_the_daemon_does_not_have_is_refused);
    RUN_TEST(an_upstream_that_is_not_an_address_is_refused);
    RUN_TEST(a_conf_that_still_names_a_skin_loads_and_drops_it);
    RUN_TEST(a_conf_that_still_names_the_fake_ptr_switch_loads_and_drops_it);
    GREATEST_MAIN_END();
}
