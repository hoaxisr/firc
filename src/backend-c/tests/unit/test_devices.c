#include "greatest.h"

#include <string.h>

#include "firc/devices.h"
#include "firc/models.h"

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {{a, b, c, d}, 4};
    return ip;
}

static firc_ip_t v6_fd00(uint8_t last) {
    firc_ip_t ip = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last}, 16};
    return ip;
}

TEST an_empty_selector_allows_every_device(void) {
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(NULL, 0, NULL, 0, &s));
    ASSERT(firc_devsel_is_empty(s));
    firc_ip_t c = v4(192, 168, 1, 10);
    ASSERT(firc_devsel_allows(s, &c, NULL, NULL, NULL));
    ASSERTm("an unknown client is allowed: the daemon as it was before selectors",
            firc_devsel_allows(s, NULL, NULL, NULL, NULL));
    firc_devsel_free(s);
    PASS();
}

/* Catches: an allow entry of either family or prefix not admitting, or a bare address admitting more. */
TEST the_allow_list_admits_addresses_and_prefixes(void) {
    static const char *allow[] = {"192.168.1.10", "10.0.0.0/8", "fd00::/64"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 3, NULL, 0, &s));
    ASSERT_FALSE(firc_devsel_is_empty(s));
    firc_ip_t in1 = v4(192, 168, 1, 10), near = v4(192, 168, 1, 11), in2 = v4(10, 200, 3, 4);
    firc_ip_t out4 = v4(172, 16, 0, 1), in6 = v6_fd00(7);
    firc_ip_t out6 = {{0xfd, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7}, 16};
    ASSERT(firc_devsel_allows(s, &in1, NULL, NULL, NULL));
    ASSERT_FALSEm("a bare address is one host, not a neighbourhood", firc_devsel_allows(s, &near, NULL, NULL, NULL));
    ASSERT(firc_devsel_allows(s, &in2, NULL, NULL, NULL));
    ASSERT_FALSE(firc_devsel_allows(s, &out4, NULL, NULL, NULL));
    ASSERT(firc_devsel_allows(s, &in6, NULL, NULL, NULL));
    ASSERT_FALSEm("the /64 boundary is a bit boundary, not a byte one", firc_devsel_allows(s, &out6, NULL, NULL, NULL));
    firc_devsel_free(s);

    static const char *look_alike[] = {"253.0.0.0/8"};
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(look_alike, 1, NULL, 0, &s));
    firc_ip_t fd = v6_fd00(1);
    ASSERT_FALSEm("families never cross", firc_devsel_allows(s, &fd, NULL, NULL, NULL));
    firc_devsel_free(s);
    PASS();
}

/* Catches: a prefix ending inside a byte rounded instead of masked. */
TEST a_prefix_inside_a_byte_is_masked_not_rounded(void) {
    static const char *allow[] = {"192.168.0.0/20"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, NULL, 0, &s));
    firc_ip_t in = v4(192, 168, 15, 255), out = v4(192, 168, 16, 0);
    ASSERT(firc_devsel_allows(s, &in, NULL, NULL, NULL));
    ASSERT_FALSE(firc_devsel_allows(s, &out, NULL, NULL, NULL));
    firc_devsel_free(s);
    PASS();
}

TEST deny_wins_over_allow_and_over_the_empty_allow_list(void) {
    static const char *allow[] = {"192.168.1.0/24"};
    static const char *deny[] = {"192.168.1.5"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, deny, 1, &s));
    firc_ip_t ok = v4(192, 168, 1, 6), no = v4(192, 168, 1, 5);
    ASSERT(firc_devsel_allows(s, &ok, NULL, NULL, NULL));
    ASSERT_FALSE(firc_devsel_allows(s, &no, NULL, NULL, NULL));
    firc_devsel_free(s);

    ASSERT_EQ(FIRC_OK, firc_devsel_compile(NULL, 0, deny, 1, &s));
    ASSERT_FALSE(firc_devsel_is_empty(s));
    ASSERT(firc_devsel_allows(s, &ok, NULL, NULL, NULL));
    ASSERT_FALSE(firc_devsel_allows(s, &no, NULL, NULL, NULL));
    firc_devsel_free(s);
    PASS();
}

static bool in_kids(const char *policy, const firc_ip_t *client, void *ud) {
    (*(int *)ud)++;
    return strcmp(policy, "Kids") == 0 && client->len == 4 && client->b[3] == 42;
}

/* Catches: a policy entry not asked of the caller's resolver, or matching without one. */
TEST a_policy_entry_is_resolved_by_the_caller(void) {
    static const char *allow[] = {"policy:Kids"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, NULL, 0, &s));
    ASSERT(firc_devsel_names_a_policy_or_mac(s));
    int asked = 0;
    firc_ip_t kid = v4(192, 168, 1, 42), other = v4(192, 168, 1, 43);
    ASSERT(firc_devsel_allows(s, &kid, in_kids, NULL, &asked));
    ASSERT_FALSE(firc_devsel_allows(s, &other, in_kids, NULL, &asked));
    ASSERT_EQ_FMT(2, asked, "%d");
    ASSERT_FALSEm("no resolver: a policy matches nothing", firc_devsel_allows(s, &kid, NULL, NULL, NULL));
    firc_devsel_free(s);

    static const char *plain[] = {"10.0.0.0/8"};
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(plain, 1, NULL, 0, &s));
    ASSERT_FALSE(firc_devsel_names_a_policy_or_mac(s));
    firc_devsel_free(s);
    PASS();
}

/* Catches: a deny-list policy entry not resolved. */
TEST a_policy_in_the_deny_list_is_resolved_too(void) {
    static const char *deny[] = {"policy:Kids"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(NULL, 0, deny, 1, &s));
    ASSERTm("a deny-only selector names a policy as much as an allow one", firc_devsel_names_a_policy_or_mac(s));
    int asked = 0;
    firc_ip_t kid = v4(192, 168, 1, 42), other = v4(192, 168, 1, 43);
    ASSERT_FALSEm("the kid is out", firc_devsel_allows(s, &kid, in_kids, NULL, &asked));
    ASSERTm("everyone else is in", firc_devsel_allows(s, &other, in_kids, NULL, &asked));
    ASSERT_EQ_FMT(2, asked, "%d");
    ASSERTm("no resolver: the deny protects nobody, so the kid is in", firc_devsel_allows(s, &kid, NULL, NULL, NULL));
    firc_devsel_free(s);
    PASS();
}

/* Catches: a v4-mapped entry kept as v6, so it never matches an unmapped client. */
TEST a_v4_mapped_entry_is_the_v4_address(void) {
    static const char *allow[] = {"::ffff:10.0.0.0/120"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, NULL, 0, &s));
    firc_ip_t in = v4(10, 0, 0, 7), out = v4(10, 0, 1, 7);
    ASSERT(firc_devsel_allows(s, &in, NULL, NULL, NULL));
    ASSERT_FALSE(firc_devsel_allows(s, &out, NULL, NULL, NULL));
    firc_devsel_free(s);

    static const char *all_v4[] = {"::ffff:0:0/96"};
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(all_v4, 1, NULL, 0, &s));
    ASSERTm("/96 is every v4 client", firc_devsel_allows(s, &out, NULL, NULL, NULL));
    firc_ip_t v6 = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 16};
    ASSERT_FALSEm("and no v6 client", firc_devsel_allows(s, &v6, NULL, NULL, NULL));
    firc_devsel_free(s);

    static const char *dead[] = {"::ffff:1.2.3.4/95"};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_compile(dead, 1, NULL, 0, &s));
    PASS();
}

/* Catches: a policy name with whitespace around it accepted, or one with spaces inside refused. */
TEST a_policy_name_with_whitespace_around_it_is_refused(void) {
    firc_devsel_t *s = NULL;
    static const char *leading[] = {"policy: Kids"};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_compile(leading, 1, NULL, 0, &s));
    static const char *trailing[] = {"policy:Kids "};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_compile(NULL, 0, trailing, 1, &s));
    static const char *inside[] = {"policy:Work VPN"};
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(inside, 1, NULL, 0, &s));
    firc_devsel_free(s);
    PASS();
}

/* The device table: one dual-stack host (the TV). */
static size_t tv_device(const firc_ip_t *client, firc_ip_t *out, size_t cap, firc_mac_t *mac, void *ud) {
    (void)mac;
    (*(int *)ud)++;
    const firc_ip_t tv4 = v4(192, 168, 1, 5);
    const firc_ip_t tv6 = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}, 16};
    bool is_tv = (client->len == 4 && memcmp(client->b, tv4.b, 4) == 0) ||
                 (client->len == 16 && memcmp(client->b, tv6.b, 16) == 0);
    if (!is_tv || cap < 2) { return 0; }
    out[0] = tv4;
    out[1] = tv6;
    return 2;
}

/* Catches: an address entry matching only that address instead of every address of its device. */
TEST an_address_entry_names_the_device_at_that_address(void) {
    static const char *deny[] = {"192.168.1.5"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(NULL, 0, deny, 1, &s));
    int asked = 0;
    firc_ip_t tv6 = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5}, 16};
    firc_ip_t other6 = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6}, 16};
    ASSERT_FALSEm("the TV over v6 is the TV", firc_devsel_allows(s, &tv6, NULL, tv_device, &asked));
    ASSERTm("another v6 host is not", firc_devsel_allows(s, &other6, NULL, tv_device, &asked));
    ASSERTm("without a table the entry is the address alone", firc_devsel_allows(s, &tv6, NULL, NULL, NULL));
    ASSERT(asked > 0);
    firc_devsel_free(s);

    static const char *allow[] = {"192.168.1.0/24"};
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, NULL, 0, &s));
    ASSERTm("the TV over v6 is inside the v4 prefix by its device", firc_devsel_allows(s, &tv6, NULL, tv_device, &asked));
    ASSERT_FALSE(firc_devsel_allows(s, &other6, NULL, tv_device, &asked));
    firc_devsel_free(s);
    PASS();
}

/* A host with more addresses than the selector's buffer. */
static size_t many_device(const firc_ip_t *client, firc_ip_t *out, size_t cap, firc_mac_t *mac, void *ud) {
    (void)client; (void)ud; (void)mac;
    size_t n = 0;
    for (n = 0; n < cap && n < 100; n++) {
        firc_ip_t a = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (uint8_t)(n + 1)}, 16};
        out[n] = a;
    }
    return n;
}

TEST a_device_with_many_addresses_is_matched_on_all_that_fit(void) {
    static const char *deny[] = {"fd00::3f"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(NULL, 0, deny, 1, &s));
    firc_ip_t client = v4(10, 0, 0, 9);
    ASSERT_FALSEm("denied through its 63rd other address", firc_devsel_allows(s, &client, NULL, many_device, NULL));
    firc_devsel_free(s);
    static const char *past[] = {"fd00::40"};
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(NULL, 0, past, 1, &s));
    ASSERTm("past the buffer the entry does not reach the device", firc_devsel_allows(s, &client, NULL, many_device, NULL));
    firc_devsel_free(s);
    PASS();
}

TEST an_entry_that_is_nothing_is_refused(void) {
    static const char *bad1[] = {"not-an-address"};
    static const char *bad2[] = {"policy:"};
    static const char *bad3[] = {"192.168.1.0/33"};
    firc_devsel_t *s = (firc_devsel_t *)1;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_compile(bad1, 1, NULL, 0, &s));
    ASSERT(s == NULL);
    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_compile(NULL, 0, bad2, 1, &s));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_compile(bad3, 1, NULL, 0, &s));
    PASS();
}

static bool same_ip(const firc_ip_t *a, const firc_ip_t *b) {
    return a->len == b->len && memcmp(a->b, b->b, a->len) == 0;
}

static const firc_mac_t MAC_A = {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}};
static const firc_mac_t MAC_B = {{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}};

static size_t two_hosts(const firc_ip_t *client, firc_ip_t *out, size_t cap, firc_mac_t *mac, void *ud) {
    (void)ud;
    const firc_ip_t a4 = v4(192, 168, 1, 5), a6 = v6_fd00(5), b4 = v4(192, 168, 1, 6);
    if (same_ip(client, &a4) || same_ip(client, &a6)) {
        *mac = MAC_A;
        if (cap < 1) { return 0; }
        out[0] = same_ip(client, &a4) ? a6 : a4;
        return 1;
    }
    if (same_ip(client, &b4)) {
        *mac = MAC_B;
        return 0;
    }
    return 0;
}

/* Catches: '-' or upper case refused, a mac: entry matched against the address, or every host matched. */
TEST a_mac_entry_matches_the_host_with_that_mac(void) {
    static const char *allow[] = {"mac:AA-bb-CC-dd-EE-01"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, NULL, 0, &s));
    firc_ip_t a4 = v4(192, 168, 1, 5), b4 = v4(192, 168, 1, 6);
    ASSERTm("host A is in", firc_devsel_allows(s, &a4, NULL, two_hosts, NULL));
    ASSERT_FALSEm("host B is not", firc_devsel_allows(s, &b4, NULL, two_hosts, NULL));
    firc_devsel_free(s);
    PASS();
}

/* Catches: a MAC looked up for v4 clients only. */
TEST a_mac_entry_covers_every_address_of_its_host(void) {
    static const char *allow[] = {"mac:aa:bb:cc:dd:ee:01"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, NULL, 0, &s));
    firc_ip_t a6 = v6_fd00(5), other6 = v6_fd00(6);
    ASSERTm("A over v6", firc_devsel_allows(s, &a6, NULL, two_hosts, NULL));
    ASSERT_FALSEm("a v6 address the table does not list", firc_devsel_allows(s, &other6, NULL, two_hosts, NULL));
    firc_devsel_free(s);
    PASS();
}

/* Catches: a MAC the table does not list matching someone. */
TEST a_mac_the_table_does_not_list_matches_nobody(void) {
    static const char *unknown[] = {"mac:aa:bb:cc:dd:ee:99"};
    firc_devsel_t *s = NULL;
    firc_ip_t a4 = v4(192, 168, 1, 5), stranger = v4(10, 0, 0, 7);
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(unknown, 1, NULL, 0, &s));
    ASSERT_FALSEm("allow: A is not that MAC", firc_devsel_allows(s, &a4, NULL, two_hosts, NULL));
    ASSERT_FALSEm("allow: a client the table does not list either", firc_devsel_allows(s, &stranger, NULL, two_hosts, NULL));
    firc_devsel_free(s);
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(NULL, 0, unknown, 1, &s));
    ASSERTm("deny: A is not denied", firc_devsel_allows(s, &a4, NULL, two_hosts, NULL));
    ASSERTm("deny: nor is a stranger", firc_devsel_allows(s, &stranger, NULL, two_hosts, NULL));
    firc_devsel_free(s);
    static const char *known[] = {"mac:aa:bb:cc:dd:ee:01"};
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(known, 1, NULL, 0, &s));
    ASSERT_FALSEm("no table: a mac: entry matches nothing", firc_devsel_allows(s, &a4, NULL, NULL, NULL));
    firc_devsel_free(s);
    PASS();
}

/* Catches: the deny list skipping mac: entries. */
TEST deny_by_mac_is_checked_before_allow(void) {
    static const char *allow[] = {"192.168.1.0/24"};
    static const char *deny[] = {"mac:aa:bb:cc:dd:ee:01"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, deny, 1, &s));
    firc_ip_t a4 = v4(192, 168, 1, 5), a6 = v6_fd00(5), b4 = v4(192, 168, 1, 6);
    ASSERT_FALSEm("A is denied by its MAC", firc_devsel_allows(s, &a4, NULL, two_hosts, NULL));
    ASSERT_FALSEm("over v6 too", firc_devsel_allows(s, &a6, NULL, two_hosts, NULL));
    ASSERTm("B is in by the prefix", firc_devsel_allows(s, &b4, NULL, two_hosts, NULL));
    firc_devsel_free(s);
    PASS();
}

/* Catches: a malformed MAC compiling, or a reason that does not name the kind of entry. */
TEST a_bad_entry_is_refused_and_says_why(void) {
    const char *bad_mac[] = {
        "mac:aa:bb:cc:dd:ee",
        "mac:aa:bb:cc:dd:ee:fg",
        "mac:aa:bb-cc:dd:ee:ff",
        "mac:aabb.ccdd.eeff",
        "mac:00:00:00:00:00:00",
        "mac:aa:bb:cc:dd:ee:ff:00",
        "mac:",
        "mac:aa:bb:cc:dd:ee-ff",
        "mac:aa:bb:cc:dd:ee!ff",
    };
    for (size_t i = 0; i < sizeof(bad_mac) / sizeof(bad_mac[0]); i++) {
        firc_devsel_t *s = (firc_devsel_t *)1;
        ASSERT_EQm(bad_mac[i], FIRC_ERR_INVAL, firc_devsel_compile(&bad_mac[i], 1, NULL, 0, &s));
        ASSERTm(bad_mac[i], s == NULL);
        const char *why = firc_devsel_entry_why(bad_mac[i]);
        ASSERTm(bad_mac[i], why != NULL && strstr(why, "MAC") != NULL);
    }
    ASSERT_STR_EQ("names no policy", firc_devsel_entry_why("policy:"));
    ASSERT_STR_EQ("is neither an address, a prefix, policy:<name> nor mac:<address>", firc_devsel_entry_why("the-tv"));
    ASSERT_STR_EQ("is a v4-mapped prefix shorter than /96, which covers no client", firc_devsel_entry_why("::ffff:0.0.0.0/95"));
    ASSERT(firc_devsel_entry_why("mac:aa:bb:cc:dd:ee:ff") == NULL);
    ASSERT(firc_devsel_entry_why("mac:AA-BB-CC-DD-EE-FF") == NULL);
    ASSERT(firc_devsel_entry_why("policy:Kids") == NULL);
    ASSERT(firc_devsel_entry_why("192.168.1.0/24") == NULL);
    ASSERT(firc_devsel_entry_why(NULL) != NULL);
    PASS();
}

/* Catches: upper case or '-' surviving, an invalid entry made valid, or a non-mac entry changed. */
TEST a_mac_entry_is_canonicalised_in_place(void) {
    char upper[] = "mac:AA-BB-CC-DD-EE-0F";
    firc_devsel_entry_canon(upper);
    ASSERT_STR_EQ("mac:aa:bb:cc:dd:ee:0f", upper);
    char mixed[] = "mac:Aa:bB:cc:DD:ee:0f";
    firc_devsel_entry_canon(mixed);
    ASSERT_STR_EQ("mac:aa:bb:cc:dd:ee:0f", mixed);
    char bad[] = "mac:AA-BB-CC-DD-EE";
    firc_devsel_entry_canon(bad);
    ASSERT_STR_EQm("an invalid entry is left for the caller to refuse", "mac:AA-BB-CC-DD-EE", bad);
    char policy[] = "policy:AA-BB";
    firc_devsel_entry_canon(policy);
    ASSERT_STR_EQ("policy:AA-BB", policy);
    firc_mac_t m;
    ASSERT(firc_mac_parse("0a:1B:2c:3D:4e:5F", &m));
    ASSERT_EQ_FMT(0x0a, m.b[0], "%#x");
    ASSERT_EQ_FMT(0x5f, m.b[5], "%#x");
    PASS();
}

/* Catches: a mac: selector not reported as needing the host table, or an address-only one reported. */
TEST a_mac_entry_needs_the_table_as_a_policy_does(void) {
    static const char *deny[] = {"mac:aa:bb:cc:dd:ee:01"};
    static const char *plain[] = {"10.0.0.1"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(NULL, 0, deny, 1, &s));
    ASSERT(firc_devsel_names_a_policy_or_mac(s));
    firc_devsel_free(s);
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(plain, 1, NULL, 0, &s));
    ASSERT_FALSE(firc_devsel_names_a_policy_or_mac(s));
    firc_devsel_free(s);
    PASS();
}

SUITE(devices) {
    RUN_TEST(an_empty_selector_allows_every_device);
    RUN_TEST(the_allow_list_admits_addresses_and_prefixes);
    RUN_TEST(a_prefix_inside_a_byte_is_masked_not_rounded);
    RUN_TEST(deny_wins_over_allow_and_over_the_empty_allow_list);
    RUN_TEST(a_policy_entry_is_resolved_by_the_caller);
    RUN_TEST(a_policy_in_the_deny_list_is_resolved_too);
    RUN_TEST(a_v4_mapped_entry_is_the_v4_address);
    RUN_TEST(a_policy_name_with_whitespace_around_it_is_refused);
    RUN_TEST(an_address_entry_names_the_device_at_that_address);
    RUN_TEST(a_device_with_many_addresses_is_matched_on_all_that_fit);
    RUN_TEST(an_entry_that_is_nothing_is_refused);
    RUN_TEST(a_mac_entry_matches_the_host_with_that_mac);
    RUN_TEST(a_mac_entry_covers_every_address_of_its_host);
    RUN_TEST(a_mac_the_table_does_not_list_matches_nobody);
    RUN_TEST(deny_by_mac_is_checked_before_allow);
    RUN_TEST(a_bad_entry_is_refused_and_says_why);
    RUN_TEST(a_mac_entry_is_canonicalised_in_place);
    RUN_TEST(a_mac_entry_needs_the_table_as_a_policy_does);
}

/* Catches: an entry's kind misreported, a mapped address not unwrapped, or a bad entry accepted. */
TEST an_entry_parses_into_what_the_answer_matches_on(void) {
    firc_devsel_entry_t e;
    ASSERT_EQ(FIRC_OK, firc_devsel_entry_parse("192.168.1.77/24", &e));
    ASSERT_EQ(FIRC_DEVSEL_ADDR, e.kind);
    ASSERT_EQ(4, e.addr.len);
    ASSERT_EQ(24, e.prefix);
    const uint8_t v4[4] = {192, 168, 1, 77};
    ASSERT_MEM_EQ(v4, e.addr.b, 4);

    ASSERT_EQ(FIRC_OK, firc_devsel_entry_parse("fd00::30", &e));
    ASSERT_EQ(16, e.addr.len);
    ASSERT_EQm("a bare v6 address is a /128", 128, e.prefix);

    ASSERT_EQ(FIRC_OK, firc_devsel_entry_parse("::ffff:10.0.0.1", &e));
    ASSERT_EQm("a v4-mapped entry is the v4 address", 4, e.addr.len);
    ASSERT_EQ(32, e.prefix);
    const uint8_t mapped[4] = {10, 0, 0, 1};
    ASSERT_MEM_EQ(mapped, e.addr.b, 4);

    ASSERT_EQ(FIRC_OK, firc_devsel_entry_parse("mac:AA-BB-CC-DD-EE-FF", &e));
    ASSERT_EQ(FIRC_DEVSEL_MAC, e.kind);
    const uint8_t mac[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    ASSERT_MEM_EQ(mac, e.mac.b, 6);

    static const char kids[] = "policy:Kids";
    ASSERT_EQ(FIRC_OK, firc_devsel_entry_parse(kids, &e));
    ASSERT_EQ(FIRC_DEVSEL_POLICY, e.kind);
    ASSERT_EQm("the name points into the text", kids + 7, e.policy);
    ASSERT_STR_EQ("Kids", e.policy);

    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_entry_parse("policy:", &e));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_entry_parse("nonsense", &e));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_devsel_entry_parse("mac:00:00:00:00:00:00", &e));
    PASS();
}

static char e_a[] = "10.0.0.1", e_b[] = "10.0.0.2", e_c[] = "10.0.0.3", e_d[] = "mac:aa:bb:cc:dd:ee:ff";

static firc_devsel_spec_t spec_of(char **allow, size_t na, char **deny, size_t nd) {
    firc_devsel_spec_t s = {.allow = allow, .n_allow = na, .deny = deny, .n_deny = nd};
    return s;
}

TEST an_edit_narrows_when_it_takes_a_device_away(void) {
    char *a[] = {e_a}, *ab[] = {e_a, e_b}, *b[] = {e_b}, *c[] = {e_c}, *cd[] = {e_c, e_d};
    struct {
        firc_devsel_spec_t was, now;
        bool narrows;
        const char *why;
    } rows[] = {
        {spec_of(NULL, 0, NULL, 0), spec_of(a, 1, NULL, 0), true, "everyone -> one device"},
        {spec_of(ab, 2, NULL, 0), spec_of(a, 1, NULL, 0), true, "a device left the allow list"},
        {spec_of(a, 1, NULL, 0), spec_of(ab, 2, NULL, 0), false, "a device joined the allow list"},
        {spec_of(a, 1, NULL, 0), spec_of(NULL, 0, NULL, 0), false, "an emptied allow list is everyone"},
        {spec_of(NULL, 0, NULL, 0), spec_of(NULL, 0, c, 1), true, "a device joined deny"},
        {spec_of(NULL, 0, c, 1), spec_of(NULL, 0, NULL, 0), false, "a device left deny"},
        {spec_of(a, 1, c, 1), spec_of(a, 1, c, 1), false, "nothing changed"},
        {spec_of(a, 1, NULL, 0), spec_of(b, 1, NULL, 0), true, "one device swapped for another"},
        {spec_of(NULL, 0, c, 1), spec_of(NULL, 0, cd, 2), true, "a second device joined deny"},
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        ASSERT_EQm(rows[i].why, rows[i].narrows, firc_devsel_spec_narrows(&rows[i].was, &rows[i].now));
    }
    PASS();
}

GREATEST_MAIN_DEFS();
int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(devices);
    RUN_TEST(an_entry_parses_into_what_the_answer_matches_on);
    RUN_TEST(an_edit_narrows_when_it_takes_a_device_away);
    GREATEST_MAIN_END();
}
