#include "greatest.h"

#include <sched.h>
#include <signal.h>
#include <unistd.h>
#include <stdatomic.h>

#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "firc/keenetic_policy.h"
#include "firc/devices.h"
#include "firc/log.h"
#include "firc/ruleset.h"
#include "firc/mark.h"

static const char HOTSPOT[] =
    "{\"host\":["
    "{\"mac\":\"aa:00:00:00:00:01\",\"ip\":\"192.168.0.124\",\"ip6\":[],\"hostname\":\"tv\",\"policy\":\"Policy0\",\"active\":true},"
    "{\"mac\":\"aa:00:00:00:00:02\",\"ip\":\"192.168.0.104\",\"ip6\":[\"fd00::104\",\"2001:db8::104\"],\"policy\":\"Policy1\"},"
    "{\"mac\":\"aa:00:00:00:00:03\",\"ip\":\"192.168.0.128\",\"ip6\":[],\"policy\":\"\"},"
    "{\"mac\":\"aa:00:00:00:00:04\",\"ip\":\"\",\"policy\":\"Policy0\"},"
    "{\"mac\":\"aa:00:00:00:00:05\",\"ip\":\"192.168.0.77\",\"policy\":\"Policy0\"}"
    "]}";
static const char SHARED[] =
    "{\"host\":["
    "{\"mac\":\"aa:00:00:00:00:01\",\"ip\":\"192.168.1.5\",\"ip6\":[\"fd00::5\"],\"policy\":\"Policy0\",\"active\":false},"
    "{\"mac\":\"aa:00:00:00:00:02\",\"ip\":\"192.168.1.5\",\"ip6\":[\"fd00::77\"],\"policy\":\"\",\"active\":true}"
    "]}";

static const char POLICIES[] =
    "{\"Policy0\":{\"description\":\"Kids\",\"permit\":[]},"
    "\"Policy1\":{\"description\":\"Work VPN\"},"
    "\"Policy9\":{\"description\":\"Guests\"},"
    "\"FircTest\":{\"description\":\"\"}}";

static firc_ip_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    firc_ip_t ip = {{a, b, c, d}, 4};
    return ip;
}

static const char NAMED[] =
    "{\"host\":["
    "{\"mac\":\"AA:00:00:00:00:01\",\"name\":\"Living room TV\",\"hostname\":\"tv\",\"ip\":\"192.168.0.124\","
    "\"ip6\":[\"fd00::124\",\"2001:db8::124\"],\"policy\":\"Policy0\",\"active\":true,\"registered\":true},"
    "{\"mac\":\"aa:00:00:00:00:02\",\"hostname\":\"laptop\",\"ip\":\"192.168.0.104\",\"ip6\":[],\"policy\":\"\","
    "\"active\":false,\"registered\":false},"
    "{\"mac\":\"aa:00:00:00:00:03\",\"name\":\"\",\"ip\":\"\"},"
    "{\"mac\":\"not-a-mac\",\"name\":\"ghost\",\"ip\":\"192.168.0.9\",\"policy\":\"Policy0\",\"active\":true},"
    "{\"mac\":\"aa:00:00:00:00:06\",\"name\":\"\",\"hostname\":\"tablet\",\"ip\":\"192.168.0.55\",\"ip6\":[],"
    "\"policy\":\"Policy0\",\"active\":true,\"registered\":true},"
    "{\"mac\":\"aa:00:00:00:00:07\",\"hostname\":\"printer\",\"ip\":\"192.168.0.66\",\"ip6\":[],\"policy\":\"\","
    "\"active\":false,\"registered\":true}"
    "]}";

static const char *str_of(const cJSON *o, const char *key) {
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);
    return cJSON_IsString(v) ? v->valuestring : "<absent>";
}

static firc_ip_t v6_of(uint8_t first, uint8_t second, uint8_t third, uint8_t fourth, uint8_t hi, uint8_t lo) {
    firc_ip_t ip = {{first, second, third, fourth, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, hi, lo}, 16};
    return ip;
}

TEST a_host_in_a_policy_is_found_by_internal_name_and_by_description(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_ip_t tv = v4(192, 168, 0, 124), other = v4(192, 168, 0, 77);
    ASSERT(firc_kn_policy_map_has(m, "Policy0", &tv));
    ASSERT(firc_kn_policy_map_has(m, "Kids", &tv));
    ASSERT(firc_kn_policy_map_has(m, "Kids", &other));
    ASSERT_EQ_FMTm("two hosts with an address; the one without contributes nothing", (size_t)2,
                   firc_kn_policy_map_count(m, "Kids"), "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

TEST hosts_outside_the_policy_are_not_in_it(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_ip_t work = v4(192, 168, 0, 104), none = v4(192, 168, 0, 128), stranger = v4(10, 0, 0, 1);
    ASSERT_FALSEm("a host of another policy", firc_kn_policy_map_has(m, "Kids", &work));
    ASSERT_FALSEm("a host with no policy", firc_kn_policy_map_has(m, "Kids", &none));
    ASSERT_FALSEm("an address the router never saw", firc_kn_policy_map_has(m, "Kids", &stranger));
    ASSERT_FALSEm("a policy nobody has", firc_kn_policy_map_has(m, "FircTest", &work));
    ASSERT_FALSEm("no policy is not a policy called \"\"", firc_kn_policy_map_has(m, "", &none));
    firc_ip_t v6_of_tv = {{192, 168, 0, 124, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x24}, 16};
    ASSERT_FALSEm("a v4 member does not cover a v6 client sharing its first bytes", firc_kn_policy_map_has(m, "Kids", &v6_of_tv));
    ASSERT_FALSEm("a name that is neither", firc_kn_policy_map_has(m, "Nope", &work));
    ASSERT_FALSE(firc_kn_policy_map_has(m, "Kids", NULL));
    firc_kn_policy_map_free(m);
    PASS();
}

TEST a_hosts_v6_addresses_count_too(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_ip_t ula = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x04}, 16};
    firc_ip_t gua = {{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x04}, 16};
    firc_ip_t v4_of_it = v4(192, 168, 0, 104);
    ASSERT(firc_kn_policy_map_has(m, "Work VPN", &ula));
    ASSERT(firc_kn_policy_map_has(m, "Policy1", &gua));
    ASSERT(firc_kn_policy_map_has(m, "Policy1", &v4_of_it));
    ASSERT_EQ_FMTm("its addresses make it a member, and it is one device", (size_t)1,
                   firc_kn_policy_map_count(m, "Policy1"), "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

TEST without_the_policy_list_only_internal_names_match(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, NULL, &m));
    firc_ip_t tv = v4(192, 168, 0, 124);
    ASSERT(firc_kn_policy_map_has(m, "Policy0", &tv));
    ASSERT_FALSE(firc_kn_policy_map_has(m, "Kids", &tv));
    firc_kn_policy_map_free(m);
    PASS();
}

TEST unexpected_shapes_are_refused(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_policy_map_parse("{oops", POLICIES, &m));
    ASSERT(m == NULL);
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_policy_map_parse("[]", POLICIES, &m));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_policy_map_parse("{\"host\":{}}", POLICIES, &m));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_policy_map_parse(HOTSPOT, "[1]", &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[1,{\"ip\":\"10.0.0.9\",\"policy\":\"P\"}]}", NULL, &m));
    firc_ip_t nine = v4(10, 0, 0, 9);
    ASSERT(firc_kn_policy_map_has(m, "P", &nine));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: the map losing an address of the host at `client`, whatever the host's policy. */
TEST the_map_knows_every_address_of_a_host(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_ip_t out[8];
    firc_ip_t ula = {{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x04}, 16};
    ASSERT_EQ_FMTm("asked by its v6, the host's two OTHER addresses", (size_t)2,
                   firc_kn_policy_map_device(m, &ula, out, 8), "%zu");
    firc_ip_t v4_of_it = v4(192, 168, 0, 104);
    bool saw_v4 = false, saw_self = false;
    for (size_t i = 0; i < 2; i++) {
        if (out[i].len == 4 && memcmp(out[i].b, v4_of_it.b, 4) == 0) { saw_v4 = true; }
        if (out[i].len == 16 && memcmp(out[i].b, ula.b, 16) == 0) { saw_self = true; }
    }
    ASSERT(saw_v4);
    ASSERT_FALSEm("the asking address itself is not repeated", saw_self);
    firc_ip_t first = v4(192, 168, 0, 124);
    ASSERT_EQ_FMTm("the FIRST host of the table is a host too (it has no other address)", (size_t)0,
                   firc_kn_policy_map_device(m, &first, out, 8), "%zu");
    ASSERTm("...and is found by policy", firc_kn_policy_map_has(m, "Policy0", &first));
    firc_ip_t none = v4(192, 168, 0, 128);
    ASSERT_EQ_FMTm("a host with no policy and one address has no others", (size_t)0, firc_kn_policy_map_device(m, &none, out, 8), "%zu");
    firc_ip_t stranger = v4(10, 0, 0, 1);
    ASSERT_EQ_FMT((size_t)0, firc_kn_policy_map_device(m, &stranger, out, 8), "%zu");
    ASSERT_EQ_FMTm("a small buffer is filled, not overrun", (size_t)1, firc_kn_policy_map_device(m, &ula, out, 1), "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a policy left out of the list (by key, by description, or with no hosts in it). */
TEST every_policy_the_router_has_can_be_listed(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));

    firc_kn_policy_info_t got[8];
    size_t n = firc_kn_policy_map_list(m, got, 8);
    ASSERT_EQ_FMTm("four policies, including the two nobody is in", (size_t)4, n, "%zu");

    struct {
        const char *name, *desc;
        size_t devices;
    } want[] = {
        {"Policy0", "Kids", 2},
        {"Policy1", "Work VPN", 1},
        {"Policy9", "Guests", 0},
        {"FircTest", "", 0},
    };
    for (size_t w = 0; w < 4; w++) {
        bool found = false;
        for (size_t i = 0; i < n && !found; i++) {
            if (strcmp(got[i].name, want[w].name) != 0) { continue; }
            found = true;
            ASSERT_STR_EQm(want[w].name, want[w].desc, got[i].description);
            ASSERT_EQ_FMTm(want[w].name, want[w].devices, got[i].devices, "%zu");
        }
        ASSERTm(want[w].name, found);
    }

    ASSERT_EQ_FMT((size_t)2, firc_kn_policy_map_list(m, got, 2), "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_kn_policy_map_list(m, got, 0), "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_kn_policy_map_list(NULL, got, 8), "%zu");

    firc_kn_policy_map_t *bare = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, NULL, &bare));
    size_t bn = firc_kn_policy_map_list(bare, got, 8);
    ASSERT_EQ_FMTm("Policy0 and Policy1, from the hosts alone", (size_t)2, bn, "%zu");
    firc_kn_policy_map_free(bare);

    firc_kn_policy_map_free(m);
    PASS();
}

TEST the_map_knows_which_policy_names_exist(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    ASSERT(firc_kn_policy_map_knows(m, "Kids"));
    ASSERT(firc_kn_policy_map_knows(m, "Policy0"));
    ASSERTm("a policy with no hosts and no description still exists", firc_kn_policy_map_knows(m, "FircTest"));
    ASSERTm("a policy with no hosts is known by its description", firc_kn_policy_map_knows(m, "Guests"));
    ASSERT_FALSE(firc_kn_policy_map_knows(m, "Kidz"));
    ASSERT_FALSE(firc_kn_policy_map_knows(m, ""));
    firc_kn_policy_map_free(m);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, NULL, &m));
    ASSERTm("without the list, a policy some host carries is known", firc_kn_policy_map_knows(m, "Policy0"));
    ASSERT_FALSE(firc_kn_policy_map_knows(m, "Kids"));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: the first listed host taken at a shared address instead of the active one. */
TEST the_active_host_is_the_device_at_a_shared_address(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(SHARED, NULL, &m));
    firc_ip_t shared = v4(192, 168, 1, 5), out[4];
    ASSERT_EQ_FMT((size_t)1, firc_kn_policy_map_device(m, &shared, out, 4), "%zu");
    ASSERT_EQ_FMTm("the phone's v6, not the offline TV's", 0x77, out[0].b[15], "%#x");
    ASSERT_FALSEm("and the phone is not in the TV's policy", firc_kn_policy_map_has(m, "Policy0", &shared));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: an empty policy document (object or array) refused instead of read as no policies. */
TEST an_empty_policy_list_is_no_policies_not_a_failure(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, "{}", &m));
    ASSERT(firc_kn_policy_map_knows(m, "Policy0"));
    firc_kn_policy_map_free(m);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, "[]", &m));
    ASSERT(firc_kn_policy_map_knows(m, "Policy0"));
    firc_kn_policy_map_free(m);
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_policy_map_parse(HOTSPOT, "[1]", &m));
    PASS();
}

/* Publishes a map from another thread after a delay, to wake the boot-time wait. */
static void *swap_later(void *ud) {
    firc_kn_policies_t *p = ud;
    struct timespec ts = {0, 50 * 1000000L};
    nanosleep(&ts, NULL);
    firc_kn_policy_map_t *m = NULL;
    if (firc_kn_policy_map_parse("{\"host\":[]}", NULL, &m) == FIRC_OK) { firc_kn_policies_swap(p, m); }
    return NULL;
}

static long ms_since(const struct timespec *t0) {
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0->tv_sec) * 1000 + (t1.tv_nsec - t0->tv_nsec) / 1000000;
}

TEST the_wait_is_woken_by_a_swap_and_by_a_stop(void) {
    firc_kn_policies_t *p = firc_kn_policies_start("http://127.0.0.1:9", 30);
    ASSERT(p != NULL);
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, swap_later, p));
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    ASSERTm("the swap from another thread ends the wait", firc_kn_policies_wait_first(p, 5000));
    ASSERTm("long before the timeout", ms_since(&t0) < 4000);
    pthread_join(th, NULL);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_kn_policies_stop(p);
    ASSERTm("stop does not wait the backoff out", ms_since(&t0) < 4000);
    PASS();
}

typedef struct {
    firc_kn_policies_t *p;
    bool result;
    _Atomic bool left;
} waiter_t;

static void *wait_long(void *ud) {
    waiter_t *w = ud;
    w->result = firc_kn_policies_wait_first(w->p, 5000);
    atomic_store(&w->left, true);
    return NULL;
}

static void loop_took_too_long(int sig) {
    (void)sig;
    static const char msg[] =
        "a_stop_does_not_free_the_object_under_a_waiter: no progress in 60s -- a waiter or a "
        "stop is deadlocked, which is what this test is about\n";
    ssize_t n = write(2, msg, sizeof(msg) - 1);
    (void)n;
    _exit(1);
}

/* Catches: a stop freeing the object while a woken waiter still unlocks it; ASan is the detector. */
TEST a_stop_does_not_free_the_object_under_a_waiter(void) {
    signal(SIGALRM, loop_took_too_long);
    alarm(60);
    firc_log_level_t saved = firc_log_level();
    firc_log_set_level(FIRC_LOG_ERROR);
    const int rounds = 2000;
    for (int i = 0; i < rounds; i++) {
        firc_kn_policies_t *p = firc_kn_policies_start("http://127.0.0.1:9", 30);
        if (p == NULL) { FAIL(); }
        waiter_t w = {p, true, false};
        pthread_t th;
        if (pthread_create(&th, NULL, wait_long, &w) != 0) { FAIL(); }
        while (firc_kn_policies_waiters_for_test(p) == 0) { sched_yield(); }
        firc_kn_policies_stop(p);
        pthread_join(th, NULL);
    }
    alarm(0);
    firc_log_set_level(saved);
    PASS();
}

TEST a_stop_wakes_the_waiter_and_the_refresher_alike(void) {
    firc_kn_policies_t *p = firc_kn_policies_start("http://127.0.0.1:9", 30);
    ASSERT(p != NULL);
    waiter_t w = {p, true, false};
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, wait_long, &w));
    struct timespec ts = {0, 100 * 1000000L};
    nanosleep(&ts, NULL);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    firc_kn_policies_stop(p);
    pthread_join(th, NULL);
    ASSERT_FALSEm("the waiter saw no map", w.result);
    ASSERTm("neither waited even the first backoff out", ms_since(&t0) < 500);
    PASS();
}

/* Catches: the first-read wait blocking with no URL, or not ending when a map arrives. */
TEST the_first_read_can_be_waited_for(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    ASSERT_FALSEm("no refresher: nothing will come", firc_kn_policies_wait_first(p, 10));
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", NULL, &m));
    firc_kn_policies_swap(p, m);
    ASSERTm("a map is there: no wait", firc_kn_policies_wait_first(p, 10));
    firc_kn_policies_stop(p);
    PASS();
}

/* Catches: the devices chain told the policies are read before any map, or never once one arrives. */
TEST the_policies_count_as_read_from_the_first_map_on(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    ASSERT_FALSE(firc_kn_policies_read(p));
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", NULL, &m));
    firc_kn_policies_swap(p, m);
    ASSERT(firc_kn_policies_read(p));
    firc_kn_policies_stop(p);
    PASS();
}

/* Catches: the resolver answering before the first read, or from a map a swap replaced. */
TEST the_resolver_answers_from_the_latest_map(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_ip_t tv = v4(192, 168, 0, 124);
    ASSERT_FALSEm("no map yet: nobody is in a policy", firc_kn_policies_resolve("Kids", &tv, p));
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_kn_policies_swap(p, m);
    ASSERT(firc_kn_policies_resolve("Kids", &tv, p));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", POLICIES, &m));
    firc_kn_policies_swap(p, m);
    ASSERT_FALSEm("the tv left the policy", firc_kn_policies_resolve("Kids", &tv, p));
    firc_ip_t out[4];
    firc_mac_t mac = {{0}};
    ASSERT_EQ_FMTm("and the device lookup follows the same map", (size_t)0, firc_kn_policies_device(&tv, out, 4, &mac, p), "%zu");
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_kn_policies_swap(p, m);
    firc_ip_t work = v4(192, 168, 0, 104);
    ASSERT_EQ_FMTm("through the wrapper, the host's other addresses", (size_t)2, firc_kn_policies_device(&work, out, 4, &mac, p), "%zu");
    firc_kn_policies_stop(p);
    PASS();
}

static const char RC_HOTSPOT[] =
    "{\"policy\":[{\"interface\":\"Bridge0\",\"access\":\"permit\"},"
    "{\"interface\":\"Wireguard9\",\"policy\":\"FircTest\"},"
    "{\"interface\":\"Bridge1\",\"policy\":\"Policy9\"},"
    "{\"interface\":\"Wireguard5\",\"policy\":\"Policy1\"}],"
    "\"host\":[{\"mac\":\"aa:00:00:00:00:01\",\"access\":\"permit\"}]}";
static const char INTERFACES[] =
    "{\"Bridge0\":{\"address\":\"192.168.1.1\",\"mask\":\"255.255.255.0\"},"
    "\"Wireguard9\":{\"address\":\"10.99.0.1\",\"mask\":\"255.255.255.0\"},"
    "\"Bridge1\":{\"address\":\"192.168.0.1\",\"mask\":\"255.255.255.0\"},"
    "\"Wireguard5\":{\"link\":\"down\"}}";

/* Catches: an access-only entry read as a segment binding, or a binding dropped. */
TEST only_entries_that_name_a_policy_are_segments(void) {
    firc_kn_segment_t seg[8];
    size_t n = firc_kn_hotspot_segments_parse(RC_HOTSPOT, seg, 8);
    ASSERT_EQ_FMT((size_t)3, n, "%zu");
    ASSERT_STR_EQ("Wireguard9", seg[0].iface);
    ASSERT_STR_EQ("FircTest", seg[0].policy);
    ASSERT_STR_EQ("Bridge1", seg[1].iface);
    ASSERT_STR_EQ("Policy9", seg[1].policy);
    ASSERT_EQ_FMTm("not an object: nothing", (size_t)0, firc_kn_hotspot_segments_parse("[]", seg, 8), "%zu");
    PASS();
}

/* Catches: a peer with no host entry outside its segment's policy, or the segment beating a host's own. */
TEST a_segment_puts_every_client_on_its_interface_in_its_policy(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_kn_segment_t seg[8];
    size_t n = firc_kn_hotspot_segments_parse(RC_HOTSPOT, seg, 8);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segments(m, seg, n, INTERFACES));

    firc_ip_t peer = v4(10, 99, 0, 2), tv = v4(192, 168, 0, 124), none = v4(192, 168, 0, 128),
              stranger = v4(10, 98, 0, 2);
    ASSERTm("an unlisted peer is in its interface's policy", firc_kn_policy_map_has(m, "FircTest", &peer));
    ASSERT_FALSE(firc_kn_policy_map_has(m, "Kids", &peer));
    ASSERTm("a host's own policy wins", firc_kn_policy_map_has(m, "Kids", &tv));
    ASSERT_FALSEm("...over its segment's", firc_kn_policy_map_has(m, "Guests", &tv));
    ASSERTm("a listed host with none takes the segment's, by description",
            firc_kn_policy_map_has(m, "Guests", &none));
    ASSERT_FALSEm("outside every segment", firc_kn_policy_map_has(m, "FircTest", &stranger));
    ASSERT_EQ_FMTm("the listed host that inherits it counts", (size_t)1, firc_kn_policy_map_count(m, "Guests"),
                   "%zu");
    firc_ip_t down = v4(192, 168, 5, 5);
    ASSERT_FALSEm("the down interface added nothing", firc_kn_policy_map_has(m, "Work VPN", &down));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_policy_map_add_segments(m, seg, n, "[]"));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a host without a MAC listed, a MAC not lower-cased, a wrong name, or a lost address or flag. */
TEST each_host_is_recorded_with_its_mac_and_names(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(NAMED, POLICIES, &m));
    cJSON *arr = firc_kn_policy_map_hosts_json(m);
    ASSERT(cJSON_IsArray(arr));
    ASSERT_EQ_FMTm("the host whose mac does not parse is left out", 5, cJSON_GetArraySize(arr), "%d");

    const cJSON *tv = cJSON_GetArrayItem(arr, 0);
    ASSERT_STR_EQm("lower case with ':'", "aa:00:00:00:00:01", str_of(tv, "mac"));
    ASSERT_STR_EQm("the firmware's name before the hostname", "Living room TV", str_of(tv, "name"));
    ASSERT_STR_EQ("192.168.0.124", str_of(tv, "ip"));
    const cJSON *ip6 = cJSON_GetObjectItemCaseSensitive(tv, "ip6");
    ASSERT_EQ_FMT(2, cJSON_GetArraySize(ip6), "%d");
    ASSERT_STR_EQ("fd00::124", cJSON_GetArrayItem(ip6, 0)->valuestring);
    ASSERT_STR_EQ("2001:db8::124", cJSON_GetArrayItem(ip6, 1)->valuestring);
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(tv, "active")));
    ASSERT(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(tv, "registered")));
    ASSERT_STR_EQm("the internal name, which a policy: entry also accepts", "Policy0", str_of(tv, "policy"));

    const cJSON *laptop = cJSON_GetArrayItem(arr, 1);
    ASSERT_STR_EQm("no name: the hostname", "laptop", str_of(laptop, "name"));
    ASSERT_EQ_FMT(0, cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(laptop, "ip6")), "%d");
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(laptop, "active")));
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(laptop, "registered")));
    ASSERT_STR_EQ("", str_of(laptop, "policy"));

    const cJSON *bare = cJSON_GetArrayItem(arr, 2);
    ASSERT_STR_EQ("aa:00:00:00:00:03", str_of(bare, "mac"));
    ASSERT_STR_EQm("neither: empty, not absent", "", str_of(bare, "name"));
    ASSERT_STR_EQ("", str_of(bare, "ip"));
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(bare, "active")));

    const cJSON *tablet = cJSON_GetArrayItem(arr, 3);
    ASSERT_STR_EQm("an empty name next to a hostname is still the hostname, not \"\"", "tablet",
                  str_of(tablet, "name"));

    const cJSON *printer = cJSON_GetArrayItem(arr, 4);
    ASSERT(cJSON_IsFalse(cJSON_GetObjectItemCaseSensitive(printer, "active")));
    ASSERTm("registered is its own flag, not active under another name",
           cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(printer, "registered")));
    cJSON_Delete(arr);

    arr = firc_kn_policy_map_hosts_json(NULL);
    ASSERT_EQ_FMTm("no map: an empty list", 0, cJSON_GetArraySize(arr), "%d");
    cJSON_Delete(arr);
    firc_kn_policy_map_free(m);
    PASS();
}

static const char *host_policy(const cJSON *arr, const char *mac) {
    const cJSON *h = NULL;
    cJSON_ArrayForEach(h, arr) {
        if (strcmp(str_of(h, "mac"), mac) == 0) { return str_of(h, "policy"); }
    }
    return "<no such host>";
}

/* Catches: a host with no policy of its own inside a segment reporting "", or the segment beating its own. */
TEST a_listed_host_reports_its_effective_policy(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    cJSON *arr = firc_kn_policy_map_hosts_json(m);
    ASSERT_STR_EQm("no segments: a host without a policy has none", "", host_policy(arr, "aa:00:00:00:00:03"));
    cJSON_Delete(arr);

    firc_kn_segment_t seg[8];
    size_t n = firc_kn_hotspot_segments_parse(RC_HOTSPOT, seg, 8);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segments(m, seg, n, INTERFACES));
    arr = firc_kn_policy_map_hosts_json(m);
    ASSERT_STR_EQm("192.168.0.128 has none of its own: Bridge1's", "Policy9", host_policy(arr, "aa:00:00:00:00:03"));
    ASSERT_STR_EQm("its own wins over the segment's", "Policy0", host_policy(arr, "aa:00:00:00:00:01"));
    ASSERT_STR_EQ("Policy1", host_policy(arr, "aa:00:00:00:00:02"));
    ASSERT_STR_EQm("no address: only its own", "Policy0", host_policy(arr, "aa:00:00:00:00:04"));
    size_t listed = 0;
    const cJSON *h = NULL;
    cJSON_ArrayForEach(h, arr) { listed += strcmp(str_of(h, "policy"), "Policy9") == 0; }
    ASSERT_EQ_FMTm("the list and the count agree", firc_kn_policy_map_count(m, "Guests"), listed, "%zu");
    cJSON_Delete(arr);
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a dual-stack host's v6 query missing its v4 segment's policy. */
TEST a_host_is_in_its_segments_policy_from_its_v6_address(void) {
    static const char DUAL[] =
        "{\"host\":[{\"mac\":\"aa:00:00:00:00:30\",\"ip\":\"192.168.0.130\",\"ip6\":[\"fd00::130\"],"
        "\"policy\":\"\",\"active\":true},"
        "{\"mac\":\"aa:00:00:00:00:31\",\"ip\":\"192.168.0.131\",\"ip6\":[\"fd00::131\"],"
        "\"policy\":\"Policy0\",\"active\":true}]}";
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(DUAL, POLICIES, &m));
    firc_kn_segment_t seg[8];
    size_t n = firc_kn_hotspot_segments_parse(RC_HOTSPOT, seg, 8);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segments(m, seg, n, INTERFACES));
    firc_ip_t v4a = v4(192, 168, 0, 130), v6a = v6_of(0xfd, 0, 0, 0, 0x01, 0x30), v6b = v6_of(0xfd, 0, 0, 0, 0x01, 0x31);
    ASSERTm("from its IPv4", firc_kn_policy_map_has(m, "Guests", &v4a));
    ASSERTm("and from its IPv6, by internal name", firc_kn_policy_map_has(m, "Policy9", &v6a));
    ASSERTm("and by description", firc_kn_policy_map_has(m, "Guests", &v6a));
    ASSERT_FALSEm("its own policy still wins from its IPv6", firc_kn_policy_map_has(m, "Guests", &v6b));
    ASSERTm("...and is the one it is in", firc_kn_policy_map_has(m, "Kids", &v6b));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a MAC found only by v4, an unparseable one reported, `*mac` written on a miss, or the wrong host. */
TEST a_client_is_known_by_the_mac_of_its_host(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(NAMED, POLICIES, &m));
    firc_mac_t mac = {{0}};
    firc_ip_t gua = v6_of(0x20, 0x01, 0x0d, 0xb8, 0x01, 0x24);
    ASSERTm("the TV by its GUA", firc_kn_policy_map_mac(m, &gua, &mac));
    ASSERT_EQ_FMT(0xaa, mac.b[0], "%#x");
    ASSERT_EQ_FMT(0x01, mac.b[5], "%#x");
    firc_ip_t ghost = v4(192, 168, 0, 9), stranger = v4(10, 0, 0, 1);
    firc_mac_t untouched = {{0x11, 0x11, 0x11, 0x11, 0x11, 0x11}};
    ASSERT_FALSEm("a host whose mac does not parse has none", firc_kn_policy_map_mac(m, &ghost, &untouched));
    ASSERT_FALSEm("an address the table does not list", firc_kn_policy_map_mac(m, &stranger, &untouched));
    ASSERT_EQ_FMTm("and *mac is left alone", 0x11, untouched.b[0], "%#x");
    firc_kn_policy_map_free(m);

    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(SHARED, NULL, &m));
    firc_ip_t shared = v4(192, 168, 1, 5);
    ASSERT(firc_kn_policy_map_mac(m, &shared, &mac));
    ASSERT_EQ_FMTm("the active phone's MAC, not the offline TV's", 0x02, mac.b[5], "%#x");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a policy counting a host once per address. */
TEST a_policy_counts_its_devices_not_their_addresses(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    ASSERT_EQ_FMTm("one host, three addresses", (size_t)1, firc_kn_policy_map_count(m, "Policy1"), "%zu");
    ASSERT_EQ_FMT((size_t)2, firc_kn_policy_map_count(m, "Kids"), "%zu");
    ASSERT_EQ_FMT((size_t)0, firc_kn_policy_map_count(m, "Guests"), "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a mac: entry matched by the address it had at compile time instead of the host's MAC. */
TEST a_mac_entry_follows_its_host_to_a_new_lease(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(NAMED, POLICIES, &m));
    firc_kn_policies_swap(p, m);
    static const char *allow[] = {"mac:aa:00:00:00:00:01"};
    firc_devsel_t *s = NULL;
    ASSERT_EQ(FIRC_OK, firc_devsel_compile(allow, 1, NULL, 0, &s));
    firc_ip_t tv4 = v4(192, 168, 0, 124), ula = v6_of(0xfd, 0, 0, 0, 0x01, 0x24);
    firc_ip_t laptop = v4(192, 168, 0, 104), moved = v4(192, 168, 0, 200);
    ASSERTm("the TV over v4", firc_devsel_allows(s, &tv4, firc_kn_policies_resolve, firc_kn_policies_device, p));
    ASSERTm("the TV over v6", firc_devsel_allows(s, &ula, firc_kn_policies_resolve, firc_kn_policies_device, p));
    ASSERT_FALSEm("another host", firc_devsel_allows(s, &laptop, firc_kn_policies_resolve, firc_kn_policies_device, p));
    ASSERT_FALSEm("nobody is at .200 yet", firc_devsel_allows(s, &moved, firc_kn_policies_resolve, firc_kn_policies_device, p));

    static const char MOVED[] =
        "{\"host\":[{\"mac\":\"aa:00:00:00:00:01\",\"name\":\"Living room TV\",\"ip\":\"192.168.0.200\","
        "\"ip6\":[],\"policy\":\"Policy0\",\"active\":true}]}";
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(MOVED, POLICIES, &m));
    firc_kn_policies_swap(p, m);
    ASSERTm("the same device at its new address", firc_devsel_allows(s, &moved, firc_kn_policies_resolve, firc_kn_policies_device, p));
    ASSERT_FALSEm("its old address is nobody's now", firc_devsel_allows(s, &tv4, firc_kn_policies_resolve, firc_kn_policies_device, p));
    firc_devsel_free(s);
    firc_kn_policies_stop(p);
    PASS();
}

/* Catches: the live host list read before the first map, or from a map other than the latest. */
TEST the_live_host_list_is_empty_until_the_first_read(void) {
    cJSON *arr = firc_kn_policies_hosts_json(NULL);
    ASSERT_EQ_FMT(0, cJSON_GetArraySize(arr), "%d");
    cJSON_Delete(arr);
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    arr = firc_kn_policies_hosts_json(p);
    ASSERT_EQ_FMTm("before the first read", 0, cJSON_GetArraySize(arr), "%d");
    cJSON_Delete(arr);
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(NAMED, POLICIES, &m));
    firc_kn_policies_swap(p, m);
    arr = firc_kn_policies_hosts_json(p);
    ASSERT_EQ_FMT(5, cJSON_GetArraySize(arr), "%d");
    cJSON_Delete(arr);
    firc_kn_policies_stop(p);
    PASS();
}

enum { GEN_HOSTS = 300, GEN_ADDRS = 3 };

typedef struct {
    firc_ip_t addr[GEN_ADDRS];
    size_t n;
    bool active, has_mac, has_v4;
    firc_mac_t mac;
} gen_host_t;

static gen_host_t gen[GEN_HOSTS];

static firc_ip_t gen_v4(size_t i) { return v4(172, 16, (uint8_t)(i / 200), (uint8_t)(i % 200 + 1)); }
static firc_ip_t gen_v6(size_t i) { return v6_of(0xfd, 0x00, 0x00, 0x42, (uint8_t)(i >> 8), (uint8_t)i); }

static void ip_text(const firc_ip_t *a, char *out, size_t cap) {
    inet_ntop(a->len == 4 ? AF_INET : AF_INET6, a->b, out, (socklen_t)cap);
}

/* A generated table with shared v4 and v6 addresses, missing addresses, inactive hosts and missing MACs. */
static char *gen_table(void) {
    size_t cap = GEN_HOSTS * 256, len = 0;
    char *s = malloc(cap);
    if (s == NULL) { return NULL; }
    len += (size_t)snprintf(s, cap, "{\"host\":[");
    for (size_t i = 0; i < GEN_HOSTS; i++) {
        gen_host_t *h = &gen[i];
        memset(h, 0, sizeof(*h));
        h->active = i % 3 != 0;
        h->has_mac = i % 13 != 0;
        h->mac = (firc_mac_t){{0x02, 0, 0, 0, (uint8_t)(i >> 8), (uint8_t)i}};
        char v4t[INET_ADDRSTRLEN] = "", v6a[INET6_ADDRSTRLEN], v6b[INET6_ADDRSTRLEN] = "";
        if (i % 17 != 8) {
            h->addr[h->n++] = gen_v4(i % 7 == 3 ? i - 1 : i);
            h->has_v4 = true;
            ip_text(&h->addr[0], v4t, sizeof(v4t));
        }
        h->addr[h->n] = gen_v6(i);
        ip_text(&h->addr[h->n++], v6a, sizeof(v6a));
        if (i % 11 == 5) {
            h->addr[h->n] = gen_v6(i - 3);
            ip_text(&h->addr[h->n++], v6b, sizeof(v6b));
        }
        char mac[32];
        snprintf(mac, sizeof(mac), "02:00:00:00:%02zx:%02zx", i >> 8, i & 0xff);
        len += (size_t)snprintf(s + len, cap - len,
                                "%s{\"mac\":\"%s\",\"ip\":\"%s\",\"ip6\":[\"%s\"%s%s%s],\"policy\":\"\",\"active\":%s}",
                                i ? "," : "", h->has_mac ? mac : "", v4t, v6a, v6b[0] ? ",\"" : "", v6b,
                                v6b[0] ? "\"" : "", h->active ? "true" : "false");
    }
    snprintf(s + len, cap - len, "]}");
    return s;
}

static bool gen_same(const firc_ip_t *a, const firc_ip_t *b) {
    return a->len == b->len && memcmp(a->b, b->b, a->len) == 0;
}

/* The linear rule the index replaces; -1 for nobody. */
static int gen_host_at(const firc_ip_t *client) {
    int host = -1;
    for (size_t i = 0; i < GEN_HOSTS; i++) {
        for (size_t k = 0; k < gen[i].n; k++) {
            if (!gen_same(&gen[i].addr[k], client)) { continue; }
            if (host < 0 || gen[i].active) { host = (int)i; }
            if (gen[i].active) { return host; }
        }
    }
    return host;
}

/* How many addresses of the generated map `m` answers differently from the linear rule. */
static size_t oracle_mismatches(const firc_kn_policy_map_t *m) {
    size_t bad = 0;
    for (size_t i = 0; i < GEN_HOSTS; i++) {
        for (size_t k = 0; k < gen[i].n; k++) {
            const firc_ip_t *client = &gen[i].addr[k];
            int want = gen_host_at(client);
            firc_mac_t mac = {{0}};
            bool has = firc_kn_policy_map_mac(m, client, &mac);
            if (has != gen[want].has_mac || (has && memcmp(mac.b, gen[want].mac.b, 6) != 0)) { bad++; }
            firc_ip_t out[8];
            size_t n = firc_kn_policy_map_device(m, client, out, 8), w = 0;
            for (size_t j = 0; j < gen[want].n; j++) {
                if (gen_same(&gen[want].addr[j], client)) { continue; }
                if (w >= n || !gen_same(&gen[want].addr[j], &out[w])) { bad++; }
                w++;
            }
            if (w != n) { bad++; }
        }
    }
    return bad;
}

/* Catches: the index picking the wrong host at a shared address, or losing a key, a MAC or an address. */
TEST the_index_answers_what_the_linear_rule_did(void) {
    char *json = gen_table();
    ASSERT(json != NULL);
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(json, NULL, &m));
    free(json);
    size_t asked = 0, active_later = 0, active_first = 0, first_of_two_inactive = 0, no_mac = 0;
    for (size_t i = 0; i < GEN_HOSTS; i++) {
        for (size_t k = 0; k < gen[i].n; k++) {
            const firc_ip_t *client = &gen[i].addr[k];
            int want = gen_host_at(client);
            ASSERT(want >= 0);
            if (want > (int)i && gen[want].active && !gen[i].active) { active_later++; }
            if (want < (int)i && gen[want].active && !gen[i].active) { active_first++; }
            if (want != (int)i && !gen[want].active && !gen[i].active) { first_of_two_inactive++; }
            firc_mac_t mac = {{0}};
            bool has = firc_kn_policy_map_mac(m, client, &mac);
            ASSERT_EQ(gen[want].has_mac, has);
            if (has) { ASSERT_MEM_EQ(gen[want].mac.b, mac.b, 6); } else { no_mac++; }
            firc_ip_t out[8];
            size_t n = firc_kn_policy_map_device(m, client, out, 8);
            size_t w = 0;
            for (size_t j = 0; j < gen[want].n; j++) {
                if (gen_same(&gen[want].addr[j], client)) { continue; }
                ASSERT(w < n);
                ASSERT(gen_same(&gen[want].addr[j], &out[w]));
                w++;
            }
            ASSERT_EQ_FMT(w, n, "%zu");
            asked++;
        }
    }
    ASSERT(asked > GEN_HOSTS);
    ASSERTm("an inactive host listed before the active one at its address", active_later > 0);
    ASSERTm("an active host listed before an inactive one at its address", active_first > 0);
    ASSERTm("two inactive hosts at one address", first_of_two_inactive > 0);
    ASSERTm("a host without a MAC", no_mac > 0);
    firc_ip_t nobody = v4(172, 16, 9, 9), nobody6 = v6_of(0xfd, 0, 0, 0x43, 0, 1);
    firc_mac_t mac = {{0}};
    firc_ip_t out[8];
    ASSERT_FALSE(firc_kn_policy_map_mac(m, &nobody, &mac));
    ASSERT_FALSE(firc_kn_policy_map_mac(m, &nobody6, &mac));
    ASSERT_EQ_FMT((size_t)0, firc_kn_policy_map_device(m, &nobody, out, 8), "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: the indexed resolver losing a host's own policy, its precedence, or a segment's policy. */
TEST the_live_resolver_keeps_every_policy_rule(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_kn_segment_t seg[8];
    size_t n = firc_kn_hotspot_segments_parse(RC_HOTSPOT, seg, 8);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segments(m, seg, n, INTERFACES));
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_kn_policies_swap(p, m);

    firc_ip_t tv = v4(192, 168, 0, 124), work6 = v6_of(0xfd, 0, 0, 0, 0x01, 0x04), none = v4(192, 168, 0, 128),
              peer = v4(10, 99, 0, 2), stranger = v4(10, 98, 0, 2);
    ASSERTm("own policy, by description", firc_kn_policies_resolve("Kids", &tv, p));
    ASSERTm("own policy, by internal name", firc_kn_policies_resolve("Policy0", &tv, p));
    ASSERTm("own policy, by a v6 address", firc_kn_policies_resolve("Work VPN", &work6, p));
    ASSERT_FALSEm("own policy wins over the segment's", firc_kn_policies_resolve("Guests", &tv, p));
    ASSERTm("a listed host with none takes its segment's", firc_kn_policies_resolve("Guests", &none, p));
    ASSERTm("an unlisted peer takes its segment's", firc_kn_policies_resolve("FircTest", &peer, p));
    static const char *const names[] = {"Kids", "Policy0", "Work VPN", "Guests", "FircTest", "Policy9"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        ASSERT_FALSEm("an address nobody has is in nothing", firc_kn_policies_resolve(names[i], &stranger, p));
    }
    firc_kn_policies_stop(p);
    PASS();
}

typedef struct {
    firc_kn_policies_t *p;
    _Atomic bool done;
    unsigned published;
} publisher_t;

static void *publish_many(void *ud) {
    publisher_t *pub = ud;
    for (unsigned i = 0; i < 3000; i++) {
        firc_kn_policy_map_t *m = NULL;
        if (firc_kn_policy_map_parse(i % 2 ? HOTSPOT : NAMED, POLICIES, &m) != FIRC_OK) { break; }
        firc_kn_policies_swap(pub->p, m);
        pub->published++;
    }
    atomic_store(&pub->done, true);
    return NULL;
}

/* Catches: a map installed or freed off the reading thread, a use after free under ASan. */
TEST a_map_is_never_freed_under_a_check(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_kn_policies_swap(p, m);
    publisher_t pub = {.p = p};
    pthread_t th;
    ASSERT_EQ(0, pthread_create(&th, NULL, publish_many, &pub));
    firc_ip_t clients[] = {v4(192, 168, 0, 124), v4(192, 168, 0, 104), v6_of(0xfd, 0, 0, 0, 0x01, 0x04),
                           v4(192, 168, 0, 55), v4(10, 0, 0, 1)};
    size_t checks = 0;
    while (!atomic_load(&pub.done)) {
        for (size_t i = 0; i < sizeof(clients) / sizeof(clients[0]); i++) {
            firc_ip_t out[8];
            firc_mac_t mac = {{0}};
            (void)firc_kn_policies_device(&clients[i], out, 8, &mac, p);
            (void)firc_kn_policies_resolve("Kids", &clients[i], p);
            checks++;
        }
    }
    pthread_join(th, NULL);
    ASSERT_EQ_FMT(3000u, pub.published, "%u");
    ASSERTm("the reader ran while the maps changed", checks > 0);
    firc_ip_t tv = v4(192, 168, 0, 124);
    ASSERTm("HOTSPOT was published last", firc_kn_policies_resolve("Kids", &tv, p));
    firc_ip_t laptop = v4(192, 168, 0, 104);
    firc_mac_t mac = {{0}};
    firc_ip_t out[8];
    ASSERT_EQ_FMTm("HOTSPOT's .104 host has two other addresses", (size_t)2,
                   firc_kn_policies_device(&laptop, out, 8, &mac, p), "%zu");
    firc_kn_policies_stop(p);
    PASS();
}

/* Catches: a constant hash seed, or an answer that depends on the seed. */
TEST two_maps_of_one_table_answer_alike_whatever_their_seeds(void) {
    char *json = gen_table();
    ASSERT(json != NULL);
    firc_kn_policy_map_t *a = NULL, *b = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(json, NULL, &a));
    for (int i = 0; i < 32; i++) {
        firc_kn_policy_map_free(b);
        b = NULL;
        ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(json, NULL, &b));
        if (firc_kn_policy_map_seed_for_test(b) != firc_kn_policy_map_seed_for_test(a)) { break; }
    }
    free(json);
    ASSERT(firc_kn_policy_map_seed_for_test(a) != firc_kn_policy_map_seed_for_test(b));
    ASSERT_EQ_FMTm("the first map answers by the rule", (size_t)0, oracle_mismatches(a), "%zu");
    ASSERT_EQ_FMTm("and so does the one seeded otherwise", (size_t)0, oracle_mismatches(b), "%zu");
    firc_kn_policy_map_free(a);
    firc_kn_policy_map_free(b);
    PASS();
}

#define HOME_FLOOR 160
TEST a_slash_24_spreads_over_the_index(void) {
    size_t cap = 64 + 250 * 96, len = 0;
    char *json = malloc(cap);
    ASSERT(json != NULL);
    len += (size_t)snprintf(json + len, cap - len, "{\"host\":[");
    for (size_t i = 1; i <= 250; i++) {
        len += (size_t)snprintf(json + len, cap - len, "%s{\"mac\":\"02:00:00:00:00:%02zx\",\"ip\":\"192.168.0.%zu\"}",
                                i > 1 ? "," : "", i, i);
    }
    snprintf(json + len, cap - len, "]}");
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(json, NULL, &m));
    free(json);
    size_t slots = 0, home = firc_kn_policy_map_home_slots_for_test(m, &slots);
    firc_kn_policy_map_free(m);
    ASSERT_EQ_FMT((size_t)512, slots, "%zu");
    ASSERT_GTEm("250 addresses of one /24 start their probes all over the index", home, (size_t)HOME_FLOOR);
    PASS();
}

/* Catches: a v6 hash that ignores the top bytes of the third and fourth words. */
TEST v6_addresses_differing_in_top_bytes_spread_over_the_index(void) {
    size_t cap = 64 + 256 * 96, len = 0;
    char *json = malloc(cap);
    ASSERT(json != NULL);
    len += (size_t)snprintf(json + len, cap - len, "{\"host\":[");
    for (size_t i = 0; i < 256; i++) {
        len += (size_t)snprintf(json + len, cap - len,
                                "%s{\"mac\":\"02:00:00:00:00:%02zx\",\"ip6\":[\"fd00::%zx:0:%zx\"]}",
                                i > 0 ? "," : "", i, i >> 4, i & 15);
    }
    snprintf(json + len, cap - len, "]}");
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(json, NULL, &m));
    free(json);
    size_t slots = 0, home = firc_kn_policy_map_home_slots_for_test(m, &slots);
    firc_kn_policy_map_free(m);
    ASSERT_EQ_FMT((size_t)512, slots, "%zu");
    ASSERT_GTEm("256 addresses do not share a handful of slots", home, (size_t)HOME_FLOOR);
    PASS();
}

/* Catches: a replaced map freed by the loop's check, never reaped, leaked, or freed twice. */
TEST a_replaced_map_is_freed_by_the_refresher_not_the_loop(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_kn_policy_map_t *a = NULL, *b = NULL, *c = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &a));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(NAMED, POLICIES, &b));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(SHARED, POLICIES, &c));
    firc_kn_policies_swap(p, a);
    ASSERT_EQ(a, firc_kn_policies_live_for_test(p));
    ASSERT_EQ_FMTm("nothing was replaced", (size_t)0, firc_kn_policies_retired_for_test(p), "%zu");
    firc_kn_policies_swap(p, b);
    ASSERT_EQ(b, firc_kn_policies_live_for_test(p));
    ASSERT_EQ_FMTm("the check put A aside instead of freeing it", (size_t)1, firc_kn_policies_retired_for_test(p),
                   "%zu");
    firc_kn_policies_swap(p, c);
    ASSERT_EQ_FMTm("the next hand-over freed it", (size_t)0, firc_kn_policies_retired_for_test(p), "%zu");
    ASSERT_EQ(c, firc_kn_policies_live_for_test(p));
    ASSERT_EQ_FMT((size_t)1, firc_kn_policies_retired_for_test(p), "%zu");
    firc_kn_policies_stop(p);
    PASS();
}

static const char QUIET_1[] =
    "{\"host\":[{\"mac\":\"aa:00:00:00:00:01\",\"name\":\"TV\",\"ip\":\"192.168.0.124\",\"ip6\":[\"fd00::124\"],"
    "\"policy\":\"Policy0\",\"active\":true,\"registered\":true,\"rxbytes\":419943121,\"rssi\":-44,"
    "\"dhcp\":{\"expires\":18536}}]}";
static const char QUIET_2[] =
    "{\"host\":[{\"mac\":\"aa:00:00:00:00:01\",\"name\":\"TV\",\"ip\":\"192.168.0.124\",\"ip6\":[\"fd00::124\"],"
    "\"policy\":\"Policy0\",\"active\":true,\"registered\":true,\"rxbytes\":419951877,\"rssi\":-47,"
    "\"dhcp\":{\"expires\":18533}}]}";
static const char QUIET_OFF[] =
    "{\"host\":[{\"mac\":\"aa:00:00:00:00:01\",\"name\":\"TV\",\"ip\":\"192.168.0.124\",\"ip6\":[\"fd00::124\"],"
    "\"policy\":\"Policy0\",\"active\":false,\"registered\":true,\"rxbytes\":419951877,\"rssi\":-47,"
    "\"dhcp\":{\"expires\":18533}}]}";
static const char QUIET_MAC[] =
    "{\"host\":[{\"mac\":\"aa:00:00:00:00:02\",\"name\":\"TV\",\"ip\":\"192.168.0.124\",\"ip6\":[\"fd00::124\"],"
    "\"policy\":\"Policy0\",\"active\":true,\"registered\":true,\"rxbytes\":419943121,\"rssi\":-44,"
    "\"dhcp\":{\"expires\":18536}}]}";
static const char QUIET_NAME[] =
    "{\"host\":[{\"mac\":\"aa:00:00:00:00:01\",\"name\":\"TV2\",\"ip\":\"192.168.0.124\",\"ip6\":[\"fd00::124\"],"
    "\"policy\":\"Policy0\",\"active\":true,\"registered\":true,\"rxbytes\":419943121,\"rssi\":-44,"
    "\"dhcp\":{\"expires\":18536}}]}";
static const char QUIET_POLICY[] =
    "{\"host\":[{\"mac\":\"aa:00:00:00:00:01\",\"name\":\"TV\",\"ip\":\"192.168.0.124\",\"ip6\":[\"fd00::124\"],"
    "\"policy\":\"Policy1\",\"active\":true,\"registered\":true,\"rxbytes\":419943121,\"rssi\":-44,"
    "\"dhcp\":{\"expires\":18536}}]}";
static const char QUIET_REG[] =
    "{\"host\":[{\"mac\":\"aa:00:00:00:00:01\",\"name\":\"TV\",\"ip\":\"192.168.0.124\",\"ip6\":[\"fd00::124\"],"
    "\"policy\":\"Policy0\",\"active\":true,\"registered\":false,\"rxbytes\":419943121,\"rssi\":-44,"
    "\"dhcp\":{\"expires\":18536}}]}";

/* Catches: an unchanged refresh handed to the loop, a real change missed, or a quiet refresh not reaping. */
TEST a_refresh_that_changes_nothing_hands_nothing_over(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m));
    ASSERTm("the first map is always new", firc_kn_policies_offer(p, m));
    const firc_kn_policy_map_t *first = firc_kn_policies_live_for_test(p);
    ASSERT_EQ(m, first);

    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_2, POLICIES, &m));
    ASSERT_FALSEm("counters moved, nothing else", firc_kn_policies_offer(p, m));
    ASSERT_EQm("the loop still answers from the first map", first, firc_kn_policies_live_for_test(p));

    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_OFF, POLICIES, &m));
    ASSERTm("the TV went offline: that is a change", firc_kn_policies_offer(p, m));
    ASSERT_EQ(m, firc_kn_policies_live_for_test(p));
    ASSERT_EQ_FMT((size_t)1, firc_kn_policies_retired_for_test(p), "%zu");

    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_OFF, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    ASSERTm("a new segment is a change", firc_kn_policies_offer(p, m));
    const firc_kn_policy_map_t *seg = firc_kn_policies_live_for_test(p);
    ASSERT_EQ(m, seg);

    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_OFF, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    ASSERT_FALSE(firc_kn_policies_offer(p, m));
    ASSERT_EQ(seg, firc_kn_policies_live_for_test(p));
    ASSERT_EQ_FMTm("a quiet refresh still frees what the loop put aside", (size_t)0,
                   firc_kn_policies_retired_for_test(p), "%zu");
    firc_kn_policies_stop(p);

    struct {
        const char *json;
        const char *why;
    } single[] = {
        {QUIET_MAC, "a different MAC is a change"},
        {QUIET_NAME, "a different name is a change"},
        {QUIET_POLICY, "a different own policy is a change"},
        {QUIET_REG, "a different registered flag is a change"},
    };
    for (size_t i = 0; i < sizeof(single) / sizeof(single[0]); i++) {
        firc_kn_policies_t *q = firc_kn_policies_start(NULL, 0);
        ASSERT(q != NULL);
        firc_kn_policy_map_t *base = NULL, *diff = NULL;
        ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &base));
        ASSERTm("the baseline is always new", firc_kn_policies_offer(q, base));
        ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(single[i].json, POLICIES, &diff));
        ASSERTm(single[i].why, firc_kn_policies_offer(q, diff));
        ASSERT_EQ(diff, firc_kn_policies_live_for_test(q));
        firc_kn_policies_stop(q);
    }
    PASS();
}

static const char MARKS[] =
    "{\"Policy0\":{\"description\":\"Kids\",\"mark\":\"ffffaab\",\"permit\":[]},"
    "\"Policy1\":{\"mark\":\"ffffaad\"},"
    "\"Policy9\":{\"description\":\"Guests\"}}";

/* Catches: a mark read as decimal, not found by description, or made up for a policy without one. */
TEST a_policys_mark_comes_from_the_ip_policy_document(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, MARKS));
    uint32_t mark = 0;
    ASSERTm("by internal name", firc_kn_policy_map_mark(m, "Policy0", &mark));
    ASSERT_EQ_FMT(0x0ffffaabu, mark, "0x%x");
    mark = 0;
    ASSERTm("by description", firc_kn_policy_map_mark(m, "Kids", &mark));
    ASSERT_EQ_FMT(0x0ffffaabu, mark, "0x%x");
    ASSERT(firc_kn_policy_map_mark(m, "Work VPN", &mark));
    ASSERT_EQ_FMT(0x0ffffaadu, mark, "0x%x");
    mark = 0x1234u;
    ASSERT_FALSEm("a policy the firmware gave no mark has none", firc_kn_policy_map_mark(m, "Guests", &mark));
    ASSERT_EQ_FMTm("and *mark is left alone", 0x1234u, mark, "0x%x");
    ASSERT_FALSE(firc_kn_policy_map_mark(m, "Nope", &mark));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a malformed mark, or one with no bits under firc's mask, taken as a mark. */
TEST a_mark_that_is_not_one_to_eight_hex_digits_is_no_mark(void) {
    static const char BAD[] =
        "{\"Policy0\":{\"mark\":\"zz\"},\"Policy1\":{\"mark\":\"\"},"
        "\"Policy9\":{\"mark\":\"1ffffffff\"},\"FircTest\":{\"mark\":12},"
        "\"Zero\":{\"mark\":\"0\"},\"Zero8\":{\"mark\":\"00000000\"},\"FircBits\":{\"mark\":\"40ff0000\"},"
        "\"LowBit\":{\"mark\":\"1\"}}";
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, BAD));
    uint32_t mark = 0;
    ASSERT_FALSE(firc_kn_policy_map_mark(m, "Policy0", &mark));
    ASSERT_FALSE(firc_kn_policy_map_mark(m, "Policy1", &mark));
    ASSERT_FALSE(firc_kn_policy_map_mark(m, "Policy9", &mark));
    ASSERT_FALSE(firc_kn_policy_map_mark(m, "FircTest", &mark));
    ASSERT_FALSEm("zero", firc_kn_policy_map_mark(m, "Zero", &mark));
    ASSERT_FALSEm("eight zeros", firc_kn_policy_map_mark(m, "Zero8", &mark));
    ASSERT_FALSEm("only firc's bits", firc_kn_policy_map_mark(m, "FircBits", &mark));
    ASSERTm("the positive twin: one bit outside firc's is a mark", firc_kn_policy_map_mark(m, "LowBit", &mark));
    ASSERT_EQ_FMT(0x1u, mark, "0x%x");
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_policy_map_add_marks(m, "[1]"));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_kn_policy_map_add_marks(m, "not json"));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, "[]"));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: map_same ignoring the marks. */
TEST a_changed_mark_is_a_change(void) {
    static const char MARKS_MOVED[] = "{\"Policy0\":{\"mark\":\"ffffaac\"},\"Policy1\":{\"mark\":\"ffffaad\"}}";
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, MARKS));
    ASSERT(firc_kn_policies_offer(p, m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_2, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, MARKS));
    ASSERT_FALSEm("the same marks are no change", firc_kn_policies_offer(p, m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_2, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, MARKS_MOVED));
    ASSERTm("a moved mark is", firc_kn_policies_offer(p, m));
    firc_kn_policies_stop(p);
    PASS();
}

static char *read_all_fd(int fd) {
    off_t n = lseek(fd, 0, SEEK_END);
    if (n < 0) { return NULL; }
    char *s = calloc((size_t)n + 1, 1);
    if (s != NULL && pread(fd, s, (size_t)n, 0) != (ssize_t)n) {
        free(s);
        return NULL;
    }
    return s;
}

static size_t count_of(const char *hay, const char *needle) {
    size_t n = 0;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p += strlen(needle)) { n++; }
    return n;
}

/* An unlinked temporary file for the log; -1 when there is none. */
static int log_file(void) {
    char path[] = "/tmp/firc-kn-log-XXXXXX";
    int fd = mkstemp(path);
    if (fd >= 0) { unlink(path); }
    return fd;
}

/* Restores the log fd, then reads and closes `fd`; call it before any assertion on the log. */
static char *log_back(int fd) {
    firc_log_set_fd(1);
    char *s = read_all_fd(fd);
    close(fd);
    return s;
}

/* Catches: a mark collision under firc's mask missed, or said on every changed map. */
TEST two_policies_whose_marks_agree_outside_firc_s_bits_are_said_once(void) {
    static const char CLASH[] = "{\"Policy0\":{\"mark\":\"ffffaab\"},\"Policy1\":{\"mark\":\"f01faab\"}}";
    firc_kn_policy_map_t *m1 = NULL, *m2 = NULL, *m3 = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m1));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m1, CLASH));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_OFF, POLICIES, &m2));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m2, CLASH));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m3));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m3, MARKS));
    int fd = log_file(), fd2 = log_file();
    ASSERT(fd >= 0 && fd2 >= 0);
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0), *q = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL && q != NULL);

    firc_log_set_fd(fd);
    bool first = firc_kn_policies_offer(p, m1);
    bool second = firc_kn_policies_offer(p, m2);
    char *log = log_back(fd);
    firc_log_set_fd(fd2);
    bool apart = firc_kn_policies_offer(q, m3);
    char *log2 = log_back(fd2);
    firc_kn_policies_stop(p);
    firc_kn_policies_stop(q);
    size_t said = log != NULL ? count_of(log, "cannot tell them apart") : 99;
    bool both = log != NULL && strstr(log, "Policy0") != NULL && strstr(log, "Policy1") != NULL;
    size_t said2 = log2 != NULL ? count_of(log2, "cannot tell them apart") : 99;
    free(log);
    free(log2);

    ASSERT(first);
    ASSERTm("a second, changed map with the same clash", second);
    ASSERT_EQ_FMTm("said once", (size_t)1, said, "%zu");
    ASSERTm("naming both", both);
    ASSERT(apart);
    ASSERT_EQ_FMTm("low bits apart: no clash", (size_t)0, said2, "%zu");
    PASS();
}

/* Catches: the clash flag never cleared, or a map with no clash saying something. */
TEST a_clash_that_returns_is_said_again(void) {
    static const char CLASH[] = "{\"Policy0\":{\"mark\":\"ffffaab\"},\"Policy1\":{\"mark\":\"f01faab\"}}";
    firc_kn_policy_map_t *m1 = NULL, *m2 = NULL, *m3 = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m1));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m1, CLASH));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m2));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m2, MARKS));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_OFF, POLICIES, &m3));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m3, CLASH));
    int fd = log_file();
    ASSERT(fd >= 0);
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_log_set_fd(fd);
    bool a = firc_kn_policies_offer(p, m1);
    bool b = firc_kn_policies_offer(p, m2);
    bool c = firc_kn_policies_offer(p, m3);
    char *log = log_back(fd);
    firc_kn_policies_stop(p);
    size_t said = log != NULL ? count_of(log, "cannot tell them apart") : 99;
    free(log);
    ASSERTm("three changed maps", a && b && c);
    ASSERT_EQ_FMTm("said, cleared, said again", (size_t)2, said, "%zu");
    PASS();
}

typedef struct {
    firc_ip_t a[80];
    size_t n;
} addrs_t;

static void collect_addr(const firc_ip_t *a, void *ud) {
    addrs_t *x = ud;
    if (x->n < 80) { x->a[x->n++] = *a; }
}

static size_t addrs_count(const addrs_t *x, const firc_ip_t *a) {
    size_t n = 0;
    for (size_t i = 0; i < x->n; i++) {
        if (x->a[i].len == a->len && memcmp(x->a[i].b, a->b, a->len) == 0) { n++; }
    }
    return n;
}

static bool addrs_have(const addrs_t *x, const firc_ip_t *a) { return addrs_count(x, a) > 0; }

/* Catches: a prefix entry writing only the covered address, a host twice, or a host outside it. */
TEST hosts_inside_a_prefix_bring_every_address_they_have(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    firc_ip_t h104 = v4(192, 168, 0, 104);
    firc_ip_t f104 = v6_of(0xfd, 0x00, 0x00, 0x00, 0x01, 0x04);
    firc_ip_t g104 = v6_of(0x20, 0x01, 0x0d, 0xb8, 0x01, 0x04);

    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &h104, 32, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)3, x.n, "%zu");
    ASSERT(addrs_have(&x, &h104) && addrs_have(&x, &f104) && addrs_have(&x, &g104));

    x.n = 0;
    firc_ip_t lan = v4(192, 168, 0, 0);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &lan, 24, false, collect_addr, &x));
    ASSERT_EQ_FMTm("four hosts, six addresses", (size_t)6, x.n, "%zu");
    firc_ip_t a124 = v4(192, 168, 0, 124), a128 = v4(192, 168, 0, 128), a77 = v4(192, 168, 0, 77);
    ASSERT(addrs_have(&x, &a124) && addrs_have(&x, &a128) && addrs_have(&x, &a77) && addrs_have(&x, &g104));

    x.n = 0;
    firc_ip_t ten = v4(10, 0, 0, 0);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &ten, 8, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    firc_ip_t no_family = {{0}, 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &no_family, 0, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");

    x.n = 0;
    firc_ip_t fd00 = v6_of(0xfd, 0x00, 0, 0, 0, 0);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &fd00, 16, false, collect_addr, &x));
    ASSERT_EQ_FMTm("the v6 prefix reaches the host's v4 address too", (size_t)3, x.n, "%zu");
    ASSERT(addrs_have(&x, &h104));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: the packet path writing the inactive host's address at a shared one. */
TEST the_host_at_a_shared_address_is_the_active_one_here_too(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(SHARED, NULL, &m));
    firc_ip_t at = v4(192, 168, 1, 5);
    firc_ip_t f77 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x77), f5 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x05);
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &at, 32, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)2, x.n, "%zu");
    ASSERT(addrs_have(&x, &at) && addrs_have(&x, &f77));
    ASSERT_FALSE(addrs_have(&x, &f5));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a host's address written without asking the index whose it is now. */
TEST a_prefix_does_not_bring_an_address_another_host_holds_now(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(SHARED, NULL, &m));
    firc_ip_t at = v4(192, 168, 1, 5);
    firc_ip_t f77 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x77), f5 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x05);
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &f5, 128, false, collect_addr, &x));
    ASSERT_EQ_FMTm("the TV's own address, and nothing the phone holds", (size_t)1, x.n, "%zu");
    ASSERT(addrs_have(&x, &f5));
    ASSERT_FALSE(addrs_have(&x, &at));

    x.n = 0;
    firc_ip_t fd00 = v6_of(0xfd, 0x00, 0, 0, 0, 0);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &fd00, 16, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)3, x.n, "%zu");
    ASSERT(addrs_have(&x, &f5) && addrs_have(&x, &f77));
    ASSERT_EQ_FMTm("the shared address once, for the phone", (size_t)1, addrs_count(&x, &at), "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: the 64-address cap on one device dropped, or a prefix walking one host per covered address. */
TEST a_host_brings_at_most_sixty_four_addresses(void) {
    char json[8192];
    size_t off = (size_t)snprintf(json, sizeof(json), "{\"host\":[{\"mac\":\"aa:00:00:00:00:09\",\"ip\":\"10.0.0.1\",\"ip6\":[");
    for (int i = 1; i <= 70; i++) {
        off += (size_t)snprintf(json + off, sizeof(json) - off, "%s\"fd00::%x\"", i == 1 ? "" : ",", i);
    }
    snprintf(json + off, sizeof(json) - off, "],\"policy\":\"\",\"active\":true}]}");
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(json, NULL, &m));
    firc_ip_t at = v4(10, 0, 0, 1);
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &at, 32, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)FIRC_DEVSEL_MAX_DEVICE_ADDRS, x.n, "%zu");
    x.n = 0;
    firc_ip_t fd00 = v6_of(0xfd, 0x00, 0, 0, 0, 0);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &fd00, 16, false, collect_addr, &x));
    ASSERT_EQ_FMTm("one host, once", (size_t)FIRC_DEVSEL_MAX_DEVICE_ADDRS, x.n, "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a policy entry missing a host through its segment, a description, or a v6 address. */
TEST a_policy_lists_every_address_of_its_hosts(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, "Kids", false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)2, x.n, "%zu");
    firc_ip_t a124 = v4(192, 168, 0, 124), a77 = v4(192, 168, 0, 77);
    ASSERT(addrs_have(&x, &a124) && addrs_have(&x, &a77));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, "Policy1", false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)3, x.n, "%zu");
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, "Nope", false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    firc_kn_policy_map_free(m);

    static const char SEG_HOST[] =
        "{\"host\":[{\"mac\":\"aa:00:00:00:00:0a\",\"ip\":\"10.99.0.5\",\"ip6\":[\"fd00::a\"],"
        "\"policy\":\"\",\"active\":true}]}";
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(SEG_HOST, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, "Guests", false, collect_addr, &x));
    ASSERT_EQ_FMTm("the segment's host, both of its addresses", (size_t)2, x.n, "%zu");
    firc_ip_t seg4 = v4(10, 99, 0, 5), seg6 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x0a);
    ASSERT(addrs_have(&x, &seg4) && addrs_have(&x, &seg6));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a policy host's address written without asking the index whose it is now. */
TEST a_policy_does_not_list_an_address_another_host_holds_now(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(SHARED, POLICIES, &m));
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, "Kids", false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)1, x.n, "%zu");
    firc_ip_t f5 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x05);
    ASSERT(addrs_have(&x, &f5));
    firc_kn_policy_map_free(m);
    PASS();
}

static const char STALE[] =
    "{\"host\":["
    "{\"mac\":\"aa:00:00:00:00:01\",\"ip\":\"192.168.1.50\",\"ip6\":[\"fd00::60\",\"2001:db8::60\"],"
    "\"policy\":\"Policy0\",\"active\":false},"
    "{\"mac\":\"aa:00:00:00:00:02\",\"ip\":\"192.168.1.50\",\"ip6\":[\"fd00::77\"],\"policy\":\"\",\"active\":true}"
    "]}";

/* The answer's policy resolver over one map, as the pipeline runs it. */
static bool map_policy(const char *policy, const firc_ip_t *client, void *ud) {
    return firc_kn_policy_map_has(ud, policy, client);
}
static size_t map_device(const firc_ip_t *client, firc_ip_t *out, size_t cap, firc_mac_t *mac, void *ud) {
    (void)firc_kn_policy_map_mac(ud, client, mac);
    return firc_kn_policy_map_device(ud, client, out, cap);
}
/* Whether the answer lets `client` through a selector of one entry. */
static bool answer_allows(const firc_kn_policy_map_t *m, const char *entry, bool deny, const firc_ip_t *client) {
    const char *list[] = {entry};
    firc_devsel_t *s = NULL;
    if (firc_devsel_compile(deny ? NULL : list, deny ? 0 : 1, deny ? list : NULL, deny ? 1 : 0, &s) != FIRC_OK) {
        abort();
    }
    bool ok = firc_devsel_allows(s, client, map_policy, map_device, (void *)m);
    firc_devsel_free(s);
    return ok;
}

/* Catches: a deny entry tied only to the host the index picks, missing other hosts that list it. */
TEST a_denied_address_brings_every_host_that_lists_it(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(STALE, POLICIES, &m));
    firc_ip_t a50 = v4(192, 168, 1, 50);
    firc_ip_t f60 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x60), g60 = v6_of(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x60);
    firc_ip_t f77 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x77);
    ASSERT_FALSEm("the answer refuses the TV at fd00::60", answer_allows(m, "192.168.1.50", true, &f60));
    ASSERT_FALSE(answer_allows(m, "192.168.1.50", true, &g60));
    ASSERT_FALSE(answer_allows(m, "192.168.1.50", true, &f77));

    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &a50, 32, true, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)4, x.n, "%zu");
    ASSERT(addrs_have(&x, &f60) && addrs_have(&x, &g60) && addrs_have(&x, &f77));
    ASSERT_EQ_FMTm("the shared address once, for the phone", (size_t)1, addrs_count(&x, &a50), "%zu");

    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &a50, 32, false, collect_addr, &x));
    ASSERT_EQ_FMTm("allow: the phone's two", (size_t)2, x.n, "%zu");
    ASSERT(addrs_have(&x, &a50) && addrs_have(&x, &f77));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a deny writing a host's stale address without asking the index whose it is now. */
TEST a_deny_does_not_bring_an_address_another_host_holds_now(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(STALE, POLICIES, &m));
    firc_ip_t a50 = v4(192, 168, 1, 50);
    firc_ip_t f60 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x60), g60 = v6_of(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x60);
    ASSERTm("the answer lets the phone through", answer_allows(m, "fd00::60", true, &a50));
    ASSERT_FALSE(answer_allows(m, "fd00::60", true, &g60));
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &f60, 128, true, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)2, x.n, "%zu");
    ASSERT(addrs_have(&x, &f60) && addrs_have(&x, &g60));
    ASSERT_FALSE(addrs_have(&x, &a50));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a deny keeping the 64-address cap, so the host's later addresses are routed. */
TEST a_deny_brings_every_address_of_its_hosts(void) {
    char json[8192];
    size_t off = (size_t)snprintf(json, sizeof(json),
                                  "{\"host\":[{\"mac\":\"aa:00:00:00:00:09\",\"ip\":\"10.0.0.1\",\"ip6\":[");
    for (int i = 1; i <= 70; i++) {
        off += (size_t)snprintf(json + off, sizeof(json) - off, "%s\"fd00::%x\"", i == 1 ? "" : ",", i);
    }
    snprintf(json + off, sizeof(json) - off, "],\"policy\":\"Policy0\",\"active\":true}]}");
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(json, POLICIES, &m));
    firc_ip_t at = v4(10, 0, 0, 1), last = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x46);
    ASSERT_FALSE(answer_allows(m, "10.0.0.1", true, &last));
    ASSERT_FALSE(answer_allows(m, "policy:Kids", true, &last));
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &at, 32, true, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)71, x.n, "%zu");
    ASSERT(addrs_have(&x, &last));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, "Kids", true, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)71, x.n, "%zu");
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, "Kids", false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)FIRC_DEVSEL_MAX_DEVICE_ADDRS, x.n, "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: an allow tied to a host through an address past the answer's 64-address window. */
TEST an_allow_past_the_answer_s_window_brings_no_host(void) {
    char json[8192];
    size_t off = (size_t)snprintf(json, sizeof(json),
                                  "{\"host\":[{\"mac\":\"aa:00:00:00:00:09\",\"ip\":\"10.0.0.1\",\"ip6\":[");
    for (int i = 1; i <= 70; i++) {
        off += (size_t)snprintf(json + off, sizeof(json) - off, "%s\"fd00::%x\"", i == 1 ? "" : ",", i);
    }
    snprintf(json + off, sizeof(json) - off, "],\"policy\":\"\",\"active\":true}]}");
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(json, NULL, &m));
    firc_ip_t at = v4(10, 0, 0, 1), f46 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x46), f3f = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x3f);
    ASSERT(answer_allows(m, "fd00::46", false, &f46));
    ASSERT_FALSEm("the answer refuses 10.0.0.1", answer_allows(m, "fd00::46", false, &at));
    ASSERT(answer_allows(m, "fd00::3f", false, &at));
    ASSERT_FALSE(answer_allows(m, "fd00::3f", false, &f46));
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &f46, 128, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &f46, 128, true, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)71, x.n, "%zu");
    firc_ip_t f40 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x40);
    ASSERT_FALSE(answer_allows(m, "fd00::40/122", false, &at));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &f40, 122, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &f3f, 128, false, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)FIRC_DEVSEL_MAX_DEVICE_ADDRS, x.n, "%zu");
    ASSERT(addrs_have(&x, &at) && addrs_have(&x, &f3f));
    ASSERT_FALSE(addrs_have(&x, &f46));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a deny policy writing a stale address, sending direct a host nothing refused. */
TEST a_denied_policy_writes_what_the_answer_refuses_and_no_more(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(STALE, POLICIES, &m));
    firc_ip_t a50 = v4(192, 168, 1, 50);
    firc_ip_t f60 = v6_of(0xfd, 0x00, 0, 0, 0x00, 0x60), g60 = v6_of(0x20, 0x01, 0x0d, 0xb8, 0x00, 0x60);
    ASSERT(answer_allows(m, "policy:Kids", true, &a50));
    ASSERT_FALSE(answer_allows(m, "policy:Kids", true, &f60));
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, "Kids", true, collect_addr, &x));
    ASSERT_EQ_FMT((size_t)2, x.n, "%zu");
    ASSERT(addrs_have(&x, &f60) && addrs_have(&x, &g60));
    firc_kn_policy_map_free(m);
    PASS();
}

typedef struct {
    firc_ip_t net[8];
    uint8_t prefix[8];
    size_t n;
} nets_t;

static void collect_net(const firc_ip_t *net, uint8_t prefix, void *ud) {
    nets_t *x = ud;
    if (x->n < 8) {
        x->net[x->n] = *net;
        x->prefix[x->n++] = prefix;
    }
}

static bool nets_have(const nets_t *x, const firc_ip_t *net, uint8_t prefix) {
    for (size_t i = 0; i < x->n; i++) {
        if (x->prefix[i] == prefix && x->net[i].len == net->len && memcmp(x->net[i].b, net->b, net->len) == 0) {
            return true;
        }
    }
    return false;
}

/* Catches: a policy's segment not written, written with its host bits, or not found by description. */
TEST a_policy_s_segment_is_its_network(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    firc_ip_t peer = v4(10, 99, 0, 7), net = v4(10, 99, 0, 0);
    ASSERT(firc_kn_policy_map_has(m, "Guests", &peer));
    nets_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Guests", false, collect_net, &x));
    ASSERT_EQ_FMT((size_t)1, x.n, "%zu");
    ASSERT(nets_have(&x, &net, 24));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Policy9", true, collect_net, &x));
    ASSERT_EQ_FMT((size_t)1, x.n, "%zu");
    ASSERT(nets_have(&x, &net, 24));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Kids", false, collect_net, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: an allow writing a segment that holds another policy's host, or a deny leaving one out. */
TEST an_allowed_segment_that_holds_another_policy_s_host_is_not_written(void) {
    static const char ON_SEG[] =
        "{\"host\":[{\"mac\":\"aa:00:00:00:00:0b\",\"ip\":\"10.99.0.5\",\"policy\":\"Policy0\",\"active\":true}]}";
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(ON_SEG, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    firc_ip_t own = v4(10, 99, 0, 5), peer = v4(10, 99, 0, 9), net = v4(10, 99, 0, 0);
    ASSERT_FALSE(firc_kn_policy_map_has(m, "Guests", &own));
    ASSERT(firc_kn_policy_map_has(m, "Guests", &peer));
    nets_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Guests", false, collect_net, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Guests", true, collect_net, &x));
    ASSERT_EQ_FMT((size_t)1, x.n, "%zu");
    ASSERT(nets_have(&x, &net, 24));
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: an allow segment ignoring an earlier overlapping one, or blocked by a later one. */
TEST an_allowed_segment_behind_an_overlapping_one_is_not_written(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy0", "10.99.0.1", "255.255.255.128"));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    firc_ip_t low = v4(10, 99, 0, 5), high = v4(10, 99, 0, 200), net = v4(10, 99, 0, 0);
    ASSERT(firc_kn_policy_map_has(m, "Kids", &low));
    ASSERT(firc_kn_policy_map_has(m, "Guests", &high));
    nets_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Guests", false, collect_net, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Kids", false, collect_net, &x));
    ASSERT_EQ_FMT((size_t)1, x.n, "%zu");
    ASSERT(nets_have(&x, &net, 25));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Guests", true, collect_net, &x));
    ASSERT_EQ_FMT((size_t)1, x.n, "%zu");
    ASSERT(nets_have(&x, &net, 24));
    firc_kn_policy_map_free(m);

    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy0", "10.99.0.1", "255.255.255.128"));
    ASSERT(firc_kn_policy_map_has(m, "Guests", &low));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Guests", false, collect_net, &x));
    ASSERT_EQ_FMT((size_t)1, x.n, "%zu");
    ASSERT(nets_have(&x, &net, 24));
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, "Kids", false, collect_net, &x));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: a segment with a non-contiguous mask kept, so the answer and the packet path disagree. */
TEST a_segment_whose_mask_is_not_a_prefix_is_refused(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", POLICIES, &m));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_kn_policy_map_add_segment(m, "Policy9", "10.1.0.1", "255.0.255.0"));
    firc_ip_t c = v4(10, 7, 0, 9);
    ASSERT_FALSE(firc_kn_policy_map_has(m, "Guests", &c));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.1.0.1", "255.255.0.0"));
    firc_ip_t in = v4(10, 1, 7, 9);
    ASSERTm("the positive case: a prefix mask is kept", firc_kn_policy_map_has(m, "Guests", &in));
    firc_kn_policy_map_free(m);
    PASS();
}

typedef struct {
    firc_ip_t net;
    uint8_t prefix;
} covered_t;

typedef struct {
    covered_t c[160];
    size_t n;
} cover_t;

static void cover_addr(const firc_ip_t *a, void *ud) {
    cover_t *x = ud;
    if (x->n < 160) { x->c[x->n++] = (covered_t){*a, (uint8_t)(a->len * 8u)}; }
}
static void cover_net(const firc_ip_t *net, uint8_t prefix, void *ud) {
    cover_t *x = ud;
    if (x->n < 160) { x->c[x->n++] = (covered_t){*net, prefix}; }
}
static bool covers(const cover_t *x, const firc_ip_t *a) {
    for (size_t i = 0; i < x->n; i++) {
        if (firc_devsel_prefix_covers(&x->c[i].net, x->c[i].prefix, a)) { return true; }
    }
    return false;
}

TEST the_packet_path_agrees_with_the_answer_client_by_client(void) {
    static const char TABLE[] =
        "{\"host\":["
        "{\"mac\":\"aa:00:00:00:00:01\",\"ip\":\"192.168.1.50\",\"ip6\":[\"fd00::60\",\"2001:db8::60\"],"
        "\"policy\":\"Policy0\",\"active\":false},"
        "{\"mac\":\"aa:00:00:00:00:02\",\"ip\":\"192.168.1.50\",\"ip6\":[\"fd00::77\"],\"policy\":\"\",\"active\":true},"
        "{\"mac\":\"aa:00:00:00:00:03\",\"ip\":\"10.99.0.3\",\"ip6\":[\"fd00::99\"],\"policy\":\"\",\"active\":true},"
        "{\"mac\":\"aa:00:00:00:00:04\",\"ip\":\"10.99.0.5\",\"policy\":\"Policy0\",\"active\":true}"
        "]}";
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(TABLE, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy0", "10.98.0.1", "255.255.255.0"));
    const firc_ip_t cand[] = {
        v4(192, 168, 1, 50), v6_of(0xfd, 0, 0, 0, 0, 0x60), v6_of(0x20, 0x01, 0x0d, 0xb8, 0, 0x60),
        v6_of(0xfd, 0, 0, 0, 0, 0x77), v4(10, 99, 0, 3), v6_of(0xfd, 0, 0, 0, 0, 0x99), v4(10, 99, 0, 5),
        v4(10, 99, 0, 9), v4(10, 98, 0, 9), v4(192, 168, 1, 51),
    };
    const char *entries[] = {"192.168.1.50", "fd00::60", "fd00::/16", "10.99.0.3", "policy:Kids", "policy:Guests"};
    size_t refused = 0, allowed = 0;
    for (size_t e = 0; e < sizeof(entries) / sizeof(entries[0]); e++) {
        for (int deny = 0; deny <= 1; deny++) {
            cover_t x = {.n = 0};
            firc_devsel_entry_t pe;
            ASSERT_EQ(FIRC_OK, firc_devsel_entry_parse(entries[e], &pe));
            if (pe.kind == FIRC_DEVSEL_ADDR) {
                x.c[x.n++] = (covered_t){pe.addr, pe.prefix};
                ASSERT_EQ(FIRC_OK, firc_kn_policy_map_hosts_in(m, &pe.addr, pe.prefix, deny, cover_addr, &x));
            } else {
                ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_hosts(m, pe.policy, deny, cover_addr, &x));
                ASSERT_EQ(FIRC_OK, firc_kn_policy_map_policy_nets(m, pe.policy, deny, cover_net, &x));
            }
            for (size_t c = 0; c < sizeof(cand) / sizeof(cand[0]); c++) {
                char txt[64];
                inet_ntop(cand[c].len == 4 ? AF_INET : AF_INET6, cand[c].b, txt, sizeof(txt));
                if (deny) {
                    bool out = !answer_allows(m, entries[e], true, &cand[c]);
                    refused += out;
                    if (out && !covers(&x, &cand[c])) { FAILm(txt); }
                } else {
                    bool in = covers(&x, &cand[c]);
                    allowed += in;
                    if (in && !answer_allows(m, entries[e], false, &cand[c])) { FAILm(txt); }
                }
            }
        }
    }
    ASSERT(refused > 0 && allowed > 0);
    firc_kn_policy_map_free(m);
    PASS();
}

/* Catches: the segment lookup reading a map other than the latest, or none. */
TEST the_loop_s_segment_lookup_answers_from_the_latest_map(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    nets_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policies_policy_nets("Guests", true, collect_net, &x, p));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse("{\"host\":[]}", POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0"));
    firc_kn_policies_swap(p, m);
    ASSERT_EQ(FIRC_OK, firc_kn_policies_policy_nets("Guests", true, collect_net, &x, p));
    firc_kn_policies_stop(p);
    firc_ip_t net = v4(10, 99, 0, 0);
    ASSERT_EQ_FMT((size_t)1, x.n, "%zu");
    ASSERT(nets_have(&x, &net, 24));
    PASS();
}

/* Catches: an allow-list segment skipped silently, or logged on every render, for a deny, or when written. */
TEST a_skipped_allow_segment_is_said_once(void) {
    static const char ON_SEG[] =
        "{\"host\":[{\"mac\":\"aa:00:00:00:00:0b\",\"ip\":\"10.99.0.5\",\"policy\":\"Policy0\",\"active\":true}]}";
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_kn_policy_map_t *m = NULL;
    if (firc_kn_policy_map_parse(ON_SEG, POLICIES, &m) != FIRC_OK ||
        firc_kn_policy_map_add_segment(m, "Policy9", "10.99.0.1", "255.255.255.0") != FIRC_OK ||
        firc_kn_policy_map_add_segment(m, "Policy0", "10.98.0.1", "255.255.255.0") != FIRC_OK) {
        firc_kn_policies_stop(p);
        FAIL();
    }
    firc_kn_policies_swap(p, m);
    int fd = log_file();
    if (fd < 0) { firc_kn_policies_stop(p); }
    ASSERT(fd >= 0);
    firc_log_set_fd(fd);
    nets_t x = {.n = 0}, d = {.n = 0}, k = {.n = 0};
    firc_err_t e1 = firc_kn_policies_policy_nets("Guests", false, collect_net, &x, p);
    firc_err_t e2 = firc_kn_policies_policy_nets("Guests", false, collect_net, &x, p);
    firc_err_t e3 = firc_kn_policies_policy_nets("Guests", true, collect_net, &d, p);
    firc_err_t e4 = firc_kn_policies_policy_nets("Kids", false, collect_net, &k, p);
    char *log = log_back(fd);
    firc_kn_policies_stop(p);
    size_t said = log != NULL ? count_of(log, "is not written") : 99;
    size_t said_guests = log != NULL ? count_of(log, "\"Guests\"") : 99;
    free(log);
    ASSERT(e1 == FIRC_OK && e2 == FIRC_OK && e3 == FIRC_OK && e4 == FIRC_OK);
    ASSERT_EQ_FMTm("allow skipped it", (size_t)0, x.n, "%zu");
    ASSERT_EQ_FMTm("deny wrote it", (size_t)1, d.n, "%zu");
    ASSERT_EQ_FMTm("Kids' segment written", (size_t)1, k.n, "%zu");
    ASSERT_EQ_FMTm("said once", (size_t)1, said, "%zu");
    ASSERT_EQ_FMTm("naming the policy", (size_t)1, said_guests, "%zu");
    PASS();
}

static int g_changes;
static bool count_changes(void *ud) {
    (void)ud;
    g_changes++;
    return true;
}

static int g_lost;
static bool lose_changes(void *ud) {
    (void)ud;
    g_changes++;
    if (g_lost > 0) {
        g_lost--;
        return false;
    }
    return true;
}

/* Catches: the first map not announced, an unchanged one announced, or a changed one missed. */
TEST every_changed_map_is_announced(void) {
    g_changes = 0;
    firc_kn_policies_t *p = firc_kn_policies_start_notify(NULL, 0, count_changes, NULL);
    ASSERT(p != NULL);
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m));
    ASSERT(firc_kn_policies_offer(p, m));
    ASSERT_EQm("the first map", 1, g_changes);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_2, POLICIES, &m));
    ASSERT_FALSE(firc_kn_policies_offer(p, m));
    ASSERT_EQm("counters moved, nothing else", 1, g_changes);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_OFF, POLICIES, &m));
    ASSERT(firc_kn_policies_offer(p, m));
    ASSERT_EQm("the TV went offline", 2, g_changes);
    firc_kn_policies_stop(p);
    PASS();
}

/* Catches: a lost announcement forgotten, or repeated after it got through. */
TEST a_lost_announcement_is_made_again_at_the_next_refresh(void) {
    g_changes = 0;
    g_lost = 1;
    firc_kn_policies_t *p = firc_kn_policies_start_notify(NULL, 0, lose_changes, NULL);
    ASSERT(p != NULL);
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m));
    ASSERT(firc_kn_policies_offer(p, m));
    ASSERT_EQm("announced, and lost", 1, g_changes);
    ASSERT_EQm("the loss fired", 0, g_lost);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_2, POLICIES, &m));
    ASSERT_FALSE(firc_kn_policies_offer(p, m));
    ASSERT_EQm("a quiet refresh owes it, and makes it", 2, g_changes);
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(QUIET_1, POLICIES, &m));
    ASSERT_FALSE(firc_kn_policies_offer(p, m));
    ASSERT_EQm("delivered: the next quiet refresh says nothing", 2, g_changes);
    firc_kn_policies_stop(p);
    PASS();
}

typedef struct {
    const char *fail;
    int asked_marks;
    const char *marks;
    const char *policies;
    const char *hotspot;
} rci_fake_t;

static firc_err_t fake_get(void *ud, const char *path, char **body) {
    rci_fake_t *r = ud;
    if (strcmp(path, "/rci/show/ip/policy") == 0) { r->asked_marks++; }
    if (r->fail != NULL && strcmp(path, r->fail) == 0) { return FIRC_ERR_IO; }
    const char *doc = strcmp(path, "/rci/show/ip/hotspot") == 0      ? (r->hotspot != NULL ? r->hotspot : HOTSPOT)
                      : strcmp(path, "/rci/show/rc/ip/policy") == 0  ? (r->policies != NULL ? r->policies : POLICIES)
                      : strcmp(path, "/rci/show/ip/policy") == 0     ? (r->marks != NULL ? r->marks : MARKS)
                      : strcmp(path, "/rci/show/rc/ip/hotspot") == 0 ? "{\"policy\":[]}"
                                                                     : NULL;
    if (doc == NULL) { return FIRC_ERR_NOENT; }
    *body = strdup(doc);
    return *body != NULL ? FIRC_OK : FIRC_ERR_NOMEM;
}

static size_t count_hosts(const firc_kn_policy_map_t *m, const char *policy) {
    addrs_t x = {.n = 0};
    (void)firc_kn_policy_map_policy_hosts(m, policy, false, collect_addr, &x);
    return x.n;
}

/* Catches: a failed or unparseable marks read failing the whole round, or keeping a mark. */
TEST a_refresh_whose_marks_cannot_be_read_keeps_its_hosts(void) {
    rci_fake_t ok = {NULL, 0, NULL, NULL, NULL};
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_fetch_for_test(fake_get, &ok, &m));
    uint32_t mark = 0;
    ASSERTm("the round read the marks", firc_kn_policy_map_mark(m, "Kids", &mark));
    ASSERT_EQ_FMT(0x0ffffaabu, mark, "0x%x");
    firc_kn_policy_map_free(m);

    rci_fake_t bad = {"/rci/show/ip/policy", 0, NULL, NULL, NULL};
    m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_fetch_for_test(fake_get, &bad, &m));
    ASSERT_EQm("the failing read was asked for", 1, bad.asked_marks);
    ASSERT(m != NULL);
    bool has_mark = firc_kn_policy_map_mark(m, "Kids", &mark);
    size_t hosts = count_hosts(m, "Kids");
    firc_kn_policy_map_free(m);
    ASSERT_FALSEm("no marks", has_mark);
    ASSERT_EQ_FMTm("the hosts stay", (size_t)2, hosts, "%zu");

    rci_fake_t garbled = {NULL, 0, "not json", NULL, NULL};
    m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_fetch_for_test(fake_get, &garbled, &m));
    ASSERT(m != NULL);
    has_mark = firc_kn_policy_map_mark(m, "Kids", &mark);
    hosts = count_hosts(m, "Kids");
    firc_kn_policy_map_free(m);
    ASSERT_FALSEm("no marks from a garbled document", has_mark);
    ASSERT_EQ_FMTm("the hosts stay", (size_t)2, hosts, "%zu");

    rci_fake_t no_table = {"/rci/show/ip/hotspot", 0, NULL, NULL, NULL};
    m = NULL;
    ASSERT_EQ(FIRC_ERR_IO, firc_kn_policy_map_fetch_for_test(fake_get, &no_table, &m));
    ASSERT_EQm("the rest is all or nothing", NULL, m);
    PASS();
}

/* Catches: a missing marks document warned every round or once per daemon, or its marks dropped. */
TEST a_missing_mark_document_is_said_once_per_streak_and_its_marks_carried(void) {
    g_changes = 0;
    firc_kn_policies_t *p = firc_kn_policies_start_notify(NULL, 0, count_changes, NULL);
    ASSERT(p != NULL);
    rci_fake_t ok = {NULL, 0, NULL, NULL, NULL}, bad = {"/rci/show/ip/policy", 0, NULL, NULL, NULL};
    int fd = log_file();
    if (fd < 0) { firc_kn_policies_stop(p); }
    ASSERT(fd >= 0);
    firc_log_set_fd(fd);
    int seen[5];
    uint32_t mark_live[5] = {0};
    rci_fake_t *round[5] = {&ok, &bad, &bad, &ok, &bad};
    firc_err_t err = FIRC_OK;
    for (size_t i = 0; i < 5 && err == FIRC_OK; i++) {
        err = firc_kn_policies_round_for_test(p, fake_get, round[i]);
        seen[i] = g_changes;
        (void)firc_kn_policy_map_mark(firc_kn_policies_live_for_test(p), "Kids", &mark_live[i]);
    }
    char *log = log_back(fd);
    firc_kn_policies_stop(p);
    size_t warned = log != NULL ? count_of(log, "policy marks could not be read") : 99;
    size_t back = log != NULL ? count_of(log, "policy marks can be read again") : 99;
    free(log);
    ASSERT_EQ(FIRC_OK, err);
    ASSERT_EQm("the failing read was asked for", 3, bad.asked_marks);
    ASSERT_EQ_FMTm("said once per streak", (size_t)2, warned, "%zu");
    ASSERT_EQ_FMTm("and its return once", (size_t)1, back, "%zu");
    for (size_t i = 0; i < 5; i++) {
        ASSERT_EQ_FMT(1, seen[i], "%d");
        ASSERT_EQ_FMT(0x0ffffaabu, mark_live[i], "0x%x");
    }
    PASS();
}

/* Catches: carried marks not checked for a clash, so it is said twice. */
TEST a_clash_carried_across_a_failed_marks_read_is_said_once(void) {
    static const char CLASH[] = "{\"Policy0\":{\"mark\":\"ffffaab\"},\"Policy1\":{\"mark\":\"f01faab\"}}";
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    rci_fake_t first = {NULL, 0, CLASH, NULL, NULL};
    rci_fake_t moved = {"/rci/show/ip/policy", 0, NULL, NULL, QUIET_1};
    rci_fake_t back = {NULL, 0, CLASH, NULL, QUIET_OFF};
    int fd = log_file();
    if (fd < 0) { firc_kn_policies_stop(p); }
    ASSERT(fd >= 0);
    firc_log_set_fd(fd);
    firc_err_t e1 = firc_kn_policies_round_for_test(p, fake_get, &first);
    firc_err_t e2 = firc_kn_policies_round_for_test(p, fake_get, &moved);
    firc_err_t e3 = firc_kn_policies_round_for_test(p, fake_get, &back);
    char *log = log_back(fd);
    firc_kn_policies_stop(p);
    size_t said = log != NULL ? count_of(log, "cannot tell them apart") : 99;
    free(log);
    ASSERT(e1 == FIRC_OK && e2 == FIRC_OK && e3 == FIRC_OK);
    ASSERTm("the failing read was asked for", moved.asked_marks == 1);
    ASSERT_EQ_FMTm("said once", (size_t)1, said, "%zu");
    PASS();
}

/* Whether deny [policy:Kids] over the live map renders its mark RETURN (0x0f00faab). */
static bool deny_kids_has_mark(firc_kn_policies_t *p) {
    firc_group_t *g = firc_group_new();
    char kids[] = "policy:Kids";
    char *deny[] = {kids};
    firc_devsel_spec_t spec = {.deny = deny, .n_deny = 1};
    if (g == NULL || firc_devsel_spec_copy(&g->devices, &spec) != FIRC_OK) { abort(); }
    firc_ruleset_lookup_t lk = {firc_kn_policies_mark, firc_kn_policies_hosts_in, firc_kn_policies_policy_hosts,
                                firc_kn_policies_policy_nets, p, firc_kn_policies_read};
    firc_nf_devices_t d;
    bool has = false;
    if (firc_ruleset_render_devices(g, &lk, &d) == FIRC_OK) {
        for (size_t i = 0; i < d.n_deny; i++) {
            has = has || (d.deny[i].kind == FIRC_NF_SRC_MARK &&
                          (d.deny[i].mark & FIRC_MARK_POLICY_MASK) == 0x0f00faabu);
        }
    }
    firc_nf_devices_clear(&d);
    firc_group_free(g);
    return has;
}

/* Catches: a failed marks read dropping a deny's mark, or a carried mark outliving its policy. */
TEST a_deny_policy_keeps_its_mark_across_a_failed_marks_read(void) {
    static const char WITHOUT_KIDS[] = "{\"Policy1\":{\"description\":\"Work VPN\"}}";
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    rci_fake_t ok = {NULL, 0, NULL, NULL, NULL}, bad = {"/rci/show/ip/policy", 0, NULL, NULL, NULL};
    rci_fake_t gone = {"/rci/show/ip/policy", 0, NULL, WITHOUT_KIDS, NULL};
    firc_log_level_t saved = firc_log_level();
    firc_log_set_level(FIRC_LOG_ERROR);
    firc_err_t e1 = firc_kn_policies_round_for_test(p, fake_get, &ok);
    bool read = deny_kids_has_mark(p);
    firc_err_t e2 = firc_kn_policies_round_for_test(p, fake_get, &bad);
    bool carried = deny_kids_has_mark(p);
    firc_err_t e3 = firc_kn_policies_round_for_test(p, fake_get, &gone);
    bool after_gone = deny_kids_has_mark(p);
    uint32_t mark = 0;
    bool by_name = firc_kn_policy_map_mark(firc_kn_policies_live_for_test(p), "Policy0", &mark);
    firc_log_set_level(saved);
    firc_kn_policies_stop(p);
    ASSERT(e1 == FIRC_OK && e2 == FIRC_OK && e3 == FIRC_OK);
    ASSERTm("the failing reads were asked for", bad.asked_marks == 1 && gone.asked_marks == 1);
    ASSERTm("read: the RETURN", read);
    ASSERTm("carried across the failed read", carried);
    ASSERT_FALSEm("not for a policy gone from the list", after_gone);
    ASSERT_FALSEm("nor by its internal name", by_name);
    PASS();
}

/* Catches: the loop's lookups reading a stale map, answering before the first, or warning every call. */
TEST the_loop_s_lookups_answer_from_the_latest_map(void) {
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    uint32_t mark = 0;
    ASSERT_FALSEm("no map yet", firc_kn_policies_mark("Kids", &mark, p));
    firc_ip_t h104 = v4(192, 168, 0, 104);
    addrs_t x = {.n = 0};
    ASSERT_EQ(FIRC_OK, firc_kn_policies_hosts_in(&h104, 32, false, collect_addr, &x, p));
    ASSERT_EQ(FIRC_OK, firc_kn_policies_policy_hosts("Kids", false, collect_addr, &x, p));
    ASSERT_EQ_FMT((size_t)0, x.n, "%zu");

    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, MARKS));
    firc_kn_policies_swap(p, m);
    ASSERT(firc_kn_policies_mark("Kids", &mark, p));
    ASSERT_EQ_FMT(0x0ffffaabu, mark, "0x%x");
    ASSERT_EQ(FIRC_OK, firc_kn_policies_hosts_in(&h104, 32, false, collect_addr, &x, p));
    ASSERT_EQ_FMT((size_t)3, x.n, "%zu");
    x.n = 0;
    ASSERT_EQ(FIRC_OK, firc_kn_policies_policy_hosts("Kids", false, collect_addr, &x, p));
    ASSERT_EQ_FMTm("the hosts at .124 and .77", (size_t)2, x.n, "%zu");

    int fd = log_file();
    if (fd < 0) { firc_kn_policies_stop(p); }
    ASSERT(fd >= 0);
    firc_log_set_fd(fd);
    bool once = firc_kn_policies_mark("Guests", &mark, p);
    bool twice = firc_kn_policies_mark("Guests", &mark, p);
    char *log = log_back(fd);
    firc_kn_policies_stop(p);
    size_t said = log != NULL ? count_of(log, "has no firmware mark") : 99;
    free(log);
    ASSERT_FALSE(once);
    ASSERT_FALSE(twice);
    ASSERT_EQ_FMTm("said once", (size_t)1, said, "%zu");
    PASS();
}

/* Catches: an unknown policy name taken for one without a mark, warned every call, or an empty name looked up. */
TEST a_mark_for_a_name_the_router_lacks_is_said_as_unknown(void) {
    firc_kn_policy_map_t *m = NULL;
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_parse(HOTSPOT, POLICIES, &m));
    ASSERT_EQ(FIRC_OK, firc_kn_policy_map_add_marks(m, MARKS));
    int fd = log_file();
    ASSERT(fd >= 0);
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    ASSERT(p != NULL);
    firc_kn_policies_swap(p, m);
    uint32_t mark = 0x1234u;
    firc_log_set_fd(fd);
    bool once = firc_kn_policies_mark("Nope", &mark, p);
    bool twice = firc_kn_policies_mark("Nope", &mark, p);
    bool empty = firc_kn_policies_mark("", &mark, p);
    bool null = firc_kn_policies_mark(NULL, &mark, p);
    char *log = log_back(fd);
    firc_kn_policies_stop(p);
    size_t unknown = log != NULL ? count_of(log, "no policy called \"Nope\"") : 99;
    size_t no_mark = log != NULL ? count_of(log, "has no firmware mark") : 99;
    size_t lines = log != NULL ? count_of(log, "\n") : 99;
    free(log);
    ASSERT_FALSE(once || twice || empty || null);
    ASSERT_EQ_FMTm("*mark untouched", 0x1234u, mark, "0x%x");
    ASSERT_EQ_FMTm("said once, as unknown", (size_t)1, unknown, "%zu");
    ASSERT_EQ_FMTm("not as a missing mark", (size_t)0, no_mark, "%zu");
    ASSERT_EQ_FMTm("and nothing for the empty name", (size_t)1, lines, "%zu");
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(a_host_in_a_policy_is_found_by_internal_name_and_by_description);
    RUN_TEST(only_entries_that_name_a_policy_are_segments);
    RUN_TEST(a_segment_puts_every_client_on_its_interface_in_its_policy);
    RUN_TEST(hosts_outside_the_policy_are_not_in_it);
    RUN_TEST(a_hosts_v6_addresses_count_too);
    RUN_TEST(without_the_policy_list_only_internal_names_match);
    RUN_TEST(unexpected_shapes_are_refused);
    RUN_TEST(the_map_knows_every_address_of_a_host);
    RUN_TEST(the_map_knows_which_policy_names_exist);
    RUN_TEST(every_policy_the_router_has_can_be_listed);
    RUN_TEST(the_active_host_is_the_device_at_a_shared_address);
    RUN_TEST(the_first_read_can_be_waited_for);
    RUN_TEST(an_empty_policy_list_is_no_policies_not_a_failure);
    RUN_TEST(the_wait_is_woken_by_a_swap_and_by_a_stop);
    RUN_TEST(a_stop_does_not_free_the_object_under_a_waiter);
    RUN_TEST(a_stop_wakes_the_waiter_and_the_refresher_alike);
    RUN_TEST(the_policies_count_as_read_from_the_first_map_on);
    RUN_TEST(the_resolver_answers_from_the_latest_map);
    RUN_TEST(each_host_is_recorded_with_its_mac_and_names);
    RUN_TEST(a_listed_host_reports_its_effective_policy);
    RUN_TEST(a_host_is_in_its_segments_policy_from_its_v6_address);
    RUN_TEST(a_client_is_known_by_the_mac_of_its_host);
    RUN_TEST(a_policy_counts_its_devices_not_their_addresses);
    RUN_TEST(a_mac_entry_follows_its_host_to_a_new_lease);
    RUN_TEST(the_live_host_list_is_empty_until_the_first_read);
    RUN_TEST(the_index_answers_what_the_linear_rule_did);
    RUN_TEST(the_live_resolver_keeps_every_policy_rule);
    RUN_TEST(a_map_is_never_freed_under_a_check);
    RUN_TEST(two_maps_of_one_table_answer_alike_whatever_their_seeds);
    RUN_TEST(a_slash_24_spreads_over_the_index);
    RUN_TEST(v6_addresses_differing_in_top_bytes_spread_over_the_index);
    RUN_TEST(a_replaced_map_is_freed_by_the_refresher_not_the_loop);
    RUN_TEST(a_refresh_that_changes_nothing_hands_nothing_over);
    RUN_TEST(a_policys_mark_comes_from_the_ip_policy_document);
    RUN_TEST(a_mark_that_is_not_one_to_eight_hex_digits_is_no_mark);
    RUN_TEST(a_changed_mark_is_a_change);
    RUN_TEST(two_policies_whose_marks_agree_outside_firc_s_bits_are_said_once);
    RUN_TEST(a_clash_that_returns_is_said_again);
    RUN_TEST(hosts_inside_a_prefix_bring_every_address_they_have);
    RUN_TEST(the_host_at_a_shared_address_is_the_active_one_here_too);
    RUN_TEST(a_prefix_does_not_bring_an_address_another_host_holds_now);
    RUN_TEST(a_host_brings_at_most_sixty_four_addresses);
    RUN_TEST(every_changed_map_is_announced);
    RUN_TEST(a_lost_announcement_is_made_again_at_the_next_refresh);
    RUN_TEST(a_refresh_whose_marks_cannot_be_read_keeps_its_hosts);
    RUN_TEST(a_missing_mark_document_is_said_once_per_streak_and_its_marks_carried);
    RUN_TEST(a_deny_policy_keeps_its_mark_across_a_failed_marks_read);
    RUN_TEST(a_clash_carried_across_a_failed_marks_read_is_said_once);
    RUN_TEST(the_loop_s_lookups_answer_from_the_latest_map);
    RUN_TEST(a_mark_for_a_name_the_router_lacks_is_said_as_unknown);
    RUN_TEST(a_policy_lists_every_address_of_its_hosts);
    RUN_TEST(a_policy_does_not_list_an_address_another_host_holds_now);
    RUN_TEST(a_denied_address_brings_every_host_that_lists_it);
    RUN_TEST(a_deny_does_not_bring_an_address_another_host_holds_now);
    RUN_TEST(a_deny_brings_every_address_of_its_hosts);
    RUN_TEST(an_allow_past_the_answer_s_window_brings_no_host);
    RUN_TEST(a_denied_policy_writes_what_the_answer_refuses_and_no_more);
    RUN_TEST(a_policy_s_segment_is_its_network);
    RUN_TEST(an_allowed_segment_that_holds_another_policy_s_host_is_not_written);
    RUN_TEST(an_allowed_segment_behind_an_overlapping_one_is_not_written);
    RUN_TEST(a_segment_whose_mask_is_not_a_prefix_is_refused);
    RUN_TEST(the_packet_path_agrees_with_the_answer_client_by_client);
    RUN_TEST(the_loop_s_segment_lookup_answers_from_the_latest_map);
    RUN_TEST(a_skipped_allow_segment_is_said_once);
    GREATEST_MAIN_END();
}
