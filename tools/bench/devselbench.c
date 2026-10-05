#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "firc/devices.h"
#include "firc/keenetic_policy.h"

static double now(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

static uint32_t rng = 2463534242u;
static uint32_t xorshift(void) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng;
}

static int lan24; /* the layout: 0 spread, 1 lan24 */

static char *hotspot_json(size_t n) {
    size_t cap = 256 + n * 256, len = 0;
    char *s = malloc(cap);
    if (s == NULL) { return NULL; }
    len += (size_t)snprintf(s + len, cap - len, "{\"host\":[");
    for (size_t i = 0; i < n; i++) {
        char policy[32] = "", addrs[96];
        if (i % 5 != 0) { snprintf(policy, sizeof(policy), "Policy%zu", i % 4); }
        if (lan24) {
            snprintf(addrs, sizeof(addrs), "\"ip\":\"192.168.%zu.%zu\",\"ip6\":[]", i / 254, i % 254 + 1);
        } else {
            snprintf(addrs, sizeof(addrs), "\"ip\":\"10.%zu.0.%zu\",\"ip6\":[\"fd00::%zx:1\",\"fe80::%zx:2\"]",
                     i / 250, i % 250 + 1, i, i);
        }
        len += (size_t)snprintf(s + len, cap - len,
                                "%s{\"mac\":\"02:00:00:00:%02zx:%02zx\",\"name\":\"h%zu\",%s,\"policy\":\"%s\","
                                "\"active\":true,\"registered\":true}",
                                i ? "," : "", (i >> 8) & 0xff, i & 0xff, i, addrs, policy);
    }
    snprintf(s + len, cap - len, "]}");
    return s;
}

static const char POLICIES[] = "{\"Policy0\":{\"description\":\"Kids\"},\"Policy1\":{\"description\":\"TV\"},"
                               "\"Policy2\":{},\"Policy3\":{\"description\":\"Guests\"}}";

int main(int argc, char **argv) {
    size_t n = argc > 1 ? strtoul(argv[1], NULL, 10) : 200;
    size_t iters = argc > 2 ? strtoul(argv[2], NULL, 10) : 2000000;
    lan24 = argc > 3 && strcmp(argv[3], "lan24") == 0;
    if (n == 0 || n > 60000 || (argc > 3 && !lan24 && strcmp(argv[3], "spread") != 0)) { return 2; }

    char *json = hotspot_json(n);
    firc_kn_policy_map_t *m = NULL;
    if (json == NULL || firc_kn_policy_map_parse(json, POLICIES, &m) != FIRC_OK) {
        fprintf(stderr, "parse failed\n");
        return 1;
    }
    free(json);
    firc_kn_policies_t *p = firc_kn_policies_start(NULL, 0);
    if (p == NULL) { return 1; }
    firc_kn_policies_swap(p, m);

    char mac[32];
    snprintf(mac, sizeof(mac), "mac:02:00:00:00:%02zx:%02zx", ((n / 2) >> 8) & 0xff, (n / 2) & 0xff);
    const char *allow[] = {mac, "policy:TV"};
    firc_devsel_t *sel = NULL;
    if (firc_devsel_compile(allow, 2, NULL, 0, &sel) != FIRC_OK) { return 1; }

    /* Random order drawn before the clock starts. */
    size_t per = lan24 ? 1 : 3, n_addrs = n * per;
    firc_ip_t *addrs = malloc(n_addrs * sizeof(*addrs));
    enum { ORDER = 1 << 16 };
    uint32_t *order = malloc(ORDER * sizeof(*order));
    if (addrs == NULL || order == NULL) { return 1; }
    for (size_t i = 0; i < n; i++) {
        firc_ip_t *a = &addrs[i * per];
        memset(a, 0, per * sizeof(*a));
        a[0].len = 4;
        if (lan24) {
            a[0].b[0] = 192;
            a[0].b[1] = 168;
            a[0].b[2] = (uint8_t)(i / 254);
            a[0].b[3] = (uint8_t)(i % 254 + 1);
            continue;
        }
        a[0].b[0] = 10;
        a[0].b[1] = (uint8_t)(i / 250);
        a[0].b[3] = (uint8_t)(i % 250 + 1);
        a[1].len = 16;
        a[1].b[0] = 0xfd;
        a[1].b[12] = (uint8_t)(i >> 8);
        a[1].b[13] = (uint8_t)i;
        a[1].b[15] = 1;
        a[2].len = 16;
        a[2].b[0] = 0xfe;
        a[2].b[1] = 0x80;
        a[2].b[12] = (uint8_t)(i >> 8);
        a[2].b[13] = (uint8_t)i;
        a[2].b[15] = 2;
    }
    for (size_t i = 0; i < ORDER; i++) { order[i] = xorshift() % (uint32_t)n_addrs; }

    /* Warm-up; `admitted` is a count the compiler cannot drop and a reader can check. */
    size_t admitted = 0;
    for (size_t i = 0; i < n_addrs; i++) {
        admitted += firc_devsel_allows(sel, &addrs[i], firc_kn_policies_resolve, firc_kn_policies_device, p);
    }
    double t0 = now();
    size_t hits = 0;
    for (size_t i = 0; i < iters; i++) {
        hits += firc_devsel_allows(sel, &addrs[order[i & (ORDER - 1)]], firc_kn_policies_resolve,
                                   firc_kn_policies_device, p);
    }
    double t1 = now();

    const char *layout = lan24 ? "lan24" : "spread";
    printf("%-6s n=%-6zu addrs=%-6zu  %7.1f ns/check  (%zu checks, %zu of %zu addresses admitted, %zu hits)\n",
           layout, n, n_addrs, (t1 - t0) * 1e9 / (double)iters, iters, admitted, n_addrs, hits);

    enum { SWAPS = 32 };
    firc_kn_policy_map_t *fresh[SWAPS];
    for (size_t k = 0; k < SWAPS; k++) {
        json = hotspot_json(n);
        if (json == NULL || firc_kn_policy_map_parse(json, POLICIES, &fresh[k]) != FIRC_OK) { return 1; }
        free(json);
    }
    double swap_s = 0, check_s = 0;
    for (size_t k = 0; k < SWAPS; k++) {
        double a = now();
        firc_kn_policies_swap(p, fresh[k]);
        double b = now();
        hits += firc_devsel_allows(sel, &addrs[order[k]], firc_kn_policies_resolve, firc_kn_policies_device, p);
        double c = now();
        swap_s += b - a;
        check_s += c - b;
    }
    printf("%-6s n=%-6zu after a changed refresh: swap %8.1f ns, next check %8.1f ns, together %8.1f ns (mean of %d)\n",
           layout, n, swap_s * 1e9 / SWAPS, check_s * 1e9 / SWAPS, (swap_s + check_s) * 1e9 / SWAPS, SWAPS);
    firc_devsel_free(sel);
    firc_kn_policies_stop(p);
    free(addrs);
    free(order);
    return 0;
}
