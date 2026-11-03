/* Catches: the IPv6 address leaving its kernel /128 route in main, which ndm cannot resolve and logs. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "../src/tunnel/ifcfg.h"

#define DEV "xs-addr6"
#define OTHER "xs-addr6b"

static int fails;

static void check(const char *what, int want, int got) {
    printf("%-62s %s\n", what, want == got ? "ok" : "FAIL");
    if (want != got) {
        printf("   expected %d, got %d\n", want, got);
        fails++;
    }
}

static int has_addr(const char *hex, const char *dev) {
    FILE *f = fopen("/proc/net/if_inet6", "r");
    if (f == NULL) return -1;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof line, f) != NULL) {
        if (strncmp(line, hex, 32) == 0 && strstr(line, dev) != NULL) found = 1;
    }
    fclose(f);
    return found;
}

static int has_route(const char *hex, const char *dev) {
    FILE *f = fopen("/proc/net/ipv6_route", "r");
    if (f == NULL) return -1;
    char dst[33], name[IFNAMSIZ];
    unsigned plen, flags;
    int found = 0;
    while (fscanf(f, "%32s %x %*s %*s %*s %*s %*s %*s %x %15s", dst, &plen, &flags, name) == 4) {
        if (strcmp(dst, hex) == 0 && plen == 128 && !(flags & 0x80000000u) && strcmp(name, dev) == 0) found = 1;
    }
    fclose(f);
    return found;
}

int main(void) {
    int fd = open("/dev/net/tun", O_RDWR);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", DEV);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (fd < 0 || ioctl(fd, TUNSETIFF, &ifr) != 0) {
        printf("SKIPPED: TUNSETIFF unavailable (no /dev/net/tun or CAP_NET_ADMIN)\n");
        return 0;
    }
    struct in_addr v4;
    inet_pton(AF_INET, "198.51.100.9", &v4);
    if (ifcfg_bring_up(DEV, v4.s_addr, 32) != 0) {
        printf("FAILED: %s not brought up\n", DEV);
        return 1;
    }
    unsigned char a6[16];
    ifcfg_addr6_of(v4.s_addr, a6);
    char want[33];
    snprintf(want, sizeof want, "20010db80000000000000000c6336409");
    if (system("ip link add " OTHER " type dummy && ip link set " OTHER " up && "
               "ip -6 route add 2001:db8::c633:6409/128 dev " OTHER " metric 1") != 0) {
        printf("FAILED: no route on %s to compare with\n", OTHER);
        return 1;
    }
    int rc = ifcfg_addr6_set((int)if_nametoindex(DEV), a6, 1);
    check("v6: the address is added", 0, rc);
    check("v6: the device holds it", 1, has_addr(want, DEV));
    check("v6: no kernel route to it in main (ndm cannot resolve the device)", 0, has_route(want, DEV));
    check("v6: the same route on another device is left alone", 1, has_route(want, OTHER));
    (void)!system("ip link del " OTHER);
    close(fd);
    if (fails) {
        printf("FAILED: %d\n", fails);
        return 1;
    }
    printf("all checks passed\n");
    return 0;
}
