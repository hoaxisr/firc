#include "greatest.h"
#include "firc/log.h"
#include "firc/tunnels.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char ONE[] =
    "tunnels:\n"
    "  - id: 3f9a1c2b\n"
    "    device: tunvless0\n"
    "    enable: true\n"
    "    uplink: iface:ppp0\n"
    "    sources:\n"
    "      - link: \"vless://u@h:443?security=none#my-vps\"\n"
    "    active: 2\n"
    "    by: site\n"
    "    interval: 60s\n"
    "    silence: 20s\n"
    "    advanced: { timeout: 8s, insecure: false, ca: \"\" }\n";

#define LINK "      - link: \"vless://u@h:443#a\"\n"

static void tun_text(char *out, size_t cap, const char *id, const char *device, const char *uplink,
                     const char *active, const char *by, const char *sources)
{
    snprintf(out, cap,
             "  - id: %s\n    device: %s\n    uplink: %s\n    active: %s\n    by: %s\n"
             "    sources:\n%s",
             id, device, uplink, active, by, sources);
}

static int refused(const char *doc, const char *where, const char *why)
{
    firc_tunnels_t t = {0};
    firc_tun_err_t e = {0};
    firc_err_t r = firc_tunnels_load_buffer(&t, doc, strlen(doc), &e);
    int ok = r != FIRC_OK && strcmp(e.where, where) == 0 && strstr(e.why, why) != NULL;
    if (!ok) {
        fprintf(stderr, "got r=%d where=\"%s\" why=\"%s\"\n", (int)r, e.where, e.why);
    }
    firc_tunnels_free(&t);
    return ok;
}

static int refused_one(const char *id, const char *device, const char *uplink, const char *active,
                       const char *by, const char *sources, const char *where, const char *why)
{
    char doc[2048] = "tunnels:\n";
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), id, device, uplink, active, by, sources);
    return refused(doc, where, why);
}

static int with_extra(const char *extra, const char *where, const char *why)
{
    char doc[2048];
    snprintf(doc, sizeof doc, "tunnels:\n  - id: a1\n    device: tunvless0\n    sources:\n" LINK "%s", extra);
    return refused(doc, where, why);
}

static int loads_extra(const char *extra)
{
    char doc[2048];
    snprintf(doc, sizeof doc, "tunnels:\n  - id: a1\n    device: tunvless0\n    sources:\n" LINK "%s", extra);
    firc_tunnels_t t = {0};
    firc_tun_err_t e = {0};
    int ok = firc_tunnels_load_buffer(&t, doc, strlen(doc), &e) == FIRC_OK;
    firc_tunnels_free(&t);
    return ok;
}

static const char SAME_LINK[] =
    "tunnels:\n  - id: x1\n    device: tunvless0\n    active: 1\n    enable: true\n    sources:\n      - link: \"vless://u@h:443#a\"\n";
static const char SAME_SUB[] =
    "tunnels:\n  - id: x1\n    device: tunvless0\n    active: 1\n    sources:\n"
    "      - subscription: { name: P, url: \"http://s.example/x\", interval: 1h }\n";

static int same_after_in(const char *base, const char *from, const char *to)
{
    char a[2048], b[2048];
    snprintf(a, sizeof a, "%s", base);
    snprintf(b, sizeof b, "%s", a);
    char *p = strstr(b, from);
    if (p == NULL) {
        return -1;
    }
    char out[2048];
    size_t pre = (size_t)(p - b);
    snprintf(out, sizeof out, "%.*s%s%s", (int)pre, b, to, p + strlen(from));
    firc_tunnels_t ta = {0}, tb = {0};
    firc_tun_err_t e = {0};
    if (firc_tunnels_load_buffer(&ta, a, strlen(a), &e) != FIRC_OK ||
        firc_tunnels_load_buffer(&tb, out, strlen(out), &e) != FIRC_OK) {
        return -1;
    }
    int r = (firc_tunnel_same_argv(&ta.t[0], &tb.t[0]) ? 1 : 0) + (firc_tunnel_same_nodes(&ta.t[0], &tb.t[0]) ? 2 : 0);
    firc_tunnels_free(&ta);
    firc_tunnels_free(&tb);
    return r;
}

static int same_after(const char *from, const char *to)
{
    return same_after_in(SAME_LINK, from, to);
}

/* catches: a field read into the wrong member or a duration unit ignored */
TEST loads_every_field(void) {
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&t, ONE, sizeof ONE - 1, &e));
    ASSERT_EQ(1u, t.n);
    ASSERT_STR_EQ("tunvless0", t.t[0].device);
    ASSERT_EQ(FIRC_UPLINK_IFACE, t.t[0].uplink);
    ASSERT_STR_EQ("ppp0", t.t[0].uplink_ref);
    ASSERT_EQ(1u, t.t[0].n_src);
    ASSERT_EQ(FIRC_TUN_SRC_LINK, t.t[0].src[0].kind);
    ASSERT_STR_EQ("vless://u@h:443?security=none#my-vps", t.t[0].src[0].link);
    ASSERT_EQ(2, t.t[0].active);
    ASSERT_STR_EQ("site", t.t[0].by);
    ASSERT_EQ(60, t.t[0].interval_s);
    ASSERT_EQ(20, t.t[0].silence_s);
    ASSERT_EQ(8, t.t[0].timeout_s);
    firc_tunnels_free(&t);
    PASS();
}

/* catches: save dropping or reordering a field so a restart sees a different tunnel */
TEST save_then_load_is_the_same_tunnel(void) {
    firc_tunnels_t a = {0}, b = {0}; firc_tun_err_t e = {0};
    char path[] = "/tmp/tconfig-XXXXXX";
    int fd = mkstemp(path); close(fd);
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&a, ONE, sizeof ONE - 1, &e));
    ASSERT_EQ(FIRC_OK, firc_tunnels_save_file(&a, path));
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_file(&b, path, &e));
    ASSERT(firc_tunnel_same_argv(&a.t[0], &b.t[0]) && firc_tunnel_same_nodes(&a.t[0], &b.t[0]));
    unlink(path); firc_tunnels_free(&a); firc_tunnels_free(&b);
    PASS();
}

static int warnings_loading(const char *path, mode_t mode, char *log, size_t cap) {
    chmod(path, mode);
    char logpath[] = "/tmp/tconfig-log-XXXXXX";
    int fd = mkstemp(logpath);
    firc_log_set_fd(fd);
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    firc_err_t r = firc_tunnels_load_file(&t, path, &e);
    firc_log_set_fd(STDOUT_FILENO);
    firc_tunnels_free(&t);
    ssize_t n = pread(fd, log, cap - 1, 0);
    log[n > 0 ? n : 0] = 0;
    close(fd);
    unlink(logpath);
    if (r != FIRC_OK) { return -1; }
    int c = 0;
    for (const char *p = strstr(log, "chmod 600"); p != NULL; p = strstr(p + 1, "chmod 600")) { c++; }
    return c;
}

/* catches: a tunnels.yaml others can read loaded silently, or a private one warned about or refused */
TEST a_file_others_can_read_is_warned_about_once(void) {
    firc_tunnels_t a = {0}; firc_tun_err_t e = {0};
    char path[] = "/tmp/tconfig-XXXXXX";
    int fd = mkstemp(path); close(fd);
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&a, ONE, sizeof ONE - 1, &e));
    ASSERT_EQ(FIRC_OK, firc_tunnels_save_file(&a, path));
    firc_tunnels_free(&a);
    char log[1024];
    ASSERT_EQ(1, warnings_loading(path, 0644, log, sizeof log));
    ASSERT(strstr(log, path) != NULL);
    ASSERT(strstr(log, "644") != NULL);
    ASSERT_EQ(1, warnings_loading(path, 0640, log, sizeof log));
    ASSERT_EQ(0, warnings_loading(path, 0600, log, sizeof log));
    ASSERT_STR_EQ("", log);
    unlink(path);
    PASS();
}

/* catches: a missing file treated as an error and fircd refusing to start */
TEST a_missing_file_is_no_tunnels(void) {
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_file(&t, "/nonexistent/tunnels.yaml", &e));
    ASSERT_EQ(0u, t.n);
    PASS();
}

/* catches: links readable by every user on the router */
TEST the_saved_file_is_mode_0600(void) {
    firc_tunnels_t a = {0}; firc_tun_err_t e = {0};
    char path[] = "/tmp/tconfig-XXXXXX";
    int fd = mkstemp(path); fchmod(fd, 0644); close(fd);
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&a, ONE, sizeof ONE - 1, &e));
    ASSERT_EQ(FIRC_OK, firc_tunnels_save_file(&a, path));
    struct stat st;
    ASSERT_EQ(0, stat(path, &st));
    ASSERT_EQ(0600, st.st_mode & 0777);
    unlink(path); firc_tunnels_free(&a);
    PASS();
}

/* catches: a link with characters YAML would reinterpret coming back altered */
TEST a_link_with_yaml_syntax_survives_save_and_load(void) {
    static const char doc[] =
        "tunnels:\n"
        "  - id: q1\n"
        "    device: tunvless1\n"
        "    sources:\n"
        "      - link: \"vless://u@h:443?a=b&c=d#n:\\\"x\\\"#y\"\n";
    firc_tunnels_t a = {0}, b = {0}; firc_tun_err_t e = {0};
    char path[] = "/tmp/tconfig-XXXXXX";
    int fd = mkstemp(path); close(fd);
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&a, doc, sizeof doc - 1, &e));
    ASSERT_EQ(FIRC_OK, firc_tunnels_save_file(&a, path));
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_file(&b, path, &e));
    ASSERT_STR_EQ("vless://u@h:443?a=b&c=d#n:\"x\"#y", b.t[0].src[0].link);
    unlink(path); firc_tunnels_free(&a); firc_tunnels_free(&b);
    PASS();
}

/* catches: a second tunnel on the same device accepted */
TEST a_device_used_twice_is_refused(void) {
    char doc[2048] = "tunnels:\n";
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "a1", "tunvless0", "auto", "1", "site", LINK);
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "b1", "tunvless0", "auto", "1", "site", LINK);
    ASSERT(refused(doc, "tunnels[1].device", "used twice"));
    PASS();
}

/* catches: a tunnel device that could collide with a Keenetic interface */
TEST a_device_outside_tunvless_is_refused(void) {
    ASSERT(refused_one("a1", "br0", "auto", "1", "site", LINK, "tunnels[0].device", "must start with tunvless"));
    PASS();
}

/* catches: a tunnel device with a suffix that is not a number below 100 */
TEST a_tunvless_suffix_that_is_not_a_small_number_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless100", "auto", "1", "site", LINK, "tunnels[0].device", "N 0..99"));
    ASSERT(refused_one("a1", "tunvlessx", "auto", "1", "site", LINK, "tunnels[0].device", "N 0..99"));
    PASS();
}

/* catches: a tunnel routed through itself */
TEST an_uplink_through_itself_is_refused(void) {
    ASSERT(refused_one("3f9a1c2b", "tunvless0", "tunnel:3f9a1c2b", "1", "site", LINK, "tunnels[0].uplink", "itself"));
    PASS();
}

/* catches: two tunnels chained into each other, an uplink that never ends */
TEST an_uplink_cycle_is_refused(void) {
    char doc[2048] = "tunnels:\n";
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "aa", "tunvless0", "tunnel:bb", "1", "site", LINK);
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "bb", "tunvless1", "tunnel:aa", "1", "site", LINK);
    ASSERT(refused(doc, "tunnels[1].uplink", "cycle"));
    PASS();
}

/* catches: an uplink naming a tunnel that does not exist */
TEST an_uplink_to_an_unknown_tunnel_is_refused(void) {
    ASSERT(refused_one("aa", "tunvless0", "tunnel:zz", "1", "site", LINK, "tunnels[0].uplink", "no tunnel"));
    PASS();
}

/* catches: an active count of zero accepted */
TEST active_zero_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "auto", "0", "site", LINK, "tunnels[0].active", "1..8"));
    PASS();
}

/* catches: an active count above the 8 the event struct holds */
TEST active_nine_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "auto", "9", "site", LINK, "tunnels[0].active", "1..8"));
    PASS();
}

/* catches: an unknown distribution mode passed through to tunvless */
TEST an_unknown_by_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "random", LINK, "tunnels[0].by", "connection"));
    PASS();
}

static const char FULL[] =
    "tunnels:\n"
    "  - id: s1\n"
    "    device: tunvless2\n"
    "    sources:\n"
    "      - id: 0a1b2c3d\n"
    "        link: \"vless://u@h:443#mine\"\n"
    "      - id: deadbeef\n"
    "        subscription: { name: Provider A, url: \"https://sub.example/x?t=1\", interval: 6h }\n"
    "      - id: 00ff00ff\n"
    "        subscription: { name: b_2.x-y, url: \"http://s2.example\", interval: 0s }\n"
    "    filter: \"NL|Netherlands\"\n"
    "    order: [\"deadbeef:NL-1\", \"0a1b2c3d:mine\"]\n"
    "    exclude: [\"deadbeef:NL-2%3Ax#2\"]\n";

static int check_full(const firc_tunnel_t *t)
{
    return t->n_src == 3 && strcmp(t->src[0].id, "0a1b2c3d") == 0 && t->src[0].kind == FIRC_TUN_SRC_LINK &&
           strcmp(t->src[0].link, "vless://u@h:443#mine") == 0 && strcmp(t->src[1].id, "deadbeef") == 0 &&
           t->src[1].kind == FIRC_TUN_SRC_SUB && strcmp(t->src[1].sub.name, "Provider A") == 0 &&
           strcmp(t->src[1].sub.url, "https://sub.example/x?t=1") == 0 && t->src[1].sub.interval_s == 21600 &&
           strcmp(t->src[2].id, "00ff00ff") == 0 && strcmp(t->src[2].sub.name, "b_2.x-y") == 0 &&
           strcmp(t->src[2].sub.url, "http://s2.example") == 0 && t->src[2].sub.interval_s == 0 &&
           t->filter != NULL && strcmp(t->filter, "NL|Netherlands") == 0 && t->n_order == 2 &&
           strcmp(t->order[0], "deadbeef:NL-1") == 0 && strcmp(t->order[1], "0a1b2c3d:mine") == 0 &&
           t->n_exclude == 1 && strcmp(t->exclude[0], "deadbeef:NL-2%3Ax#2") == 0;
}

/* catches: a subscription, a source id, the filter, order or exclude lost or altered by load or save */
TEST subscriptions_filter_order_exclude_survive_save_and_load(void) {
    firc_tunnels_t a = {0}, b = {0}; firc_tun_err_t e = {0};
    char path[] = "/tmp/tconfig-XXXXXX";
    int fd = mkstemp(path); close(fd);
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&a, FULL, sizeof FULL - 1, &e));
    ASSERT(check_full(&a.t[0]));
    ASSERT_EQ(FIRC_OK, firc_tunnels_save_file(&a, path));
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_file(&b, path, &e));
    ASSERT(check_full(&b.t[0]));
    unlink(path); firc_tunnels_free(&a); firc_tunnels_free(&b);
    PASS();
}

static int ids_of(const char *sources, char out[][9], size_t n)
{
    char doc[2048];
    snprintf(doc, sizeof doc, "tunnels:\n  - id: a1\n    device: tunvless0\n    sources:\n%s", sources);
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    if (firc_tunnels_load_buffer(&t, doc, strlen(doc), &e) != FIRC_OK || t.t[0].n_src != n) {
        firc_tunnels_free(&t);
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        memcpy(out[i], t.t[0].src[i].id, 9);
    }
    firc_tunnels_free(&t);
    return 1;
}

/* catches: an id-less source given a new id on every load, which orphans its order and exclude keys */
TEST a_source_without_an_id_gets_one_derived_from_it(void) {
    char a[2][9], b[2][9];
    const char *src = LINK "      - subscription: { name: P, url: \"https://x.example\" }\n";
    ASSERT(ids_of(src, a, 2));
    ASSERT(ids_of(src, b, 2));
    ASSERT_STR_EQ("1d4b90d8", a[0]);
    ASSERT_STR_EQ("218cfca4", a[1]);
    ASSERT_STR_EQ(a[0], b[0]);
    ASSERT_STR_EQ(a[1], b[1]);
    PASS();
}

/* catches: two identical links given one id, or a derived id taking one written in the file */
TEST a_derived_id_steps_past_one_already_taken(void) {
    char a[2][9];
    ASSERT(ids_of(LINK LINK, a, 2));
    ASSERT_STR_EQ("1d4b90d8", a[0]);
    ASSERT_STR_EQ("15822221", a[1]);
    ASSERT(ids_of(LINK "      - id: 1d4b90d8\n        link: \"vless://u@h:443#b\"\n", a, 2));
    ASSERT_STR_EQ("15822221", a[0]);
    ASSERT_STR_EQ("1d4b90d8", a[1]);
    PASS();
}

/* catches: a refresh interval default other than 6h */
TEST a_subscription_without_an_interval_refreshes_every_6h(void) {
    static const char doc[] = "tunnels:\n  - id: a1\n    device: tunvless0\n    sources:\n"
                              "      - subscription: { name: P, url: \"https://x.example\" }\n";
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&t, doc, sizeof doc - 1, &e));
    ASSERT_EQ(21600, t.t[0].src[0].sub.interval_s);
    firc_tunnels_free(&t);
    PASS();
}

/* catches: a source id that is not 8 hex digits, or one used twice, accepted */
TEST a_bad_or_repeated_source_id_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site", "      - id: 0A1B2C3D\n        link: \"vless://u@h:1#a\"\n",
                       "tunnels[0].sources[0].id", "8 hex"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site", "      - id: abc\n        link: \"vless://u@h:1#a\"\n",
                       "tunnels[0].sources[0].id", "8 hex"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - id: 0a1b2c3d\n        link: \"vless://u@h:1#a\"\n"
                       "      - id: 0a1b2c3d\n        link: \"vless://u@h:1#b\"\n",
                       "tunnels[0].sources[1].id", "used twice"));
    PASS();
}

/* catches: a subscription URL that is not http(s), has whitespace or is over 2048 bytes accepted */
TEST a_bad_subscription_url_is_refused(void) {
    const char *where = "tunnels[0].sources[0].subscription.url";
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { name: P, url: \"ftp://x.example\" }\n", where, "http"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { name: P, url: \"https://x.example/a b\" }\n", where, "http"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { name: P, url: \"https://\" }\n", where, "http"));
    char src[2400];
    char longurl[2100] = "https://x.example/";
    while (strlen(longurl) < 2049) { strcat(longurl, "a"); }
    snprintf(src, sizeof src, "      - subscription: { name: P, url: \"%s\" }\n", longurl);
    char doc[4096] = "tunnels:\n";
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "a1", "tunvless0", "auto", "1", "site", src);
    ASSERT(refused(doc, where, "2048"));
    longurl[2048] = 0;
    snprintf(src, sizeof src, "      - subscription: { name: P, url: \"%s\" }\n", longurl);
    snprintf(doc, sizeof doc, "tunnels:\n");
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "a1", "tunvless0", "auto", "1", "site", src);
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&t, doc, strlen(doc), &e));
    firc_tunnels_free(&t);
    PASS();
}

static int sub_interval(const char *iv)
{
    char src[256], doc[1024] = "tunnels:\n";
    snprintf(src, sizeof src, "      - subscription: { name: P, url: \"https://x.example\", interval: %s }\n", iv);
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "a1", "tunvless0", "auto", "1", "site", src);
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    int r = firc_tunnels_load_buffer(&t, doc, strlen(doc), &e) == FIRC_OK ? t.t[0].src[0].sub.interval_s : -1;
    if (r < 0 && (strcmp(e.where, "tunnels[0].sources[0].subscription.interval") != 0 || strstr(e.why, "10m") == NULL)) {
        r = -2;
    }
    firc_tunnels_free(&t);
    return r;
}

/* catches: a refresh interval outside 0 or 10m..7d accepted, or a bound refused */
TEST a_subscription_interval_outside_its_bounds_is_refused(void) {
    ASSERT_EQ(0, sub_interval("0s"));
    ASSERT_EQ(600, sub_interval("10m"));
    ASSERT_EQ(604800, sub_interval("168h"));
    ASSERT_EQ(-1, sub_interval("599s"));
    ASSERT_EQ(-1, sub_interval("1s"));
    ASSERT_EQ(-1, sub_interval("604801s"));
    ASSERT_EQ(-1, sub_interval("600.5s"));
    ASSERT_EQ(5400, sub_interval("1.5h"));
    PASS();
}

/* catches: a subscription name that is empty, too long, has odd characters or repeats accepted */
TEST a_bad_or_repeated_subscription_name_is_refused(void) {
    const char *where = "tunnels[0].sources[0].subscription.name";
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { name: \"\", url: \"https://x.example\" }\n", where, "1..63"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { name: \"a/b\", url: \"https://x.example\" }\n", where, "1..63"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { name: \"a:b\", url: \"https://x.example\" }\n", where, "1..63"));
    char src[256];
    snprintf(src, sizeof src, "      - subscription: { name: %064d, url: \"https://x.example\" }\n", 7);
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site", src, where, "1..63"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { name: P, url: \"https://x.example\" }\n"
                       "      - subscription: { name: P, url: \"https://y.example\" }\n",
                       "tunnels[0].sources[1].subscription.name", "used twice"));
    PASS();
}

/* catches: a file source or an unknown key inside a subscription silently ignored */
TEST an_unknown_source_kind_or_subscription_key_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site", "      - file: /tmp/x\n",
                       "tunnels[0].sources[0]", "link: or subscription:"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - link: \"vless://u@h:1#a\"\n        subscription: { name: P, url: \"https://x.example\" }\n",
                       "tunnels[0].sources[0]", "link: or subscription:"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { name: P, url: \"https://x.example\", every: 6h }\n",
                       "tunnels[0].sources[0].subscription.every", "unknown key"));
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - subscription: { url: \"https://x.example\" }\n",
                       "tunnels[0].sources[0].subscription.name", "required"));
    PASS();
}

/* catches: a tunnel whose only source is a subscription refused as having no source */
TEST a_subscription_alone_is_a_source(void) {
    static const char doc[] = "tunnels:\n  - id: a1\n    device: tunvless0\n    sources:\n"
                              "      - subscription: { name: P, url: \"https://x.example\" }\n";
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&t, doc, sizeof doc - 1, &e));
    firc_tunnels_free(&t);
    PASS();
}

/* catches: a non-vless link handed to tunvless */
TEST a_link_that_is_not_vless_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site", "      - link: \"vmess://abc\"\n",
                       "tunnels[0].sources[0]", "vless://"));
    PASS();
}

/* catches: a link with a newline that would split into two stdin lines */
TEST a_link_with_a_newline_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site",
                       "      - link: \"vless://u@h:443\\nvless://x\"\n", "tunnels[0].sources[0]", "vless://"));
    PASS();
}

/* catches: a filter that is not a valid regular expression saved and failing at every rebuild */
TEST a_filter_that_does_not_compile_is_refused(void) {
    ASSERT(with_extra("    filter: \"NL(\"\n", "tunnels[0].filter", "regular expression"));
    ASSERT(with_extra("    filter: [a]\n", "tunnels[0].filter", "regular expression"));
    ASSERT(loads_extra("    filter: \"^(nl|de)-[0-9]+$\"\n"));
    PASS();
}

/* catches: an order or exclude entry over 191 bytes or not a string accepted */
TEST a_long_order_or_exclude_key_is_refused(void) {
    char extra[512], key[200];
    memset(key, 'k', 192);
    key[192] = 0;
    snprintf(extra, sizeof extra, "    order: [\"ok\", \"%s\"]\n", key);
    ASSERT(with_extra(extra, "tunnels[0].order[1]", "191"));
    snprintf(extra, sizeof extra, "    exclude: [\"%s\"]\n", key);
    ASSERT(with_extra(extra, "tunnels[0].exclude[0]", "191"));
    ASSERT(with_extra("    order: \"a\"\n", "tunnels[0].order", "list"));
    key[191] = 0;
    snprintf(extra, sizeof extra, "    order: [\"%s\"]\n", key);
    ASSERT(loads_extra(extra));
    PASS();
}

/* catches: a filter edit restarting tunvless although the links it is sent stay the same */
TEST same_run_ignores_filter_order_and_exclude(void) {
    ASSERT_EQ(3, same_after("active: 1", "active: 1\n    filter: x\n    order: [a]\n    exclude: [b]"));
    PASS();
}

static int save_and_reload(const char *doc, firc_tunnels_t *b, char *file, size_t cap)
{
    firc_tunnels_t a = {0};
    firc_tun_err_t e = {0};
    char path[] = "/tmp/tconfig-XXXXXX";
    int fd = mkstemp(path);
    close(fd);
    int ok = firc_tunnels_load_buffer(&a, doc, strlen(doc), &e) == FIRC_OK && firc_tunnels_save_file(&a, path) == FIRC_OK &&
             firc_tunnels_load_file(b, path, &e) == FIRC_OK;
    FILE *f = fopen(path, "r");
    size_t n = f != NULL ? fread(file, 1, cap - 1, f) : 0;
    file[n] = '\0';
    if (f != NULL) {
        fclose(f);
    }
    unlink(path);
    firc_tunnels_free(&a);
    return ok;
}

/* catches: a description dropped, cut or altered by YAML quoting on save and load */
TEST a_description_survives_save_and_load(void) {
    static const char doc[] =
        "tunnels:\n  - id: a1\n    device: tunvless0\n    description: \"\xd0\x9f\xd0\xa0\xd0\x90\xd0\x92-1: \\\"x\\\" #y\"\n"
        "    sources:\n" LINK;
    firc_tunnels_t b = {0};
    char file[4096];
    ASSERT(save_and_reload(doc, &b, file, sizeof file));
    ASSERT_STR_EQ("\xd0\x9f\xd0\xa0\xd0\x90\xd0\x92-1: \"x\" #y", b.t[0].description);
    firc_tunnels_free(&b);
    PASS();
}

/* catches: an absent description loaded as something, or written back as an empty key */
TEST no_description_is_empty_and_not_written(void) {
    firc_tunnels_t b = {0};
    char file[4096];
    ASSERT(save_and_reload(ONE, &b, file, sizeof file));
    ASSERT_STR_EQ("", b.t[0].description);
    ASSERT(strstr(file, "description") == NULL);
    firc_tunnels_free(&b);
    PASS();
}

/* catches: the 63-byte limit counted in characters, off by one, or a description over it accepted */
TEST a_description_over_63_bytes_is_refused(void) {
    char extra[256];
    char cyr[80] = "";
    for (int i = 0; i < 31; i++) {
        strcat(cyr, "\xd0\x9f");
    }
    snprintf(extra, sizeof extra, "    description: \"%s1\"\n", cyr);
    ASSERT(loads_extra(extra));
    snprintf(extra, sizeof extra, "    description: \"%s\xd0\x9f\"\n", cyr);
    ASSERT(with_extra(extra, "tunnels[0].description", "63 bytes"));
    snprintf(extra, sizeof extra, "    description: \"%s12\"\n", cyr);
    ASSERT(with_extra(extra, "tunnels[0].description", "63 bytes"));
    PASS();
}

/* catches: a tab, newline, DEL or C1 control character in a description accepted */
TEST a_description_with_a_control_character_is_refused(void) {
    static const char *const bad[] = {"a\\tb", "a\\nb", "\\x01", "a\\x7f", "a\\u009b"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char extra[128];
        snprintf(extra, sizeof extra, "    description: \"%s\"\n", bad[i]);
        ASSERTm(bad[i], with_extra(extra, "tunnels[0].description", "control"));
    }
    ASSERT(loads_extra("    description: \"a b\"\n"));
    PASS();
}

/* catches: a description edit restarting tunvless or resending its nodes */
TEST same_run_ignores_the_description(void) {
    ASSERT_EQ(3, same_after("active: 1", "active: 1\n    description: x"));
    PASS();
}

/* catches: a ninth tunnel accepted past the cap */
TEST nine_tunnels_are_refused(void) {
    char doc[16384] = "tunnels:\n";
    for (int i = 0; i < 9; i++) {
        char id[8], dev[16];
        snprintf(id, sizeof id, "t%d", i);
        snprintf(dev, sizeof dev, "tunvless%d", i);
        tun_text(doc + strlen(doc), sizeof doc - strlen(doc), id, dev, "auto", "1", "site", LINK);
    }
    ASSERT(refused(doc, "tunnels[8]", "at most 8"));
    PASS();
}

/* catches: a change that needs a restart being skipped (active), or read as a node change */
TEST same_run_is_false_when_only_active_differs(void) {
    ASSERT_EQ(2, same_after("active: 1", "active: 2"));
    PASS();
}

/* catches: a change that needs a restart being skipped (enable), or read as a node change */
TEST same_run_is_false_when_only_enable_differs(void) {
    ASSERT_EQ(2, same_after("enable: true", "enable: false"));
    PASS();
}

/* catches: a changed link read as a restart, or not seen as a node change */
TEST same_run_is_false_when_a_link_differs(void) {
    ASSERT_EQ(1, same_after("#a\"", "#b\""));
    PASS();
}

/* catches: a subscription's name or interval read as a change of what tunvless runs with */
TEST a_subscription_name_or_interval_changes_nothing_sent(void) {
    ASSERT_EQ(3, same_after_in(SAME_SUB, "name: P", "name: Q"));
    ASSERT_EQ(3, same_after_in(SAME_SUB, "interval: 1h", "interval: 2h"));
    ASSERT_EQ(1, same_after_in(SAME_SUB, "s.example/x", "s.example/y"));
    PASS();
}

/* catches: an argv-affecting field left out of the restart check */
TEST every_argv_field_is_a_restart(void) {
    ASSERT_EQ(2, same_after("active: 1", "active: 1\n    by: site"));
    ASSERT_EQ(2, same_after("active: 1", "active: 1\n    interval: 61s"));
    ASSERT_EQ(2, same_after("active: 1", "active: 1\n    silence: 21s"));
    ASSERT_EQ(2, same_after("active: 1", "active: 1\n    advanced: { timeout: 9s }"));
    ASSERT_EQ(2, same_after("active: 1", "active: 1\n    advanced: { insecure: true }"));
    ASSERT_EQ(2, same_after("active: 1", "active: 1\n    advanced: { ca: /x.pem }"));
    ASSERT_EQ(2, same_after("active: 1", "active: 1\n    uplink: iface:ppp0"));
    ASSERT_EQ(2, same_after("tunvless0", "tunvless1"));
    PASS();
}

/* catches: every apply restarting a tunnel that did not change */
TEST same_run_is_true_for_two_loads_of_one_document(void) {
    ASSERT_EQ(3, same_after("active: 1", "active: 1"));
    PASS();
}

/* catches: a default that differs from tunvless's own (spec: by connection) */
TEST a_minimal_tunnel_gets_every_default(void) {
    static const char doc[] = "tunnels:\n  - id: a1\n    device: tunvless3\n    sources:\n" LINK;
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&t, doc, sizeof doc - 1, &e));
    ASSERT(t.t[0].enable);
    ASSERT_EQ(FIRC_UPLINK_AUTO, t.t[0].uplink);
    ASSERT_EQ(1, t.t[0].active);
    ASSERT_STR_EQ("connection", t.t[0].by);
    ASSERT_EQ(60, t.t[0].interval_s);
    ASSERT_EQ(20, t.t[0].silence_s);
    ASSERT_EQ(8, t.t[0].timeout_s);
    ASSERT(!t.t[0].insecure);
    ASSERT_STR_EQ("", t.t[0].ca);
    firc_tunnels_free(&t);
    PASS();
}

/* catches: a timeout outside 1..600 s saved and tunvless then exiting 2 */
TEST timeout_outside_tunvless_bounds_is_refused(void) {
    ASSERT(with_extra("    advanced: { timeout: 0s }\n", "tunnels[0].advanced.timeout", "1s..600s"));
    ASSERT(with_extra("    advanced: { timeout: 601s }\n", "tunnels[0].advanced.timeout", "1s..600s"));
    ASSERT(loads_extra("    advanced: { timeout: 1s }\n"));
    ASSERT(loads_extra("    advanced: { timeout: 600s }\n"));
    PASS();
}

/* catches: a silence outside 0..3600 s accepted, or silence 0 refused */
TEST silence_outside_tunvless_bounds_is_refused(void) {
    ASSERT(with_extra("    silence: 3601s\n", "tunnels[0].silence", "0s..1h"));
    ASSERT(with_extra("    silence: -1s\n", "tunnels[0].silence", "0s..1h"));
    ASSERT(loads_extra("    silence: 0s\n"));
    ASSERT(loads_extra("    silence: 3600s\n"));
    PASS();
}

/* catches: an interval outside 5..86400 s accepted */
TEST interval_outside_tunvless_bounds_is_refused(void) {
    ASSERT(with_extra("    interval: 4s\n", "tunnels[0].interval", "5s..24h"));
    ASSERT(with_extra("    interval: 86401s\n", "tunnels[0].interval", "5s..24h"));
    ASSERT(loads_extra("    interval: 5s\n"));
    ASSERT(loads_extra("    interval: 24h\n"));
    PASS();
}

/* catches: a fractional duration truncated silently */
TEST a_fractional_duration_is_refused(void) {
    ASSERT(with_extra("    silence: 1500ms\n", "tunnels[0].silence", "whole seconds"));
    PASS();
}

/* catches: a second sources key overwriting the first and leaking its links */
TEST a_key_given_twice_is_refused(void) {
    ASSERT(with_extra("    sources:\n" LINK, "tunnels[0].sources", "twice"));
    ASSERT(with_extra("    advanced: { insecure: true, insecure: false }\n", "tunnels[0].advanced.insecure", "twice"));
    PASS();
}

/* catches: a typo in a key silently ignored */
TEST an_unknown_key_is_refused(void) {
    ASSERT(with_extra("    actve: 2\n", "tunnels[0].actve", "unknown key"));
    PASS();
}

/* catches: a key holding a link echoed into the error text */
TEST an_unknown_key_that_is_a_link_is_not_echoed(void) {
    static const char doc[] =
        "tunnels:\n  - id: a1\n    device: tunvless0\n    sources:\n" LINK
        "    \"vless://11111111-2222-3333-4444-555555555555@h:443\": 1\n";
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    ASSERT(firc_tunnels_load_buffer(&t, doc, sizeof doc - 1, &e) != FIRC_OK);
    ASSERT_STR_EQ("tunnels[0]", e.where);
    ASSERT_STR_EQ("unknown key", e.why);
    ASSERT(strstr(e.where, "1111") == NULL && strstr(e.why, "1111") == NULL);
    PASS();
}

/* catches: two tunnels with the same id accepted */
TEST a_duplicate_id_is_refused(void) {
    char doc[2048] = "tunnels:\n";
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "a1", "tunvless0", "auto", "1", "site", LINK);
    tun_text(doc + strlen(doc), sizeof doc - strlen(doc), "a1", "tunvless1", "auto", "1", "site", LINK);
    ASSERT(refused(doc, "tunnels[1].id", "twice"));
    PASS();
}

/* catches: an id with characters outside letters, digits, - and _ */
TEST an_id_with_odd_characters_is_refused(void) {
    ASSERT(refused_one("a b", "tunvless0", "auto", "1", "site", LINK, "tunnels[0].id", "letters"));
    ASSERT(refused_one("a:b", "tunvless0", "auto", "1", "site", LINK, "tunnels[0].id", "letters"));
    PASS();
}

/* catches: enable read as true for a value that is not a bool */
TEST an_enable_that_is_not_a_bool_is_refused(void) {
    ASSERT(with_extra("    enable: yes\n", "tunnels[0].enable", "true or false"));
    PASS();
}

/* catches: a link with whitespace splitting into two stdin lines */
TEST a_link_with_whitespace_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "auto", "1", "site", "      - link: \"vless://u@h:443#a b\"\n",
                       "tunnels[0].sources[0]", "whitespace"));
    PASS();
}

/* catches: an iface uplink onto a tunnel device bypassing the cycle check */
TEST an_iface_uplink_on_a_tunvless_device_is_refused(void) {
    ASSERT(refused_one("a1", "tunvless0", "iface:tunvless1", "1", "site", LINK, "tunnels[0].uplink", "tunnel:<id>"));
    PASS();
}

/* catches: an enabled tunnel with no node accepted, or a disabled empty one refused */
TEST an_enabled_tunnel_without_sources_is_refused(void) {
    static const char on[] = "tunnels:\n  - id: a1\n    device: tunvless0\n    sources: []\n";
    static const char off[] = "tunnels:\n  - id: a1\n    device: tunvless0\n    enable: false\n    sources: []\n";
    ASSERT(refused(on, "tunnels[0].sources", "at least one source"));
    firc_tunnels_t t = {0}; firc_tun_err_t e = {0};
    ASSERT_EQ(FIRC_OK, firc_tunnels_load_buffer(&t, off, sizeof off - 1, &e));
    ASSERT_EQ(1u, t.n);
    firc_tunnels_free(&t);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(loads_every_field);
    RUN_TEST(save_then_load_is_the_same_tunnel);
    RUN_TEST(a_file_others_can_read_is_warned_about_once);
    RUN_TEST(a_missing_file_is_no_tunnels);
    RUN_TEST(the_saved_file_is_mode_0600);
    RUN_TEST(a_link_with_yaml_syntax_survives_save_and_load);
    RUN_TEST(a_device_used_twice_is_refused);
    RUN_TEST(a_device_outside_tunvless_is_refused);
    RUN_TEST(a_tunvless_suffix_that_is_not_a_small_number_is_refused);
    RUN_TEST(an_uplink_through_itself_is_refused);
    RUN_TEST(an_uplink_cycle_is_refused);
    RUN_TEST(an_uplink_to_an_unknown_tunnel_is_refused);
    RUN_TEST(active_zero_is_refused);
    RUN_TEST(active_nine_is_refused);
    RUN_TEST(an_unknown_by_is_refused);
    RUN_TEST(subscriptions_filter_order_exclude_survive_save_and_load);
    RUN_TEST(a_source_without_an_id_gets_one_derived_from_it);
    RUN_TEST(a_derived_id_steps_past_one_already_taken);
    RUN_TEST(a_subscription_without_an_interval_refreshes_every_6h);
    RUN_TEST(a_bad_or_repeated_source_id_is_refused);
    RUN_TEST(a_bad_subscription_url_is_refused);
    RUN_TEST(a_subscription_interval_outside_its_bounds_is_refused);
    RUN_TEST(a_bad_or_repeated_subscription_name_is_refused);
    RUN_TEST(an_unknown_source_kind_or_subscription_key_is_refused);
    RUN_TEST(a_subscription_alone_is_a_source);
    RUN_TEST(a_link_that_is_not_vless_is_refused);
    RUN_TEST(a_link_with_a_newline_is_refused);
    RUN_TEST(a_filter_that_does_not_compile_is_refused);
    RUN_TEST(a_long_order_or_exclude_key_is_refused);
    RUN_TEST(same_run_ignores_filter_order_and_exclude);
    RUN_TEST(nine_tunnels_are_refused);
    RUN_TEST(a_description_survives_save_and_load);
    RUN_TEST(no_description_is_empty_and_not_written);
    RUN_TEST(a_description_over_63_bytes_is_refused);
    RUN_TEST(a_description_with_a_control_character_is_refused);
    RUN_TEST(same_run_ignores_the_description);
    RUN_TEST(same_run_is_false_when_only_active_differs);
    RUN_TEST(same_run_is_false_when_only_enable_differs);
    RUN_TEST(same_run_is_false_when_a_link_differs);
    RUN_TEST(same_run_is_true_for_two_loads_of_one_document);
    RUN_TEST(a_subscription_name_or_interval_changes_nothing_sent);
    RUN_TEST(every_argv_field_is_a_restart);
    RUN_TEST(a_minimal_tunnel_gets_every_default);
    RUN_TEST(timeout_outside_tunvless_bounds_is_refused);
    RUN_TEST(silence_outside_tunvless_bounds_is_refused);
    RUN_TEST(interval_outside_tunvless_bounds_is_refused);
    RUN_TEST(a_fractional_duration_is_refused);
    RUN_TEST(a_key_given_twice_is_refused);
    RUN_TEST(an_unknown_key_is_refused);
    RUN_TEST(an_unknown_key_that_is_a_link_is_not_echoed);
    RUN_TEST(a_duplicate_id_is_refused);
    RUN_TEST(an_id_with_odd_characters_is_refused);
    RUN_TEST(an_enable_that_is_not_a_bool_is_refused);
    RUN_TEST(a_link_with_whitespace_is_refused);
    RUN_TEST(an_iface_uplink_on_a_tunvless_device_is_refused);
    RUN_TEST(an_enabled_tunnel_without_sources_is_refused);
    GREATEST_MAIN_END();
}
