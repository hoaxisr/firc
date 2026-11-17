/* Subscription parsing: what sub.c takes from vless:// links and Xray configs, and how it counts
 * what it does not take.
 *
 * sub.c is where text from the internet comes in: a panel serves the subscription, and nobody
 * guarantees its format. A parser error does not look like a failure: the node just does not
 * appear, and the user looks for the cause everywhere but the parser.
 *
 * So the main property checked is the arithmetic: usable + skipped + foreign must equal the
 * number of links in the text, whatever they look like, including links the parser cannot read.
 *
 * The file includes the sources it tests, to reach their static functions. They need no network
 * and no crypto library, so the test builds without them. */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "../src/proto/vless/sub.c"
/* vless_proto.c holds the UUID derivation: a panel link must both pass the usability check in
 * sub.c and give the 16 bytes that go into the request header. */
#include "../src/proto/vless/vless_proto.c"

static int g_pass, g_fail;

/* A UUID in canonical form, so that a mismatch is readable in the report. */
static const char *uuid_str(const unsigned char u[16]) {
    static char s[37];
    snprintf(s, sizeof(s),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7],
             u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]);
    return s;
}

static void check(const char *name, const char *expected, const char *actual) {
    if (!strcmp(expected, actual)) {
        g_pass++;
        printf("%-56s ok\n", name);
    } else {
        g_fail++;
        printf("FAIL %s\n  expected: %s\n  got:      %s\n", name, expected, actual);
    }
}

static void check_n(const char *name, long expected, long actual) {
    char e[32], a[32];
    snprintf(e, sizeof(e), "%ld", expected);
    snprintf(a, sizeof(a), "%ld", actual);
    check(name, e, a);
}

/* 1 if the whole string is valid UTF-8. A cut multi-byte sequence leaves a byte no consumer can
 * read, and it shows only at the end of the string. */
static int utf8_ok(const char *s) {
    const unsigned char *p = (const unsigned char *)s;
    while (*p) {
        size_t need;
        if (*p < 0x80) { p++; continue; }
        else if ((*p & 0xE0) == 0xC0) need = 1;
        else if ((*p & 0xF0) == 0xE0) need = 2;
        else if ((*p & 0xF8) == 0xF0) need = 3;
        else return 0;                       /* a continuation byte or an invalid lead byte */
        p++;
        for (size_t i = 0; i < need; i++) {
            if ((*p & 0xC0) != 0x80) return 0;
            p++;
        }
    }
    return 1;
}

/* A malformed Xray config comes from the internet, and parsing must return, not hang. The alarm
 * turns a hang into a test failure. The output is flushed first: _exit does not, and when stdout
 * is a pipe or a file (a CI log) the report would end without saying what hung. */
static size_t g_json_case;
static void on_alarm(int sig) {
    (void)sig;
    printf("HANG: parsing malformed JSON %zu did not return within 2 s\n", g_json_case);
    fflush(stdout);
    _exit(1);
}

#define XHU "b831381d-6324-4d53-ad4f-8cda48b30811"

static const char *xhx_of(const struct vless_node *n) {
    return !n->xhx ? "(null)" : n->xhx == SL_BAD_XHX ? "(bad)" : n->xhx == SL_BAD_XHX_JSON ? "(bad json)" :
           n->xhx == SL_FULL ? "(full)" : n->xhx;
}

static int xhx_link(const char *query, const char *json, struct vless_node *n) {
    static char url[16384];
    size_t o = (size_t)snprintf(url, sizeof url, "vless://" XHU "@example.org:443?type=xhttp&security=none&path=%%2Fx%s&extra=", query);
    for (const unsigned char *p = (const unsigned char *)json; *p && o + 4 < sizeof url; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) url[o++] = (char)*p;
        else o += (size_t)snprintf(url + o, sizeof url - o, "%%%02X", *p);
    }
    snprintf(url + o, sizeof url - o, "#x");
    return vless_parse_url(url, n);
}

static size_t xhx_xray(const char *xhttp, struct vless_node *out, struct vless_sub_stats *st) {
    static char js[8192];
    snprintf(js, sizeof js,
             "{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"j\",\"settings\":{\"vnext\":[{\"address\":\"example.org\","
             "\"port\":443,\"users\":[{\"id\":\"" XHU "\"}]}]},\"streamSettings\":{\"network\":\"xhttp\","
             "\"xhttpSettings\":%s}}]}", xhttp);
    memset(st, 0, sizeof *st);
    return vless_parse_sub(js, out, 4, st);
}

static size_t xhx_clash(const char *opts, struct vless_node *out, struct vless_sub_stats *st) {
    static char y[8192];
    snprintf(y, sizeof y,
             "proxies:\n  - name: c\n    type: vless\n    server: example.org\n    port: 443\n"
             "    uuid: " XHU "\n    network: xhttp\n    xhttp-opts:\n      path: /x\n%s", opts);
    memset(st, 0, sizeof *st);
    return vless_parse_sub(y, out, 4, st);
}

static const char *dl_host(const struct vless_node *n);

static const char *xhx_reason(size_t got, const struct vless_sub_stats *st) {
    return got ? "(usable)" : st->reasons_n ? st->reasons[0].reason : "(no reason)";
}

static void t_xhx_link_keeps_supported_keys_in_order_and_pad_from_extra(void) {
    struct vless_node n, m;
    const char *ex = "{\"sessionIDPlacement\":\"header\",\"xPaddingBytes\":\"20-40\",\"uplinkChunkSize\":\"200-100\"}";
    check_n("xhx link: usable", 0, xhx_link("", ex, &n));
    check("xhx link: canonical string", "sessionIDPlacement=header\nuplinkChunkSize=200-100\n", xhx_of(&n));
    check_n("xhx link: pad from extra, lower", 20, n.pad_from);
    check_n("xhx link: pad from extra, upper", 40, n.pad_to);
    xhx_link("", "{\"uplinkChunkSize\":\"200-100\",\"sessionIDPlacement\":\"header\"}", &m);
    check_n("xhx link: key order does not matter, one interned copy", 1, n.xhx == m.xhx);
    xhx_link("", "{\"xPaddingBytes\":\"20-40\",\"sessionIDKey\":\"\"}", &m);
    check("xhx link: only defaults leave no string", "(null)", xhx_of(&m));
    xhx_link("", "{\"sessionIDKey\":\"a\",\"seqKey\":\"q\",\"sessionIDKey\":\"b\"}", &m);
    check("xhx link: a repeated key keeps the last value", "sessionIDKey=b\nseqKey=q\n", xhx_of(&m));
    xhx_link("&headers=X-L%3A%201%0A", "{\"xPaddingBytes\":\"20-40\"}", &m);
    check("xhx link: extra without headers keeps the link's", "X-L: 1\n", m.headers);
    xhx_link("&mode=packet-up", "{\"scMaxBufferedPosts\":40}", &m);
    check("xhx link: scMaxBufferedPosts kept", "scMaxBufferedPosts=40\n", xhx_of(&m));
    struct vless_node j[4];
    struct vless_sub_stats st;
    size_t got = xhx_xray("{\"path\":\"/x\",\"mode\":\"packet-up\",\"scMaxBufferedPosts\":40}", j, &st);
    check("xhx xray: scMaxBufferedPosts kept", "scMaxBufferedPosts=40\n", got ? xhx_of(&j[0]) : xhx_reason(got, &st));
}

static void t_xhx_settings_over_the_buffer_are_refused(void) {
    static char ex[1024];
    struct vless_node n;
    size_t o = (size_t)snprintf(ex, sizeof ex, "{\"sessionIDTable\":\"");
    for (int i = 0; i < 400; i++) ex[o++] = 'a';
    o += (size_t)snprintf(ex + o, sizeof ex - o, "\",\"xPaddingKey\":\"");
    for (int i = 0; i < 400; i++) ex[o++] = 'b';
    snprintf(ex + o, sizeof ex - o, "\"}");
    check_n("xhx overflow: skipped", 1, xhx_link("", ex, &n));
    check("xhx overflow: reason", "xhttp: invalid extra value", n.skip_reason);
}

static void t_xhx_link_ranges_from_number_and_object(void) {
    struct vless_node n;
    check_n("xhx ranges: usable", 0,
            xhx_link("", "{\"sessionIDLength\":16,\"uplinkChunkSize\":{\"from\":300,\"to\":200}}", &n));
    check("xhx ranges: number and object", "sessionIDLength=16\nuplinkChunkSize=300-200\n", xhx_of(&n));
    xhx_link("", "{\"xPaddingBytes\":{\"from\":30,\"to\":70}}", &n);
    check_n("xhx ranges: xPaddingBytes object, upper", 70, n.pad_to);
}

static void t_xhx_long_extra_read_whole_and_cut_one_does_not_parse(void) {
    static char ex[4096];
    struct vless_node n;
    size_t o = (size_t)snprintf(ex, sizeof ex, "{\"scStreamUpServerSecs\":\"");
    while (o < 2900) ex[o++] = 'z';
    o += (size_t)snprintf(ex + o, sizeof ex - o,
                          "\",\"headers\":{\"X-A\":\"1\",\"X-B\":\"2\"},\"xPaddingBytes\":\"100-1000\","
                          "\"xPaddingKey\":\"x_pad\",\"xPaddingMethod\":\"repeat-x\"}");
    check_n("xhx long extra: over 3 KB", 1, o > 3000);
    check_n("xhx long extra: usable", 0, xhx_link("", ex, &n));
    check("xhx long extra: keys after the long member", "xPaddingKey=x_pad\nxPaddingMethod=repeat-x\n", xhx_of(&n));
    check("xhx long extra: headers", "X-A: 1\nX-B: 2\n", n.headers);
    check_n("xhx long extra: pad upper", 1000, n.pad_to);
    ex[o / 2] = '\0';
    check_n("xhx long extra cut: skipped", 1, xhx_link("", ex, &n));
    check("xhx long extra cut: reason", "xhttp: extra does not parse", n.skip_reason);
    check_n("xhx extra not an object: skipped", 1, xhx_link("", "[1]", &n));
    check("xhx extra not an object: reason", "xhttp: extra does not parse", n.skip_reason);
    check_n("xhx extra with trailing bytes: skipped", 1, xhx_link("", "{}x", &n));
    check_n("xhx broken extra on tcp: tcp ignores it", 0,
            vless_parse_url("vless://" XHU "@example.org:443?type=tcp&security=none&extra=%7B#t", &n));
}

/* catches: xhttp keys matched case-exactly where Xray folds case */
static void t_xhx_keys_fold_case_like_go(void) {
    struct vless_node out[4], n;
    struct vless_sub_stats st;
    size_t got = xhx_xray("{\"Path\":\"/x\",\"SessionIDPlacement\":\"query\",\"XPADDINGBYTES\":{\"From\":30,\"TO\":60},"
                          "\"Xmux\":{\"MaxConnections\":2}}", out, &st);
    check("xhx case: usable", "(usable)", xhx_reason(got, &st));
    check("xhx case: canonical names", "sessionIDPlacement=query\nxmux.maxConnections=2\n", got ? xhx_of(&out[0]) : "");
    check_n("xhx case: padding key folded", 60, got ? out[0].pad_to : -1);
    check("xhx case: path key folded", "/x", got ? out[0].path : "");
    xhx_link("", "{\"sessionIDKey\":\"a\",\"sessionidkey\":\"b\"}", &n);
    check("xhx case: two spellings are one key, the last wins", "sessionIDKey=b\n", xhx_of(&n));
}

static void t_xhx_xray_json_nested_extra_replaces_top_level(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    size_t got = xhx_xray("{\"path\":\"/x\",\"seqPlacement\":\"cookie\"}", out, &st);
    check("xhx xray: top level usable", "(usable)", xhx_reason(got, &st));
    check("xhx xray: top level field", "seqPlacement=cookie\n", got ? xhx_of(&out[0]) : "");
    got = xhx_xray("{\"path\":\"/x\",\"extra\":{\"sessionIDPlacement\":\"query\",\"xPaddingBytes\":\"30-60\"},"
                   "\"seqPlacement\":\"cookie\",\"xPaddingBytes\":\"500-600\"}", out, &st);
    check("xhx xray: extra first, only extra counts", "sessionIDPlacement=query\n", got ? xhx_of(&out[0]) : "");
    check_n("xhx xray: extra first, pad from extra", 60, got ? out[0].pad_to : -1);
    check("xhx xray: extra keeps the outer path", "/x", got ? out[0].path : "");
    got = xhx_xray("{\"seqPlacement\":\"cookie\",\"xPaddingBytes\":\"500-600\",\"path\":\"/x\","
                   "\"extra\":{\"sessionIDPlacement\":\"query\",\"xPaddingBytes\":\"30-60\"}}", out, &st);
    check("xhx xray: extra last, only extra counts", "sessionIDPlacement=query\n", got ? xhx_of(&out[0]) : "");
    check_n("xhx xray: extra last, pad from extra", 60, got ? out[0].pad_to : -1);
    got = xhx_xray("{\"path\":\"/x\",\"extra\":{\"sessionIDKey\":}}", out, &st);
    check("xhx xray: extra without a value", "xhttp: extra does not parse", xhx_reason(got, &st));
}

static void t_xhx_clash_maps_kebab_keys_and_download_settings(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    size_t got = xhx_clash("      x-padding-method: tokenish\n      seq-placement: query\n"
                           "      download-settings:\n        server: d.example\n", out, &st);
    check("xhx clash: download-settings with server only, usable as mihomo fills the port", "(usable)", xhx_reason(got, &st));
    check("xhx clash: download-settings with server only, block host", "d.example", got ? dl_host(&out[0]) : "");
    check("xhx clash: download-settings leaves no xhttp key", "seqPlacement=query\nxPaddingMethod=tokenish\n",
          got ? xhx_of(&out[0]) : "");
    got = xhx_clash("      x-padding-method: tokenish\n      seq-placement: query\n"
                    "      reuse-settings:\n        max-connections: 4\n", out, &st);
    check("xhx clash: usable", "(usable)", xhx_reason(got, &st));
    check("xhx clash: canonical string", "seqPlacement=query\nxPaddingMethod=tokenish\nxmux.maxConnections=4\n",
          got ? xhx_of(&out[0]) : "");
}

static void t_xhx_clash_every_key_reaches_its_xray_name(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    size_t got = xhx_clash("      mode: packet-up\n      x-padding-bytes: 100-200\n      x-padding-obfs-mode: true\n"
                           "      x-padding-key: xk\n      x-padding-header: X-Pk\n      x-padding-placement: header\n"
                           "      x-padding-method: tokenish\n      uplink-http-method: PUT\n"
                           "      session-placement: query\n      session-key: sk\n      session-table: hex\n"
                           "      session-length: 16\n      seq-placement: header\n      seq-key: X-Sq\n"
                           "      uplink-data-placement: body\n      uplink-data-key: dk\n"
                           "      uplink-chunk-size: 100-200\n      no-grpc-header: true\n", out, &st);
    check("xhx clash map: usable", "(usable)", xhx_reason(got, &st));
    check("xhx clash map: every key",
          "sessionIDPlacement=query\nsessionIDKey=sk\nsessionIDTable=hex\nsessionIDLength=16\n"
          "seqPlacement=header\nseqKey=X-Sq\nuplinkDataPlacement=body\nuplinkDataKey=dk\n"
          "uplinkChunkSize=100-200\nuplinkHTTPMethod=PUT\nxPaddingObfsMode=true\nxPaddingKey=xk\n"
          "xPaddingHeader=X-Pk\nxPaddingPlacement=header\nxPaddingMethod=tokenish\nnoGRPCHeader=true\n",
          got ? xhx_of(&out[0]) : "");
    check_n("xhx clash map: pad upper", 200, got ? out[0].pad_to : -1);
}

static void t_xhx_hostile_value_refused_in_every_format(void) {
    static const char *const js[] = { "a\\\"b", "a;b", "a\\nb", "a=b", "a,b", "a\\\\b" };
    static const char *const ya[] = { "\"a\\\"b\"", "a;b", "\"a\\nb\"", "a=b", "a,b", "\"a\\\\b\"" };
    struct vless_node n, out[4];
    struct vless_sub_stats st;
    char buf[256], name[64];
    for (int i = 0; i < 6; i++) {
        snprintf(buf, sizeof buf, "{\"sessionIDKey\":\"%s\"}", js[i]);
        snprintf(name, sizeof name, "xhx hostile %d: link", i);
        xhx_link("", buf, &n);
        check(name, "xhttp: invalid extra value", n.skip_reason);
        snprintf(name, sizeof name, "xhx hostile %d: xray", i);
        check(name, "xhttp: invalid extra value", xhx_reason(xhx_xray(buf, out, &st), &st));
        snprintf(buf, sizeof buf, "      session-key: %s\n", ya[i]);
        snprintf(name, sizeof name, "xhx hostile %d: clash", i);
        check(name, "xhttp: invalid extra value", xhx_reason(xhx_clash(buf, out, &st), &st));
    }
}

static void t_xhx_data_in_cookie_needs_packet_up(void) {
    struct vless_node n;
    check_n("xhx mode rule: skipped", 1, xhx_link("", "{\"uplinkDataPlacement\":\"cookie\"}", &n));
    check("xhx mode rule: reason", "xhttp: uplinkDataPlacement needs mode=packet-up", n.skip_reason);
    check_n("xhx mode rule: packet-up usable", 0, xhx_link("&mode=packet-up", "{\"uplinkDataPlacement\":\"cookie\"}", &n));
}

static void t_xhx_headers_reach_the_node_and_host_is_refused(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    size_t got = xhx_xray("{\"path\":\"/x\",\"headers\":{\"X-A\":\"1\"}}", out, &st);
    check("xhx headers xray: usable", "(usable)", xhx_reason(got, &st));
    check("xhx headers xray: lines", "X-A: 1\n", got ? out[0].headers : "");
    got = xhx_xray("{\"path\":\"/x\",\"headers\":{\"Host\":\"x\"}}", out, &st);
    check("xhx headers xray: Host refused", "invalid headers for xhttp", xhx_reason(got, &st));
    got = xhx_clash("      headers:\n        X-A: 1\n", out, &st);
    check("xhx headers clash: lines", "X-A: 1\n", got ? out[0].headers : "");
    got = xhx_clash("      headers:\n        Host: x\n", out, &st);
    check("xhx headers clash: Host refused", "invalid headers for xhttp", xhx_reason(got, &st));
}

static void xhx_long_value(char *ex, size_t cap, size_t len) {
    size_t o = (size_t)snprintf(ex, cap, "{\"sessionIDTable\":\"");
    for (size_t i = 0; i < len; i++) ex[o++] = 'a';
    snprintf(ex + o, cap - o, "\"}");
}

static void t_xhx_line_that_fills_the_buffer_exactly_is_refused(void) {
    static char ex[1024];
    struct vless_node n;
    xhx_long_value(ex, sizeof ex, 752);
    xhx_link("", ex, &n);
    check("xhx exact capacity: refused", "xhttp: invalid extra value", n.skip_reason);
    xhx_long_value(ex, sizeof ex, 751);
    xhx_link("", ex, &n);
    const char *x = xhx_of(&n);
    check_n("xhx one byte shorter: stored whole", 767, (long)strlen(x));
    check_n("xhx one byte shorter: last line terminated", '\n', x[strlen(x) - 1]);
}

static void t_xhx_null_extra_resets_to_defaults_keeping_path(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    size_t got = xhx_xray("{\"path\":\"/x\",\"seqPlacement\":\"cookie\",\"xPaddingBytes\":\"500-600\",\"extra\":null}", out, &st);
    check("xhx null extra: usable", "(usable)", xhx_reason(got, &st));
    check("xhx null extra: top level discarded", "(null)", got ? xhx_of(&out[0]) : "");
    check_n("xhx null extra: pad discarded", 0, got ? out[0].pad_to : -1);
    check("xhx null extra: path kept", "/x", got ? out[0].path : "");
}

static void t_xhx_settings_reach_only_xhttp_nodes(void) {
    struct vless_node n, out[4];
    struct vless_sub_stats st;
    check_n("xhx ws link: usable", 0,
            vless_parse_url("vless://" XHU "@example.org:443?type=ws&security=none&path=%2Fw&headers=X-W%3A%202%0A"
                            "&extra=%7B%22headers%22%3A%7B%22X-A%22%3A%221%22%7D%2C%22seqPlacement%22%3A%22query%22%7D#w", &n));
    check("xhx ws link: own headers kept", "X-W: 2\n", n.headers);
    check("xhx ws link: no xhx", "(null)", xhx_of(&n));
    vless_parse_url("vless://" XHU "@example.org:443?extra=%7B%22seqPlacement%22%3A%22query%22%7D&security=none&path=%2Fx&type=xhttp#x", &n);
    check("xhx link: extra before type still read", "seqPlacement=query\n", xhx_of(&n));
    static char js[2048];
    static const char *const nets[] = { "tcp", "xhttp" };
    size_t got = 0;
    for (int k = 0; k < 2; k++) {
        snprintf(js, sizeof js,
                 "{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"j\",\"settings\":{\"vnext\":[{\"address\":\"example.org\","
                 "\"port\":443,\"users\":[{\"id\":\"" XHU "\"}]}]},\"streamSettings\":{"
                 "\"xhttpSettings\":{\"seqPlacement\":\"cookie\",\"headers\":{\"X-A\":\"1\"}},\"network\":\"%s\"}}]}", nets[k]);
        memset(&st, 0, sizeof st);
        got = vless_parse_sub(js, out, 4, &st);
        if (k) break;
        check("xhx tcp json: no xhx", "(null)", got ? xhx_of(&out[0]) : "");
        check("xhx tcp json: no xhttp headers", "", got ? out[0].headers : "x");
    }
    check("xhx json: network after xhttpSettings still read", "seqPlacement=cookie\n", got ? xhx_of(&out[0]) : "");
}

static void t_xhx_embedded_nul_is_refused(void) {
    struct vless_node n;
    xhx_link("", "{\"sessionIDKey\":\"a\\u0000b\"}", &n);
    check("xhx embedded NUL: refused", "xhttp: invalid extra value", n.skip_reason);
}

static void t_xhx_range_object_needs_numeric_from_and_to(void) {
    struct vless_node n;
    xhx_link("", "{\"uplinkChunkSize\":{\"from\":300}}", &n);
    check("xhx range object without to: refused", "xhttp: invalid extra value", n.skip_reason);
    xhx_link("", "{\"uplinkChunkSize\":{\"from\":true,\"to\":400}}", &n);
    check("xhx range object with a non-number: refused", "xhttp: invalid extra value", n.skip_reason);
    xhx_link("", "{\"sessionIDLength\":{\"to\":16}}", &n);
    check("xhx range object without from: refused", "xhttp: invalid extra value", n.skip_reason);
}

static const char *xhx_no_room(const char *v, size_t len) {
    (void)v; (void)len;
    return NULL;
}

static void t_xhx_full_intern_table_is_named(void) {
    struct vless_node n;
    sl_set_interner(xhx_no_room);
    xhx_link("", "{\"seqPlacement\":\"query\"}", &n);
    sl_set_interner(NULL);
    check("xhx full table: marker", "(full)", xhx_of(&n));
    check("xhx full table: reason", "too many distinct keys", n.skip_reason);
}

static void t_xhx_no_grpc_header_from_every_format(void) {
    struct vless_node n, out[4];
    struct vless_sub_stats st;
    /* catches: noGRPCHeader dropped by the collector of one format, or out of the canonical order */
    xhx_link("&mode=stream-up", "{\"noGRPCHeader\":true,\"seqKey\":\"q\"}", &n);
    check("xhx noGRPCHeader link: kept after the other keys", "seqKey=q\nnoGRPCHeader=true\n", xhx_of(&n));
    size_t got = xhx_xray("{\"path\":\"/x\",\"mode\":\"stream-up\",\"noGRPCHeader\":false}", out, &st);
    check("xhx noGRPCHeader xray: kept", "noGRPCHeader=false\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    got = xhx_clash("      mode: stream-up\n      no-grpc-header: true\n", out, &st);
    check("xhx noGRPCHeader clash: mapped", "noGRPCHeader=true\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    /* catches: a non-bool noGRPCHeader listed as usable, or its reason not naming the key */
    xhx_link("", "{\"noGRPCHeader\":\"yes\"}", &n);
    check("xhx noGRPCHeader link yes: reason", "xhttp: unsupported noGRPCHeader: yes", n.skip_reason);
    check("xhx noGRPCHeader xray 1: reason", "xhttp: unsupported noGRPCHeader: 1",
          xhx_reason(xhx_xray("{\"path\":\"/x\",\"noGRPCHeader\":1}", out, &st), &st));
    check("xhx noGRPCHeader clash maybe: reason", "xhttp: unsupported noGRPCHeader: maybe",
          xhx_reason(xhx_clash("      no-grpc-header: maybe\n", out, &st), &st));
    xhx_link("", "{\"noGRPCHeader\":[true]}", &n);
    check("xhx noGRPCHeader array: refused", "xhttp: invalid extra value", n.skip_reason);
}

static void t_xhx_server_max_header_bytes_from_link_and_xray(void) {
    struct vless_node n, out[4];
    struct vless_sub_stats st;
    /* catches: serverMaxHeaderBytes dropped by the link or Xray JSON collector */
    xhx_link("&mode=packet-up", "{\"serverMaxHeaderBytes\":4096,\"noGRPCHeader\":true}", &n);
    check("xhx serverMaxHeaderBytes link: kept after noGRPCHeader", "noGRPCHeader=true\nserverMaxHeaderBytes=4096\n",
          xhx_of(&n));
    size_t got = xhx_xray("{\"path\":\"/x\",\"serverMaxHeaderBytes\":\"6000\"}", out, &st);
    check("xhx serverMaxHeaderBytes xray: kept", "serverMaxHeaderBytes=6000\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    /* catches: a bad serverMaxHeaderBytes listed as usable */
    xhx_link("", "{\"serverMaxHeaderBytes\":-5}", &n);
    check("xhx serverMaxHeaderBytes -5: reason", "xhttp: unsupported serverMaxHeaderBytes: -5", n.skip_reason);
    check("xhx serverMaxHeaderBytes xray true: reason", "xhttp: unsupported serverMaxHeaderBytes: true",
          xhx_reason(xhx_xray("{\"path\":\"/x\",\"serverMaxHeaderBytes\":true}", out, &st), &st));
}

static void t_xhx_min_posts_interval_from_link_and_xray(void) {
    struct vless_node n, out[4];
    struct vless_sub_stats st;
    /* catches: scMinPostsIntervalMs dropped, or its number, string or object form not read as a range */
    check_n("xhx scMinPostsIntervalMs link: usable", 0,
            xhx_link("&mode=packet-up", "{\"scMinPostsIntervalMs\":30,\"serverMaxHeaderBytes\":4096}", &n));
    check("xhx scMinPostsIntervalMs link: kept last", "serverMaxHeaderBytes=4096\nscMinPostsIntervalMs=30\n", xhx_of(&n));
    xhx_link("&mode=packet-up", "{\"scMinPostsIntervalMs\":{\"from\":10,\"to\":50}}", &n);
    check("xhx scMinPostsIntervalMs object: a range", "scMinPostsIntervalMs=10-50\n", xhx_of(&n));
    size_t got = xhx_xray("{\"path\":\"/x\",\"mode\":\"packet-up\",\"scMinPostsIntervalMs\":\"20-40\"}", out, &st);
    check("xhx scMinPostsIntervalMs xray: kept", "scMinPostsIntervalMs=20-40\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    /* catches: a negative scMinPostsIntervalMs, which Xray takes as pacing off, making the node unusable */
    check_n("xhx scMinPostsIntervalMs -1: usable", 0, xhx_link("&mode=packet-up", "{\"scMinPostsIntervalMs\":-1}", &n));
    check("xhx scMinPostsIntervalMs -1: kept", "scMinPostsIntervalMs=-1\n", xhx_of(&n));
    got = xhx_xray("{\"path\":\"/x\",\"mode\":\"packet-up\",\"scMinPostsIntervalMs\":\"-5--1\"}", out, &st);
    check("xhx scMinPostsIntervalMs xray -5--1: kept", "scMinPostsIntervalMs=-5--1\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    /* catches: a bad scMinPostsIntervalMs listed as usable */
    xhx_link("", "{\"scMinPostsIntervalMs\":\"soon\"}", &n);
    check("xhx scMinPostsIntervalMs soon: reason", "xhttp: unsupported scMinPostsIntervalMs: soon", n.skip_reason);
    xhx_link("", "{\"scMinPostsIntervalMs\":{\"from\":10}}", &n);
    check("xhx scMinPostsIntervalMs object without to: refused", "xhttp: invalid extra value", n.skip_reason);
}

static void t_xhx_all(void) {
    t_xhx_keys_fold_case_like_go();
    t_xhx_min_posts_interval_from_link_and_xray();
    t_xhx_server_max_header_bytes_from_link_and_xray();
    t_xhx_no_grpc_header_from_every_format();
    t_xhx_line_that_fills_the_buffer_exactly_is_refused();
    t_xhx_null_extra_resets_to_defaults_keeping_path();
    t_xhx_settings_reach_only_xhttp_nodes();
    t_xhx_embedded_nul_is_refused();
    t_xhx_range_object_needs_numeric_from_and_to();
    t_xhx_full_intern_table_is_named();
    t_xhx_link_keeps_supported_keys_in_order_and_pad_from_extra();
    t_xhx_link_ranges_from_number_and_object();
    t_xhx_settings_over_the_buffer_are_refused();
    t_xhx_long_extra_read_whole_and_cut_one_does_not_parse();
    t_xhx_xray_json_nested_extra_replaces_top_level();
    t_xhx_clash_maps_kebab_keys_and_download_settings();
    t_xhx_clash_every_key_reaches_its_xray_name();
    t_xhx_hostile_value_refused_in_every_format();
    t_xhx_data_in_cookie_needs_packet_up();
    t_xhx_headers_reach_the_node_and_host_is_refused();
}

static void t_intern_blob(void) {
    struct vless_node a, b, c, d;
    memset(&a, 0, sizeof a);
    strcpy(a.host, "a.example");
    b = a;
    c = a;
    c.sni[0] = 'x';
    d = a;
    d.host[20] = 'z';
    const char *pa = (const char *)sl_intern_node(&a), *pb = (const char *)sl_intern_node(&b);
    const char *pc = (const char *)sl_intern_node(&c), *pd = (const char *)sl_intern_node(&d);
    /* catches: a blob compared by strlen (every node blob has strlen 0) */
    check_n("intern blob: equal nodes share one pointer", 1, pa && pa == pb && !memcmp(pa, &a, sizeof a));
    check_n("intern blob: a byte in sni gives another pointer", 1, pc && pc != pa);
    check_n("intern blob: a byte after the NUL of host gives another pointer", 1, pd && pd != pa && pd != pc);
    sl_intern_reset();
}

static void t_intern_blob_full(void) {
    struct vless_node n;
    memset(&n, 0, sizeof n);
    int ok = 1;
    for (int i = 1; i <= 512; i++) {
        n.port = (uint16_t)i;
        if (!sl_intern_node(&n)) ok = 0;
    }
    n.port = 513;
    /* catches: SL_FULL returned as a pointer to a node, or no bound */
    check_n("intern blob full: 512 accepted", 1, ok);
    check_n("intern blob full: the 513th is NULL", 1, sl_intern_node(&n) == NULL);
    sl_intern_reset();
    check_n("intern blob full: after reset the 513th is accepted", 1, sl_intern_node(&n) != NULL);
    sl_intern_reset();
}

static size_t g_hook_n;

static const char *hook_echo(const char *v, size_t len) {
    g_hook_n = len;
    return v;
}

static void t_intern_node_hook(void) {
    struct vless_node a;
    memset(&a, 0, sizeof a);
    strcpy(a.host, "h.example");
    sl_set_interner(hook_echo);
    const struct vless_node *echo = sl_intern_node(&a);
    size_t seen = g_hook_n;
    sl_set_interner(xhx_no_room);
    const struct vless_node *none = sl_intern_node(&a);
    sl_set_interner(NULL);
    /* catches: the hook bypassed for node blobs, or its NULL turned into a pointer */
    check_n("intern node hook: the hook's pointer is returned", 1, echo == &a);
    check_n("intern node hook: the whole node goes to the hook", (long)sizeof a, (long)seen);
    check_n("intern node hook: NULL from the hook passes through", 1, none == NULL);
}

#define DL_PBK "Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"
#define DL_D "{\"address\":\"d.example\",\"port\":8443,\"network\":\"xhttp\",\"security\":\"tls\",\"tlsSettings\":" \
             "{\"serverName\":\"dl.example\",\"fingerprint\":\"firefox\"},\"xhttpSettings\":{\"host\":\"cdn.example\"," \
             "\"path\":\"/dl?k=v\",\"xPaddingBytes\":\"20-40\",\"sessionIDPlacement\":\"header\",\"headers\":{\"X-D\":\"1\"}}}"
#define DL_B(h) "{\"address\":\"" h "\",\"port\":443,\"network\":\"xhttp\"}"
#define DL_TLS(tls) "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"security\":\"tls\"," \
                    "\"tlsSettings\":{\"serverName\":\"dl.example\"" tls "}}"
#define DL_X(x) "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"xhttpSettings\":" x "}"

static const struct vless_node g_no_dl;

static const struct vless_node *dl_of(const struct vless_node *n) {
    return n->dl && n->dl != &SL_DL_FULL ? n->dl : &g_no_dl;
}

static const char *dl_host(const struct vless_node *n) {
    return !n->dl ? "(none)" : n->dl == &SL_DL_FULL ? "(full)" : n->dl->host;
}

static int dl_link_as(const char *main, const char *json, struct vless_node *n) {
    static char url[16384];
    size_t o = (size_t)snprintf(url, sizeof url, "vless://" XHU "@m.example:443?%s&extra=", main);
    for (const unsigned char *p = (const unsigned char *)json; *p && o + 4 < sizeof url; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) url[o++] = (char)*p;
        else o += (size_t)snprintf(url + o, sizeof url - o, "%%%02X", *p);
    }
    snprintf(url + o, sizeof url - o, "#d");
    return vless_parse_url(url, n);
}

static int dl_link_json(const char *json, struct vless_node *n) {
    return dl_link_as("type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=packet-up", json, n);
}

static int dl_link(const char *block, struct vless_node *n) {
    static char js[8192];
    snprintf(js, sizeof js, "{\"downloadSettings\":%s}", block);
    return dl_link_json(js, n);
}

static struct vless_node g_dl_last;

static void dl_hook(void *ud, const struct vless_node *n, const char *why) {
    (void)ud;
    (void)why;
    g_dl_last = *n;
}

static const char *dl_xray(const char *xhttp) {
    struct vless_node out[4];
    static struct vless_sub_stats st;
    memset(&g_dl_last, 0, sizeof g_dl_last);
    vless_set_node_hook(dl_hook, NULL);
    size_t got = xhx_xray(xhttp, out, &st);
    vless_set_node_hook(NULL, NULL);
    return xhx_reason(got, &st);
}

static void t_dl_no_grpc_header_in_the_block(void) {
    struct vless_node n;
    /* catches: noGRPCHeader dropped from a download block, or a bad one there not refusing the node */
    dl_link(DL_X("{\"noGRPCHeader\":true}"), &n);
    check("dl noGRPCHeader: block xhx", "noGRPCHeader=true\n", xhx_of(dl_of(&n)));
    dl_link(DL_X("{\"noGRPCHeader\":\"x\"}"), &n);
    check("dl noGRPCHeader x: reason", "downloadSettings: xhttp: unsupported noGRPCHeader: x", n.skip_reason);
}

static void t_dl_link_extra(void) {
    struct vless_node n;
    int rc = dl_link(DL_D, &n);
    const struct vless_node *d = dl_of(&n);
    /* catches: block fields landing on the main node, or the block dropped */
    check_n("dl link: usable, as Xray takes a download block", 0, rc);
    check("dl link: reason", "", n.skip_reason);
    check("dl link: block host", "d.example", dl_host(&n));
    check_n("dl link: block port", 8443, d->port);
    check("dl link: block type", "xhttp", d->type);
    check("dl link: block security", "tls", d->security);
    check("dl link: block sni", "dl.example", d->sni);
    check("dl link: block fp", "firefox", d->fp);
    check("dl link: block http_host", "cdn.example", d->http_host);
    check("dl link: block path", "/dl?k=v", d->path);
    check_n("dl link: block pad lower", 20, d->pad_from);
    check_n("dl link: block pad upper", 40, d->pad_to);
    check("dl link: block xhx", "sessionIDPlacement=header\n", xhx_of(d));
    check("dl link: block headers", "X-D: 1\n", d->headers);
    check("dl link: block mode", "", d->mode);
    check_n("dl link: block has no block", 1, d->dl == NULL);
    check("dl link: block reason", "", d->skip_reason);
    check("dl link: main host", "m.example", n.host);
    check_n("dl link: main pad untouched", 0, n.pad_to);
    check("dl link: main headers untouched", "", n.headers);
}

static void t_dl_xray_json(void) {
    const char *why = dl_xray("{\"path\":\"/x\",\"mode\":\"packet-up\",\"downloadSettings\":{\"address\":\"[2001:db8::5]\","
                              "\"port\":\"8443\",\"network\":\"splithttp\",\"security\":\"reality\",\"realitySettings\":"
                              "{\"serverName\":\"r.example\",\"publicKey\":\"" DL_PBK "\",\"shortId\":\"ab\"}}}");
    const struct vless_node *d = dl_of(&g_dl_last);
    /* catches: a string port, a bracketed address or splithttp refused */
    check("dl xray: usable, as Xray takes a download block", "(usable)", why);
    check("dl xray: block host unbracketed", "2001:db8::5", dl_host(&g_dl_last));
    check_n("dl xray: block port from a string", 8443, d->port);
    check("dl xray: splithttp is xhttp", "xhttp", d->type);
    check("dl xray: block pbk", DL_PBK, d->pbk);
    check("dl xray: block sid", "ab", d->sid);
    check("dl xray: block sni", "r.example", d->sni);
    check("dl xray: block reason", "", d->skip_reason);
}

static void t_dl_extra_wins(void) {
    struct vless_node n;
    /* catches: the outer block kept when extra replaces the settings, or the first heap block leaked */
    dl_xray("{\"path\":\"/x\",\"downloadSettings\":" DL_B("outer.example") ",\"extra\":{\"downloadSettings\":"
            DL_B("inner.example") "}}");
    check("dl extra after block: extra's block", "inner.example", dl_host(&g_dl_last));
    dl_xray("{\"path\":\"/x\",\"extra\":{\"downloadSettings\":" DL_B("inner.example") "},\"downloadSettings\":"
            DL_B("outer.example") "}");
    check("dl extra before block: extra's block", "inner.example", dl_host(&g_dl_last));
    const char *why = dl_xray("{\"path\":\"/x\",\"downloadSettings\":" DL_B("outer.example") ",\"extra\":{\"seqPlacement\":\"cookie\"}}");
    check("dl extra without a block: no block", "(none)", dl_host(&g_dl_last));
    check("dl extra without a block: usable", "(usable)", why);
    dl_xray("{\"path\":\"/x\",\"extra\":{\"downloadSettings\":" DL_B("one.example") "},\"extra\":{\"downloadSettings\":"
            DL_B("two.example") "}}");
    check("dl two extras: the second's block", "two.example", dl_host(&g_dl_last));
    dl_link_json("{\"downloadSettings\":" DL_B("one.example") ",\"downloadSettings\":" DL_B("two.example") "}", &n);
    check("dl repeated key: the second block", "two.example", dl_host(&n));
    dl_link_json("{\"downloadSettings\":" DL_B("one.example") ",\"downloadSettings\":null}", &n);
    check("dl repeated key: null drops the first", "(none)", dl_host(&n));
    static char js[2048];
    struct vless_node out[4];
    struct vless_sub_stats st;
    snprintf(js, sizeof js,
             "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"address\":\"example.org\",\"port\":443,\"id\":\"" XHU "\"},"
             "\"streamSettings\":{\"network\":\"xhttp\",\"xhttpSettings\":{\"downloadSettings\":" DL_B("one.example") "},"
             "\"xhttpSettings\":{\"downloadSettings\":" DL_B("two.example") "}}}]}");
    memset(&g_dl_last, 0, sizeof g_dl_last);
    vless_set_node_hook(dl_hook, NULL);
    memset(&st, 0, sizeof st);
    vless_parse_sub(js, out, 4, &st);
    vless_set_node_hook(NULL, NULL);
    check("dl repeated xhttpSettings: the second block", "two.example", dl_host(&g_dl_last));
}

static void t_xhttp_host_main(void) {
    /* catches: main xhttpSettings.host still dropped, or read from extra */
    check("xhttp host main: usable", "(usable)", dl_xray("{\"host\":\"h.example\",\"path\":\"/p\"}"));
    check("xhttp host main: read", "h.example", g_dl_last.http_host);
    dl_xray("{\"path\":\"/p\",\"extra\":{\"host\":\"h.example\"}}");
    check("xhttp host in extra: not read", "", g_dl_last.http_host);
    dl_xray("{\"host\":\"h.example\",\"path\":\"/p\",\"extra\":{\"seqPlacement\":\"cookie\"}}");
    check("xhttp host with extra: the outer one", "h.example", g_dl_last.http_host);
}

static void t_dl_refusals(void) {
    static const char *const cases[][2] = {
        { "{\"port\":443,\"network\":\"xhttp\"}", "downloadSettings: no address" },
        { "{\"network\":\"ws\"}", "downloadSettings: no address" },
        { "{\"address\":\"d.example\",\"network\":\"xhttp\"}", "downloadSettings: no port" },
        { "{\"address\":\"d.example\",\"port\":443}", "downloadSettings: network tcp is not xhttp" },
        { "{\"address\":\"d.example\",\"port\":443,\"network\":\"ws\"}", "downloadSettings: network ws is not xhttp" },
        { "{\"address\":\"d.example\",\"port\":443,\"network\":\"ws\",\"finalmask\":{}}", "downloadSettings: network ws is not xhttp" },
        { "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"security\":\"xtls\"}",
          "downloadSettings: security=xtls is not supported" },
        { "{\"address\":\"192.0.2.7\",\"port\":443,\"network\":\"xhttp\",\"security\":\"tls\"}",
          "downloadSettings: tls to an IP address without sni: nothing to verify" },
        { "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"security\":\"reality\","
          "\"realitySettings\":{\"serverName\":\"r.example\"}}", "downloadSettings: reality without pbk" },
        { DL_B("0.0.0.0"), "downloadSettings: 0.0.0.0: nobody to answer" },
        { "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"quicParams\":{}}",
          "downloadSettings: quicParams is not supported" },
        { DL_TLS(",\"alpn\":[\"h3\"]"), "downloadSettings: alpn h3 is not supported" },
        { DL_TLS(",\"alpn\":[\"http/1.1\"]"), "downloadSettings: alpn http/1.1 is not supported" },
        { DL_TLS(",\"alpn\":\"h3\""), "downloadSettings: alpn h3 is not supported" },
        { DL_TLS(",\"alpn\":\"http/1.1\""), "downloadSettings: alpn http/1.1 is not supported" },
        { DL_TLS(",\"alpn\":[\"h3\",1]"), "downloadSettings: does not parse" },
        { "\"x\"", "downloadSettings: does not parse" },
        { DL_TLS(",\"allowInsecure\":true"), "downloadSettings: allowInsecure: needs --insecure" },
    };
    struct vless_node n;
    char name[80];
    vless_set_insecure(0);
    /* catches: any refusal missing, or a fallback to the main endpoint */
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        int rc = dl_link(cases[i][0], &n);
        snprintf(name, sizeof name, "dl refusal %zu: skipped", i);
        check_n(name, 1, rc);
        snprintf(name, sizeof name, "dl refusal %zu: reason", i);
        check(name, cases[i][1], n.skip_reason);
    }
}

static void t_dl_accepted(void) {
    static const char *const cases[] = {
        DL_TLS(",\"alpn\":[\"h2\",\"http/1.1\"]"),
        DL_TLS(",\"alpn\":[\"h3\",\"h2\"]"),
        DL_TLS(",\"alpn\":\"h3,h2\""),
        DL_X("{\"uplinkDataPlacement\":\"header\"}"),
        DL_X("{\"uplinkHTTPMethod\":\"GET\"}"),
        DL_X("{\"sessionIDTable\":\"hex\",\"sessionIDLength\":7,\"seqKey\":\"q\"}"),
        DL_X("{\"mode\":\"stream-one\"}"),
        DL_X("{\"mode\":\"stream-down\"}"),
        DL_X("{\"downloadSettings\":{\"address\":\"x.example\"}}"),
        "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"sockopt\":{\"mark\":5},\"xhttpSettings\":{\"xmux\":{}}}",
    };
    struct vless_node n;
    char name[80];
    /* catches: the download's own upload checks, id table, mode, sockopt or a nested block refusing it */
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        dl_link(cases[i], &n);
        snprintf(name, sizeof name, "dl accepted %zu: block reason", i);
        check(name, "", dl_of(&n)->skip_reason);
        snprintf(name, sizeof name, "dl accepted %zu: node reason", i);
        check(name, "", n.skip_reason);
        snprintf(name, sizeof name, "dl accepted %zu: block mode", i);
        check(name, "", dl_of(&n)->mode);
        snprintf(name, sizeof name, "dl accepted %zu: block host", i);
        check(name, "d.example", dl_host(&n));
    }
    dl_link(cases[5], &n);
    check("dl accepted: id table and length dropped", "seqKey=q\n", xhx_of(dl_of(&n)));
    dl_link(cases[8], &n);
    check_n("dl accepted: nested block ignored", 1, dl_of(&n)->dl == NULL);
    check_n("dl null: usable", 0, dl_link("null", &n));
    check("dl null: no block", "(none)", dl_host(&n));
    vless_set_insecure(1);
    dl_link(DL_TLS(",\"allowInsecure\":true"), &n);
    vless_set_insecure(0);
    check("dl insecure: block reason", "", dl_of(&n)->skip_reason);
    check_n("dl insecure: block not verified", 1, dl_of(&n)->insecure);
}

static void t_dl_stream_one_refused(void) {
    struct vless_node n;
    int tls = dl_link_as("type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=stream-one",
                         "{\"downloadSettings\":" DL_D "}", &n);
    /* catches: Xray's build-time refusal not copied */
    check_n("dl stream-one tls: skipped", 1, tls);
    check("dl stream-one tls: reason", "xhttp: downloadSettings cannot be used in stream-one mode", n.skip_reason);
    int rea = dl_link_as("type=xhttp&security=reality&pbk=" DL_PBK "&sni=m.example&path=%2Fxp&mode=stream-one",
                         "{\"downloadSettings\":" DL_D "}", &n);
    check_n("dl stream-one reality: skipped", 1, rea);
    check("dl stream-one reality: reason", "xhttp: downloadSettings cannot be used in stream-one mode", n.skip_reason);
    int one = dl_link_as("type=xhttp&security=reality&pbk=" DL_PBK "&sni=m.example&path=%2Fxp&mode=stream-one",
                         "{\"seqKey\":\"q\"}", &n);
    check_n("stream-one without a block: usable", 0, one);
    int au = dl_link_as("type=xhttp&security=reality&pbk=" DL_PBK "&sni=m.example&path=%2Fxp&mode=auto",
                        "{\"downloadSettings\":" DL_D "}", &n);
    check_n("dl auto reality: usable, Xray picks stream-up", 0, au);
}

static void t_dl_block_checked_as_packet_up(void) {
    struct vless_node n;
    int rc = dl_link_as("type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=stream-up",
                        "{\"downloadSettings\":" DL_X("{\"uplinkDataPlacement\":\"header\"}") "}", &n);
    /* catches: the block's xhttp keys checked under the main mode, where the GET side checks them as packet-up */
    check_n("dl packet-up check: usable under main stream-up", 0, rc);
    check("dl packet-up check: block reason", "", dl_of(&n)->skip_reason);
    check("dl packet-up check: block keys kept", "uplinkDataPlacement=header\n", xhx_of(dl_of(&n)));
    rc = dl_link_as("type=xhttp&security=tls&sni=m.example&path=%2Fxp&mode=stream-up",
                    "{\"downloadSettings\":" DL_X("{\"uplinkDataPlacement\":\"path\"}") "}", &n);
    check_n("dl packet-up check: a key the GET side refuses, skipped", 1, rc);
    check("dl packet-up check: its reason", "downloadSettings: xhttp: unsupported uplinkDataPlacement: path", n.skip_reason);
}

static void t_dl_full(void) {
    struct vless_node b, n;
    memset(&b, 0, sizeof b);
    sl_intern_reset();
    for (int i = 1; i <= 512; i++) {
        b.port = (uint16_t)i;
        sl_intern_node(&b);
    }
    int rc = dl_link(DL_D, &n);
    sl_intern_reset();
    /* catches: a full table read as a usable or empty block */
    check_n("dl full: skipped", 1, rc);
    check("dl full: marker", "(full)", dl_host(&n));
    check("dl full: reason", "too many distinct download blocks", n.skip_reason);
}

static void t_dl_shared(void) {
    struct vless_node a, b;
    dl_link(DL_D, &a);
    dl_link(DL_D, &b);
    /* catches: a block allocated per node */
    check_n("dl shared: one pointer for equal blocks", 1, a.dl && a.dl != &SL_DL_FULL && a.dl == b.dl);
}

#define DLC_MAIN "    server: m.example\n    port: 443\n    tls: true\n    servername: m.example\n    client-fingerprint: chrome\n"
#define DLC_B0 "\n        server: d.example\n        port: 8443\n"
#define DLC_PA "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define DLC_PB "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define DLC_E1 "AAj+DQAEAQIDBA=="
#define DLC_E2 "AAj+DQAEBQYHCA=="
#define DLC_PBK1 "A84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw"

static const char *dl_clash(const char *mainx, const char *mx, const char *block) {
    static char y[8192];
    struct vless_node out[4];
    static struct vless_sub_stats st;
    snprintf(y, sizeof y, "proxies:\n  - name: c\n    type: vless\n    uuid: " XHU "\n    network: xhttp\n%s"
             "    xhttp-opts:\n      path: /xp\n%s      download-settings:%s", mainx, mx, block);
    memset(&g_dl_last, 0, sizeof g_dl_last);
    memset(&st, 0, sizeof st);
    vless_set_node_hook(dl_hook, NULL);
    size_t got = vless_parse_sub(y, out, 4, &st);
    vless_set_node_hook(NULL, NULL);
    return xhx_reason(got, &st);
}

static void t_dl_clash(void) {
    const char *why = dl_clash(DLC_MAIN, "      host: h.example\n      headers: {X-M: \"2\"}\n      x-padding-bytes: 100-200\n"
                               "      session-placement: header\n      session-length: 16\n      seq-key: sq\n",
                               DLC_B0 "        tls: true\n        servername: dl.example\n        client-fingerprint: firefox\n"
                               "        fingerprint: " DLC_PB "\n        skip-cert-verify: false\n        alpn: [h2]\n"
                               "        ech-opts: {enable: true, config: \"" DLC_E2 "\"}\n        path: /dl\n"
                               "        host: cdn.example\n        headers: {X-D: \"1\"}\n        x-padding-bytes: 20-40\n"
                               "        session-placement: query\n        reuse-settings: {max-connections: 4}\n");
    const struct vless_node *d = dl_of(&g_dl_last);
    /* catches: the Clash block mapped to the wrong fields or not read */
    check("dl clash: usable, as mihomo takes download-settings", "(usable)", why);
    check("dl clash: block host", "d.example", dl_host(&g_dl_last));
    check_n("dl clash: block port", 8443, d->port);
    check("dl clash: block type", "xhttp", d->type);
    check("dl clash: block security", "tls", d->security);
    check("dl clash: block sni", "dl.example", d->sni);
    check("dl clash: block fp", "firefox", d->fp);
    check("dl clash: block pins", DLC_PB, d->pcs ? d->pcs : "(null)");
    check_n("dl clash: block not insecure", 0, d->allow_insecure);
    check("dl clash: block ech", DLC_E2, d->ech ? d->ech : "(null)");
    check("dl clash: block http_host", "cdn.example", d->http_host);
    check("dl clash: block path", "/dl", d->path);
    check("dl clash: block headers", "X-D: 1\n", d->headers);
    check_n("dl clash: pad from the main proxy, lower", 100, d->pad_from);
    check_n("dl clash: pad from the main proxy, upper", 200, d->pad_to);
    check("dl clash: xhttp keys from the main proxy", "sessionIDPlacement=header\nseqKey=sq\nxmux.maxConnections=4\n",
          xhx_of(d));
    check("dl clash: block mode", "", d->mode);
    check("dl clash: block uuid", "", d->uuid);
    check("dl clash: block name", "", d->name);
    check_n("dl clash: block has no block", 1, d->dl == NULL);
    check("dl clash: block reason", "", d->skip_reason);
    check("dl clash: main http_host", "h.example", g_dl_last.http_host);
    check("dl clash: main headers", "X-M: 2\n", g_dl_last.headers);
    check("dl clash: main host", "m.example", g_dl_last.host);
}

static void t_dl_clash_reality(void) {
    dl_clash(DLC_MAIN, "", DLC_B0 "        reality-opts: {public-key: " DL_PBK ", short-id: ab}\n");
    const struct vless_node *d = dl_of(&g_dl_last);
    /* catches: reality-opts of the block ignored */
    check("dl clash reality: security", "reality", d->security);
    check("dl clash reality: pbk", DL_PBK, d->pbk);
    check("dl clash reality: sid", "ab", d->sid);
    check("dl clash reality: block reason", "", d->skip_reason);
}

static char g_dlc_buf[160];

static const char *dlc_host(const struct vless_node *d) { return d->host; }
static const char *dlc_port(const struct vless_node *d) { snprintf(g_dlc_buf, sizeof g_dlc_buf, "%u", d->port); return g_dlc_buf; }
static const char *dlc_security(const struct vless_node *d) { return d->security; }
static const char *dlc_sni(const struct vless_node *d) { return d->sni; }
static const char *dlc_fp(const struct vless_node *d) { return d->fp; }
static const char *dlc_pcs(const struct vless_node *d) { return d->pcs ? d->pcs : "(null)"; }
static const char *dlc_insecure(const struct vless_node *d) { return d->allow_insecure ? "1" : "0"; }
static const char *dlc_ech(const struct vless_node *d) { return d->ech ? d->ech : "(null)"; }
static const char *dlc_reason(const struct vless_node *d) { return d->skip_reason; }
static const char *dlc_http_host(const struct vless_node *d) { return d->http_host; }
static const char *dlc_path(const struct vless_node *d) { return d->path; }
static const char *dlc_headers(const struct vless_node *d) { return d->headers; }
static const char *dlc_reality(const struct vless_node *d) {
    snprintf(g_dlc_buf, sizeof g_dlc_buf, "%s %s %s", d->security, d->pbk, d->sid);
    return g_dlc_buf;
}

static void dl_inherit(const char *field, const char *mainx, const char *mx, const char *without, const char *with,
                       const char *(*get)(const struct vless_node *), const char *mainv, const char *ownv) {
    char name[96];
    dl_clash(mainx, mx, without);
    snprintf(name, sizeof name, "dl clash inherits %s: the main value", field);
    check(name, mainv, get(dl_of(&g_dl_last)));
    dl_clash(mainx, mx, with);
    snprintf(name, sizeof name, "dl clash inherits %s: its own value", field);
    check(name, ownv, get(dl_of(&g_dl_last)));
}

static void t_dl_clash_inherits_server(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("server", DLC_MAIN, "", "\n        port: 8443\n", DLC_B0, dlc_host, "m.example", "d.example");
}

static void t_dl_clash_inherits_port(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("port", DLC_MAIN, "", "\n        server: d.example\n", DLC_B0, dlc_port, "443", "8443");
}

static void t_dl_clash_inherits_tls(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("tls", DLC_MAIN, "", DLC_B0, DLC_B0 "        tls: false\n", dlc_security, "tls", "none");
    dl_inherit("tls off", "    server: m.example\n    port: 443\n", "", DLC_B0 "        servername: dl.example\n",
               DLC_B0 "        servername: dl.example\n        tls: true\n", dlc_security, "none", "tls");
}

static void t_dl_clash_inherits_servername(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("servername", DLC_MAIN, "", DLC_B0, DLC_B0 "        servername: dl.example\n", dlc_sni, "m.example", "dl.example");
}

static void t_dl_clash_inherits_client_fingerprint(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("client-fingerprint", DLC_MAIN, "", DLC_B0, DLC_B0 "        client-fingerprint: firefox\n", dlc_fp,
               "chrome", "firefox");
}

static void t_dl_clash_inherits_fingerprint(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("fingerprint", DLC_MAIN "    fingerprint: " DLC_PA "\n", "", DLC_B0,
               DLC_B0 "        fingerprint: " DLC_PB "\n", dlc_pcs, DLC_PA, DLC_PB);
}

static void t_dl_clash_inherits_skip_cert_verify(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("skip-cert-verify", DLC_MAIN "    skip-cert-verify: true\n", "", DLC_B0,
               DLC_B0 "        skip-cert-verify: false\n", dlc_insecure, "1", "0");
}

static void t_dl_clash_inherits_ech_opts(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("ech-opts", DLC_MAIN "    ech-opts:\n      enable: true\n      config: \"" DLC_E1 "\"\n", "", DLC_B0,
               DLC_B0 "        ech-opts: {enable: true, config: \"" DLC_E2 "\"}\n", dlc_ech, DLC_E1, DLC_E2);
}

static void t_dl_clash_inherits_reality_opts(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("reality-opts", DLC_MAIN "    reality-opts:\n      public-key: " DLC_PBK1 "\n      short-id: aa\n", "",
               DLC_B0, DLC_B0 "        reality-opts: {public-key: " DL_PBK ", short-id: ab}\n", dlc_reality,
               "reality " DLC_PBK1 " aa", "reality " DL_PBK " ab");
    dl_inherit("reality-opts empty key", DLC_MAIN "    reality-opts:\n      public-key: " DLC_PBK1 "\n", "", DLC_B0,
               DLC_B0 "        reality-opts: {public-key: \"\"}\n", dlc_reality, "reality " DLC_PBK1 " ", "tls  ");
}

static void t_dl_clash_inherits_alpn(void) {
    /* catches: an alpn inherited from the main proxy refused, or the block's own h3 accepted */
    dl_inherit("alpn", DLC_MAIN "    alpn: [h3]\n", "", DLC_B0, DLC_B0 "        alpn: [h3]\n", dlc_reason,
               "", "alpn h3 is not supported");
}

static void t_dl_clash_inherits_host(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("host", DLC_MAIN, "      host: h.example\n", DLC_B0, DLC_B0 "        host: cdn.example\n", dlc_http_host,
               "h.example", "cdn.example");
}

static void t_dl_clash_inherits_path(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("path", DLC_MAIN, "", DLC_B0, DLC_B0 "        path: /dl\n", dlc_path, "/xp", "/dl");
}

static void t_dl_clash_inherits_headers(void) {
    /* catches: an inherited field left empty (refused) or a non-inherited one copied */
    dl_inherit("headers", DLC_MAIN, "      headers: {X-M: \"2\"}\n", DLC_B0, DLC_B0 "        headers: {X-D: \"1\"}\n",
               dlc_headers, "X-M: 2\n", "X-D: 1\n");
}

static void t_dl_clash_refusals(void) {
    static const char *const cases[][3] = {
        { DLC_MAIN, DLC_B0 "        tls: false\n        reality-opts: {public-key: " DL_PBK "}\n",
          "downloadSettings: reality requires tls" },
        { DLC_MAIN "    reality-opts:\n      public-key: " DL_PBK "\n", DLC_B0 "        tls: false\n",
          "downloadSettings: reality requires tls" },
        { DLC_MAIN, DLC_B0 "        reality-opts: {short-id: ab}\n", "downloadSettings: does not parse" },
        { DLC_MAIN, DLC_B0 "        alpn: h2\n", "downloadSettings: does not parse" },
        { DLC_MAIN, " x\n", "downloadSettings: does not parse" },
        { DLC_MAIN, "\n        server: 0.0.0.0\n", "downloadSettings: 0.0.0.0: nobody to answer" },
        { DLC_MAIN, DLC_B0 "        alpn:\n          - h3\n", "downloadSettings: alpn h3 is not supported" },
        { DLC_MAIN, DLC_B0 "        alpn: [http/1.1]\n", "downloadSettings: alpn http/1.1 is not supported" },
        { DLC_MAIN, DLC_B0 "        skip-cert-verify: true\n", "downloadSettings: allowInsecure: needs --insecure" },
    };
    char name[80];
    vless_set_insecure(0);
    /* catches: Clash refusals diverging from mihomo */
    for (size_t i = 0; i < sizeof cases / sizeof *cases; i++) {
        snprintf(name, sizeof name, "dl clash refusal %zu: reason", i);
        check(name, cases[i][2], dl_clash(cases[i][0], "", cases[i][1]));
    }
    static const char *const ok[] = {
        DLC_B0 "        alpn: [h3, h2]\n",
        DLC_B0 "        network: ws\n",
        DLC_B0 "        uplink-data-placement: header\n        mode: stream-one\n",
        "\n        port: 8443\n",
    };
    for (size_t i = 0; i < sizeof ok / sizeof *ok; i++) {
        snprintf(name, sizeof name, "dl clash accepted %zu: node reason", i);
        check(name, "(usable)", dl_clash(DLC_MAIN, "", ok[i]));
        snprintf(name, sizeof name, "dl clash accepted %zu: block reason", i);
        check(name, "", dl_of(&g_dl_last)->skip_reason);
    }
    check("dl clash null: usable", "(usable)", dl_clash(DLC_MAIN, "", " null\n"));
    check("dl clash null: no block", "(none)", dl_host(&g_dl_last));
}

static void t_xhttp_host_main_clash(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    size_t got = xhx_clash("      host: h.example\n", out, &st);
    /* catches: Clash main host still dropped */
    check("xhttp host main clash: usable", "(usable)", xhx_reason(got, &st));
    check("xhttp host main clash: read", "h.example", got ? out[0].http_host : "");
}

static void t_tr_nodes(void) {
    struct vless_node n;
    struct tr_node t, td;
    vless_set_insecure(1);
    dl_link(DL_TLS(",\"fingerprint\":\"chrome\",\"pinnedPeerCertSha256\":\"" DLC_PB "\",\"allowInsecure\":true"), &n);
    vless_set_insecure(0);
    const struct vless_node *d = dl_of(&n);
    /* catches: the fp override or the tls-only fields skipped on the download side */
    vless_set_fp("firefox");
    memset(&td, 0, sizeof td);
    sl_tr_nodes(&n, &t, &td);
    vless_set_fp(NULL);
    check_n("tr nodes: dl points at the download node", 1, t.dl == &td);
    check("tr nodes: download host", "d.example", td.host ? td.host : "(null)");
    check_n("tr nodes: download port", 443, td.port);
    check("tr nodes: download sni", "dl.example", td.sni ? td.sni : "(null)");
    check("tr nodes: override fp on the download", "firefox", td.fp ? td.fp : "(null)");
    check_n("tr nodes: download pins", 1, td.pcs && td.pcs == d->pcs);
    check_n("tr nodes: download insecure", 1, td.insecure);
    check("tr nodes: main host", "m.example", t.host);
    memset(&td, 0, sizeof td);
    sl_tr_nodes(&n, &t, &td);
    check("tr nodes: the download's own fp", "chrome", td.fp ? td.fp : "(null)");
    dl_link("null", &n);
    t.dl = &td;
    sl_tr_nodes(&n, &t, &td);
    check_n("tr nodes: no block, no dl", 1, t.dl == NULL);
}

static void t_dl_all(void) {
    t_intern_node_hook();
    t_dl_link_extra();
    t_dl_no_grpc_header_in_the_block();
    t_dl_xray_json();
    t_dl_extra_wins();
    t_xhttp_host_main();
    t_dl_refusals();
    t_dl_accepted();
    t_dl_stream_one_refused();
    t_dl_block_checked_as_packet_up();
    t_dl_full();
    t_tr_nodes();
    t_dl_shared();
    t_dl_clash();
    t_dl_clash_reality();
    t_dl_clash_inherits_server();
    t_dl_clash_inherits_port();
    t_dl_clash_inherits_tls();
    t_dl_clash_inherits_servername();
    t_dl_clash_inherits_client_fingerprint();
    t_dl_clash_inherits_fingerprint();
    t_dl_clash_inherits_skip_cert_verify();
    t_dl_clash_inherits_ech_opts();
    t_dl_clash_inherits_reality_opts();
    t_dl_clash_inherits_alpn();
    t_dl_clash_inherits_host();
    t_dl_clash_inherits_path();
    t_dl_clash_inherits_headers();
    t_dl_clash_refusals();
    t_xhttp_host_main_clash();
}

static void t_xmux_link_extra(void) {
    struct vless_node n;
    /* catches: xmux still dropped, or lines in input order */
    check_n("xmux link: usable", 0,
            xhx_link("", "{\"xmux\":{\"cMaxReuseTimes\":\"8\",\"maxConcurrency\":\"16-32\",\"hKeepAlivePeriod\":-1}}", &n));
    check("xmux link: canonical lines", "xmux.maxConcurrency=16-32\nxmux.cMaxReuseTimes=8\nxmux.hKeepAlivePeriod=-1\n",
          xhx_of(&n));
    xhx_link("", "{\"seqKey\":\"q\",\"xmux\":{\"hMaxReusableSecs\":\"10-20\",\"hMaxRequestTimes\":5,\"maxConnections\":2}}", &n);
    check("xmux link: after the other keys, every name", "seqKey=q\nxmux.maxConnections=2\nxmux.hMaxRequestTimes=5\n"
          "xmux.hMaxReusableSecs=10-20\n", xhx_of(&n));
    xhx_link("", "{\"xmux\":{\"hKeepAlivePeriod\":\"30\"}}", &n);
    check("xmux link: keepalive as a string refused", "xhttp: invalid extra value", n.skip_reason);
    check_n("xmux link: not an object", 1, xhx_link("", "{\"xmux\":5}", &n));
    check("xmux link: not an object, reason", "xhttp: extra does not parse", n.skip_reason);
    check_n("xmux link: null", 0, xhx_link("", "{\"xmux\":null,\"seqKey\":\"q\"}", &n));
    check("xmux link: null, nothing", "seqKey=q\n", xhx_of(&n));
}

static void t_xmux_xray_json(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    /* catches: Xray JSON xmux ignored, or the outer one kept over extra */
    size_t got = xhx_xray("{\"path\":\"/x\",\"xmux\":{\"maxConnections\":2}}", out, &st);
    check("xmux xray: outer", "xmux.maxConnections=2\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    got = xhx_xray("{\"path\":\"/x\",\"xmux\":{\"maxConnections\":2},\"extra\":{\"xmux\":{\"maxConnections\":5}}}", out, &st);
    check("xmux xray: extra replaces", "xmux.maxConnections=5\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    got = xhx_xray("{\"path\":\"/x\",\"xmux\":{}}", out, &st);
    check("xmux xray: empty", "(null)", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
}

static void t_xmux_block(void) {
    struct vless_node n;
    /* catches: the block's own xmux dropped or put on the main side */
    check_n("xmux block: usable", 0, dl_link(DL_X("{\"xmux\":{\"maxConnections\":1}}"), &n));
    check("xmux block: in the block", "xmux.maxConnections=1\n", xhx_of(dl_of(&n)));
    check("xmux block: not on the main side", "(null)", xhx_of(&n));
}

static void t_xmux_clash(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    /* catches: Clash reuse-settings still ignored */
    size_t got = xhx_clash("      reuse-settings:\n        max-connections: \"2\"\n        h-keep-alive-period: 30\n", out, &st);
    check("xmux clash: main", "xmux.maxConnections=2\nxmux.hKeepAlivePeriod=30\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    got = xhx_clash("      reuse-settings:\n        max-concurrency: 1-4\n        c-max-reuse-times: 3\n"
                    "        h-max-request-times: 9\n        h-max-reusable-secs: 5-6\n", out, &st);
    check("xmux clash: every key", "xmux.maxConcurrency=1-4\nxmux.cMaxReuseTimes=3\nxmux.hMaxRequestTimes=9\n"
          "xmux.hMaxReusableSecs=5-6\n", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    got = xhx_clash("      mode: packet-up\n", out, &st);
    check("xmux clash: none", "(null)", got ? xhx_of(&out[0]) : xhx_reason(got, &st));
    check("xmux clash block: usable", "(usable)",
          dl_clash(DLC_MAIN, "", DLC_B0 "        reuse-settings:\n          max-concurrency: \"8\"\n"));
    check("xmux clash block: in the block", "xmux.maxConcurrency=8\n", xhx_of(dl_of(&g_dl_last)));
    check("xmux clash block: not on the main side", "(null)", xhx_of(&g_dl_last));
    dl_clash(DLC_MAIN, "      seq-key: sq\n      reuse-settings: {max-connections: 2}\n", DLC_B0);
    check("xmux clash block: the main's when the block has none", "seqKey=sq\nxmux.maxConnections=2\n",
          xhx_of(dl_of(&g_dl_last)));
    dl_clash(DLC_MAIN, "      seq-key: sq\n      reuse-settings: {max-connections: 2}\n",
             DLC_B0 "        reuse-settings: {h-max-request-times: 7}\n");
    check("xmux clash block: its own replaces the main's", "seqKey=sq\nxmux.hMaxRequestTimes=7\n", xhx_of(dl_of(&g_dl_last)));
    check("xmux clash block: the main keeps its own", "seqKey=sq\nxmux.maxConnections=2\n", xhx_of(&g_dl_last));
}

static void t_xmux_node_refused(void) {
    struct vless_node n;
    /* catches: the refusal not reaching the node row */
    check_n("xmux both: skipped", 1, xhx_link("", "{\"xmux\":{\"maxConcurrency\":4,\"maxConnections\":2}}", &n));
    check("xmux both: reason", "xhttp: maxConnections cannot be specified together with maxConcurrency", n.skip_reason);
    check_n("xmux 40: usable", 0, xhx_link("", "{\"xmux\":{\"maxConnections\":40}}", &n));
}

static void t_xmux_all(void) {
    t_xmux_link_extra();
    t_xmux_xray_json();
    t_xmux_block();
    t_xmux_clash();
    t_xmux_node_refused();
}

#define FM_FRAG "{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"packets\":\"tlshello\",\"length\":\"10-20\"}}]}"
#define FM_FRAG_WS "{ \"tcp\" : [ { \"type\" : \"fragment\" ,\n \"settings\" : { \"packets\" : \"tlshello\" , \"length\" : \"10-20\" } } ] }"
#define FM_SUDOKU "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"ascii\":\"bogus\"}}]}"
#define FM_XMC "{\"tcp\":[{\"type\":\"xmc\",\"settings\":{}}]}"
#define FM_FILTER "{\"tcp\":[{\"type\":\"filter\",\"settings\":{\"allowedSourceIPs\":[\"10.0.0.1\"]}}]}"
#define FM_HC "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":{\"clients\":[[{\"packet\":\"GET / HTTP/1.1\\r\\n\\r\\n\",\"type\":\"str\"}]]}}]}"
#define FM_HC_WS "{ \"tcp\": [ { \"type\": \"header-custom\", \"settings\": { \"clients\": [ [ { \"packet\": \"GET / HTTP/1.1\\r\\n\\r\\n\", \"type\": \"str\" } ] ] } } ] }"
#define DL_FM(fm) "{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\",\"finalmask\":" fm "}"
#define FM_MAIN_Q "type=xhttp&security=tls&sni=m.example&path=/xp&mode=packet-up"

static const char *fm_of(const struct vless_node *n) {
    return !n->fm ? "(null)" : n->fm == SL_BAD_FM ? "(bad)" : n->fm == SL_FULL ? "(full)" : n->fm;
}

static const char *fm_pct(const char *s) {
    static char b[4][16384];
    static unsigned at;
    char *o = b[at++ & 3];
    size_t k = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p && k + 4 < sizeof b[0]; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9')) o[k++] = (char)*p;
        else k += (size_t)snprintf(o + k, sizeof b[0] - k, "%%%02X", *p);
    }
    o[k] = '\0';
    return o;
}

static int fm_link(struct vless_node *n, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static int fm_link(struct vless_node *n, const char *fmt, ...) {
    static char q[40000], url[40100];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(q, sizeof q, fmt, ap);
    va_end(ap);
    snprintf(url, sizeof url, "vless://" XHU "@h.example:443?%s#f", q);
    return vless_parse_url(url, n);
}

static const char *fm_xray(const char *stream) {
    static char js[16384];
    static struct vless_sub_stats st;
    struct vless_node out[4];
    snprintf(js, sizeof js,
             "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"example.org\","
             "\"port\":443,\"users\":[{\"id\":\"" XHU "\"}]}]},\"streamSettings\":{%s}}]}", stream);
    memset(&st, 0, sizeof st);
    memset(&g_dl_last, 0, sizeof g_dl_last);
    vless_set_node_hook(dl_hook, NULL);
    size_t got = vless_parse_sub(js, out, 4, &st);
    vless_set_node_hook(NULL, NULL);
    return xhx_reason(got, &st);
}

static void t_fm_link(void) {
    struct vless_node n;
    /* catches: fm= ignored (today's sublink.c:799), or a refused type dialed */
    check_n("fm link: fragment usable", 0, fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%s", fm_pct(FM_FRAG)));
    check("fm link: fragment compact", FM_FRAG, fm_of(&n));
    const char *first = n.fm;
    check_n("fm link: spaced usable", 0, fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%s", fm_pct(FM_FRAG_WS)));
    check("fm link: spaced compacted", FM_FRAG, fm_of(&n));
    check_n("fm link: spaced interned once", 1, n.fm == first);
    check_n("fm link: sudoku skipped", 1, fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%s", fm_pct(FM_SUDOKU)));
    check("fm link: sudoku reason", "finalmask: sudoku: invalid sudoku ascii mode: bogus", n.skip_reason);
    check_n("fm link: %7B skipped", 1, fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%%7B"));
    check("fm link: %7B reason", "finalmask: does not parse", n.skip_reason);
    check_n("fm link: empty tcp usable", 0, fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%s", fm_pct("{\"tcp\":[]}")));
    check("fm link: empty tcp carries nothing", "(null)", fm_of(&n));
    check_n("fm link: filter usable", 0, fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%s", fm_pct(FM_FILTER)));
    check("fm link: filter carried", FM_FILTER, fm_of(&n));
    check_n("fm link: no fm, no mask", 0, fm_link(&n, "type=tcp&security=tls&sni=h.example"));
    check("fm link: no fm carries nothing", "(null)", fm_of(&n));
    check_n("fm link: bad then good, last wins", 0,
            fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%s&fm=%s", fm_pct(FM_SUDOKU), fm_pct(FM_FRAG)));
    check("fm link: bad then good, the good mask", FM_FRAG, fm_of(&n));
    check("fm link: bad then good, no stale reason", "", n.skip_reason);
    check_n("fm link: good then bad, last wins", 1,
            fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%s&fm=%s", fm_pct(FM_FRAG), fm_pct(FM_XMC)));
    check("fm link: good then bad, reason", "finalmask: xmc is not supported yet", n.skip_reason);
}

static void t_fm_xray_json(void) {
    /* catches: the main node's finalmask still skipped (sub.c:615) */
    check("fm xray: header-custom usable", "(usable)", fm_xray("\"network\":\"tcp\",\"security\":\"none\",\"finalmask\": " FM_HC_WS));
    check("fm xray: compact, escapes as written", FM_HC, fm_of(&g_dl_last));
    check("fm xray: xmc skipped", "finalmask: xmc is not supported yet",
          fm_xray("\"network\":\"tcp\",\"security\":\"none\",\"finalmask\":" FM_XMC));
    check("fm xray: null usable", "(usable)", fm_xray("\"network\":\"tcp\",\"security\":\"none\",\"finalmask\":null"));
    check("fm xray: null carries nothing", "(null)", fm_of(&g_dl_last));
    check("fm xray: before network", "(usable)", fm_xray("\"finalmask\":" FM_FRAG ",\"network\":\"tcp\""));
    check("fm xray: before network, carried", FM_FRAG, fm_of(&g_dl_last));
    check("fm xray: string value", "finalmask: invalid finalmask",
          fm_xray("\"network\":\"tcp\",\"finalmask\":\"x\""));
    check("fm xray: finalMask key", "finalmask: sudoku: invalid sudoku ascii mode: bogus",
          fm_xray("\"network\":\"tcp\",\"finalMask\":" FM_SUDOKU));
    check("fm xray: FINALMASK key", "finalmask: sudoku: invalid sudoku ascii mode: bogus",
          fm_xray("\"network\":\"tcp\",\"FINALMASK\":" FM_SUDOKU));
    check("fm xray: FinalMask key carried", "(usable)", fm_xray("\"network\":\"tcp\",\"FinalMask\":" FM_FRAG));
    check("fm xray: FinalMask key, mask", FM_FRAG, fm_of(&g_dl_last));
    check("fm xray: block finalMask key", "downloadSettings: finalmask: sudoku: invalid sudoku ascii mode: bogus",
          fm_xray("\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/x\",\"downloadSettings\":{\"address\":"
                  "\"d.example\",\"port\":443,\"network\":\"xhttp\",\"finalMask\":" FM_SUDOKU "}}"));
}

static void t_fm_dl(void) {
    static const char *const blocks[3] = { DL_FM("{}"), DL_FM(FM_FRAG), DL_FM(FM_SUDOKU) };
    struct vless_node n;
    char js[1024], name[96];
    /* catches: the download block inheriting the main mask */
    for (int path = 0; path < 3; path++) {
        static const char *const pn[3] = { "link extra", "xray block", "xray extra" };
        const char *why[3];
        const struct vless_node *d[3];
        for (int i = 0; i < 3; i++) {
            if (path == 0) {
                int rc = dl_link(blocks[i], &n);
                why[i] = rc ? n.skip_reason : "(usable)";
                g_dl_last = n;
            } else {
                snprintf(js, sizeof js, path == 1 ? "{\"path\":\"/x\",\"downloadSettings\":%s}"
                                                  : "{\"path\":\"/x\",\"extra\":{\"downloadSettings\":%s}}", blocks[i]);
                why[i] = dl_xray(js);
            }
            snprintf(name, sizeof name, "fm dl %s %d: main mask", pn[path], i);
            check(name, "(null)", fm_of(&g_dl_last));
            d[i] = dl_of(&g_dl_last);
            if (i == 0) {
                snprintf(name, sizeof name, "fm dl %s: {} usable", pn[path]);
                check(name, "(usable)", why[0]);
                snprintf(name, sizeof name, "fm dl %s: {} carries nothing", pn[path]);
                check(name, "(null)", fm_of(d[0]));
                snprintf(name, sizeof name, "fm dl %s: {} block host", pn[path]);
                check(name, "d.example", dl_host(&g_dl_last));
            } else if (i == 1) {
                snprintf(name, sizeof name, "fm dl %s: fragment usable", pn[path]);
                check(name, "(usable)", why[1]);
                snprintf(name, sizeof name, "fm dl %s: fragment on the block", pn[path]);
                check(name, FM_FRAG, fm_of(d[1]));
            } else {
                snprintf(name, sizeof name, "fm dl %s: sudoku refused", pn[path]);
                check(name, "downloadSettings: finalmask: sudoku: invalid sudoku ascii mode: bogus", why[2]);
            }
        }
    }
    snprintf(js, sizeof js, FM_MAIN_Q "&fm=%s", fm_pct(FM_FRAG));
    check_n("fm dl: main mask, plain block usable", 0, dl_link_as(js, "{\"downloadSettings\":" DL_B("d.example") "}", &n));
    check("fm dl: main mask kept", FM_FRAG, fm_of(&n));
    check("fm dl: plain block not masked", "(null)", fm_of(dl_of(&n)));
    check("fm dl xray: main mask, plain block usable", "(usable)",
          fm_xray("\"network\":\"xhttp\",\"finalmask\":" FM_FRAG ",\"xhttpSettings\":{\"path\":\"/x\",\"downloadSettings\":"
                  DL_B("d.example") "}"));
    check("fm dl xray: main mask kept", FM_FRAG, fm_of(&g_dl_last));
    check("fm dl xray: plain block not masked", "(null)", fm_of(dl_of(&g_dl_last)));
}

static void fm_own_case(const char *what, const char *main, const char *block, const char *want_node,
                        const char *want_block) {
    char name[128], blk[1024];
    struct vless_node n;
    snprintf(blk, sizeof blk, "{\"downloadSettings\":{\"address\":\"d.example\",\"port\":443,\"network\":\"xhttp\","
                              "\"finalmask\":%s}}", block);
    for (int order = 0; order < 4; order++) {
        static const char *const on[4] = { "xray fm first", "xray fm last", "link fm first", "link fm last" };
        static char st[4096];
        const char *why;
        if (order < 2) {
            if (order == 0)
                snprintf(st, sizeof st, "\"network\":\"xhttp\",\"finalmask\":%s,\"xhttpSettings\":{\"path\":\"/x\",%s",
                         main, blk + 1);
            else
                snprintf(st, sizeof st, "\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/x\",%s,\"finalmask\":%s",
                         blk + 1, main);
            why = fm_xray(st);
            n = g_dl_last;
        } else {
            static char q[16384];
            if (order == 2) snprintf(q, sizeof q, FM_MAIN_Q "&fm=%s&extra=%s", fm_pct(main), fm_pct(blk));
            else snprintf(q, sizeof q, FM_MAIN_Q "&extra=%s&fm=%s", fm_pct(blk), fm_pct(main));
            why = fm_link(&n, "%s", q) ? n.skip_reason : "(usable)";
        }
        snprintf(name, sizeof name, "fm own %s, %s: node reason", what, on[order]);
        check(name, want_node, why);
        snprintf(name, sizeof name, "fm own %s, %s: block reason", what, on[order]);
        check(name, want_block, dl_of(&n)->skip_reason);
    }
}

static void t_fm_reason_own_node(void) {
    /* catches: a shared reason buffer overwritten by the other node */
    fm_own_case("both bad", FM_SUDOKU, FM_XMC, "finalmask: sudoku: invalid sudoku ascii mode: bogus",
                "finalmask: xmc is not supported yet");
    fm_own_case("main bad", FM_SUDOKU, FM_FRAG, "finalmask: sudoku: invalid sudoku ascii mode: bogus", "");
    fm_own_case("block bad", FM_FRAG, FM_XMC, "downloadSettings: finalmask: xmc is not supported yet",
                "finalmask: xmc is not supported yet");
}

static void t_fm_clash_singbox(void) {
    struct vless_node out[4];
    struct vless_sub_stats st;
    size_t got;
    /* catches: a stray key read as finalmask */
    memset(&st, 0, sizeof st);
    got = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"s\",\"server\":\"h.example\",\"server_port\":443,"
                          "\"uuid\":\"" XHU "\",\"finalmask\":" FM_SUDOKU ",\"fm\":" FM_XMC "}]}", out, 4, &st);
    check_n("fm sing-box: usable", 1, (long)got);
    check("fm sing-box: no mask", "(null)", got ? fm_of(&out[0]) : "");
    memset(&st, 0, sizeof st);
    got = vless_parse_sub("proxies:\n  - name: c\n    type: vless\n    server: h.example\n    port: 443\n"
                          "    uuid: " XHU "\n    fm: '" FM_SUDOKU "'\n    finalmask: '" FM_XMC "'\n", out, 4, &st);
    check_n("fm clash: usable", 1, (long)got);
    check("fm clash: no mask", "(null)", got ? fm_of(&out[0]) : "");
}

static void t_fm_full(void) {
    struct vless_node n;
    char v[32];
    sl_intern_reset();
    for (int i = 0; i < 5000; i++) {
        snprintf(v, sizeof v, "fm-fill-%d", i);
        sl_intern(v, strlen(v));
    }
    /* catches: a full table of long values taken as no mask */
    check_n("fm full table: skipped", 1, fm_link(&n, "type=tcp&security=tls&sni=h.example&fm=%s", fm_pct(FM_FRAG)));
    check("fm full table: reason", "too many distinct keys", n.skip_reason);
    sl_intern_reset();
}

static void t_fm_sudoku_per_list(void) {
    static const char sd[] = "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{\"password\":\"p\"}}]}";
    static const char two[] = "{\"tcp\":[{\"type\":\"sudoku\"},{\"type\":\"sudoku\"}]}";
    struct vless_node n;
    static char q[16384], blk[1024];
    /* catches: stacked sudoku accepted (Vision's room closes for good), or the check counted across main and block */
    snprintf(blk, sizeof blk, "{\"downloadSettings\":" DL_FM("%s") "}", sd);
    snprintf(q, sizeof q, FM_MAIN_Q "&fm=%s&extra=%s", fm_pct(sd), fm_pct(blk));
    check("fm sudoku link: main and block usable", "(usable)", fm_link(&n, "%s", q) ? n.skip_reason : "(usable)");
    check("fm sudoku link: main carried", sd, fm_of(&n));
    check("fm sudoku link: block carried", sd, fm_of(dl_of(&n)));
    snprintf(q, sizeof q, "\"network\":\"xhttp\",\"finalmask\":%s,\"xhttpSettings\":{\"path\":\"/x\","
             "\"downloadSettings\":" DL_FM("%s") "}", sd, sd);
    check("fm sudoku xray: main and block usable", "(usable)", fm_xray(q));
    check("fm sudoku xray: main carried", sd, fm_of(&g_dl_last));
    check("fm sudoku xray: block carried", sd, fm_of(dl_of(&g_dl_last)));
    snprintf(q, sizeof q, "\"network\":\"tcp\",\"finalmask\":%s", two);
    check("fm sudoku xray: two in one list", "finalmask: sudoku: more than one sudoku mask is not supported", fm_xray(q));
}

static void t_fm_all(void) {
    t_fm_full();
    t_fm_link();
    t_fm_xray_json();
    t_fm_dl();
    t_fm_reason_own_node();
    t_fm_clash_singbox();
    t_fm_sudoku_per_list();
}

#define HY2_RANGES8 "60000-60001,60002-60003,60004-60005,60006-60007,60008-60009,60010-60011,60012-60013,60014-60015"
#define HY2_LONG_OK HY2_RANGES8 "," HY2_RANGES8 "," HY2_RANGES8 "," HY2_RANGES8
#define HY2_LONG_BAD HY2_LONG_OK ",1"
#define HY2_SHORT32 "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32"
#define HY2_SHORT33 HY2_SHORT32 ",33"
#define HY2_PIN8 "AB:CD:EF:01:23:45:67:89"
#define HY2_PIN HY2_PIN8 ":" HY2_PIN8 ":" HY2_PIN8 ":" HY2_PIN8
#define HY2_ECH "AEX+DQBBNwAgACANG785NbYxf2vAoHiUugO7PDLchnWNz2f+95epg2DJewAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA="
#define HY2_P1 "0000000000000000000000000000000000000000000000000000000000000001"
#define HY2_P2 "0000000000000000000000000000000000000000000000000000000000000002"
#define HY2_P3 "0000000000000000000000000000000000000000000000000000000000000003"
#define HY2_P4 "0000000000000000000000000000000000000000000000000000000000000004"
#define HY2_P5 "0000000000000000000000000000000000000000000000000000000000000005"
#define HY2_P6 "0000000000000000000000000000000000000000000000000000000000000006"
#define HY2_P7 "0000000000000000000000000000000000000000000000000000000000000007"
#define HY2_P8 "0000000000000000000000000000000000000000000000000000000000000008"
#define HY2_P9 "0000000000000000000000000000000000000000000000000000000000000009"
#define HY2_PIN_HEX "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

static char g_fail_store[8][128];
static size_t g_fail_n;

static const char *hy2_pick(const char *v, size_t n) {
    if ((n == 4 && !memcmp(v, "FAIL", 4)) || (n && v[0] == '{' && strstr(v, "FAIL"))) return NULL;
    for (size_t i = 0; i < g_fail_n; i++)
        if (strlen(g_fail_store[i]) == n && !memcmp(g_fail_store[i], v, n)) return g_fail_store[i];
    if (g_fail_n == 8 || n >= sizeof g_fail_store[0]) return NULL;
    memcpy(g_fail_store[g_fail_n], v, n);
    g_fail_store[g_fail_n][n] = '\0';
    return g_fail_store[g_fail_n++];
}

static void t_hy2_all(void) {
    struct vless_node n;
    vless_set_insecure(0);

    int rc = vless_parse_url("hysteria2://p%40ss%3Aw@example.com:8443/?sni=cdn.example&obfs=salamander"
                             "&obfs-password=secret12&pinSHA256=" HY2_PIN "&insecure=0#Node%201", &n);
    check_n("a_hysteria2_link_parses_into_the_node: rc", 0, rc);
    check_n("a_hysteria2_link_parses_into_the_node: proto", VLESS_PROTO_HY2, n.proto);
    check("a_hysteria2_link_parses_into_the_node: type", "quic", n.type);
    check("a_hysteria2_link_parses_into_the_node: security", "tls", n.security);
    check_n("a_hysteria2_link_parses_into_the_node: uuid cleared", 0, n.uuid[0]);
    check("a_hysteria2_link_parses_into_the_node: auth", "p@ss:w", n.auth ? n.auth : "(null)");
    check("a_hysteria2_link_parses_into_the_node: host", "example.com", n.host);
    check_n("a_hysteria2_link_parses_into_the_node: port", 8443, n.port);
    check("a_hysteria2_link_parses_into_the_node: sni", "cdn.example", n.sni);
    check("a_hysteria2_link_parses_into_the_node: obfs", "salamander", n.obfs);
    check("a_hysteria2_link_parses_into_the_node: obfs_pw", "secret12", n.obfs_pw ? n.obfs_pw : "(null)");
    check("a_hysteria2_link_parses_into_the_node: pcs", HY2_PIN_HEX, n.pcs ? n.pcs : "(null)");
    check("a_hysteria2_link_parses_into_the_node: name", "Node 1", n.name);
    check("a_hysteria2_link_parses_into_the_node: ports", "", n.ports);

    static const char *const same[] = { "hy2://pw@1.2.3.4", "hy2://pw@1.2.3.4/?" };
    for (size_t i = 0; i < 2; i++) {
        rc = vless_parse_url(same[i], &n);
        check_n("hy2_is_the_same_scheme_and_the_port_defaults_to_443: rc", 0, rc);
        check_n("hy2_is_the_same_scheme_and_the_port_defaults_to_443: proto", VLESS_PROTO_HY2, n.proto);
        check("hy2_is_the_same_scheme_and_the_port_defaults_to_443: host", "1.2.3.4", n.host);
        check_n("hy2_is_the_same_scheme_and_the_port_defaults_to_443: port", 443, n.port);
        check("hy2_is_the_same_scheme_and_the_port_defaults_to_443: sni", "", n.sni);
        check("hy2_is_the_same_scheme_and_the_port_defaults_to_443: ports", "", n.ports);
    }

    static const struct { const char *url; int rc; unsigned port; const char *ports; } pl[] = {
        { "hysteria2://pw@h.example:443,5000-6000/?sni=s", 0, 443, "443,5000-6000" },
        { "hysteria2://pw@h.example:5000-6000,443/?sni=s", 0, 5000, "5000-6000,443" },
        { "hysteria2://pw@h.example:6000-5000/?sni=s", -1, 0, "" },
        { "hysteria2://pw@h.example:0/?sni=s", -1, 0, "" },
        { "hysteria2://pw@h.example:443,/?sni=s", -1, 0, "" },
        { "hysteria2://pw@h.example:443,0-9/?sni=s", -1, 0, "" },
        { "hysteria2://pw@h.example:65536/?sni=s", -1, 0, "" },
        { "hysteria2://pw@h.example:44a/?sni=s", -1, 0, "" },
        { "hysteria2://pw@h.example:5000-6000x/?sni=s", -1, 0, "" },
        { "hysteria2://pw@:443/?sni=s", -1, 0, "" },
        { "hysteria2://pw@[2001:db8::1]/?sni=s", 0, 443, "" },
        { "hysteria2://pw@[2001:db8::1]:5000-6000,443/?sni=s", 0, 5000, "5000-6000,443" },
        { "hysteria2://pw@h.example:443/?sni=s&mport=5000-6000", 0, 443, "443,5000-6000" },
        { "hysteria2://pw@h.example:5000-6000/?sni=s&mport=7000", 0, 5000, "5000-6000,7000" },
        { "hysteria2://pw@h.example:443,6000/?sni=s&mport=7000-7100", 0, 443, "443,6000,7000-7100" },
        { "hysteria2://pw@h.example:" HY2_LONG_OK "/?sni=s", 0, 60000, HY2_LONG_OK },
        { "hysteria2://pw@h.example:" HY2_SHORT32 "/?sni=s", 0, 1, HY2_SHORT32 },
    };
    for (size_t i = 0; i < sizeof pl / sizeof *pl; i++) {
        rc = vless_parse_url(pl[i].url, &n);
        check_n("a_port_list_keeps_its_hops_and_dials_the_first: rc", pl[i].rc, rc);
        if (pl[i].rc) continue;
        check_n("a_port_list_keeps_its_hops_and_dials_the_first: port", pl[i].port, n.port);
        check_n("other_forms_hop_like_hysteria: a link with a list hops locally and remotely, one without does not",
                pl[i].ports[0] ? HY2_HOP_LOCAL | HY2_HOP_REMOTE : 0, n.hop_mode);
        check("a_port_list_keeps_its_hops_and_dials_the_first: ports", pl[i].ports, n.ports);
    }

    static const struct { const char *url; unsigned port; const char *ports; unsigned mode; } one[] = {
        { "hysteria2://pw@h.example:443-443/?sni=s", 443, "", HY2_HOP_LOCAL | HY2_HOP_REMOTE },
        { "hysteria2://pw@h.example:443,443/?sni=s", 443, "443,443", HY2_HOP_LOCAL | HY2_HOP_REMOTE },
        { "hysteria2://pw@h.example:443/?sni=s&mport=443", 443, "443,443", HY2_HOP_LOCAL | HY2_HOP_REMOTE },
        { "hysteria2://pw@h.example:443/?sni=s", 443, "", 0 },
        { "hysteria2://pw@h.example/?sni=s", 443, "", 0 },
        { "hysteria2://pw@h.example:443-443/?sni=s&hopmode=remote", 443, "", HY2_HOP_REMOTE },
    };
    for (size_t i = 0; i < sizeof one / sizeof *one; i++) {
        rc = vless_parse_url(one[i].url, &n);
        check_n("one_listed_port_and_none: link rc", 0, rc);
        check_n("one_listed_port_and_none: link port", one[i].port, n.port);
        check("one_listed_port_and_none: link ports", one[i].ports, n.ports);
        check_n("one_listed_port_and_none: link mode", one[i].mode, n.hop_mode);
    }

    static const struct { const char *url; const char *why; } bad[] = {
        { "hysteria2://ab%00cd@h.example:443/?sni=s", "NUL byte in auth, obfs or obfs-password" },
        { "hysteria2://pw@h.example:443/?sni=s&obfs=salamander%00x&obfs-password=abcd",
          "NUL byte in auth, obfs or obfs-password" },
        { "hysteria2://pw@h.example:443/?sni=s&obfs=salamander&obfs-password=abcd%00zz",
          "NUL byte in auth, obfs or obfs-password" },
        { "hysteria2://pw@h.example:443/?sni=s&qp=%7B", "qp does not parse" },
        { "hysteria2://pw@h.example:443/?sni=s&obfs=%01%7f&obfs-password=abcd", "obfs ?? is not supported" },
        { "hysteria2://pw@h.example:443/?sni=s&mport=x", "mport: not a port list" },
        { "hysteria2://pw@h.example:443/?sni=s&mport=0", "mport: not a port list" },
        { "hysteria2://pw@h.example:" HY2_LONG_BAD "/?sni=s", "port list too long" },
        { "hysteria2://pw@h.example:" HY2_SHORT33 "/?sni=s", "port list too long" },
        { "hysteria2://pw@h.example:443/?sni=s&mport=" HY2_LONG_OK, "port list too long" },
        { "hysteria2://pw@h.example:443/?sni=s&mport=" HY2_SHORT32, "port list too long" },
        { "hysteria2://pw@h.example:443/?sni=s&pinSHA256=zz", "pinSHA256: not a hex SHA-256" },
        { "hysteria2://pw@h.example:443/?sni=s&pcs=zz", "pinSHA256: not a hex SHA-256" },
        { "hysteria2://pw@h.example:443/?sni=s&pinSHA256=" HY2_P1 "," HY2_P2 "," HY2_P3 "," HY2_P4 "," HY2_P5 ","
          HY2_P6 "," HY2_P7 "," HY2_P8 "," HY2_P9, "pinSHA256: more than 8 pins" },
        { "hysteria2://h.example:443/?sni=s", "auth is empty" },
        { "hysteria2://@h.example:443/?sni=s", "auth is empty" },
        { "hysteria2://h.example:443/?sni=s#a@b", "auth is empty" },
        { "hysteria2://pw@h.example:443/?sni=s&obfs=gecko&obfs-password=secret12", "obfs gecko is not supported" },
        { "hysteria2://pw@h.example:443/?sni=s&obfs=salamander&obfs-password=abc",
          "obfs-password shorter than 4 bytes" },
        { "hysteria2://pw@h.example:443/?sni=s&obfs-password=abc", "obfs-password shorter than 4 bytes" },
        { "hysteria2://pw@h.example:443/?sni=s&obfs=salamander", "obfs-password missing" },
        { "hysteria2://pw@h.example:443/?sni=s&insecure=1", "allowInsecure: needs --insecure" },
        { "hysteria2://pw@h.example:443/?sni=s&pks=" HY2_PIN_HEX, "pks is not supported for hysteria2" },
        { "hysteria2://pw@h.example:443/?sni=s&ech=" HY2_ECH, "ech is not supported for hysteria2" },
        { "hysteria2://pw@h.example:443/?sni=s&vcn=a.example,b.example", "verifyPeerCertByName: one name only" },
        { "hysteria2://pw@h.example:443/?sni=s&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22fragment%22%2C%22settings%22%3A"
          "%7B%22packets%22%3A%221-3%22%2C%22length%22%3A%22100-200%22%2C%22delay%22%3A%2210-20%22%7D%7D%5D%7D",
          "finalmask tcp is not supported for hysteria2" },
        { "hysteria2://pw@0.0.0.0:443/?sni=s", "0.0.0.0: nobody to answer" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        rc = vless_parse_url(bad[i].url, &n);
        check_n("unusable_hysteria2_nodes_name_their_reason: rc", 1, rc);
        check("unusable_hysteria2_nodes_name_their_reason: reason", bad[i].why, n.skip_reason);
    }

    rc = vless_parse_url("hysteria2://pw@h.example:443/?sni=s&vcn=a.example", &n);
    check_n("hysteria2_keeps_one_verify_name: rc", 0, rc);

    rc = vless_parse_url("hysteria2://pw@h.example:443/?sni=s&obfs=salamander&obfs-password=abcd", &n);
    check_n("a_four_byte_obfs_password_is_enough: rc", 0, rc);
    rc = vless_parse_url("hysteria2://pw@h.example:443/?sni=s&pinSHA256=" HY2_P1 "," HY2_P2 "," HY2_P3 "," HY2_P4 ","
                         HY2_P5 "," HY2_P6 "," HY2_P7 "," HY2_P8, &n);
    check_n("eight_pins_are_usable: rc", 0, rc);
    rc = vless_parse_url("hysteria2://pw@h.example:443/?sni=s&pcs=" HY2_PIN_HEX, &n);
    check_n("pcs_and_pinSHA256_read_the_same_pin: rc", 0, rc);
    check("pcs_and_pinSHA256_read_the_same_pin: pcs", HY2_PIN_HEX, n.pcs ? n.pcs : "(null)");

    rc = vless_parse_url("hysteria2://a@b@h.example:443", &n);
    check_n("the_auth_ends_at_the_last_at_sign: rc", 0, rc);
    check("the_auth_ends_at_the_last_at_sign: auth", "a@b", n.auth ? n.auth : "(null)");
    check("the_auth_ends_at_the_last_at_sign: host", "h.example", n.host);

    static const struct { const char *q; unsigned hf, ht, up, down; int rc; const char *why; } nm[] = {
        { "hop=10-5", 5, 10, 0, 0, 0, NULL },
        { "hop=30-10", 10, 30, 0, 0, 0, NULL },
        { "hop=10-4", 0, 0, 0, 0, 1, "interval must be at least 5" },
        { "hop=0-5", 0, 0, 0, 0, 1, "interval must be at least 5" },
        { "hop=5-10x", 0, 0, 0, 0, 1, "interval is not a number or range" },
        { "hop=abc", 0, 0, 0, 0, 1, "interval is not a number or range" },
        { "hop=-5", 0, 0, 0, 0, 1, "interval is not a number or range" },
        { "hop=65536", 0, 0, 0, 0, 1, "interval is not a number or range" },
        { "hop=5-", 0, 0, 0, 0, 1, "interval is not a number or range" },
        { "hop=", 0, 0, 0, 0, 0, NULL },
        { "hop=0", 0, 0, 0, 0, 0, NULL },
        { "hop=7", 7, 7, 0, 0, 0, NULL },
        { "hop=1-65535", 0, 0, 0, 0, 1, "interval must be at least 5" },
        { "hop=4-10", 0, 0, 0, 0, 1, "interval must be at least 5" },
        { "hop=4", 0, 0, 0, 0, 1, "interval must be at least 5" },
        { "hop=5-10", 5, 10, 0, 0, 0, NULL },
        { "hop=5-65535", 5, 65535, 0, 0, 0, NULL },
        { "hop=0-0", 0, 0, 0, 0, 0, NULL },
        { "upmbps=100000&downmbps=100000", 0, 0, 100000, 100000, 0, NULL },
        { "upmbps=100001&downmbps=100001", 0, 0, 0, 0, 0, NULL },
        { "upmbps=1x&downmbps=2y", 0, 0, 0, 0, 0, NULL },
    };
    for (size_t i = 0; i < sizeof nm / sizeof *nm; i++) {
        char u[160];
        snprintf(u, sizeof u, "hysteria2://pw@h.example:443/?sni=s&%s", nm[i].q);
        rc = vless_parse_url(u, &n);
        check_n("hop_and_rate_values_are_kept_inside_their_bounds: rc", nm[i].rc, rc);
        if (nm[i].rc) {
            check("a_link_hop_reads_as_xray_reads_an_interval: reason", nm[i].why, n.skip_reason);
            continue;
        }
        check_n("hop_and_rate_values_are_kept_inside_their_bounds: hop_from", nm[i].hf, n.hop_from);
        check_n("hop_and_rate_values_are_kept_inside_their_bounds: hop_to", nm[i].ht, n.hop_to);
        check_n("hop_and_rate_values_are_kept_inside_their_bounds: up", nm[i].up, (long)n.up_mbps);
        check_n("hop_and_rate_values_are_kept_inside_their_bounds: down", nm[i].down, (long)n.down_mbps);
    }

    static const struct { const char *url; const char *why; } full[] = {
        { "hysteria2://FAIL@h.example:443/?sni=s", "too many distinct keys" },
        { "hysteria2://pw@h.example:443/?sni=s&obfs=salamander&obfs-password=FAIL", "too many distinct keys" },
        { "hysteria2://pw@h.example:443/?sni=s&qp=%7B%22FAIL%22%3A1%7D", "too many distinct keys" },
    };
    for (size_t i = 0; i < sizeof full / sizeof *full; i++) {
        g_fail_n = 0;
        sl_set_interner(hy2_pick);
        rc = vless_parse_url(full[i].url, &n);
        sl_set_interner(NULL);
        check_n("a_full_intern_table_names_its_reason: rc", 1, rc);
        check("a_full_intern_table_names_its_reason: reason", full[i].why, n.skip_reason);
    }

    static const char *const gone[] = {
        "vless://u@h", "vless://h:443", "vless://u@h:443/?security=none", "vless://u@h:443,5000#x",
        "vless://u@h:443-5000#x",
    };
    for (size_t i = 0; i < sizeof gone / sizeof *gone; i++)
        check_n("vless_links_parse_as_before: still not a link", -1, vless_parse_url(gone[i], &n));
    rc = vless_parse_url("vless://u@h:443?security=none#x", &n);
    check_n("vless_links_parse_as_before: rc", 0, rc);
    check_n("vless_links_parse_as_before: proto", VLESS_PROTO_VLESS, n.proto);
    check_n("vless_links_parse_as_before: no auth", 1, n.auth == NULL);
    check_n("vless_links_parse_as_before: port", 443, n.port);
    check_n("vless_links_parse_as_before: ports", 0, n.ports[0]);
    check_n("vless_links_parse_as_before: not hy2 scheme", 0, (long)vless_link_scheme("hy2:/x"));
    check_n("vless_links_parse_as_before: scheme vless", 8, (long)vless_link_scheme("vless://"));
    check_n("vless_links_parse_as_before: scheme hysteria2", 12, (long)vless_link_scheme("hysteria2://x"));
    check_n("vless_links_parse_as_before: scheme hy2", 6, (long)vless_link_scheme("hy2://x"));
}


#define HXS(v) "{\"version\":" v ",\"address\":\"h.example\",\"port\":443}"
#define HXT(net, sec, hv, fm) "{\"network\":\"" net "\",\"security\":\"" sec "\",\"tlsSettings\":{\"serverName\":\"s.example\"}," \
                              "\"hysteriaSettings\":{\"version\":" hv ",\"auth\":\"pw\"},\"finalmask\":" fm "}"
#define HXO(s, t) "{\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"x\",\"settings\":" s ",\"streamSettings\":" t "}]}"
#define HXOK(fm) HXO(HXS("2"), HXT("hysteria", "tls", "2", fm))
#define SAL(extra) "{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":\"obfs1234\"" extra "}}]}"
#define HUDP(settings) "{\"udp\":[{\"type\":\"udphop\",\"settings\":" settings "}]}"

#define HX_BRIEF "{\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"x\",\"settings\":{\"version\":2,\"address\":\"h.example\",\"port\":443}," \
                 "\"streamSettings\":{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"s.example\"}," \
                 "\"hysteriaSettings\":{\"version\":2,\"auth\":\"pw\"},\"finalmask\":{\"udp\":[{\"type\":\"salamander\"," \
                 "\"settings\":{\"password\":\"obfs1234\"}}],\"quicParams\":{\"brutalUp\":\"100 mbps\",\"brutalDown\":\"50 mbps\"}}}}]}"

#define SB_BRIEF "{\"outbounds\":[{\"type\":\"hysteria2\",\"tag\":\"sb\",\"server\":\"h.example\",\"server_port\":443," \
                 "\"server_ports\":[\"2000:3000\"],\"hop_interval\":\"30s\",\"up_mbps\":100,\"down_mbps\":200,\"password\":\"pw\"," \
                 "\"obfs\":{\"type\":\"salamander\",\"password\":\"obfs1234\"},\"tls\":{\"enabled\":true,\"server_name\":\"s.example\"}}]}"
#define SBO(extra) "{\"outbounds\":[{\"type\":\"hysteria2\",\"tag\":\"sb\",\"server\":\"h.example\",\"server_port\":443," \
                   "\"password\":\"pw\",\"tls\":{\"enabled\":true,\"server_name\":\"s.example\"}" extra "}]}"

#define SBP ",\"server_ports\":[\"2000:3000\"]"
#define SBTLS "\"tls\":{\"enabled\":true,\"server_name\":\"s.example\"}"
#define CL_PIN "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
#define CL_HEAD "proxies:\n  - name: cl\n    type: hysteria2\n    server: h.example\n"
#define CL_BRIEF CL_HEAD "    port: 443\n    ports: 2000-3000\n    password: pw\n    obfs: salamander\n    obfs-password: obfs1234\n" \
                 "    sni: s.example\n    skip-cert-verify: true\n    fingerprint: " CL_PIN "\n    up: 100 Mbps\n    down: 50 Mbps\n"
#define CLO(extra) CL_HEAD "    port: 443\n    password: pw\n    sni: s.example\n" extra

#define LIST4 "vless://u@h.example:443?security=none#v\nhysteria2://pw@h.example:443/?sni=s.example#a\n" \
              "hy2://pw@h2.example:443/?sni=s.example#b\ntrojan://p@h.example:1#t\n"

static size_t hs_parse(const char *text, struct vless_node *nodes, struct vless_sub_stats *st) {
    memset(nodes, 0, 4 * sizeof *nodes);
    return vless_parse_sub(text, nodes, 4, st);
}

static const char *hs_reason(const struct vless_sub_stats *st) {
    return st->reasons_n ? st->reasons[0].reason : "(none)";
}

static const char *hs_s(const char *s) { return s ? s : "(null)"; }

static void hs_refused(const char *what, const char *text, const char *why) {
    struct vless_node nodes[4];
    struct vless_sub_stats st;
    size_t n = hs_parse(text, nodes, &st);
    check_n(what, 0, (long)n);
    check(what, why, hs_reason(&st));
}

static void hs_usable(const char *what, const char *text) {
    struct vless_node nodes[4];
    struct vless_sub_stats st;
    check_n(what, 1, (long)hs_parse(text, nodes, &st));
    check(what, "(none)", hs_reason(&st));
}

static void t_hy2_xray(void) {
    struct vless_node nodes[4];
    struct vless_sub_stats st;
    vless_set_insecure(0);

    size_t n = hs_parse(HX_BRIEF, nodes, &st);
    check_n("an_xray_hysteria_outbound_is_a_node: count", 1, (long)n);
    check_n("an_xray_hysteria_outbound_is_a_node: skipped", 0, (long)st.skipped);
    check_n("an_xray_hysteria_outbound_is_a_node: proto", VLESS_PROTO_HY2, nodes[0].proto);
    check("an_xray_hysteria_outbound_is_a_node: name", "x", nodes[0].name);
    check("an_xray_hysteria_outbound_is_a_node: host", "h.example", nodes[0].host);
    check_n("an_xray_hysteria_outbound_is_a_node: port", 443, nodes[0].port);
    check("an_xray_hysteria_outbound_is_a_node: type", "quic", nodes[0].type);
    check("an_xray_hysteria_outbound_is_a_node: security", "tls", nodes[0].security);
    check("an_xray_hysteria_outbound_is_a_node: auth", "pw", hs_s(nodes[0].auth));
    check("an_xray_hysteria_outbound_is_a_node: sni", "s.example", nodes[0].sni);
    check("an_xray_hysteria_outbound_is_a_node: obfs", "salamander", nodes[0].obfs);
    check("an_xray_hysteria_outbound_is_a_node: obfs_pw", "obfs1234", hs_s(nodes[0].obfs_pw));
    check_n("an_xray_hysteria_outbound_is_a_node: up", 104, (long)nodes[0].up_mbps);
    check_n("an_xray_hysteria_outbound_is_a_node: down", 52, (long)nodes[0].down_mbps);
    check("an_xray_hysteria_outbound_is_a_node: qp", "{\"brutalUp\":\"100 mbps\",\"brutalDown\":\"50 mbps\"}", hs_s(nodes[0].qp));
    check_n("an_xray_hysteria_outbound_is_a_node: fm", 1, nodes[0].fm == NULL);
    check("an_xray_hysteria_outbound_is_a_node: ports", "", nodes[0].ports);
    check_n("an_xray_hysteria_outbound_is_a_node: uuid", 0, nodes[0].uuid[0]);

    n = hs_parse(HXOK("{\"quicParams\":{ }}"), nodes, &st);
    check_n("an_empty_quic_params_object_keeps_no_qp: count", 1, (long)n);
    check_n("an_empty_quic_params_object_keeps_no_qp: qp", 1, nodes[0].qp == NULL);
    n = hs_parse(HXOK("{\"quicParams\":{\"congestion\":\"bbr\"}}"), nodes, &st);
    check("quic_params_other_than_rates_stay_in_qp: qp", "{\"congestion\":\"bbr\"}", hs_s(nodes[0].qp));

    hs_usable("a_hysteria_outbound_with_remarks_is_named_by_them: usable",
              "{\"remarks\":\"R\",\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"x\",\"settings\":" HXS("2")
              ",\"streamSettings\":" HXT("hysteria", "tls", "2", "null") "}]}");
    n = hs_parse("{\"remarks\":\"R\",\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"x\",\"settings\":" HXS("2")
                 ",\"streamSettings\":" HXT("hysteria", "tls", "2", "null") "}]}", nodes, &st);
    check("a_hysteria_outbound_with_remarks_is_named_by_them: name", "R", nodes[0].name);

    static const struct { const char *json; const char *why; } refuse[] = {
        { HXO(HXS("1"), HXT("hysteria", "tls", "2", "null")), "hysteria version 1 is not supported" },
        { HXO(HXS("2"), HXT("hysteria", "tls", "1", "null")), "hysteriaSettings version 1 is not supported" },
        { HXO(HXS("1"), "{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"s.example\","
                        "\"allowInsecure\":true},\"hysteriaSettings\":{\"version\":2,\"auth\":\"pw\"}}"),
          "hysteria version 1 is not supported" },
        { HXO("{\"address\":\"h.example\",\"port\":443}", HXT("hysteria", "tls", "2", "null")),
          "hysteria version 0 is not supported" },
        { HXO(HXS("{}"), HXT("hysteria", "tls", "2", "null")), "hysteria version 0 is not supported" },
        { HXO(HXS("2"), HXT("ws", "tls", "2", "null")), "hysteria needs network hysteria" },
        { HXO(HXS("2"), HXT("hysteria", "none", "2", "null")), "hysteria needs security tls" },
        { HXOK("{\"udp\":[{\"type\":\"noise\",\"settings\":{}}]}"), "finalmask udp noise is not supported" },
        { HXOK("{\"udp\":[{\"settings\":{}}]}"), "finalmask udp mask has no type" },
        { HXOK("{\"udp\":{\"type\":\"salamander\"}}"), "finalmask udp is not a list" },
        { HXOK("{\"udp\":[5]}"), "finalmask udp mask is not an object" },
        { HXOK("{\"quicParams\":\"x\"}"), "finalmask quicParams is not an object" },
        { HXOK(SAL(",\"packetSize\":\"512-1200\"")), "salamander packetSize is not supported" },
        { HXOK(SAL(",\"packetSize\":1200")), "salamander packetSize is not supported" },
        { HXOK(SAL(",\"packetSize\":{}")), "salamander packetSize is not supported" },
        { HXOK("{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":\"obfs1234\"}},"
               "{\"type\":\"salamander\",\"settings\":{\"password\":\"obfs5678\"}}]}"),
          "finalmask udp salamander twice is not supported" },
        { HXOK("{\"udp\":[{\"type\":\"salamander\",\"settings\":{}}]}"), "obfs-password missing" },
        { HXOK("{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":\"abc\"}}]}"),
          "obfs-password shorter than 4 bytes" },
        { HXOK("{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":5}}]}"), "obfs-password missing" },
        { HXOK("{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":\"ab\\u0000cd\"}}]}"),
          "NUL byte in auth, obfs or obfs-password" },
        { HXOK("{\"quicParams\":{\"brutalUp\":\"1000 bps\"}}"), "BrutalUp must be at least 65536 bytes per second" },
        { HXOK("{\"quicParams\":{\"brutalDown\":\"1 mbps\",\"brutalUp\":\"fast\"}}"), "strconv.ParseFloat: parsing \"\": invalid syntax" },
        { HXOK("{\"quicParams\":{\"brutalDown\":\"5 parsec\"}}"), "unsupported unit: parsec" },
        { HXOK("{\"quicParams\":{\"brutalDown\":\"1.2.3 mbps\"}}"), "strconv.ParseFloat: parsing \"1.2.3\": invalid syntax" },
        { HXOK("{\"quicParams\":{\"brutalDown\":7}}"), "quicParams: brutalDown is not a string" },
        { HXO(HXS("2"), "{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"s.example\"},"
                        "\"hysteriaSettings\":{\"version\":2}}"), "auth is empty" },
        { HXO(HXS("2"), "{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"s.example\"},"
                        "\"hysteriaSettings\":{\"version\":2,\"auth\":5}}"), "auth is empty" },
        { HXO(HXS("2"), "{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"s.example\"}}"),
          "hysteriaSettings version 0 is not supported" },
        { HXO(HXS("2"), "{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"s.example\"},"
                        "\"hysteriaSettings\":{\"version\":2,\"auth\":\"p\\u0000w\"}}"),
          "NUL byte in auth, obfs or obfs-password" },
        { HXOK("{\"tcp\":[{\"type\":\"fragment\",\"settings\":{\"packets\":\"1-3\",\"length\":\"100-200\",\"delay\":\"10-20\"}}]}"),
          "finalmask tcp is not supported for hysteria2" },
        { HXO("{\"version\":2,\"address\":\"h.example\"}", HXT("hysteria", "tls", "2", "null")), "port is missing" },
        { HXO("{\"version\":2,\"port\":443}", HXT("hysteria", "tls", "2", "null")), "address is empty" },
    };
    for (size_t i = 0; i < sizeof refuse / sizeof *refuse; i++)
        hs_refused("xray_hysteria_refusals_are_named", refuse[i].json, refuse[i].why);

    static const char *const usable[] = {
        HXOK(SAL(",\"packetSize\":0")), HXOK(SAL(",\"packetSize\":\"0\"")), HXOK(SAL("")), HXOK("null"),
        HXOK("{\"udp\":[]}"), HXOK("{\"udp\":null,\"quicParams\":null}"), HXOK("{\"quicParams\":{}}"),
        HXOK("{\"quicParams\":{\"brutalUp\":\"\",\"brutalDown\":\"512 kbps\"}}"),
    };
    for (size_t i = 0; i < sizeof usable / sizeof *usable; i++)
        hs_usable("xray_hysteria_refusals_are_named: a usable form stays usable", usable[i]);

    static const struct { const char *rate; unsigned mbps; } rate[] = {
        { "100 mbps", 104 }, { "50 mbps", 52 }, { "1 gbps", 1073 }, { "1mbps", 1 }, { "8 MB", 8 }, { "512 kbps", 0 },
        { "1.5 mbps", 1 }, { "1 tbps", 0 }, { "10 gbps", 10737 }, { "524288", 0 }, { "  100 Mbps ", 104 },
    };
    for (size_t i = 0; i < sizeof rate / sizeof *rate; i++) {
        char js[600];
        snprintf(js, sizeof js, HXOK("{\"quicParams\":{\"brutalUp\":\"%s\"}}"), rate[i].rate);
        n = hs_parse(js, nodes, &st);
        check_n("brutal_rates_are_1024_based_bytes_turned_into_decimal_mbps: count", 1, (long)n);
        check_n("brutal_rates_are_1024_based_bytes_turned_into_decimal_mbps: up", rate[i].mbps, (long)nodes[0].up_mbps);
    }

    static const struct { const char *settings; const char *ports; unsigned from, to; const char *why; unsigned mode, port; } hop[] = {
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\"443, 20000-30000,\",\"interval\":\"10-30\"}",
          "443,20000-30000", 10, 30, NULL, HY2_HOP_REMOTE, 443 },
        { "{\"mode\":\"intervallocal,PerConnRemote\",\"remotePorts\":443,\"interval\":7}", "", 7, 7, NULL,
          HY2_HOP_LOCAL | HY2_HOP_ONCE, 443 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\" ,443,, 20000-30000 ,\"}", "443,20000-30000", 0, 0, NULL,
          HY2_HOP_REMOTE, 443 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\" ,443,, 20000 - 30000 ,\"}", "", 0, 0, "remotePorts: not a port list", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\"20 000-30 000\"}", "", 0, 0, "remotePorts: not a port list", 0, 0 },
        { "{\"mode\":\"intervalLocal\",\"remotePorts\":\"20 000\"}", "", 0, 0, "remotePorts: not a port list", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"bogus\"]}", "", 0, 0, "invalid ip bogus", 0, 0 },
        { "{\"mode\":\"intervalLocal\",\"remoteIPs\":[\"192.0.2.0/33\"]}", "", 0, 0, "invalid ip 192.0.2.0/33", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"192.0.2.0/024\"]}", "", 0, 0, "invalid ip 192.0.2.0/024", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"192.0.2.0/\"]}", "", 0, 0, "invalid ip 192.0.2.0/", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"/24\"]}", "", 0, 0, "invalid ip /24", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"\"]}", "", 0, 0, "invalid ip ", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"2001:0db8:0000:0000:0000:0000:0000:0001/128000000000000000000000000000000\"]}", "", 0, 0, "invalid ip 2001:0db8:0000:0000:0000:0000:0000:0001/12800000000000000000000", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"192.0.2.0/24\",\"2001:db8::/129\"]}", "", 0, 0, "invalid ip 2001:db8::/129", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[5]}", "", 0, 0, "remoteIPs is not a list of addresses", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":\"192.0.2.1\"}", "", 0, 0, "remoteIPs is not a list of addresses", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[]}", "", 0, 0, NULL, HY2_HOP_REMOTE, 443 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":null}", "", 0, 0, NULL, HY2_HOP_REMOTE, 443 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"192.0.2.5\",\"2001:db8::/32\"]}", "", 0, 0, NULL,
          HY2_HOP_REMOTE | HY2_HOP_IPS, 443 },
        { "{\"remotePorts\":\"443,20000-30000\",\"interval\":\"10-30\"}", "", 0, 0, "invalid mode ", 0, 0 },
        { "{\"mode\":\"\",\"remotePorts\":\"443,20000-30000\"}", "", 0, 0, "invalid mode ", 0, 0 },
        { "{\"mode\":5,\"remotePorts\":\"443,20000-30000\"}", "", 0, 0, "invalid mode ", 0, 0 },
        { "{\"mode\":\"intervalRemote,bogus\"}", "", 0, 0, "invalid mode bogus", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"interval\":4}", "", 0, 0, "interval must be at least 5", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"interval\":\"30-10\"}", "", 10, 30, NULL, HY2_HOP_REMOTE, 443 },
        { "{\"mode\":\"intervalRemote\",\"interval\":{}}", "", 0, 0, "interval is not a number or range", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"interval\":\"a-b\"}", "", 0, 0, "interval is not a number or range", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"interval\":99999}", "", 0, 0, "interval is not a number or range", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\"0\"}", "", 0, 0, "remotePorts: not a port list", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":{}}", "", 0, 0, "remotePorts: not a port list", 0, 0 },
        { "{\"mode\":\"intervalLocal\",\"remotePorts\":\"a-b\"}", "", 0, 0, "remotePorts: not a port list", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"ports\":\"1000-2000\"}", "", 0, 0, NULL, HY2_HOP_REMOTE, 443 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"1.2.3.4\"],\"remotePorts\":\"5000-6000\"}", "5000-6000", 0, 0, NULL,
          HY2_HOP_REMOTE | HY2_HOP_IPS, 5000 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\"" HY2_LONG_BAD "\"}", "", 0, 0, "port list too long", 0, 0 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\"" HY2_LONG_OK "\"}", HY2_LONG_OK, 0, 0, NULL, HY2_HOP_REMOTE, 60000 },
        { "{\"mode\":\"IntervalLocal\",\"remotePorts\":\"20000-20010\"}", "", 0, 0, NULL, HY2_HOP_LOCAL, 443 },
        { "{\"mode\":\"intervalLocal\",\"remotePorts\":\"" HY2_LONG_BAD "\"}", "", 0, 0, NULL, HY2_HOP_LOCAL, 443 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\"20000-20010\"}", "20000-20010", 0, 0, NULL, HY2_HOP_REMOTE, 20000 },
        { "{\"mode\":\"perConnRemote\",\"remotePorts\":\"20000-20010\"}", "20000-20010", 0, 0, NULL, HY2_HOP_ONCE, 20000 },
        { "{\"mode\":\"intervalLocal,intervalRemote\",\"remotePorts\":\"20000-20010\"}", "20000-20010", 0, 0, NULL,
          HY2_HOP_LOCAL | HY2_HOP_REMOTE, 20000 },
        { "{\"mode\":\"intervalRemote\",\"remotePorts\":\"5000\"}", "", 0, 0, NULL, HY2_HOP_REMOTE, 5000 },
        { "{\"mode\":\"intervalLocal\",\"remotePorts\":\"5000\"}", "", 0, 0, NULL, HY2_HOP_LOCAL, 443 },
        { "{\"mode\":\"intervalRemote\"}", "", 0, 0, NULL, HY2_HOP_REMOTE, 443 },
        { "{\"mode\":\"intervalRemote\",\"remoteIPs\":[\"192.0.2.0/24\"],\"remotePorts\":\"20000-20010\"}", "20000-20010", 0, 0, NULL,
          HY2_HOP_REMOTE | HY2_HOP_IPS, 20000 },
        { "{\"mode\":\"intervalLocal\",\"remoteIPs\":[\"192.0.2.0/24\"]}", "", 0, 0, NULL, HY2_HOP_LOCAL, 443 },
    };
    for (size_t i = 0; i < sizeof hop / sizeof *hop; i++) {
        char js[1400], fm[800];
        snprintf(fm, sizeof fm, HUDP("%s"), hop[i].settings);
        snprintf(js, sizeof js, HXOK("%s"), fm);
        n = hs_parse(js, nodes, &st);
        if (hop[i].why) {
            check_n("xray_udphop_is_kept: refused", 0, (long)n);
            check("xray_udphop_is_kept: reason", hop[i].why, hs_reason(&st));
            continue;
        }
        check_n("xray_udphop_is_kept: count", 1, (long)n);
        check("xray_udphop_is_kept: ports", hop[i].ports, nodes[0].ports);
        check_n("xray_udphop_is_kept: hop_from", hop[i].from, nodes[0].hop_from);
        check_n("xray_udphop_is_kept: hop_to", hop[i].to, nodes[0].hop_to);
        check_n("xray_hop_modes_are_kept: mode", hop[i].mode, nodes[0].hop_mode);
        check_n("one_listed_port_and_none: the dialled port", hop[i].port, nodes[0].port);
    }

    {
        char js[1400];
        char big[700];
        memset(big, 'a', sizeof big - 1);
        big[sizeof big - 1] = '\0';
        snprintf(js, sizeof js, "{\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"x\",\"settings\":" HXS("2")
                 ",\"streamSettings\":{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"s.example\"},"
                 "\"hysteriaSettings\":{\"version\":2,\"auth\":\"%s\"}}}]}", big);
        hs_refused("a_long_secret_is_refused_not_cut: auth", js, "auth, obfs or obfs-password longer than 510 bytes");
        snprintf(js, sizeof js, "{\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"x\",\"settings\":" HXS("2")
                 ",\"streamSettings\":{\"network\":\"hysteria\",\"security\":\"tls\",\"tlsSettings\":{\"serverName\":\"s.example\"},"
                 "\"hysteriaSettings\":{\"version\":2,\"auth\":\"pw\"},\"finalmask\":{\"udp\":[{\"type\":\"salamander\","
                 "\"settings\":{\"password\":\"%s\"}}]}}}]}", big);
        hs_refused("a_long_secret_is_refused_not_cut: obfs password", js, "auth, obfs or obfs-password longer than 510 bytes");
    }

    {
        static char js[2600], pad[1200];
        memset(pad, ' ', sizeof pad - 1);
        pad[sizeof pad - 1] = '\0';
        char fm[1600];
        snprintf(fm, sizeof fm, HUDP("{\"mode\":\"intervalRemote\",\"remotePorts\":\"443,%s5000\"}"), pad);
        snprintf(js, sizeof js, HXOK("%s"), fm);
        hs_refused("a_remote_port_list_that_does_not_fit_is_refused_not_cut", js, "port list too long");
        pad[313] = '\0';
        snprintf(fm, sizeof fm, HUDP("{\"mode\":\"intervalRemote\",\"remotePorts\":\"443,%s5000\"}"), pad);
        snprintf(js, sizeof js, HXOK("%s"), fm);
        n = hs_parse(js, nodes, &st);
        check_n("a_padded_remote_port_list_that_fits_is_read_whole: count", 1, (long)n);
        check("a_padded_remote_port_list_that_fits_is_read_whole: ports", "443,5000", nodes[0].ports);
    }

    n = hs_parse("{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"v\",\"settings\":{\"version\":1E5,\"address\":\"h.example\","
                 "\"port\":443,\"id\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\"},\"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}]}",
                 nodes, &st);
    check_n("a_vless_outbound_with_an_odd_version_token_is_still_a_node: count", 1, (long)n);
    check("a_vless_outbound_with_an_odd_version_token_is_still_a_node: host", "h.example", nodes[0].host);

    static const char *const stray[] = {
        "{\"outbounds\":[{\"protocol\":\"hysteria\",\"settings\":[],\"streamSettings\":[]}]}",
        "{\"outbounds\":[{\"protocol\":\"hysteria\",\"settings\":5,\"streamSettings\":\"x\"}]}",
        "{\"outbounds\":[{\"protocol\":\"hysteria\",\"settings\":{\"version\":[],\"address\":{},\"port\":[]},"
        "\"streamSettings\":{\"network\":[],\"security\":{},\"hysteriaSettings\":[],\"finalmask\":[],\"tlsSettings\":5}}]}",
        "{\"outbounds\":[{\"protocol\":\"hysteria\",\"settings\":" HXS("2") ",\"streamSettings\":{\"network\":\"hysteria\","
        "\"security\":\"tls\",\"hysteriaSettings\":{\"version\":2,\"auth\":\"pw\"},\"finalmask\":{\"udp\":[{\"type\":\"udphop\","
        "\"settings\":[]},{\"type\":\"salamander\",\"settings\":5}],\"quicParams\":[]}}}]}",
        "{\"outbounds\":[{\"protocol\":\"hysteria\",\"settings\":" HXS("2") ",\"streamSettings\":{\"hysteriaSettings\":{\"auth\":\"x",
        "{\"outbounds\":[{\"protocol\":\"hysteria\",\"settings\":" HXS("2") ",\"streamSettings\":{\"finalmask\":{\"udp\":[{\"type\":",
    };
    for (size_t i = 0; i < sizeof stray / sizeof *stray; i++) {
        n = hs_parse(stray[i], nodes, &st);
        check_n("wrongly_typed_or_cut_hysteria_json_gives_no_node: count", 0, (long)n);
    }
}

static void t_hy2_singbox(void) {
    struct vless_node nodes[4];
    struct vless_sub_stats st;
    vless_set_insecure(0);

    size_t n = hs_parse(SB_BRIEF, nodes, &st);
    check_n("a_sing_box_hysteria2_outbound_is_a_node: count", 1, (long)n);
    check_n("a_sing_box_hysteria2_outbound_is_a_node: proto", VLESS_PROTO_HY2, nodes[0].proto);
    check("a_sing_box_hysteria2_outbound_is_a_node: name", "sb", nodes[0].name);
    check("a_sing_box_hysteria2_outbound_is_a_node: host", "h.example", nodes[0].host);
    check_n("a_sing_box_hysteria2_outbound_is_a_node: port is the first listed port", 2000, nodes[0].port);
    check("a_sing_box_hysteria2_outbound_is_a_node: ports", "2000-3000", nodes[0].ports);
    check_n("a_sing_box_hysteria2_outbound_is_a_node: hop_from", 30, nodes[0].hop_from);
    check_n("a_sing_box_hysteria2_outbound_is_a_node: hop_to", 30, nodes[0].hop_to);
    check_n("other_forms_hop_like_hysteria: sing-box server_ports", HY2_HOP_LOCAL | HY2_HOP_REMOTE, nodes[0].hop_mode);
    check_n("a_sing_box_hysteria2_outbound_is_a_node: up", 100, (long)nodes[0].up_mbps);
    check_n("a_sing_box_hysteria2_outbound_is_a_node: down", 200, (long)nodes[0].down_mbps);
    check("a_sing_box_hysteria2_outbound_is_a_node: auth", "pw", hs_s(nodes[0].auth));
    check("a_sing_box_hysteria2_outbound_is_a_node: obfs", "salamander", nodes[0].obfs);
    check("a_sing_box_hysteria2_outbound_is_a_node: obfs_pw", "obfs1234", hs_s(nodes[0].obfs_pw));
    check("a_sing_box_hysteria2_outbound_is_a_node: sni", "s.example", nodes[0].sni);
    check("a_sing_box_hysteria2_outbound_is_a_node: type", "quic", nodes[0].type);
    check("a_sing_box_hysteria2_outbound_is_a_node: security", "tls", nodes[0].security);

    static const struct { const char *extra; const char *ports; unsigned from, to, up, down; const char *why; } sb[] = {
        { ",\"server_ports\":\"2000:3000\"", "2000-3000", 0, 0, 0, 0, NULL },
        { ",\"server_ports\":[\"2000:3000\",\"4000:4000\"]", "2000-3000,4000", 0, 0, 0, 0, NULL },
        { ",\"server_ports\":[\"2000:\"]", "2000-65535", 0, 0, 0, 0, NULL },
        { ",\"server_ports\":[\"4000:4000\"]", "", 0, 0, 0, 0, NULL },
        { ",\"server_ports\":[\"4000\"]", "", 0, 0, 0, 0, "server_ports: not a port list" },
        { ",\"server_ports\":[\":3000\"]", "", 0, 0, 0, 0, "server_ports: not a port list" },
        { ",\"server_ports\":[\"3000:2000\"]", "", 0, 0, 0, 0, "server_ports: not a port list" },
        { ",\"server_ports\":[\"2000: 3000\"]", "", 0, 0, 0, 0, "server_ports: not a port list" },
        { ",\"server_ports\":[\"2000:3000\"],\"hop_interval\":\"30s\",\"hop_interval_max\":\"1m\"", "2000-3000", 30, 60, 0, 0, NULL },
        { SBP ",\"hop_interval\":\"2m\"", "2000-3000", 120, 120, 0, 0, NULL },
        { SBP ",\"hop_interval\":\"1m30s\"", "2000-3000", 90, 90, 0, 0, NULL },
        { SBP ",\"hop_interval\":\"1.5m\",\"hop_interval_max\":\"+2m\"", "2000-3000", 90, 120, 0, 0, NULL },
        { SBP ",\"hop_interval\":\"5s\"", "2000-3000", 5, 5, 0, 0, NULL },
        { SBP ",\"hop_interval\":\"1d\"", "2000-3000", 0, 0, 0, 0, "hop_interval: not whole seconds up to 65535" },
        { SBP ",\"hop_interval\":\"4s\"", "", 0, 0, 0, 0, "hop_interval must be at least 5 seconds" },
        { SBP ",\"hop_interval\":\"1h\",\"hop_interval_max\":\"10s\"", "", 0, 0, 0, 0, "hop_interval must not exceed hop_interval_max" },
        { SBP ",\"hop_interval_max\":\"10s\"", "", 0, 0, 0, 0, "hop_interval_max needs hop_interval" },
        { SBP ",\"hop_interval\":\"fast\"", "", 0, 0, 0, 0, "hop_interval: not a duration" },
        { SBP ",\"hop_interval\":30", "", 0, 0, 0, 0, "hop_interval: not a duration" },
        { SBP ",\"hop_interval\":\"\"", "", 0, 0, 0, 0, "hop_interval: not a duration" },
        { SBP ",\"hop_interval\":\"500ms\"", "", 0, 0, 0, 0, "hop_interval: not whole seconds up to 65535" },
        { SBP ",\"hop_interval\":\"9223372036854775808ns\"", "", 0, 0, 0, 0, "hop_interval: not a duration" },
        { SBP ",\"hop_interval\":\"-9223372036854775808ns\"", "", 0, 0, 0, 0, "hop_interval must be at least 5 seconds" },
        { ",\"hop_interval\":\"2m\"", "", 0, 0, 0, 0, NULL },
        { ",\"up_mbps\":100000,\"down_mbps\":\"7\"", "", 0, 0, 100000, 7, NULL },
        { ",\"up_mbps\":100001,\"down_mbps\":-5", "", 0, 0, 0, 0, NULL },
        { ",\"up_mbps\":12.5,\"down_mbps\":{}", "", 0, 0, 0, 0, NULL },
        { ",\"server_ports\":[\"x\"]", "", 0, 0, 0, 0, "server_ports: not a port list" },
        { ",\"server_ports\":[{}]", "", 0, 0, 0, 0, "server_ports: not a port list" },
        { ",\"obfs\":{\"type\":\"gecko\",\"password\":\"obfs1234\"}", "", 0, 0, 0, 0, "obfs gecko is not supported" },
        { ",\"obfs\":{\"type\":\"salamander\"}", "", 0, 0, 0, 0, "obfs-password missing" },
        { ",\"tls\":{\"enabled\":false,\"server_name\":\"s.example\"}", "", 0, 0, 0, 0, "hysteria2 needs tls" },
        { ",\"tls\":{\"server_name\":\"s.example\"}", "", 0, 0, 0, 0, "hysteria2 needs tls" },
        { ",\"obfs\":[]", "", 0, 0, 0, 0, "obfs is not an object" },
        { ",\"obfs\":{}", "", 0, 0, 0, 0, "obfs-password missing" },
        { ",\"obfs\":{\"password\":\"obfs1234\"}", "", 0, 0, 0, 0, "obfs type is missing" },
        { ",\"obfs\":{\"type\":\"\",\"password\":\"obfs1234\"}", "", 0, 0, 0, 0, "obfs type is missing" },
        { ",\"obfs\":{\"type\":\"salamander\",\"password\":\"ab\\u0000cd\"}", "", 0, 0, 0, 0, "NUL byte in auth, obfs or obfs-password" },
        { ",\"password\":\"pw\\u0000x\"", "", 0, 0, 0, 0, "NUL byte in auth, obfs or obfs-password" },
        { ",\"tls\":{\"enabled\":true,\"server_name\":\"s.example\",\"insecure\":true}", "", 0, 0, 0, 0, "allowInsecure: needs --insecure" },
        { ",\"tls\":{\"enabled\":true,\"server_name\":\"s.example\",\"certificate_public_key_sha256\":[\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]}",
          "", 0, 0, 0, 0, "pks is not supported for hysteria2" },
    };
    for (size_t i = 0; i < sizeof sb / sizeof *sb; i++) {
        char js[1200];
        snprintf(js, sizeof js, SBO("%s"), sb[i].extra);
        if (strstr(sb[i].extra, "\"tls\":")) {
            snprintf(js, sizeof js, "{\"outbounds\":[{\"type\":\"hysteria2\",\"tag\":\"sb\",\"server\":\"h.example\","
                     "\"server_port\":443,\"password\":\"pw\"%s}]}", sb[i].extra);
        }
        n = hs_parse(js, nodes, &st);
        if (sb[i].why) {
            check_n("sing_box_hysteria2_values_keep_their_units_and_refusals: refused", 0, (long)n);
            check("sing_box_hysteria2_values_keep_their_units_and_refusals: reason", sb[i].why, hs_reason(&st));
            continue;
        }
        check_n("sing_box_hysteria2_values_keep_their_units_and_refusals: count", 1, (long)n);
        check("sing_box_hysteria2_values_keep_their_units_and_refusals: ports", sb[i].ports, nodes[0].ports);
        check_n("sing_box_hysteria2_values_keep_their_units_and_refusals: hop_from", sb[i].from, nodes[0].hop_from);
        check_n("sing_box_hysteria2_values_keep_their_units_and_refusals: hop_to", sb[i].to, nodes[0].hop_to);
        check_n("sing_box_hysteria2_values_keep_their_units_and_refusals: up", sb[i].up, (long)nodes[0].up_mbps);
        check_n("sing_box_hysteria2_values_keep_their_units_and_refusals: down", sb[i].down, (long)nodes[0].down_mbps);
    }

    hs_refused("a_sing_box_hysteria2_without_a_password_is_refused",
               "{\"outbounds\":[{\"type\":\"hysteria2\",\"server\":\"h.example\",\"server_port\":443," SBTLS "}]}", "auth is empty");
    hs_refused("a_sing_box_hysteria2_without_tls_is_refused",
               "{\"outbounds\":[{\"type\":\"hysteria2\",\"server\":\"h.example\",\"server_port\":443,\"password\":\"pw\"}]}",
               "hysteria2 needs tls");
    hs_refused("a_sing_box_hysteria2_without_any_port_is_refused",
               "{\"outbounds\":[{\"type\":\"hysteria2\",\"server\":\"h.example\",\"password\":\"pw\"," SBTLS "}]}", "port is missing");
    n = hs_parse("{\"outbounds\":[{\"type\":\"hysteria2\",\"server\":\"h.example\",\"password\":\"pw\","
                 "\"server_ports\":[\"5000:6000\"]," SBTLS "}]}", nodes, &st);
    check_n("a_sing_box_hysteria2_without_server_port_dials_the_first_hop_port: count", 1, (long)n);
    check_n("a_sing_box_hysteria2_without_server_port_dials_the_first_hop_port: port", 5000, nodes[0].port);
    n = hs_parse(SBO(",\"server_ports\":[\"4000:4000\"]"), nodes, &st);
    check_n("a_sing_box_single_port_list_dials_that_port_not_server_port: count", 1, (long)n);
    check_n("a_sing_box_single_port_list_dials_that_port_not_server_port: port", 4000, nodes[0].port);
    check("a_sing_box_single_port_list_dials_that_port_not_server_port: ports", "", nodes[0].ports);
    check_n("one_listed_port_and_none: a sing-box single port hops like any list", HY2_HOP_LOCAL | HY2_HOP_REMOTE, nodes[0].hop_mode);
    n = hs_parse(SBO(",\"server_ports\":[\"7000:7100\",\"3000:3001\"]"), nodes, &st);
    check_n("a_sing_box_port_list_dials_the_first_listed_port: port", 7000, nodes[0].port);
    n = hs_parse("{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"v\",\"server\":\"h.example\",\"server_port\":443,"
                 "\"uuid\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\",\"password\":\"pw\",\"up_mbps\":5,\"server_ports\":[\"1:2\"]}]}",
                 nodes, &st);
    check_n("a_vless_outbound_ignores_hysteria_keys: count", 1, (long)n);
    check_n("a_vless_outbound_ignores_hysteria_keys: proto", VLESS_PROTO_VLESS, nodes[0].proto);
    check_n("a_vless_outbound_ignores_hysteria_keys: no auth", 1, nodes[0].auth == NULL);
    check_n("a_vless_outbound_ignores_hysteria_keys: no rate", 0, (long)nodes[0].up_mbps);
    check("a_vless_outbound_ignores_hysteria_keys: no ports", "", nodes[0].ports);
}

static void t_hy2_clash(void) {
    struct vless_node nodes[4];
    struct vless_sub_stats st;

    vless_set_insecure(1);
    size_t n = hs_parse(CL_BRIEF, nodes, &st);
    vless_set_insecure(0);
    check_n("a_clash_hysteria2_proxy_is_a_node: count", 1, (long)n);
    check_n("a_clash_hysteria2_proxy_is_a_node: proto", VLESS_PROTO_HY2, nodes[0].proto);
    check("a_clash_hysteria2_proxy_is_a_node: name", "cl", nodes[0].name);
    check("a_clash_hysteria2_proxy_is_a_node: host", "h.example", nodes[0].host);
    check_n("a_clash_hysteria2_proxy_is_a_node: port is the first listed port", 2000, nodes[0].port);
    check_n("other_forms_hop_like_hysteria: clash ports", HY2_HOP_LOCAL | HY2_HOP_REMOTE, nodes[0].hop_mode);
    check("a_clash_hysteria2_proxy_is_a_node: ports", "2000-3000", nodes[0].ports);
    check("a_clash_hysteria2_proxy_is_a_node: auth", "pw", hs_s(nodes[0].auth));
    check("a_clash_hysteria2_proxy_is_a_node: obfs", "salamander", nodes[0].obfs);
    check("a_clash_hysteria2_proxy_is_a_node: obfs_pw", "obfs1234", hs_s(nodes[0].obfs_pw));
    check("a_clash_hysteria2_proxy_is_a_node: sni", "s.example", nodes[0].sni);
    check_n("a_clash_hysteria2_proxy_is_a_node: allow_insecure", 1, nodes[0].allow_insecure);
    check("a_clash_hysteria2_proxy_is_a_node: pcs", CL_PIN, hs_s(nodes[0].pcs));
    check_n("a_clash_hysteria2_proxy_is_a_node: up", 100, (long)nodes[0].up_mbps);
    check_n("a_clash_hysteria2_proxy_is_a_node: down", 50, (long)nodes[0].down_mbps);
    check("a_clash_hysteria2_proxy_is_a_node: type", "quic", nodes[0].type);
    check("a_clash_hysteria2_proxy_is_a_node: security", "tls", nodes[0].security);

    n = hs_parse(CL_BRIEF, nodes, &st);
    check_n("skip_cert_verify_needs_the_insecure_switch: count", 0, (long)n);
    check("skip_cert_verify_needs_the_insecure_switch: reason", "allowInsecure: needs --insecure", hs_reason(&st));

    static const struct { const char *rate; unsigned mbps; } rate[] = {
        { "100 Mbps", 100 }, { "50 Mbps", 50 }, { "100", 100 }, { "100Mbps", 100 }, { "1 Gbps", 1000 },
        { "800 Kbps", 0 }, { "100 MBps", 800 }, { "100 Bps", 0 }, { "125000 Bps", 1 }, { "100 mbps", 0 }, { "abc", 0 },
        { "100 Gbps", 100000 }, { "2305843015463694 KBps", 0 }, { "1 Tbps", 0 }, { "-5", 0 }, { "", 0 }, { "5 Mbps extra", 0 },
        { "0", 0 },
    };
    for (size_t i = 0; i < sizeof rate / sizeof *rate; i++) {
        char y[400];
        snprintf(y, sizeof y, CLO("    up: \"%s\"\n    down: \"%s\"\n"), rate[i].rate, rate[i].rate);
        n = hs_parse(y, nodes, &st);
        check_n("clash_rates_follow_the_mihomo_rule: count", 1, (long)n);
        check_n("clash_rates_follow_the_mihomo_rule: up", rate[i].mbps, (long)nodes[0].up_mbps);
        check_n("clash_rates_follow_the_mihomo_rule: down", rate[i].mbps, (long)nodes[0].down_mbps);
    }

    static const struct { const char *extra; const char *ports; unsigned port, from, to; const char *why; } cl[] = {
        { "    ports: 2000-3000\n", "2000-3000", 2000, 0, 0, NULL },
        { "    ports: 443,2000-3000/4000\n", "443,2000-3000,4000", 443, 0, 0, NULL },
        { "    ports: \"2000-3000, 4000,\"\n", "2000-3000,4000", 2000, 0, 0, NULL },
        { "    ports: 5000\n", "", 5000,
        0, 0, NULL },
        { "    ports: \",443,,2000-3000\"\n", "443,2000-3000", 443, 0, 0, NULL },
        { "    ports: 2000-3000\n    hop-interval: 15-20\n", "2000-3000", 2000, 15, 20, NULL },
        { "    ports: 2000-3000\n    hop-interval: 30\n", "2000-3000", 2000, 30, 30, NULL },
        { "    ports: 2000-3000\n    hop-interval: 3\n", "2000-3000", 2000, 5, 5, NULL },
        { "    ports: 2000-3000\n    hop-interval: 40-20\n", "2000-3000", 2000, 20, 40, NULL },
        { "    ports: 2000-3000\n    hop-interval: 0\n", "2000-3000", 2000, 0, 0, NULL },
        { "    ports: 2000-3000\n    hop-interval: soon\n", "", 443, 0, 0, "hop-interval: not a number or range" },
        { "    ports: x-y\n", "", 443, 0, 0, "ports: not a port list" },
        { "    ports: 0\n", "", 443, 0, 0, "ports: not a port list" },
        { "    fingerprint: chrome\n", "", 443, 0, 0, "pinSHA256: not a hex SHA-256" },
        { "    obfs: gecko\n    obfs-password: obfs1234\n", "", 443, 0, 0, "obfs gecko is not supported" },
        { "    obfs: salamander\n", "", 443, 0, 0, "obfs-password missing" },
        { "    ech-opts:\n      enable: true\n      config: AEX+DQBBNwAgACANG785NbYxf2vAoHiUugO7PDLchnWNz2f+95epg2DJewAEAAEAAQASY2xvdWRmbGFyZS1lY2guY29tAAA=\n",
          "", 443, 0, 0, "ech is not supported for hysteria2" },
        { "    name-cert-verify: a.example,b.example\n", "", 443, 0, 0, "verifyPeerCertByName: one name only" },
    };
    for (size_t i = 0; i < sizeof cl / sizeof *cl; i++) {
        char y[900];
        snprintf(y, sizeof y, CLO("%s"), cl[i].extra);
        n = hs_parse(y, nodes, &st);
        if (cl[i].why) {
            check_n("clash_hysteria2_keys_keep_their_values_and_refusals: refused", 0, (long)n);
            check("clash_hysteria2_keys_keep_their_values_and_refusals: reason", cl[i].why, hs_reason(&st));
            continue;
        }
        check_n("clash_hysteria2_keys_keep_their_values_and_refusals: count", 1, (long)n);
        check("clash_hysteria2_keys_keep_their_values_and_refusals: ports", cl[i].ports, nodes[0].ports);
        check_n("clash_hysteria2_keys_keep_their_values_and_refusals: port", cl[i].port, nodes[0].port);
        check_n("clash_hysteria2_keys_keep_their_values_and_refusals: hop_from", cl[i].from, nodes[0].hop_from);
        check_n("clash_hysteria2_keys_keep_their_values_and_refusals: hop_to", cl[i].to, nodes[0].hop_to);
    }

    n = hs_parse(CL_HEAD "    ports: 5000-6000\n    password: pw\n    sni: s.example\n", nodes, &st);
    check_n("a_clash_proxy_without_port_dials_the_first_hop_port: count", 1, (long)n);
    check_n("a_clash_proxy_without_port_dials_the_first_hop_port: port", 5000, nodes[0].port);
    check_n("other_forms_hop_like_hysteria: clash ports without a port", HY2_HOP_LOCAL | HY2_HOP_REMOTE, nodes[0].hop_mode);
    n = hs_parse(CL_HEAD "    port: 443\n    ports: 6000\n    password: pw\n    sni: s.example\n", nodes, &st);
    check_n("one_listed_port_and_none: a clash single port: port", 6000, nodes[0].port);
    check_n("one_listed_port_and_none: a clash single port: mode", HY2_HOP_LOCAL | HY2_HOP_REMOTE, nodes[0].hop_mode);
    hs_refused("a_nul_escape_in_a_clash_password_is_refused", CL_HEAD "    port: 443\n    password: \"p\\x00w\"\n",
               "NUL byte in auth, obfs or obfs-password");
    hs_refused("a_nul_escape_in_a_clash_obfs_password_is_refused",
               CLO("    obfs: salamander\n    obfs-password: \"ab\\u0000cd\"\n"), "NUL byte in auth, obfs or obfs-password");
    hs_refused("a_clash_proxy_without_any_port_is_refused", CL_HEAD "    password: pw\n", "port is missing");
    hs_refused("a_clash_proxy_without_a_password_is_refused", CL_HEAD "    port: 443\n", "auth is empty");
    n = hs_parse(CLO("    name-cert-verify: a.example\n"), nodes, &st);
    check_n("name_cert_verify_is_the_verify_name: count", 1, (long)n);
    check("name_cert_verify_is_the_verify_name: vcn", "a.example", hs_s(nodes[0].vcn));
    n = hs_parse("proxies:\n  - {name: fl, type: hysteria2, server: h.example, port: 8443, password: pw, sni: s.example, up: 10 Mbps, down: 20 Mbps}\n",
                 nodes, &st);
    check_n("a_flow_style_clash_hysteria2_proxy_is_a_node: count", 1, (long)n);
    check_n("a_flow_style_clash_hysteria2_proxy_is_a_node: port", 8443, nodes[0].port);
    check_n("a_flow_style_clash_hysteria2_proxy_is_a_node: up", 10, (long)nodes[0].up_mbps);
    check_n("a_flow_style_clash_hysteria2_proxy_is_a_node: down", 20, (long)nodes[0].down_mbps);
    n = hs_parse("proxies:\n  - name: old\n    type: hysteria\n    server: h.example\n    port: 443\n"
                 "  - name: v\n    type: vless\n    server: h.example\n    port: 443\n    uuid: 8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\n",
                 nodes, &st);
    check_n("hysteria_v1_in_clash_is_foreign: count", 1, (long)n);
    check_n("hysteria_v1_in_clash_is_foreign: foreign", 1, (long)st.foreign);
}

static void t_hy2_list(void) {
    struct vless_node nodes[4];
    struct vless_sub_stats st;
    vless_set_insecure(0);

    size_t n = hs_parse(LIST4, nodes, &st);
    check_n("a_mixed_link_list_counts_no_foreign_hysteria: usable", 3, (long)n);
    check_n("a_mixed_link_list_counts_no_foreign_hysteria: skipped", 0, (long)st.skipped);
    check_n("a_mixed_link_list_counts_no_foreign_hysteria: foreign", 1, (long)st.foreign);
    check_n("a_mixed_link_list_counts_no_foreign_hysteria: first is vless", VLESS_PROTO_VLESS, nodes[0].proto);
    check_n("a_mixed_link_list_counts_no_foreign_hysteria: second is hysteria2", VLESS_PROTO_HY2, nodes[1].proto);
    check_n("a_mixed_link_list_counts_no_foreign_hysteria: third is hysteria2", VLESS_PROTO_HY2, nodes[2].proto);
    check("a_mixed_link_list_counts_no_foreign_hysteria: hy2 host", "h2.example", nodes[2].host);

    n = hs_parse("hysteria2://pw@h.example:443/?sni=s.example#onehysteria2://pw@h2.example:443/?sni=s.example#b\n", nodes, &st);
    check_n("a_glued_hysteria2_link_splits_by_scheme: usable", 2, (long)n);
    check_n("a_glued_hysteria2_link_splits_by_scheme: skipped", 0, (long)st.skipped);
    check("a_glued_hysteria2_link_splits_by_scheme: first name", "one", nodes[0].name);
    check("a_glued_hysteria2_link_splits_by_scheme: second host", "h2.example", nodes[1].host);

    n = hs_parse("vless://u@h.example:443?security=none#onehy2://pw@h2.example:443/?sni=s.example#b\n", nodes, &st);
    check_n("a_hysteria2_link_glued_after_vless_splits_by_scheme: usable", 2, (long)n);

    n = hs_parse("hysteria2://pw@h.example:443/?sni=s.example#xanytls://u@h.example:1\n", nodes, &st);
    check_n("a_hysteria2_link_glued_to_an_unknown_scheme_is_noted: usable", 0, (long)n);
    check_n("a_hysteria2_link_glued_to_an_unknown_scheme_is_noted: skipped", 1, (long)st.skipped);
    check("a_hysteria2_link_glued_to_an_unknown_scheme_is_noted: reason", "links glued without a separator", hs_reason(&st));

    n = hs_parse("hy2://pw@h.example:0/?sni=s\n", nodes, &st);
    check_n("an_unparsable_hysteria2_link_is_skipped_not_foreign: usable", 0, (long)n);
    check_n("an_unparsable_hysteria2_link_is_skipped_not_foreign: skipped", 1, (long)st.skipped);
    check_n("an_unparsable_hysteria2_link_is_skipped_not_foreign: foreign", 0, (long)st.foreign);
    check("an_unparsable_hysteria2_link_is_skipped_not_foreign: reason", "cannot parse the link", hs_reason(&st));

    n = hs_parse("hysteria2://@h.example:443/?sni=s\nhysteria://pw@h.example:443\n", nodes, &st);
    check_n("an_unusable_hysteria2_link_is_skipped_with_its_reason: usable", 0, (long)n);
    check_n("an_unusable_hysteria2_link_is_skipped_with_its_reason: skipped", 1, (long)st.skipped);
    check_n("an_unusable_hysteria2_link_is_skipped_with_its_reason: foreign", 1, (long)st.foreign);
    check("an_unusable_hysteria2_link_is_skipped_with_its_reason: reason", "auth is empty", hs_reason(&st));

    {
        static char big[9000];
        size_t o = (size_t)snprintf(big, sizeof big, "hysteria2://pw@h.example:443/?sni=s&x=");
        memset(big + o, 'a', 8500);
        big[o + 8500] = '\0';
        n = hs_parse(big, nodes, &st);
        check_n("a_too_long_hysteria2_link_is_skipped_not_foreign: usable", 0, (long)n);
        check_n("a_too_long_hysteria2_link_is_skipped_not_foreign: skipped", 1, (long)st.skipped);
        check_n("a_too_long_hysteria2_link_is_skipped_not_foreign: foreign", 0, (long)st.foreign);
        check("a_too_long_hysteria2_link_is_skipped_not_foreign: reason", "link longer than 8191 bytes", hs_reason(&st));
    }
}

static void t_hy2_count(void) {
    check_n("the_count_bounds_every_form: xray hand count", 3, (long)vless_sub_count(HX_BRIEF));
    check_n("the_count_bounds_every_form: sing-box hand count", 1, (long)vless_sub_count(SB_BRIEF));
    check_n("the_count_bounds_every_form: clash hand count", 1, (long)vless_sub_count(CL_BRIEF));
    check_n("the_count_bounds_every_form: list hand count", 3, (long)vless_sub_count(LIST4));
    struct vless_node nodes[4];
    struct vless_sub_stats st;
    check_n("the_count_bounds_every_form: xray bound", 1, vless_sub_count(HX_BRIEF) >= hs_parse(HX_BRIEF, nodes, &st));
    check_n("the_count_bounds_every_form: sing-box bound", 1, vless_sub_count(SB_BRIEF) >= hs_parse(SB_BRIEF, nodes, &st));
    vless_set_insecure(1);
    check_n("the_count_bounds_every_form: clash bound", 1, vless_sub_count(CL_BRIEF) >= hs_parse(CL_BRIEF, nodes, &st));
    vless_set_insecure(0);
    check_n("the_count_bounds_every_form: list bound", 1, vless_sub_count(LIST4) >= hs_parse(LIST4, nodes, &st));
    check_n("the_count_reads_each_word_in_any_case: mixed", 3, (long)vless_sub_count("VLESS://a Hysteria2://b hY2://c"));
    check_n("the_count_reads_each_word_in_any_case: adjacent", 2, (long)vless_sub_count("hy2hy2"));
    check_n("the_count_reads_each_word_in_any_case: hysteria2 is one", 1, (long)vless_sub_count("hysteria2"));
    check_n("the_count_reads_each_word_in_any_case: empty", 0, (long)vless_sub_count(""));
    check_n("the_count_reads_each_word_in_any_case: other words", 0, (long)vless_sub_count("trojan:// vmess:// hy1 hysteri"));
    check_n("the_count_reads_each_word_in_any_case: cut at the end", 0, (long)vless_sub_count("vles hysteri hy"));
}

static void t_hy2_secrets_up_to_the_node_cap(void) {
    size_t cap = 1024, room = cap * 400;
    char *text = malloc(room);
    struct vless_node *nodes = calloc(cap + 1, sizeof *nodes);
    if (!text || !nodes) {
        check_n("every_node_up_to_the_cap_keeps_its_own_secrets: memory", 1, 0);
        free(text);
        free(nodes);
        return;
    }
    size_t o = 0;
    for (size_t i = 0; i < cap; i++)
        o += (size_t)snprintf(text + o, room - o,
                              "hysteria2://auth%zu@h%zu.example:443/?sni=s.example&obfs=salamander&obfs-password=obfs%zu"
                              "&pinSHA256=%064zx&qp=%%7B%%22k%%22%%3A%zu%%7D#n%zu\n",
                              i, i, i, i + 1, i, i);
    struct vless_sub_stats st;
    sl_intern_reset();
    size_t n = vless_parse_sub(text, nodes, cap + 1, &st);
    check_n("every_node_up_to_the_cap_keeps_its_own_secrets: usable", 1024, (long)n);
    check_n("every_node_up_to_the_cap_keeps_its_own_secrets: refused", 0, (long)st.skipped);
    check("every_node_up_to_the_cap_keeps_its_own_secrets: last auth", "auth1023",
          n == cap && nodes[cap - 1].auth ? nodes[cap - 1].auth : "");
    check("every_node_up_to_the_cap_keeps_its_own_secrets: last obfs-password", "obfs1023",
          n == cap && nodes[cap - 1].obfs_pw ? nodes[cap - 1].obfs_pw : "");
    sl_intern_reset();
    free(text);
    free(nodes);
}

static void t_hy2_link_secret_bound(void) {
    static char u[1400], s[520];
    struct vless_node n;
    memset(s, 'a', 511);
    s[511] = '\0';
    snprintf(u, sizeof u, "hysteria2://%s@h.example:443/?sni=s", s);
    check_n("a_long_link_secret_is_refused: auth of 511 refused", 1, vless_parse_url(u, &n));
    check("a_long_link_secret_is_refused: reason", "auth, obfs or obfs-password longer than 510 bytes", n.skip_reason);
    snprintf(u, sizeof u, "hysteria2://pw@h.example:443/?sni=s&obfs=salamander&obfs-password=%s", s);
    check_n("a_long_link_secret_is_refused: obfs-password of 511 refused", 1, vless_parse_url(u, &n));
    check("a_long_link_secret_is_refused: its reason", "auth, obfs or obfs-password longer than 510 bytes", n.skip_reason);
    s[510] = '\0';
    snprintf(u, sizeof u, "hysteria2://%s@h.example:443/?sni=s&obfs=salamander&obfs-password=%s", s, s);
    check_n("a_long_link_secret_is_refused: 510 of each is taken", 0, vless_parse_url(u, &n));
    check_n("a_long_link_secret_is_refused: whole", 1, n.auth && n.obfs_pw && strlen(n.auth) == 510 && strlen(n.obfs_pw) == 510);
}

static int qp_rc(const char *json, struct hy2_qp *q, char *why, size_t wn) {
    memset(q, 0xA5, sizeof *q);
    why[0] = '\0';
    return hy2_qp_parse(json, strlen(json), q, why, wn);
}

static void qp_refused(const char *name, const char *json, const char *why) {
    struct hy2_qp q;
    char w[160];
    int rc = qp_rc(json, &q, w, sizeof w);
    check_n(name, -1, rc);
    check(name, why, w);
}

static void qp_ok(const char *name, const char *json) {
    struct hy2_qp q;
    char w[160];
    int rc = qp_rc(json, &q, w, sizeof w);
    check_n(name, 0, rc);
}

static void t_qp_all(void) {
    struct hy2_qp q;
    char w[160];
    int rc = qp_rc("{\"congestion\":\"Force-Brutal\",\"brutalUp\":\"100 mbps\",\"brutalDown\":\"50 mbps\","
                   "\"brutalDisableLossCompensation\":true,\"initStreamReceiveWindow\":1048576,"
                   "\"maxStreamReceiveWindow\":4194304,\"initConnectionReceiveWindow\":2097152,"
                   "\"maxConnectionReceiveWindow\":16777216,\"maxIdleTimeout\":60,\"keepAlivePeriod\":20,"
                   "\"disablePathMTUDiscovery\":true,\"futureKey\":{\"a\":1}}", &q, w, sizeof w);
    check_n("quic_params_are_read_as_xray_reads_them: rc", 0, rc);
    check_n("quic_params_are_read_as_xray_reads_them: cc", HY2_CC_FORCE, q.cc);
    check_n("quic_params_are_read_as_xray_reads_them: up", 13107200, (long)q.up_bps);
    check_n("quic_params_are_read_as_xray_reads_them: down", 6553600, (long)q.down_bps);
    check_n("quic_params_are_read_as_xray_reads_them: loss", 1, q.no_loss_comp);
    check_n("quic_params_are_read_as_xray_reads_them: init stream", 1048576, (long)q.init_stream_win);
    check_n("quic_params_are_read_as_xray_reads_them: max stream", 4194304, (long)q.max_stream_win);
    check_n("quic_params_are_read_as_xray_reads_them: init conn", 2097152, (long)q.init_conn_win);
    check_n("quic_params_are_read_as_xray_reads_them: max conn", 16777216, (long)q.max_conn_win);
    check_n("quic_params_are_read_as_xray_reads_them: idle", 60, (long)q.idle_s);
    check_n("quic_params_are_read_as_xray_reads_them: keepalive", 20, (long)q.keepalive_s);
    check_n("quic_params_are_read_as_xray_reads_them: pmtud", 1, q.no_pmtud);
    check_n("quic_params_are_read_as_xray_reads_them: ignored", 0, (long)q.ignored);

    rc = qp_rc("{\"bbrProfile\":\"aggressive\",\"debug\":true,\"disableChromeParrot\":true,\"disableGSO\":true,"
               "\"maxIncomingStreams\":64,\"disableStatelessReset\":true}", &q, w, sizeof w);
    check_n("params_xrays_client_ignores_are_named: rc", 0, rc);
    check_n("params_xrays_client_ignores_are_named: all", 59, (long)q.ignored);
    check_n("params_xrays_client_ignores_are_named: no_parrot", 1, q.no_parrot);
    rc = qp_rc("{\"bbrProfile\":\"\",\"debug\":false,\"maxIncomingStreams\":0}", &q, w, sizeof w);
    check_n("params_xrays_client_ignores_are_named: none rc", 0, rc);
    check_n("params_xrays_client_ignores_are_named: none", 0, (long)q.ignored);
    check_n("params_xrays_client_ignores_are_named: none no_parrot", 0, q.no_parrot);
    rc = qp_rc("{\"congestion\":\"bbr\",\"brutalUp\":\"1 mbps\"}", &q, w, sizeof w);
    check_n("params_xrays_client_ignores_are_named: cc bbr", HY2_CC_BBR, q.cc);
    rc = qp_rc("{\"congestion\":\"RENO\"}", &q, w, sizeof w);
    check_n("params_xrays_client_ignores_are_named: cc reno", HY2_CC_RENO, q.cc);
    rc = qp_rc("{\"congestion\":\"brutal\"}", &q, w, sizeof w);
    check_n("params_xrays_client_ignores_are_named: cc brutal", HY2_CC_AUTO, q.cc);
    rc = qp_rc("{}", &q, w, sizeof w);
    check_n("params_xrays_client_ignores_are_named: empty", 0, rc + (long)q.cc + (long)q.up_bps + (long)q.idle_s);

    static const struct { const char *json; const char *why; } ref[] = {
        { "{\"congestion\":\"Cubic\"}", "unknown congestion control: cubic, valid values: reno, bbr, brutal, force-brutal" },
        { "{\"congestion\":\"force-brutal\"}", "force-brutal requires up" },
        { "{\"bbrProfile\":\"fast\"}", "unknown bbr profile" },
        { "{\"initStreamReceiveWindow\":16383}", "InitStreamReceiveWindow must be at least 16384" },
        { "{\"maxStreamReceiveWindow\":16383}", "MaxStreamReceiveWindow must be at least 16384" },
        { "{\"initConnectionReceiveWindow\":16383}", "InitConnectionReceiveWindow must be at least 16384" },
        { "{\"maxConnectionReceiveWindow\":16383}", "MaxConnectionReceiveWindow must be at least 16384" },
        { "{\"maxIdleTimeout\":3}", "MaxIdleTimeout must be between 4 and 120" },
        { "{\"maxIdleTimeout\":121}", "MaxIdleTimeout must be between 4 and 120" },
        { "{\"maxIdleTimeout\":-1}", "MaxIdleTimeout must be between 4 and 120" },
        { "{\"keepAlivePeriod\":1}", "KeepAlivePeriod must be between 2 and 60" },
        { "{\"keepAlivePeriod\":61}", "KeepAlivePeriod must be between 2 and 60" },
        { "{\"maxIncomingStreams\":7}", "MaxIncomingStreams must be at least 8" },
        { "{\"brutalUp\":\"100\"}", "BrutalUp must be at least 65536 bytes per second" },
        { "{\"brutalDown\":\"100\"}", "BrutalDown must be at least 65536 bytes per second" },
        { "{\"brutalUp\":\"fast\"}", "strconv.ParseFloat: parsing \"\": invalid syntax" },
        { "{\"brutalUp\":\"5 parsec\"}", "unsupported unit: parsec" },
        { "{\"brutalUp\":\"5 x\\ntunvless[info]: forged\\u001b[31m\"}", "unsupported unit: x?tunvless[info]: forged?[31m" },
        { "{\"congestion\":\"a\\r\\nb\\u007f\"}", "unknown congestion control: a??b?, valid values: reno, bbr, brutal, force-brutal" },
        { "{\"congestion\":\"x\",\"maxIdleTimeout\":3}", "unknown congestion control: x, valid values: reno, bbr, brutal, force-brutal" },
        { "{\"maxIdleTimeout\":3,\"bbrProfile\":\"fast\",\"brutalUp\":\"fast\"}", "unknown bbr profile" },
        { "{\"brutalUp\":\"fast\",\"brutalDown\":\"5 parsec\"}", "strconv.ParseFloat: parsing \"\": invalid syntax" },
        { "{\"brutalUp\":\"100\",\"congestion\":\"x\"}", "BrutalUp must be at least 65536 bytes per second" },
        { "{\"initStreamReceiveWindow\":16383,\"maxIdleTimeout\":3}", "InitStreamReceiveWindow must be at least 16384" },
        { "{\"maxIdleTimeout\":3,\"keepAlivePeriod\":1}", "MaxIdleTimeout must be between 4 and 120" },
        { "{\"keepAlivePeriod\":1,\"maxIncomingStreams\":7}", "KeepAlivePeriod must be between 2 and 60" },
    };
    for (size_t i = 0; i < sizeof ref / sizeof *ref; i++) qp_refused("xray_refusals_keep_xrays_words", ref[i].json, ref[i].why);

    static const char *const okq[] = {
        "{\"initStreamReceiveWindow\":16384}", "{\"maxStreamReceiveWindow\":16384}",
        "{\"initConnectionReceiveWindow\":16384}", "{\"maxConnectionReceiveWindow\":16384}",
        "{\"maxIdleTimeout\":4}", "{\"maxIdleTimeout\":120}", "{\"keepAlivePeriod\":2}", "{\"keepAlivePeriod\":60}",
        "{\"maxIncomingStreams\":8}", "{\"brutalUp\":\"512 kbps\"}", "{\"congestion\":\"force-brutal\",\"brutalUp\":\"1 mbps\"}",
        "{\"brutalUp\":\"\"}", "{\"bbrProfile\":\"Standard\"}", "{\"brutalDown\":null,\"debug\":null}",
    };
    for (size_t i = 0; i < sizeof okq / sizeof *okq; i++) qp_ok("xray_refusals_keep_xrays_words: accepted", okq[i]);
    rc = qp_rc("{\"brutalUp\":\"512 kbps\"}", &q, w, sizeof w);
    check_n("xray_refusals_keep_xrays_words: 512 kbps", 65536, (long)q.up_bps);

    rc = qp_rc("{\"BRUTALUP\":\"100 mbps\"}", &q, w, sizeof w);
    check_n("the_decoder_rules_come_first: case rc", 0, rc);
    check_n("the_decoder_rules_come_first: case up", 13107200, (long)q.up_bps);
    rc = qp_rc("{\"maxIdleTimeout\":10,\"maxIdleTimeout\":60}", &q, w, sizeof w);
    check_n("the_decoder_rules_come_first: duplicate", 60, (long)q.idle_s);
    rc = qp_rc("{\"maxIdleTimeout\":60,\"maxIdleTimeout\":10}", &q, w, sizeof w);
    check_n("the_decoder_rules_come_first: duplicate last", 10, (long)q.idle_s);
    qp_refused("the_decoder_rules_come_first", "{\"initStreamReceiveWindow\":-1}", "quicParams: initStreamReceiveWindow is not a number");
    qp_refused("the_decoder_rules_come_first", "{\"maxStreamReceiveWindow\":1.5}", "quicParams: maxStreamReceiveWindow is not a number");
    qp_refused("the_decoder_rules_come_first", "{\"maxIdleTimeout\":\"60\"}", "quicParams: maxIdleTimeout is not a number");
    qp_refused("the_decoder_rules_come_first", "{\"maxIdleTimeout\":060}", "quicParams: maxIdleTimeout is not a number");
    qp_refused("the_decoder_rules_come_first", "{\"brutalDown\":1000}", "quicParams: brutalDown is not a string");
    qp_refused("the_decoder_rules_come_first", "{\"debug\":\"yes\"}", "quicParams: debug is not a boolean");
    qp_refused("the_decoder_rules_come_first", "{\"disableGSO\":1}", "quicParams: disableGSO is not a boolean");
    qp_refused("the_decoder_rules_come_first", "{\"congestion\":5}", "quicParams: congestion is not a string");
    qp_refused("the_decoder_rules_come_first", "{\"brutalUp\":{}}", "quicParams: brutalUp is not a string");
    qp_refused("the_decoder_rules_come_first", "{\"congestion\":\"x\",\"debug\":\"yes\"}", "quicParams: debug is not a boolean");
    qp_refused("the_decoder_rules_come_first", "{\"maxIdleTimeout\":3,\"bbrProfile\":5}", "quicParams: bbrProfile is not a string");
    qp_refused("string_values_not_held_whole_are_refused", "{\"brutalUp\":\"100000000                                                                                                                        kbps\"}", "quicParams: brutalUp is too long");
    qp_refused("string_values_not_held_whole_are_refused", "{\"brutalUp\":\"100 mbps                                                                                                                       garbage\"}", "quicParams: brutalUp is too long");
    qp_refused("string_values_not_held_whole_are_refused", "{\"congestion\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", "quicParams: congestion is too long");
    {
        char js[200];
        snprintf(js, sizeof js, "{\"brutalUp\":\"100 mbps%*s\"}", 119, "");
        rc = qp_rc(js, &q, w, sizeof w);
        check_n("string_values_not_held_whole_are_refused: 127 bytes held", 0, rc);
        check_n("string_values_not_held_whole_are_refused: 127 bytes up", 13107200, (long)q.up_bps);
        snprintf(js, sizeof js, "{\"brutalUp\":\"100 mbps%*s\"}", 120, "");
        qp_refused("string_values_not_held_whole_are_refused: 128 bytes", js, "quicParams: brutalUp is too long");
    }
    qp_refused("a_decoded_nul_is_never_dropped", "{\"congestion\":\"brutal\\u0000zzz\"}", "quicParams: congestion holds a NUL byte");
    qp_refused("a_decoded_nul_is_never_dropped", "{\"congestion\":\"brutal\\u0000\"}", "quicParams: congestion holds a NUL byte");
    qp_refused("a_decoded_nul_is_never_dropped", "{\"brutalUp\":\"100 mbps\\u0000x\"}", "quicParams: brutalUp holds a NUL byte");
    qp_refused("a_decoded_nul_is_never_dropped", "{\"bbrProfile\":\"fast\",\"congestion\":\"b\\u0000\"}", "unknown bbr profile");
    qp_refused("a_decoded_nul_is_never_dropped", "{\"congestion\":\"b\\u0000\",\"maxIdleTimeout\":3}", "quicParams: congestion holds a NUL byte");
    qp_refused("a_decoded_nul_is_never_dropped", "{\"bbrProfile\":\"standard\\u0000\"}", "unknown bbr profile");
    qp_refused("a_decoded_nul_is_never_dropped", "{\"brutalDown\":\"100 mbps\\u0000\"}", "quicParams: brutalDown holds a NUL byte");
    qp_refused("string_values_not_held_whole_are_refused", "{\"bbrProfile\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}", "quicParams: bbrProfile is too long");
    rc = qp_rc("{\"brutalUp\":\"100 mbps\",\"brutalUp\\u0000x\":\"1\",\"debug\\u0000\":\"yes\"}", &q, w, sizeof w);
    check_n("a_key_holding_a_nul_is_unknown: rc", 0, rc);
    check_n("a_key_holding_a_nul_is_unknown: up", 13107200, (long)q.up_bps);
    rc = qp_rc("{\"brutalUp\":\"100 mbps\",\"brutalUp\\u0000\":\"1 mbps\"}", &q, w, sizeof w);
    check_n("a_key_holding_a_nul_is_unknown: real key rc", 0, rc);
    check_n("a_key_holding_a_nul_is_unknown: the real key's value stays", 13107200, (long)q.up_bps);
    rc = qp_rc("{\"congestion\":\"b\\u0000\",\"congestion\":\"reno\"}", &q, w, sizeof w);
    check_n("the_last_value_wins_after_a_flagged_one: rc", 0, rc);
    check_n("the_last_value_wins_after_a_flagged_one: reno", HY2_CC_RENO, q.cc);
}

static void t_qp_node(void) {
    struct vless_node nodes[4];
    struct vless_sub_stats st;
    struct hy2_qp q;
    size_t n = hs_parse(HXOK("{\"quicParams\":{\"brutalUp\":\"100 mbps\"}}"), nodes, &st);
    check_n("a_node_keeps_xrays_exact_rates: xray count", 1, (long)n);
    hy2_node_qp(&nodes[0], &q);
    check_n("a_node_keeps_xrays_exact_rates: xray up", 13107200, (long)q.up_bps);
    check_n("a_node_keeps_xrays_exact_rates: xray up_mbps", 104, (long)nodes[0].up_mbps);
    check_n("a_node_keeps_xrays_exact_rates: xray down", 0, (long)q.down_bps);

    struct vless_node ln;
    memset(&ln, 0, sizeof ln);
    int rc = vless_parse_url("hysteria2://pw@h:443?upmbps=100&downmbps=40", &ln);
    check_n("a_node_keeps_xrays_exact_rates: link rc", 0, rc);
    hy2_node_qp(&ln, &q);
    check_n("a_node_keeps_xrays_exact_rates: link up", 12500000, (long)q.up_bps);
    check_n("a_node_keeps_xrays_exact_rates: link down", 5000000, (long)q.down_bps);
    check_n("a_node_keeps_xrays_exact_rates: link cc", HY2_CC_AUTO, q.cc);

    memset(&ln, 0, sizeof ln);
    rc = vless_parse_url("hysteria2://pw@h:443?upmbps=5&qp=%7B%22brutalUp%22%3A%22100%20mbps%22%7D", &ln);
    check_n("a_node_keeps_xrays_exact_rates: qp rc", 0, rc);
    hy2_node_qp(&ln, &q);
    check_n("a_node_keeps_xrays_exact_rates: qp wins up", 13107200, (long)q.up_bps);
    memset(&ln, 0, sizeof ln);
    rc = vless_parse_url("hysteria2://pw@h:443?downmbps=8&qp=%7B%22congestion%22%3A%22bbr%22%7D", &ln);
    hy2_node_qp(&ln, &q);
    check_n("a_node_keeps_xrays_exact_rates: unnamed rate falls to mbps", 1000000, (long)q.down_bps);
    check_n("a_node_keeps_xrays_exact_rates: qp cc", HY2_CC_BBR, q.cc);

    memset(&ln, 0, sizeof ln);
    rc = vless_parse_url("hysteria2://pw@h:443?qp=%7B%22congestion%22%3A%22cubic%22%7D", &ln);
    check_n("a_link_qp_xray_refuses_makes_no_node: rc", 1, rc);
    check("a_link_qp_xray_refuses_makes_no_node: why",
          "unknown congestion control: cubic, valid values: reno, bbr, brutal, force-brutal", ln.skip_reason);

    memset(&ln, 0, sizeof ln);
    rc = vless_parse_url("hysteria2://pw@h:443?qp=%7B%22a%22%3A1%7D%00junk", &ln);
    check_n("a_link_qp_with_a_nul_makes_no_node: rc", 1, rc);
    check("a_link_qp_with_a_nul_makes_no_node: why", "qp does not parse", ln.skip_reason);
}

static void t_hy2_sub_all(void) {
    t_hy2_link_secret_bound();
    t_hy2_secrets_up_to_the_node_cap();
    t_hy2_xray();
    t_hy2_singbox();
    t_hy2_clash();
    t_hy2_list();
    t_hy2_count();
}

int main(void) {
    /* ---- base64: how subscriptions usually arrive ------------------------------ */
    {
        char out[64];
        /* No '=' padding and a line break in the middle: panels send both, and both must
         * decode, not truncate. */
        size_t n = b64_decode("dmxlc3M6\nLy9h", 13, out, sizeof(out));
        check("base64 without padding, with a line break", "vless://a", out);
        check_n("base64: output length", 9, (long)n);

        /* URL-safe alphabet: '-' for '+', '_' for '/'. */
        n = b64_decode("Pz8_", 4, out, sizeof(out));
        check("base64 URL-safe: _ decodes as /", "??\?", out);
        check_n("base64 URL-safe: length", 3, (long)n);
        n = b64_decode("Pj4-", 4, out, sizeof(out));
        check("base64 URL-safe: - decodes as +", ">>>", out);
        check_n("base64 URL-safe: - length", 3, (long)n);

        /* Padding inside the text: concatenated base64 blocks, each with its own '='. The bits
         * left before '=' end the block, and the next block starts with an empty accumulator;
         * without that, "QQ==QQ==" decodes to 41 04 10 instead of "AA". */
        n = b64_decode("QQ==QQ==", 8, out, sizeof(out));
        check("base64: two blocks with '=' inside", "AA", out);
        check_n("base64: two blocks with '=' inside, length", 2, (long)n);
        n = b64_decode("QUI=Qw==", 8, out, sizeof(out));
        check("base64: a block with one '=' then one with two", "ABC", out);
    }

    /* ---- trimming an incomplete UTF-8 tail ------------------------------------- */
    {
        /* A lone continuation byte after ASCII goes alone: "ab\x80" must keep its "b". */
        char s1[] = "ab\x80";
        sl_utf8_trim_tail(s1);
        check("utf8: lone continuation byte after ASCII removed", "ab", s1);
        char s2[] = "ab\xC3";
        sl_utf8_trim_tail(s2);
        check("utf8: lead byte without continuation removed", "ab", s2);
        char s3[] = "a\xC3\xA9";
        sl_utf8_trim_tail(s3);
        check("utf8: a complete letter is kept", "a\xC3\xA9", s3);
        char s4[] = "a\xE2\x82";
        sl_utf8_trim_tail(s4);
        check("utf8: incomplete 3-byte sequence removed whole", "a", s4);
    }

    /* ---- one link: every field lands where it should --------------------------- */
    {
        struct vless_node n;
        int rc = vless_parse_url(
            "vless://11111111-2222-3333-4444-555555555555@example.com:8443"
            "?security=reality&sni=www.microsoft.com&pbk=ABCDEF&sid=aa11&fp=chrome"
            "&type=tcp&flow=xtls-rprx-vision#%D0%A3%D0%B7%D0%B5%D0%BB", &n);
        check_n("reality link: node is usable", 0, rc);
        check("reality: host", "example.com", n.host);
        check_n("reality: port", 8443, (long)n.port);
        check("reality: uuid", "11111111-2222-3333-4444-555555555555", n.uuid);
        check("reality: sni", "www.microsoft.com", n.sni);
        check("reality: security", "reality", n.security);
        check("reality: pbk", "ABCDEF", n.pbk);
        check("reality: sid", "aa11", n.sid);
        check("reality: fingerprint", "chrome", n.fp);
        check("reality: flow", "xtls-rprx-vision", n.flow);
        /* The name arrives percent-encoded and must be shown decoded. */
        check("name is percent-decoded", "Узел", n.name);
    }

    /* ---- unusable nodes: skipped with a reason, not dropped -------------------- */
    {
        struct vless_node n;
        /* security=tls is usable: the certificate proves the server, and certverify.c
         * checks it. */
        check_n("security=tls to a host name: usable",
                0, vless_parse_url("vless://u@node.example.org:443?security=tls#x", &n));
        check("security=tls: security field kept", "tls", n.security);

        /* An IP address without sni is unusable for its own reason: a certificate is issued
         * for a name, and there is nothing to check it against. The reason differs from "not
         * supported" because the fix differs. */
        check_n("security=tls to an IP without sni: skipped",
                1, vless_parse_url("vless://u@9.9.9.9:443?security=tls#x", &n));
        check("security=tls to an IP without sni: reason given",
              "tls to an IP address without sni: nothing to verify", n.skip_reason);

        /* An IP address with sni is usable: there is a name to verify against. */
        check_n("security=tls to an IP with sni: usable",
                0, vless_parse_url("vless://u@9.9.9.9:443?security=tls&sni=node.example.org#x", &n));

        /* xtls stays unusable: it is its own handshake, not TLS with verification. */
        check_n("security=xtls: skipped",
                1, vless_parse_url("vless://u@h:443?security=xtls#x", &n));
        check("security=xtls: reason given", "security=xtls is not supported", n.skip_reason);

        check_n("reality without pbk: skipped",
                1, vless_parse_url("vless://u@h:443?security=reality&sni=a.com#x", &n));
        check("reality without pbk: reason given", "reality without pbk", n.skip_reason);

        /* Reality without sni is usable. The server checks the name against its
         * `serverNames`, where an empty string is valid: it then expects a ClientHello
         * without server_name, and Xray sends one. Such nodes occur in real subscriptions. */
        check_n("reality without sni: node is usable", 0,
                vless_parse_url("vless://u@h:443?security=reality&pbk="
                                "Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA&sid=ab12"
                                "&flow=xtls-rprx-vision#x", &n));
        check("reality without sni: sni is empty", "", n.sni);

        /* ws and httpupgrade are supported (their cases are below); kcp stands for an
         * unsupported transport. */
        check_n("transport kcp: skipped",
                1, vless_parse_url("vless://u@h:443?security=none&type=kcp#x", &n));
        check("transport kcp: reason given", "transport kcp is not supported", n.skip_reason);

        /* No security parameter means VLESS without TLS, which is supported. */
        check_n("security omitted: node is usable",
                0, vless_parse_url("vless://u@h:443#x", &n));
        check("security omitted: defaults to none", "none", n.security);
        check("type defaults to tcp", "tcp", n.type);
    }

    /* ---- glued links: a panel may leave out the separator ----------------------
     *
     * The boundary must be found by known scheme names. Stepping back over letters and digits
     * would put it before "onevless" in "#onevless://…": the second link would no longer
     * start with vless:// and would count as foreign, and the first node would lose its
     * name. */
    {
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443#one" "vless://b@h2:443#two",
                                   nodes, 8, &st);
        check_n("two glued links parse as two", 2, (long)n);
        check("glued: first name does not swallow the second link", "one", nodes[0].name);
        check("glued: second link keeps its own host", "h2", nodes[1].host);
        check_n("glued: no foreign links counted", 0, (long)st.foreign);
    }
    {
        /* Without '#' names: the boundary must follow the scheme, not the port digits. */
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443" "vless://b@h2:8443",
                                   nodes, 8, &st);
        check_n("glued without names: two links", 2, (long)n);
        check_n("glued without names: first port intact", 443, (long)nodes[0].port);
        check_n("glued without names: second link has its own port", 8443, (long)nodes[1].port);
    }
    {
        /* A name that ends like a scheme ("Express" before "ss://"): the boundary is still
         * taken from the bytes before "://". */
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443#Express" "ss://b@h2:443#other",
                                   nodes, 8, &st);
        check_n("name ends like a scheme: one vless node", 1, (long)n);
        check("name ends like a scheme: name not cut", "Express", nodes[0].name);
        check_n("name ends like a scheme: ss link counted as foreign", 1, (long)st.foreign);
    }

    /* ---- glue with an unknown scheme: reported, not guessed --------------------
     *
     * The blocks above glue a scheme from the splitter's list: the boundary is right and both
     * nodes live. An unknown scheme gets no boundary at all, so "vless…#one" + "anytls://…"
     * would read as one link: the first node named "oneanytls://p@h2:443#two", the second
     * gone from every counter, and no number off (one link, one usable node).
     *
     * So the boundary rule stays, but the glue is reported: the node is unusable. The second
     * condition ('@' in the glued link) tells a glue from a link inside a node name, where
     * sellers put their channel; the second case below checks that this node stays usable. */
    {
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443#one" "anytls://p@h2:443#two",
                                   nodes, 8, &st);
        check_n("unknown scheme: node with a foreign tail not taken", 0, (long)n);
        check_n("unknown scheme: link counted as unusable", 1, (long)st.skipped);
        check("unknown scheme: reason names the glue",
              "links glued without a separator", st.reasons[0].reason);
        /* The example names no scheme: stepping back by form would give "oneanytls", a
         * confident lie. It gives what is known for sure, the tail's length and first bytes,
         * which locate the glue in the subscription text. */
        check("unknown scheme: example gives the tail's length and bytes",
              "tail of 15 bytes: ://p@h2:443#two", st.reasons[0].example);
        check_n("unknown scheme: counters add up", 1,
                (long)(n + st.skipped + st.foreign));
    }
    /* The reason goes into the subscription stats whole: st.reasons[].reason has the size of the
     * node's skip_reason. The reasons written today are at most 51 bytes, so a stats field cut
     * anywhere above that would pass with every one of them; a reason that fills skip_reason is
     * given to sl_skip_note, the one way into the stats, to check the whole size. */
    {
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        vless_set_insecure(0);
        size_t n = vless_parse_sub("vless://11111111-2222-3333-4444-555555555555@b.test:443"
                                   "?security=tls&sni=b.test&allowInsecure=1#B\n", nodes, 4, &st);
        check_n("allowInsecure without --insecure: node skipped", 0, (long)n);
        check("allowInsecure: reason in skipped_reasons",
              "allowInsecure: needs --insecure", st.reasons[0].reason);

        struct vless_node t;
        memset(&t, 0, sizeof(t));
        memset(t.skip_reason, 'r', sizeof(t.skip_reason) - 1);
        memset(&st, 0, sizeof(st));
        sl_skip_note(&st, &t, t.skip_reason);
        check("reason that fills skip_reason: not cut in skipped_reasons",
              t.skip_reason, st.reasons[0].reason);

        /* A node without a name is reported by host:port; the example field is longer than the
         * host field so that the longest host fits with the longest port. */
        char host[sizeof(t.host)], link[256], want[sizeof(t.host) + 8];
        memset(host, 'h', sizeof(host) - 1);
        host[sizeof(host) - 1] = '\0';
        snprintf(link, sizeof(link), "vless://u@%s:65535?type=kcp\n", host);
        snprintf(want, sizeof(want), "%s:65535", host);
        vless_parse_sub(link, nodes, 4, &st);
        check("node without a name: example is the longest host:port, whole", want,
              st.reasons[0].example);
    }
    {
        /* The same glue, longer than the line buffer. A really long link and a glued pair
         * would both read as "link longer than 8191 bytes", but they need different fixes (a
         * higher limit, a fixed subscription), so the glue is reported before the length. */
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        static char big[16384];
        int k = snprintf(big, sizeof(big), "vless://u@h:443?sni=");
        memset(big + k, 'x', 9000);
        k += 9000;
        k += snprintf(big + k, sizeof(big) - (size_t)k, "#one" "anytls://p@h2:443#two");
        big[k] = '\0';
        size_t n = vless_parse_sub(big, nodes, 4, &st);
        check_n("long glue: node not taken", 0, (long)n);
        check_n("long glue: counted as unusable", 1, (long)st.skipped);
        check("long glue: reason is the glue, not the length",
              "links glued without a separator", st.reasons[0].reason);
    }
    {
        /* A link inside a node name is not a glue, and the node stays usable. The one
         * difference: a glued proxy link has '@' (credentials), a channel address in a name
         * has none. Without that test every node whose name carries the seller's Telegram
         * channel would be unusable. */
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443#канал https://t.me/shop",
                                   nodes, 8, &st);
        check_n("link in name: node taken", 1, (long)n);
        check_n("link in name: nothing skipped", 0, (long)st.skipped);
        check("link in name: name unchanged", "канал https://t.me/shop", nodes[0].name);
    }
    {
        /* A known scheme is still split, not reported as a glue: the list of scheme names
         * is tried before the general glue rule, and this case guards that order. */
        struct vless_node nodes[8];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443#one" "vless://b@h2:443#two",
                                   nodes, 8, &st);
        check_n("known scheme: still two links", 2, (long)n);
        check_n("known scheme: nothing skipped", 0, (long)st.skipped);
        check("known scheme: first name is clean", "one", nodes[0].name);
    }

    /* ---- subscription arithmetic -----------------------------------------------
     *
     * No link may vanish without landing in a counter. Two of these links make
     * vless_parse_url return -1: an IPv6 literal with no closing
     * bracket and port 0. Both must still count as skipped. */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *sub =
            "vless://a@1.2.3.4:443?security=reality&pbk=K&sni=x.com#ok\n"
            "vless://b@[2001:db8::1:443?security=reality&pbk=K&sni=x.com#ipv6\n"
            "vless://c@5.6.7.8:0?security=reality&pbk=K&sni=x.com#zero-port\n"
            "vless://d@9.9.9.9:443?security=tls#tls\n"
            "trojan://e@10.0.0.1:443#foreign\n";
        size_t n = vless_parse_sub(sub, nodes, 16, &st);
        check_n("arithmetic: usable nodes", 1, (long)n);
        check_n("arithmetic: foreign links", 1, (long)st.foreign);
        /* Four vless links: one taken, the other three must all be counted. */
        check_n("arithmetic: unusable vless links counted", 3, (long)st.skipped);
        check_n("arithmetic: counters add up to the links in the text",
                5, (long)(n + st.skipped + st.foreign));
    }

    /* A link longer than the line buffer is counted as unusable, not dropped before
     * parsing. */
    {
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        char big[16384];
        int k = snprintf(big, sizeof(big), "vless://u@h:443?sni=");
        memset(big + k, 'x', 9000);
        big[k + 9000] = '\0';
        size_t n = vless_parse_sub(big, nodes, 4, &st);
        check_n("too long link: not taken", 0, (long)n);
        check_n("too long link: counted as unusable", 1, (long)st.skipped);
        check("too long link: reason gives the limit", "link longer than 8191 bytes",
              st.reasons[0].reason);
        /* The example is the length and the start of the address: the reason alone cannot
         * tell a link just over the limit from a blob of many kilobytes, and their fixes
         * differ. The start is taken after '@': the id before it does not belong in a log. */
        check("too long link: example is the length and start of the address",
              "9020 bytes: …@h:443?sni=xxxxxxxxxxxxxxxxxxxxxx", st.reasons[0].example);
    }

    /* A post-quantum Reality link. Xray-core 25.9+ puts `pqv`, an ML-DSA-65 public key (1952
     * bytes, 2603 base64url characters), into the link, which makes a link of about 2860
     * bytes. This checks that such a length does not drop the node. */
    {
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        char big[16384];
        int k = snprintf(big, sizeof(big),
                         "vless://11111111-2222-3333-4444-555555555555@150.241.72.190:443"
                         "?encryption=none&flow=xtls-rprx-vision&fp=firefox&security=reality"
                         "&sni=www.nvidia.com&sid=0da048326ed2&type=tcp&pbk=PBK&pqv=");
        memset(big + k, 'Z', 2603);
        k += 2603;
        k += snprintf(big + k, sizeof(big) - (size_t)k, "#Unlim");
        big[k] = '\0';
        size_t n = vless_parse_sub(big, nodes, 4, &st);
        /* The link must be longer than the old 2048-byte limit, which dropped such nodes. */
        check_n("pq link: longer than the old 2048-byte limit", 1, k > 2048);
        check_n("pq link: node taken", 1, (long)n);
        check_n("pq link: nothing skipped", 0, (long)st.skipped);
        check("pq link: name intact", "Unlim", nodes[0].name);
        check("pq link: address intact", "150.241.72.190", nodes[0].host);
    }

    /* The same branch with a link of another protocol: a long foreign link is counted in
     * foreign like a short one, or usable + skipped + foreign would not add up. */
    {
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        char big[16384];
        int k = snprintf(big, sizeof(big), "vless://u@h:443?security=none&type=tcp#ok\n"
                                           "trojan://u@h:443?x=");
        memset(big + k, 'y', 9000);
        big[k + 9000] = '\0';
        size_t n = vless_parse_sub(big, nodes, 4, &st);
        check_n("long foreign link: vless node taken", 1, (long)n);
        check_n("long foreign link: counted as foreign", 1, (long)st.foreign);
        check_n("long foreign link: no vless link skipped", 0, (long)st.skipped);
        check_n("long foreign link: counters add up", 2,
                (long)(n + st.skipped + st.foreign));
    }

    /* ---- skip reasons: grouped, and they add up --------------------------------
     *
     * Two properties: the counts add up (their sum equals skipped, so no node is lost in the
     * explanation), and equal reasons collapse into one line with a count (three tls nodes
     * without sni give one line, not three). */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *sub =
            "vless://a@1.1.1.1:443?security=tls#Первый\n"
            "vless://b@2.2.2.2:443?security=tls#Второй\n"
            "vless://c@3.3.3.3:443?security=tls#Третий\n"
            "vless://d@4.4.4.4:443?type=kcp&security=none#Вебсокет\n"
            "vless://e@[2001:db8::1:443?security=none#IPv6\n"
            "vless://f@6.6.6.6:443?security=reality&pbk=K&sni=x.com#Годный\n";
        size_t n = vless_parse_sub(sub, nodes, 16, &st);
        check_n("reasons: one node usable", 1, (long)n);
        check_n("reasons: five skipped", 5, (long)st.skipped);
        check_n("reasons: three distinct reasons", 3, (long)st.reasons_n);
        check_n("reasons: none dropped", 0, (long)st.reasons_dropped);

        size_t sum = 0;
        for (size_t i = 0; i < st.reasons_n; i++) sum += st.reasons[i].count;
        check_n("reasons: counts add up to skipped", (long)st.skipped, (long)sum);

        /* Reasons keep the order of first appearance, so the order can be checked. */
        check("first reason: tls to an IP without sni",
              "tls to an IP address without sni: nothing to verify",
              st.reasons[0].reason);
        check_n("tls reasons collapsed into one line with count 3", 3, (long)st.reasons[0].count);
        check("tls: example is the first node's name", "Первый", st.reasons[0].example);
        check("second reason: transport kcp", "transport kcp is not supported",
              st.reasons[1].reason);
        check("kcp: example is its own node's name", "Вебсокет", st.reasons[1].example);
        /* The unclosed IPv6 literal does not parse and never reaches the usability check, so the
         * subscription loop names the reason itself; otherwise it would be one more skip
         * without an explanation. */
        check("third reason: link cannot be parsed", "cannot parse the link",
              st.reasons[2].reason);
    }

    /* More reasons than slots: the ninth goes to reasons_dropped, and the counts plus dropped
     * still equal skipped. */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        char sub[1024];
        size_t off = 0;
        for (int i = 1; i <= 9; i++)
            off += (size_t)snprintf(sub + off, sizeof(sub) - off,
                                    "vless://u@h%d:443?security=s%d#n%d\n", i, i, i);
        size_t n = vless_parse_sub(sub, nodes, 16, &st);
        check_n("overflow: no node usable", 0, (long)n);
        check_n("overflow: nine skipped", 9, (long)st.skipped);
        check_n("overflow: eight reasons fit", 8, (long)st.reasons_n);
        check_n("overflow: ninth counted as dropped", 1, (long)st.reasons_dropped);
        size_t sum = st.reasons_dropped;
        for (size_t i = 0; i < st.reasons_n; i++) sum += st.reasons[i].count;
        check_n("overflow: counts still add up", (long)st.skipped, (long)sum);
    }

    /* ---- user id: Xray's rule, not strict hex ----------------------------------
     *
     * Panels serve ids like "TMG_74317ba5f91", and that is valid VLESS: Xray
     * (common/uuid/uuid.go) decides by length. 32 to 36 characters parse as a hex UUID
     * (dashes optional); 1 to 30 are derived: sha1(16 zero bytes || id), the first 16 bytes,
     * version 5 and the variant set in bytes 6 and 8. Exactly 31, more than 36, or empty is
     * refused. The usability check and the UUID parser must agree, or a node is taken and
     * then fails at connect without a reason. */
    {
        struct vless_node n;
        int rc = vless_parse_url(
            "vless://TMG_74317ba5f91@203.0.113.7:443?type=xhttp&encryption=none"
            "&path=%2FdRh-l74-MZE3z&host=amazon.com&mode=auto&security=reality"
            "&fp=firefox&pbk=KEY&sni=amazon.com&sid=9392&spx=%2F"
            "#TMG_74317ba5f91-%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F", &n);
        check_n("panel link with a short id: node usable", 0, rc);
        check("panel link: id kept as is", "TMG_74317ba5f91", n.uuid);

        unsigned char u[16] = { 0 };
        check_n("short id parses", 0, vless_uuid_parse(n.uuid, u));
        /* The vector was computed independently, in Python, by Xray's algorithm. */
        check("short id gives a version 5 UUID",
              "dd4748e6-1f48-5b36-bbc6-656b42ccfd75", uuid_str(u));
    }

    /* SHA-1 is pinned to the published NIST vector. vless_proto.c has its own implementation,
     * and an error in it would only show as a server that rejects the user. */
    {
        unsigned char d[20];
        char hex[41];
        check_n("sha1: message too long for one block refused", -1,
                sha1_short((const unsigned char *)"", 56, d));
        check_n("sha1(\"abc\") computed", 0, sha1_short((const unsigned char *)"abc", 3, d));
        for (int i = 0; i < 20; i++) snprintf(hex + 2 * i, 3, "%02x", d[i]);
        check("sha1(\"abc\") matches the NIST vector",
              "a9993e364706816aba3e25717850c26c9cd0d89d", hex);
    }

    /* A UUID with and without dashes gives the same 16 bytes; subscriptions use both. */
    {
        unsigned char a[16] = { 0 }, b[16] = { 0 };
        check_n("UUID of 36 characters with dashes parses", 0,
                vless_uuid_parse("11111111-2222-3333-4444-555555555555", a));
        check_n("UUID of 32 characters without dashes parses", 0,
                vless_uuid_parse("11111111222233334444555555555555", b));
        check("UUID with dashes: expected bytes", "11111111-2222-3333-4444-555555555555",
              uuid_str(a));
        check_n("UUID without dashes gives the same bytes", 0, memcmp(a, b, 16));
        /* Xray accepts uppercase (hex.Decode), so this parser must too. */
        unsigned char c[16] = { 0 };
        check_n("uppercase UUID parses", 0,
                vless_uuid_parse("AABBCCDD-EEFF-0011-2233-445566778899", c));
        check("uppercase UUID: expected bytes", "aabbccdd-eeff-0011-2233-445566778899",
              uuid_str(c));
    }

    /* Length bounds. The rule cannot be "try hex, else derive": 32 and 36 parse, 30 is
     * derived, 31 and 37 are refused, all decided by length, not by whether the string looks
     * like hex. */
    {
        unsigned char u[16] = { 0 };
        char s30[31], s31[32], s37[38];
        memset(s30, 'a', 30); s30[30] = '\0';
        memset(s31, 'a', 31); s31[31] = '\0';
        memset(s37, 'a', 37); s37[37] = '\0';

        check_n("30 characters: form is derived", VLESS_UUID_DERIVED, vless_uuid_form(s30));
        check_n("30 characters: UUID derived", 0, vless_uuid_parse(s30, u));
        /* The vector was computed in Python by Xray's algorithm, not by this code. */
        check("30 characters: derived UUID matches", "d20a3bd4-9d58-52e0-8caa-820ca42d1ad0",
              uuid_str(u));

        check_n("31 characters: form is the gap", VLESS_UUID_GAP, vless_uuid_form(s31));
        check_n("31 characters: does not parse", -1, vless_uuid_parse(s31, u));

        check_n("37 characters: form is too long", VLESS_UUID_TOOLONG,
                vless_uuid_form(s37));
        check_n("37 characters: does not parse", -1, vless_uuid_parse(s37, u));

        check_n("32 hex characters: form is UUID", VLESS_UUID_HEX,
                vless_uuid_form("0123456789abcdef0123456789abcdef"));
        check_n("36 characters with dashes: form is UUID", VLESS_UUID_HEX,
                vless_uuid_form("01234567-89ab-cdef-0123-456789abcdef"));

        check_n("empty: form is empty", VLESS_UUID_EMPTY, vless_uuid_form(""));
        check_n("empty: does not parse", -1, vless_uuid_parse("", u));

        /* UUID length with a non-hex character: a hex.Decode error in Xray, and too long to
         * be derived instead. */
        check_n("32 characters with a non-hex one: form is not hex", VLESS_UUID_NOTHEX,
                vless_uuid_form("0123456789abcdef0123456789abcdeZ"));
        check_n("32 characters with a non-hex one: does not parse", -1,
                vless_uuid_parse("0123456789abcdef0123456789abcdeZ", u));
        /* A dash is allowed only between groups; inside a group it is a non-hex character. */
        check_n("dash inside a group: not hex", VLESS_UUID_NOTHEX,
                vless_uuid_form("0123-456789ab-cdef-0123-456789abcdef"));
    }

    /* Length 31 falls between the two forms: too long to derive, too short for a UUID. The
     * characters are hex, so the refusal is by length, as in Xray. */
    {
        struct vless_node n;
        check_n("id of 31 characters: node skipped", 1,
                vless_parse_url("vless://0123456789abcdef0123456789abcde@h:443"
                                "?security=none#x", &n));
        check("id of 31 characters: reason given", "id: 31 characters, need a UUID",
              n.skip_reason);
    }

    /* The other unusable forms, each with its own reason. */
    {
        struct vless_node n;
        char url[128];
        check_n("empty id: node skipped", 1,
                vless_parse_url("vless://@h:443?security=none#x", &n));
        check("empty id: reason given", "id is empty", n.skip_reason);

        char long_id[40];
        memset(long_id, 'a', 37); long_id[37] = '\0';
        snprintf(url, sizeof(url), "vless://%s@h:443?security=none#x", long_id);
        check_n("id longer than a UUID: node skipped", 1, vless_parse_url(url, &n));
        check("id longer than a UUID: reason given", "id longer than a UUID",
              n.skip_reason);

        check_n("id of UUID length with a non-hex character: skipped", 1,
                vless_parse_url("vless://0123456789abcdef0123456789abcdeZ@h:443"
                                "?security=none#x", &n));
        check("id with a non-hex character: reason given", "UUID with an invalid character",
              n.skip_reason);
    }

    /* A panel stub instead of a subscription. Panels that bind a subscription to devices
     * answer a client without a device id (no x-hwid header) with valid links to `0.0.0.0:1`
     * and put the message for the user in the node name. Such a node is unusable, and the
     * example of its reason carries the panel's message, so the user sees why. */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *stub =
            "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1"
            "?encryption=none&type=tcp&security=none#%F0%9F%93%B1%20%D0%9D%D0%B5%D0%BF%D1%80"
            "%D0%B0%D0%B2%D0%B8%D0%BB%D1%8C%D0%BD%D1%8B%D0%B9%20%D0%BA%D0%BB%D0%B8%D0%B5%D0"
            "%BD%D1%82\n"
            "vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1"
            "?encryption=none&type=tcp&security=none#Happ\n";
        size_t n = vless_parse_sub(stub, nodes, 16, &st);
        check_n("panel stub: no node usable", 0, (long)n);
        check_n("panel stub: both nodes counted", 2, (long)st.skipped);
        check("panel stub: reason names the address",
              "0.0.0.0: nobody to answer", st.reasons[0].reason);
        check("panel stub: example is the panel's message from the node name",
              "📱 Неправильный клиент", st.reasons[0].example);
        check_n("panel stub: counters add up", 2, (long)(n + st.skipped + st.foreign));
    }

    /* The other side: addresses that can answer stay usable. A private network is a valid
     * setup (a node inside the LAN or behind another tunnel). */
    {
        struct vless_node n;
        check_n("node in a private network is usable", 0,
                vless_parse_url("vless://11111111-2222-3333-4444-555555555555@10.8.0.1:443"
                                "?security=none#Свой", &n));
        check_n("loopback node is unusable", 1,
                vless_parse_url("vless://11111111-2222-3333-4444-555555555555@127.0.0.1:443"
                                "?security=none#Петля", &n));
        /* All of 127.0.0.0/8: stubs use 127.0.0.53 too. */
        check_n("loopback node other than 127.0.0.1 is unusable", 1,
                vless_parse_url("vless://11111111-2222-3333-4444-555555555555@127.0.0.53:443"
                                "?security=none#Петля", &n));
        check_n("host starting with 127 but not loopback is usable", 0,
                vless_parse_url("vless://11111111-2222-3333-4444-555555555555@127a.example.com:443"
                                "?security=none#Имя", &n));
        /* "127." followed by a name: only an address of digits and dots is loopback. */
        check_n("name whose first label is 127 is usable", 0,
                vless_parse_url("vless://11111111-2222-3333-4444-555555555555"
                                "@127.node.example.com:443?security=none#Имя", &n));
    }

    /* A whole subscription: nodes with both kinds of id are taken, the one with a bad id is
     * counted and explained, and the counters add up. */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *sub =
            "vless://TMG_74317ba5f91@1.2.3.4:443?security=reality&pbk=K&sni=x.com#Короткий\n"
            "vless://11111111-2222-3333-4444-555555555555@5.6.7.8:443"
            "?security=reality&pbk=K&sni=x.com#UUID\n"
            "vless://0123456789abcdef0123456789abcde@9.9.9.9:443"
            "?security=reality&pbk=K&sni=x.com#Щель\n";
        size_t n = vless_parse_sub(sub, nodes, 16, &st);
        check_n("subscription: both kinds of id usable", 2, (long)n);
        check("subscription: short id kept", "TMG_74317ba5f91", nodes[0].uuid);
        check_n("subscription: one skipped", 1, (long)st.skipped);
        check("subscription: reason for the skipped node given",
              "id: 31 characters, need a UUID", st.reasons[0].reason);
        check("subscription: example is its node's name", "Щель", st.reasons[0].example);
        check_n("subscription: counters add up", 3, (long)(n + st.skipped + st.foreign));
    }

    {
        /* ---- subscription as an Xray config ------------------------------------
         *
         * The shape comes from a real panel, which picks the format by User-Agent and gives an
         * unknown client no link list at all. Checked: a node is assembled from the nested
         * objects, other outbounds (freedom, blackhole) are not nodes, and key order does not
         * matter ("protocol" may come after "settings"). */
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *cfg =
            "[{\"dns\":{\"servers\":[{\"address\":\"https://dns.google/dns-query\"}]},"
            " \"outbounds\":["
            "  {\"tag\":\"ch01_tcp\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"179.237.82.105\",\"port\":443,"
            "     \"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\","
            "                 \"flow\":\"xtls-rprx-vision\",\"encryption\":\"none\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"ch01.example.org\","
            "       \"fingerprint\":\"chrome\",\"publicKey\":\"PBK123\",\"shortId\":\"a1b2\"}}},"
            "  {\"tag\":\"direct\",\"protocol\":\"freedom\",\"settings\":{}},"
            "  {\"tag\":\"block\",\"protocol\":\"blackhole\",\"settings\":{}}"
            " ]},"
            " {\"outbounds\":["
            "  {\"settings\":{\"vnext\":[{\"address\":\"87.120.126.31\",\"port\":2087,"
            "     \"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\"}]}]},"
            "   \"streamSettings\":{\"network\":\"grpc\",\"security\":\"reality\","
            "     \"grpcSettings\":{\"serviceName\":\"svc\"},"
            "     \"realitySettings\":{\"serverName\":\"de01.example.org\",\"publicKey\":\"PBK456\"}},"
            "   \"protocol\":\"vless\",\"tag\":\"de01_grpc\"}"
            " ]}]";
        size_t n = vless_parse_sub(cfg, nodes, 16, &st);
        check_n("Xray config: nodes taken", 2, (long)n);
        check("Xray config: name from tag", "ch01_tcp", nodes[0].name);
        check("Xray config: address", "179.237.82.105", nodes[0].host);
        check_n("Xray config: port", 443, (long)nodes[0].port);
        check("Xray config: transport", "tcp", nodes[0].type);
        check("Xray config: security", "reality", nodes[0].security);
        check("Xray config: sni from realitySettings", "ch01.example.org", nodes[0].sni);
        check("Xray config: pbk", "PBK123", nodes[0].pbk);
        check("Xray config: sid", "a1b2", nodes[0].sid);
        check("Xray config: fingerprint", "chrome", nodes[0].fp);
        check("Xray config: flow", "xtls-rprx-vision", nodes[0].flow);
        check("Xray config: second config read too", "de01_grpc", nodes[1].name);
        check("Xray config: grpc serviceName", "svc", nodes[1].service);
        /* tcp above is also the default: network is read only if grpc is. */
        check("Xray config: transport of the second node", "grpc", nodes[1].type);
        check_n("Xray config: port of the second node", 2087, (long)nodes[1].port);
        check_n("Xray config: freedom and blackhole not counted as skipped", 0, (long)st.skipped);
        check_n("Xray config: freedom and blackhole not counted as foreign", 0, (long)st.foreign);
    }
    {
        /* A single config, not an array: panels serve this too. */
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *cfg =
            "{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"one\","
            "  \"settings\":{\"vnext\":[{\"address\":\"1.2.3.4\",\"port\":443,"
            "    \"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\"}]}]},"
            "  \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "    \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P\"}}}]}";
        size_t n = vless_parse_sub(cfg, nodes, 16, &st);
        check_n("Xray config: single object", 1, (long)n);
        check("Xray config: single object, name", "one", nodes[0].name);
    }
    {
        /* ---- xhttp padding length comes from the server ------------------------
         *
         * An xhttp server checks the length of x_padding and answers 400 to one outside its
         * range. The range arrives in the link as `xPaddingBytes` inside `extra`; a client
         * that ignores it fails on every such node although TLS and Reality work. */
        struct vless_node n;
        char url[512];
        const char *base = "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com&path=%2Fx";

        snprintf(url, sizeof(url), "%s#x", base);
        check_n("no extra: no range set", 0, (int)(vless_parse_url(url, &n), n.pad_to));

        /* The form servers use: percent-encoded JSON. */
        snprintf(url, sizeof(url),
                 "%s&extra=%%7B%%22xmux%%22%%3A%%7B%%22maxConcurrency%%22%%3A%%2216-32%%22%%7D%%2C"
                 "%%22xPaddingBytes%%22%%3A%%2250-150%%22%%7D#x", base);
        vless_parse_url(url, &n);
        check_n("extra: lower bound", 50, (int)n.pad_from);
        check_n("extra: upper bound", 150, (int)n.pad_to);

        /* A long extra: headers before xPaddingBytes, about 1500 bytes once percent-encoded,
         * more than a buffer of 512 or 1024 bytes holds. The JSON must not be cut before
         * decoding, or the range is lost. */
        {
            char big[2048] = "%7B%22headers%22%3A%7B";
            for (int i = 0; i < 40; i++) {
                char kv[96];
                snprintf(kv, sizeof(kv), "%s%%22h%d%%22%%3A%%22" "vvvvvvvvvvvvvvvv" "%%22",
                         i ? "%2C" : "", i);
                strncat(big, kv, sizeof(big) - strlen(big) - 1);
            }
            strncat(big, "%7D%2C%22xPaddingBytes%22%3A%2250-150%22%7D", sizeof(big) - strlen(big) - 1);
            char url2[4096];
            snprintf(url2, sizeof(url2), "%s&extra=%s#x", base, big);
            memset(&n, 0, sizeof(n));
            vless_parse_url(url2, &n);
            check_n("long extra: lower bound read", 50, (int)n.pad_from);
            check_n("long extra: upper bound read", 150, (int)n.pad_to);
        }

        /* A single number is valid too: a range of one value. */
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22xPaddingBytes%%22%%3A512%%7D#x", base);
        vless_parse_url(url, &n);
        check_n("extra: single number, lower bound", 512, (int)n.pad_from);
        check_n("extra: single number, upper bound", 512, (int)n.pad_to);

        /* Garbage keeps the node usable and sets no bounds; the default applies. */
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22xPaddingBytes%%22%%3A%%22ой%%22%%7D#x", base);
        check_n("extra: garbage, node usable", 0, vless_parse_url(url, &n));
        check_n("extra: garbage, no bounds set", 0, (int)n.pad_to);

        /* An inverted range is garbage too: no length can be picked from it. */
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22xPaddingBytes%%22%%3A%%22900-100%%22%%7D#x", base);
        vless_parse_url(url, &n);
        check_n("extra: inverted range refused", 0, (int)n.pad_to);

        /* scMaxEachPostBytes: the server answers 413 to a larger packet-up POST (Xray hub.go),
         * so the limit is read, as a number or a range. */
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22scMaxEachPostBytes%%22%%3A4096%%7D#x", base);
        vless_parse_url(url, &n);
        check_n("extra: scMaxEachPostBytes number, lower", 4096, (int)n.post_from);
        check_n("extra: scMaxEachPostBytes number, upper", 4096, (int)n.post_to);
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22scMaxEachPostBytes%%22%%3A%%22500000-1000000%%22%%7D#x", base);
        vless_parse_url(url, &n);
        check_n("extra: scMaxEachPostBytes range, lower", 500000, (int)n.post_from);
        check_n("extra: scMaxEachPostBytes range, upper", 1000000, (int)n.post_to);

        /* Settings that change the requests on the wire skip the node, by VALUE: panels write
         * Xray's defaults out, and those are what the client sends. */
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22uplinkDataPlacement%%22%%3A%%22auto%%22%%2C%%22sessionPlacement%%22%%3A%%22path%%22%%2C%%22seqPlacement%%22%%3A%%22path%%22%%2C%%22xPaddingMethod%%22%%3A%%22repeat-x%%22%%2C%%22xPaddingObfsMode%%22%%3Afalse%%7D#x", base);
        check_n("extra: Xray defaults written out, usable", 0, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22uplinkDataPlacement%%22%%3A%%22header%%22%%7D#x", base);
        check_n("extra: uplinkDataPlacement=header without packet-up, skipped by Xray's mode rule", 1, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22sessionPlacement%%22%%3A%%22query%%22%%7D#x", base);
        check_n("extra: sessionPlacement=query, usable as Xray's query placement", 0, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22xPaddingMethod%%22%%3A%%22tokenish%%22%%7D#x", base);
        check_n("extra: xPaddingMethod=tokenish, usable as Xray's tokenish padding", 0, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22xPaddingObfsMode%%22%%3Atrue%%7D#x", base);
        check_n("extra: xPaddingObfsMode, usable as Xray's obfuscated padding", 0, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22downloadSettings%%22%%3A%%7B%%22address%%22%%3A%%22d.example%%22%%7D%%7D#x", base);
        check_n("extra: downloadSettings without a port, skipped as Xray refuses it", 1, vless_parse_url(url, &n));
        check("extra: downloadSettings without a port, reason", "downloadSettings: no port", n.skip_reason);
    }
    {
        /* ---- xhttp modes -------------------------------------------------------
         *
         * Mode support is decided here, not at connect, so an unusable node never becomes a
         * candidate. Every supported mode is checked, and the refusal of the unsupported one. */
        struct vless_node n;
        const char *base = "vless://u@h:443?type=xhttp&security=reality&pbk=K&sni=a.com"
                           "&path=%2Fx";
        char url[256];

        snprintf(url, sizeof(url), "%s#x", base);
        check_n("xhttp without mode: usable", 0, vless_parse_url(url, &n));

        snprintf(url, sizeof(url), "%s&mode=auto#x", base);
        check_n("xhttp mode=auto: usable", 0, vless_parse_url(url, &n));

        snprintf(url, sizeof(url), "%s&mode=stream-one#x", base);
        check_n("xhttp mode=stream-one: usable", 0, vless_parse_url(url, &n));
        check("xhttp mode=stream-one: mode kept", "stream-one", n.mode);

        snprintf(url, sizeof(url), "%s&mode=stream-up#x", base);
        check_n("xhttp mode=stream-up: usable", 0, vless_parse_url(url, &n));
        check("xhttp mode=stream-up: mode kept", "stream-up", n.mode);

        snprintf(url, sizeof(url), "%s&mode=packet-up#x", base);
        check_n("xhttp mode=packet-up: usable", 0, vless_parse_url(url, &n));
        check("xhttp mode=packet-up: mode kept", "packet-up", n.mode);

        /* stream-down is the half of a split setup with a separate download server and has no
         * upload at all. It is refused with a reason. */
        snprintf(url, sizeof(url), "%s&mode=stream-down#x", base);
        check_n("xhttp mode=stream-down: skipped", 1, vless_parse_url(url, &n));
        check("xhttp mode=stream-down: reason given",
              "xhttp mode=stream-down is not supported", n.skip_reason);
    }
    {
        /* ---- name from remarks, not from tag -----------------------------------
         *
         * The shape follows a real panel's answer: remarks comes after outbounds, plain nodes
         * all have the tag "proxy", and a config with a balancer has two outbounds whose tags
         * end in a random suffix that changes on every request. Without remarks the list
         * would read "proxy, proxy, proxy" plus two names that change tomorrow. */
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *cfg =
            "[{\"outbounds\":["
            "  {\"tag\":\"proxy\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"de.example.org\",\"port\":443,"
            "     \"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P1\"}}},"
            "  {\"tag\":\"direct\",\"protocol\":\"freedom\",\"settings\":{}}],"
            " \"remarks\":\"🇩🇪 Германия\"},"
            " {\"outbounds\":["
            "  {\"tag\":\"tl-8-1-43al6bgvgg4\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"de.example.org\",\"port\":443,"
            "     \"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P2\"}}},"
            "  {\"tag\":\"tl-8-2-8mj546dasfg\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"backup.example.org\",\"port\":443,"
            "     \"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P3\"}}}],"
            " \"remarks\":\"МОБИЛЬНЫЙ АВТО\"},"
            " {\"outbounds\":["
            "  {\"tag\":\"proxy\",\"protocol\":\"vless\","
            "   \"settings\":{\"vnext\":[{\"address\":\"fi.example.org\",\"port\":443,"
            "     \"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\"}]}]},"
            "   \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "     \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P4\"}}}],"
            " \"remarks\":\"🇫🇮 Финляндия\"}]";
        size_t n = vless_parse_sub(cfg, nodes, 16, &st);
        check_n("remarks: nodes taken", 4, (long)n);
        check("remarks: name used instead of tag 'proxy'", "🇩🇪 Германия", nodes[0].name);
        check("remarks: name read although it follows outbounds", "🇫🇮 Финляндия", nodes[3].name);
        check("remarks: first node of a config has no number", "МОБИЛЬНЫЙ АВТО", nodes[1].name);
        check("remarks: second node of the same config is numbered",
              "МОБИЛЬНЫЙ АВТО (2)", nodes[2].name);
        check("remarks: numbered node keeps its own address", "backup.example.org", nodes[2].host);
    }
    {
        /* Empty remarks: the name stays from the tag, never an empty name. */
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        const char *cfg =
            "[{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"ch01_tcp\","
            "  \"settings\":{\"vnext\":[{\"address\":\"1.2.3.4\",\"port\":443,"
            "    \"users\":[{\"id\":\"11111111-2222-3333-4444-555555555555\"}]}]},"
            "  \"streamSettings\":{\"network\":\"tcp\",\"security\":\"reality\","
            "    \"realitySettings\":{\"serverName\":\"a.example\",\"publicKey\":\"P\"}}}],"
            " \"remarks\":\"\"}]";
        size_t n = vless_parse_sub(cfg, nodes, 4, &st);
        check_n("empty remarks: node taken", 1, (long)n);
        check("empty remarks: name from tag", "ch01_tcp", nodes[0].name);
    }
    {
        /* An unusable node of a config with remarks is reported under the remarks name, the
         * one the user sees in the panel, not "proxy". */
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        const char *cfg =
            "[{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"proxy\","
            "  \"settings\":{\"vnext\":[{\"address\":\"0.0.0.0\",\"port\":1,"
            "    \"users\":[{\"id\":\"00000000-0000-0000-0000-000000000000\"}]}]},"
            "  \"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}],"
            " \"remarks\":\"🇱🇻 Латвия\"}]";
        size_t n = vless_parse_sub(cfg, nodes, 4, &st);
        check_n("remarks: unusable node not taken", 0, (long)n);
        check_n("remarks: unusable node counted", 1, (long)st.skipped);
        check("remarks: skip example is the remarks name", "🇱🇻 Латвия", st.reasons[0].example);
    }
    {
        /* An unusable node of a config is explained like an unusable link: both paths share
         * node_usable. Here, the panel stub for a client without a device id. */
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *cfg =
            "[{\"outbounds\":[{\"protocol\":\"vless\",\"tag\":\"Неправильный клиент\","
            "  \"settings\":{\"vnext\":[{\"address\":\"0.0.0.0\",\"port\":1,"
            "    \"users\":[{\"id\":\"00000000-0000-0000-0000-000000000000\"}]}]},"
            "  \"streamSettings\":{\"network\":\"tcp\",\"security\":\"none\"}}]}]";
        size_t n = vless_parse_sub(cfg, nodes, 16, &st);
        check_n("Xray config: stub not usable", 0, (long)n);
        check_n("Xray config: stub counted", 1, (long)st.skipped);
        check("Xray config: stub reason given",
              "0.0.0.0: nobody to answer", st.reasons[0].reason);
        check("Xray config: example carries the panel's message",
              "Неправильный клиент", st.reasons[0].example);
    }
    {
        /* The form is told by the first character. A config with "://" (a DNS URL) would also
         * pass a search for "://", so this one has none: only the first character keeps it
         * from being decoded as base64. */
        char dec[256];
        const char *json = "  [{\"dns\":{\"servers\":[\"1.1.1.1\"]},\"outbounds\":[]}]";
        check("form: config without \"://\" returned as is", json,
              vless_sub_text(json, strlen(json), dec, sizeof(dec)));
        const char *links = "vless://a@h:443#n\n";
        check("form: link list returned as is", links,
              vless_sub_text(links, strlen(links), dec, sizeof(dec)));
        /* base64 of "vless://a@h:443" */
        const char *b64 = "dmxlc3M6Ly9hQGg6NDQz";
        const char *got = vless_sub_text(b64, strlen(b64), dec, sizeof(dec));
        check("form: base64 decoded", "vless://a@h:443", got);
    }

    /* ---- node name at the buffer end: UTF-8 is not split ----------------------- */
    {
        /* A node name can hold anything, and its buffer is 128 bytes. A cut in the middle of a
         * multi-byte letter leaves a lone lead byte, which goes on to every consumer that must
         * parse UTF-8. A letter can be split two ways, and both are checked:
         *
         *   - percent form (how panels send names): the cut falls between "%D0" and "%9F",
         *     and decoding leaves 0xD0 without its continuation;
         *   - raw UTF-8 bytes in the fragment: the cut splits the letter directly.
         *
         * The name must stay valid UTF-8; its length is not checked. */
        struct vless_node n;
        char url[1024];

        /* 70 two-byte letters (D0 9F) percent-encoded are 420 bytes, well over 128. The
         * four-letter ASCII prefix puts the cut right after a "%D0", whose "%9F" no longer
         * fits. */
        char pct[512] = {0};
        strcat(pct, "node");
        for (int i = 0; i < 70; i++) strcat(pct, "%D0%9F");
        snprintf(url, sizeof(url),
                 "vless://11111111-2222-3333-4444-555555555555@example.com:8443"
                 "?security=reality&sni=a.example&pbk=k&fp=chrome#%s", pct);
        check_n("long name: node parses", 0, vless_parse_url(url, &n));
        check_n("long percent-encoded name: UTF-8 intact", 1, utf8_ok(n.name));

        /* The same with raw bytes: 70 letters (D0 9F) directly in the fragment. */
        char raw[512] = {0};
        for (int i = 0; i < 70; i++) strcat(raw, "\xD0\x9F");
        snprintf(url, sizeof(url),
                 "vless://11111111-2222-3333-4444-555555555555@example.com:8443"
                 "?security=reality&sni=a.example&pbk=k&fp=chrome#%s", raw);
        check_n("long name: node parses (raw bytes)", 0, vless_parse_url(url, &n));
        check_n("long raw-byte name: UTF-8 intact", 1, utf8_ok(n.name));

        /* A short name must not be touched by the cut. */
        snprintf(url, sizeof(url),
                 "vless://11111111-2222-3333-4444-555555555555@example.com:8443"
                 "?security=reality&sni=a.example&pbk=k&fp=chrome#%%D0%%A3%%D0%%B7%%D0%%B5%%D0%%BB");
        check_n("short name: node parses", 0, vless_parse_url(url, &n));
        check("short name not cut", "Узел", n.name);

        for (int pre = 5; pre <= 6; pre++) {
            char cut[512], want[160];
            snprintf(cut, sizeof(cut), "%.*s", pre, "nodexy");
            snprintf(want, sizeof(want), "%.*s", pre, "nodexy");
            for (int i = 0; i < 70; i++) strcat(cut, "%D0%9F");
            for (int i = 0; i < (pre == 5 ? 61 : 60); i++) strcat(want, "\xD0\x9F");
            snprintf(url, sizeof(url),
                     "vless://11111111-2222-3333-4444-555555555555@example.com:8443"
                     "?security=reality&sni=a.example&pbk=k&fp=chrome#%s", cut);
            vless_parse_url(url, &n);
            check(pre == 5 ? "long name: decoded, then cut to whole letters"
                           : "long name: decoded, then a split letter dropped", want, n.name);
        }
    }

    /* ---- malformed JSON: parsing returns ------------------------------------- */
    {
        static const char *const bad[] = {
            "[null]", "[1,{\"outbounds\":[]}]", "{\"outbounds\":[null]}", "{\"outbounds\":[}",
            "{\"outbounds\":[{\"protocol\":\"vless\"} x]}",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[}]}",
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"h\",\"port\":\"443\","
            "\"users\":[{\"id\":\"u\"}]}]},\"streamSettings\":{\"network\":\"tcp\"}}]}",
        };
        signal(SIGALRM, on_alarm);
        for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
            struct vless_node nodes[4];
            struct vless_sub_stats st;
            g_json_case = i;
            alarm(2);
            size_t n = vless_parse_sub(bad[i], nodes, 4, &st);
            alarm(0);
            char what[96];
            snprintf(what, sizeof(what), "malformed JSON %zu: parsing returned", i);
            check_n(what, 1, 1);
            if (i == 6) check_n("port given as a string is read", 443, (long)(n ? nodes[0].port : 0));
        }
    }
    /* ---- Xray config: default transport and network raw ---------------------- */
    {
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub(
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"h\",\"port\":443,"
            "\"users\":[{\"id\":\"u\"}]}]}}]}", nodes, 4, &st);
        check_n("config without streamSettings: node usable", 1, (long)n);
        check("config without streamSettings: transport tcp", "tcp", n ? nodes[0].type : "");
        n = vless_parse_sub(
            "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"h\",\"port\":443,"
            "\"users\":[{\"id\":\"u\"}]}]},\"streamSettings\":{\"network\":\"raw\"}}]}", nodes, 4, &st);
        check_n("network raw: node usable", 1, (long)n);
        check("network raw reads as tcp", "tcp", n ? nodes[0].type : "");
    }
    /* ---- ws and httpupgrade -------------------------------------------------- */
    {
        struct vless_node n;
        check_n("ws link: usable", 0, vless_parse_url(
            "vless://u@h:443?type=ws&security=tls&sni=s.example&path=%2Fws%3Fed%3D2048&host=cdn.example#w", &n));
        check("ws: path decoded, ed kept (the transport strips it)", "/ws?ed=2048", n.path);
        check("ws: host from the link", "cdn.example", n.http_host);
        check_n("httpupgrade link: usable", 0,
                vless_parse_url("vless://u@h:443?type=httpupgrade&path=/up#h", &n));
        check("httpupgrade: type", "httpupgrade", n.type);
        /* A long, fully percent-encoded path is decoded before it is cut to the field size. */
        check_n("long percent-encoded path: usable", 0, vless_parse_url(
            "vless://u@h:443?type=ws&path=%2F%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61"
            "%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61%61#w", &n));
        check("long percent-encoded path: decoded whole",
              "/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", n.path);
        check_n("ws with vision: skipped", 1,
                vless_parse_url("vless://u@h:443?type=ws&flow=xtls-rprx-vision#w", &n));
        check("ws with vision: reason given", "vision cannot run over ws", n.skip_reason);
        check_n("type=raw with reality and vision: usable", 0, vless_parse_url(
            "vless://u@h:443?type=raw&security=reality&pbk=K&sni=a.com&flow=xtls-rprx-vision#r", &n));
        check("type=raw reads as tcp", "tcp", n.type);
        check_n("type=%72aw percent-encoded: usable", 0, vless_parse_url(
            "vless://u@h:443?type=%72aw&security=reality&pbk=K&sni=a.com#r", &n));
        check("type=%72aw reads as tcp", "tcp", n.type);
        check_n("type=websocket: usable", 0,
                vless_parse_url("vless://u@h:443?type=websocket&path=/ws#w", &n));
        check("type=websocket reads as ws", "ws", n.type);
        check_n("grpc with vision: skipped", 1, vless_parse_url(
            "vless://u@h:443?type=grpc&serviceName=s&security=reality&pbk=K&flow=xtls-rprx-vision#g", &n));
        check("grpc with vision: reason given", "vision cannot run over grpc", n.skip_reason);
        check_n("xhttp with vision-udp443: skipped", 1, vless_parse_url(
            "vless://u@h:443?type=xhttp&path=/x&security=reality&pbk=K&flow=xtls-rprx-vision-udp443#x", &n));
        check("xhttp with vision: reason given", "vision cannot run over xhttp", n.skip_reason);
        check_n("httpupgrade with vision: skipped", 1,
                vless_parse_url("vless://u@h:443?type=httpupgrade&path=/up&flow=xtls-rprx-vision#h", &n));
        check("httpupgrade with vision: reason given", "vision cannot run over httpupgrade", n.skip_reason);
        check_n("grpc without vision: usable", 0, vless_parse_url(
            "vless://u@h:443?type=grpc&serviceName=s&security=reality&pbk=K#g", &n));
        check_n("tcp with vision: usable", 0, vless_parse_url(
            "vless://u@h:443?type=tcp&security=reality&pbk=K&flow=xtls-rprx-vision#t", &n));
        check_n("type=raws: not a known transport", 1, vless_parse_url("vless://u@h:443?type=raws#w", &n));
        check("type=raws: reason names it", "transport raws is not supported", n.skip_reason);
        check_n("ws with bad %XX in path: skipped", 1,
                vless_parse_url("vless://u@h:443?type=ws&path=/a%25zz#w", &n));
        check("ws with bad %XX: reason given", "bad %XX in path", n.skip_reason);
        check_n("httpupgrade with the same path: usable (Xray escapes it whole)", 0,
                vless_parse_url("vless://u@h:443?type=httpupgrade&path=/a%25zz#w", &n));
        check_n("host with a space: skipped", 1,
                vless_parse_url("vless://u@h:443?type=ws&host=a%20b#w", &n));
        check("host with a space: reason given", "invalid host for ws", n.skip_reason);
        check_n("ws over reality: usable (security and transport independent)", 0, vless_parse_url(
            "vless://u@h:443?type=ws&security=reality&pbk=Zm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyZm9vYmFyMDA#w", &n));
    }
    {
        struct vless_node nodes[4];
        struct vless_sub_stats st;
#define XO(stream) "{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"h\"," \
                   "\"port\":443,\"users\":[{\"id\":\"u\"}]}]},\"streamSettings\":" stream "}]}"
        size_t n = vless_parse_sub(XO("{\"wsSettings\":{\"path\":\"/w?ed=2048\",\"headers\":"
            "{\"Host\":\"hdr.example\",\"X-A\":\"1\"}},\"xhttpSettings\":{\"path\":\"/x\"},\"network\":\"websocket\"}"),
            nodes, 4, &st);
        check_n("config: network websocket gives a ws node", 1, (long)n);
        check("ws config: type", "ws", n ? nodes[0].type : "");
        check("ws config: wsSettings path, not xhttpSettings", "/w?ed=2048", n ? nodes[0].path : "");
        check("ws config: Host header becomes host (as in Xray Build)", "hdr.example", n ? nodes[0].http_host : "");
        check("ws config: other headers", "X-A: 1\n", n ? nodes[0].headers : "");
        n = vless_parse_sub(XO("{\"network\":\"ws\",\"wsSettings\":{\"host\":\"h1\",\"headers\":{\"host\":\"h2\"}}}"),
                            nodes, 4, &st);
        check("ws config: explicit host wins over Host header", "h1", n ? nodes[0].http_host : "");
        n = vless_parse_sub(XO("{\"network\":\"httpupgrade\",\"httpupgradeSettings\":{\"path\":\"/u\","
                               "\"host\":\"c\",\"headers\":{\"x-b\":\"2\"}}}"), nodes, 4, &st);
        check_n("httpupgrade config: usable", 1, (long)n);
        check("httpupgrade config: path", "/u", n ? nodes[0].path : "");
        check("httpupgrade config: header kept as written", "x-b: 2\n", n ? nodes[0].headers : "");
        n = vless_parse_sub(XO("{\"network\":\"httpupgrade\",\"httpupgradeSettings\":{\"headers\":{\"Host\":\"x\"}}}"),
                            nodes, 4, &st);
        check_n("httpupgrade config with Host in headers: skipped (Xray rejects it)", 0, (long)n);
        check("httpupgrade Host header: reason", "invalid headers for httpupgrade", st.reasons_n ? st.reasons[0].reason : "");
        n = vless_parse_sub(XO("{\"network\":\"ws\",\"wsSettings\":{\"headers\":{\"Upgrade\":\"x\"}}}"),
                            nodes, 4, &st);
        check_n("ws config with Upgrade in headers: skipped", 0, (long)n);
        /* sing-box and Clash headers get the same checks: a raw line break in a value would
         * add a header of its own to the request. */
        n = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"sb\",\"server\":\"h\","
                            "\"server_port\":443,\"uuid\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\","
                            "\"transport\":{\"type\":\"ws\",\"headers\":{\"X-A\":\"1\r\nX-Evil: 2\"}}}]}",
                            nodes, 4, &st);
        check_n("sing-box header with a line break: skipped", 0, (long)n);
        n = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"sb\",\"server\":\"h\","
                            "\"server_port\":443,\"uuid\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\","
                            "\"transport\":{\"type\":\"ws\",\"headers\":{\"X-A\":\"1\"}}}]}",
                            nodes, 4, &st);
        check("sing-box header: kept", "X-A: 1\n", n ? nodes[0].headers : "");
        n = vless_parse_sub("proxies:\n  - {name: c, type: vless, server: h, port: 443, "
                            "uuid: 8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124, network: ws, "
                            "ws-opts: {path: /, headers: {\"X A\": 1}}}\n", nodes, 4, &st);
        check_n("Clash header name with a space: skipped", 0, (long)n);
        /* For httpupgrade Xray accepts such a header (gorilla is not used there), and so does
         * this parser. */
        n = vless_parse_sub(XO("{\"network\":\"httpupgrade\",\"httpupgradeSettings\":{\"headers\":"
                               "{\"connection\":\"keep-alive\"}}}"), nodes, 4, &st);
        check_n("httpupgrade config with Connection in headers: usable", 1, (long)n);
        n = vless_parse_sub(XO("{\"network\":\"ws\",\"wsSettings\":{\"headers\":{\"X\":1}}}"), nodes, 4, &st);
        check_n("ws config: header value not a string, skipped", 0, (long)n);
        n = vless_parse_sub(XO("{\"network\":\"xhttp\",\"security\":\"reality\",\"realitySettings\":"
                               "{\"serverName\":\"a.com\",\"publicKey\":\"K\"}}"), nodes, 4, &st);
        check_n("xhttp config without vision: usable", 1, (long)n);
        n = vless_parse_sub("{\"outbounds\":[{\"protocol\":\"vless\",\"settings\":{\"vnext\":[{\"address\":\"h\","
                            "\"port\":443,\"users\":[{\"id\":\"u\",\"flow\":\"xtls-rprx-vision\"}]}]},"
                            "\"streamSettings\":{\"network\":\"xhttp\",\"security\":\"reality\",\"realitySettings\":"
                            "{\"serverName\":\"a.com\",\"publicKey\":\"K\"}}}]}", nodes, 4, &st);
        check_n("Xray config: vision over xhttp skipped", 0, (long)n);
        check("Xray config: vision over xhttp, reason", "vision cannot run over xhttp",
              st.reasons_n ? st.reasons[0].reason : "");
        n = vless_parse_sub("{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"sb\",\"server\":\"h\","
                            "\"server_port\":443,\"uuid\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\","
                            "\"flow\":\"xtls-rprx-vision\",\"transport\":{\"type\":\"grpc\",\"service_name\":\"s\"}}]}",
                            nodes, 4, &st);
        check_n("sing-box: vision over grpc skipped", 0, (long)n);
        check("sing-box: vision over grpc, reason", "vision cannot run over grpc",
              st.reasons_n ? st.reasons[0].reason : "");
        n = vless_parse_sub("proxies:\n  - {name: c, type: vless, server: h, port: 443, "
                            "uuid: 8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124, network: grpc, flow: xtls-rprx-vision, "
                            "grpc-opts: {grpc-service-name: s}}\n", nodes, 4, &st);
        check_n("Clash: vision over grpc skipped", 0, (long)n);
        check("Clash: vision over grpc, reason", "vision cannot run over grpc",
              st.reasons_n ? st.reasons[0].reason : "");
        n = vless_parse_sub("proxies:\n  - {name: c, type: vless, server: h, port: 443, "
                            "uuid: 8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124, network: grpc, "
                            "grpc-opts: {grpc-service-name: s}}\n", nodes, 4, &st);
        check_n("Clash: grpc without vision usable", 1, (long)n);
        n = vless_parse_sub(XO("{\"network\":\"xhttp\",\"xhttpSettings\":{\"path\":\"/x\"},"
                               "\"wsSettings\":{\"path\":\"/w\"}}"), nodes, 4, &st);
        check("xhttp config with stray wsSettings: xhttp path", "/x", n ? nodes[0].path : "");
#undef XO
    }
    /* ---- link: port and name boundaries ------------------------------------- */
    {
        struct vless_node n;
        check_n("port 70000: link not parsed", -1, vless_parse_url("vless://u@h:70000#x", &n));
        check_n("port -1: link not parsed", -1, vless_parse_url("vless://u@h:-1#x", &n));
        check_n("port 443abc: link not parsed", -1, vless_parse_url("vless://u@h:443abc#x", &n));
        check_n("'?' only in the name: node taken", 0, vless_parse_url("vless://u@h:443#Fast?type=ws", &n));
        check("'?' only in the name: transport tcp", "tcp", n.type);
        check_n("host with '?' before '#': no port taken from the parameters", -1,
                vless_parse_url("vless://u@host.example?type=tcp#name:1", &n));
    }
    /* ---- percent decoding: non-hex stays as is ---------------------------------- */
    {
        struct vless_node n;
        vless_parse_url("vless://u@h:443#a%40%40b", &n);
        check("percent decoding: %40 is @", "a@@b", n.name);
        vless_parse_url("vless://u@h:443#a%@@b", &n);
        check("percent decoding: %@@ is not hex, kept as is", "a%@@b", n.name);
    }

    /* ---- fewer slots than links: the rest is counted ------------------------- */
    {
        struct vless_node nodes[1];
        struct vless_sub_stats st;
        size_t n = vless_parse_sub("vless://a@h1:443#one\nvless://b@h2:443#two\nss://c@h3:443#x\n",
                                   nodes, 1, &st);
        check_n("one slot: one node taken", 1, (long)n);
        check_n("second vless link counted as skipped", 1, (long)st.skipped);
        /* A usable node without a slot must not read as a link that did not parse. */
        check("  reason: more nodes than fit", "more nodes than fit", st.reasons[0].reason);
        check_n("foreign link past the slots counted", 1, (long)st.foreign);
    }

    /* ---- 500-node subscription file: slots grow with the number of links -------- */
    {
        char path[64];
        snprintf(path, sizeof(path), "/tmp/submatch-500.%d", (int)getpid());
        FILE *f = fopen(path, "w");
        for (int i = 0; f && i < 500; i++)
            fprintf(f, "vless://a@h%d:443#node%d\n", i, i);
        if (f) fclose(f);
        struct vless_sub_stats st;
        size_t n = 0;
        struct vless_node *nodes = vless_load_sub(path, &n, &st);
        unlink(path);
        check_n("500 nodes from a file: all taken", 500, (long)n);
        check_n("  none skipped", 0, (long)st.skipped);
        if (nodes && n == 500) check("  last node has its own name", "node499", nodes[499].name);
        free(nodes);
    }

    /* ---- sing-box and Clash files: one slot per node, though they have no "://" ---------- */
    {
        static const char *const files[] = {
            "{\"outbounds\":["
            "{\"type\":\"vless\",\"tag\":\"sb1\",\"server\":\"h1\",\"server_port\":443,"
            "\"uuid\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\"},"
            "{\"type\":\"vless\",\"tag\":\"sb2\",\"server\":\"h2\",\"server_port\":443,"
            "\"uuid\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\"},"
            "{\"type\":\"vless\",\"tag\":\"sb3\",\"server\":\"h3\",\"server_port\":443,"
            "\"uuid\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\"}]}",
            "proxies:\n"
            "  - name: c1\n    type: vless\n    server: h1\n    port: 443\n"
            "    uuid: 8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\n"
            "  - {name: c2, type: vless, server: h2, port: 443, uuid: 8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124}\n"
            "  - name: c3\n    type: vless\n    server: h3\n    port: 443\n"
            "    uuid: 8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\n",
        };
        static const char *const what[] = { "sing-box file: 3 nodes", "Clash file: 3 nodes" };
        for (int k = 0; k < 2; k++) {
            char path[64];
            snprintf(path, sizeof(path), "/tmp/submatch-cfg.%d", (int)getpid());
            FILE *f = fopen(path, "w");
            if (f) { fputs(files[k], f); fclose(f); }
            struct vless_sub_stats st;
            size_t n = 0;
            struct vless_node *nodes = vless_load_sub(path, &n, &st);
            unlink(path);
            check_n(what[k], 3, (long)n);
            check_n("  none skipped for lack of slots", 0, (long)st.skipped);
            free(nodes);
        }
    }

    {
        struct vless_node nodes[4];
        struct vless_sub_stats st;
        size_t n;
#define SB(tag) "{\"outbounds\":[{\"type\":\"vless\",\"tag\":\"" tag "\",\"server\":\"h\",\"server_port\":443," \
                "\"uuid\":\"8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\"}]}"
        n = vless_parse_sub(SB("\\u26a1 \\u2b50 \\u0412\\u0435"), nodes, 4, &st);
        check("json \\u: BMP letters decoded to UTF-8", "\xE2\x9A\xA1 \xE2\xAD\x90 \xD0\x92\xD0\xB5",
              n ? nodes[0].name : "");
        n = vless_parse_sub(SB("\\ud83d\\udcf1 \\u00E9"), nodes, 4, &st);
        check("json \\u: a surrogate pair is one character", "\xF0\x9F\x93\xB1 \xC3\xA9", n ? nodes[0].name : "");
        n = vless_parse_sub(SB("a\\ud83d b\\udcf1c\\ud83d\\u0041"), nodes, 4, &st);
        check("json \\u: lone surrogates become U+FFFD",
              "a\xEF\xBF\xBD b\xEF\xBF\xBD" "c\xEF\xBF\xBD" "A", n ? nodes[0].name : "");
        n = vless_parse_sub(SB("\\udbff\\udfff\\ud800\\udc00"), nodes, 4, &st);
        check("json \\u: the pair range ends decode", "\xF4\x8F\xBF\xBF\xF0\x90\x80\x80", n ? nodes[0].name : "");
        n = vless_parse_sub(SB("\\u07ff\\u0800\\u007f\\u0080"), nodes, 4, &st);
        check("json \\u: two and three byte boundaries", "\xDF\xBF\xE0\xA0\x80\x7F\xC2\x80", n ? nodes[0].name : "");
        n = vless_parse_sub(SB("q\\\"b\\\\s\\/t\\tn\\nr\\rb\\bf\\fe"), nodes, 4, &st);
        check("json escapes: quote, backslash, slash, controls", "q\"b\\s/t\tn\nr\rb\bf\fe", n ? nodes[0].name : "");
        n = vless_parse_sub(SB("x\\u12g4y\\x41"), nodes, 4, &st);
        check("json: a short \\u and \\x stay letters", "xu12g4yx41", n ? nodes[0].name : "");
        n = vless_parse_sub(SB("a\\u0000b"), nodes, 4, &st);
        check("json \\u0000 is dropped, the rest kept", "ab", n ? nodes[0].name : "");
        n = vless_parse_sub(SB("\\u0000"), nodes, 4, &st);
        check_n("json name of only \\u0000: the node is still read", 1, (long)n);
        check("json name of only \\u0000: empty", "", n ? nodes[0].name : "x");
        n = vless_parse_sub(SB("\\ud83d\\xdc00"), nodes, 4, &st);
        check("json \\u: a high surrogate before \\x is lone", "\xEF\xBF\xBD" "xdc00", n ? nodes[0].name : "");
        char tag[200], want[200];
        memset(tag, 'a', sizeof(nodes[0].name) - 3);
        tag[sizeof(nodes[0].name) - 3] = 0;
        memcpy(want, tag, sizeof(nodes[0].name) - 2);
        char cfg[512];
        snprintf(cfg, sizeof cfg, SB("%s\\ud83d\\udcf1b"), tag);
        n = vless_parse_sub(cfg, nodes, 4, &st);
        check("json \\u: a character that does not fit is dropped with the rest", want, n ? nodes[0].name : "");
        memset(want, 'a', sizeof(nodes[0].name) - 2);
        want[sizeof(nodes[0].name) - 2] = 0;
        snprintf(cfg, sizeof cfg, SB("%s\\u00e9b"), want);
        n = vless_parse_sub(cfg, nodes, 4, &st);
        check("json \\u: a two byte character that does not fit is dropped", want, n ? nodes[0].name : "");
#undef SB
        n = vless_parse_sub("{\"remarks\":\"\\u0413\\u0435\\u0440\",\"outbounds\":[{\"protocol\":\"vless\",\"settings\":"
                            "{\"vnext\":[{\"address\":\"h\",\"port\":443,\"users\":[{\"id\":\"u\"}]}]}}]}",
                            nodes, 4, &st);
        check("Xray remarks: \\u decoded", "\xD0\x93\xD0\xB5\xD1\x80", n ? nodes[0].name : "");
#define CL(name) "proxies:\n  - name: " name "\n    type: vless\n    server: h\n    port: 443\n" \
                 "    uuid: 8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124\n"
        n = vless_parse_sub(CL("\"\\U0001F4F1 \\x41\\u00e9\\ud83d\\udcf1\""), nodes, 4, &st);
        check("Clash double quotes: \\U, \\x, \\u and a pair", "\xF0\x9F\x93\xB1 A\xC3\xA9\xF0\x9F\x93\xB1",
              n ? nodes[0].name : "");
        n = vless_parse_sub(CL("\"\\U0000D800\\U00110000\\x4\""), nodes, 4, &st);
        check("Clash: a surrogate or out of range \\U stays letters", "U0000D800U00110000x4", n ? nodes[0].name : "");
        n = vless_parse_sub(CL("\"a\\x00b\\U00000000c\\u0000d\""), nodes, 4, &st);
        check("Clash \\x00, \\U00000000, \\u0000 are dropped", "abcd", n ? nodes[0].name : "");
        n = vless_parse_sub(CL("'\\u00e9'"), nodes, 4, &st);
        check("Clash single quotes: no escapes", "\\u00e9", n ? nodes[0].name : "");
        n = vless_parse_sub(CL("\\u00e9"), nodes, 4, &st);
        check("Clash plain scalar: no escapes", "\\u00e9", n ? nodes[0].name : "");
#undef CL
        {
            const char *q = "\"aaa\\u00e9b\"";
            char out[5];
            size_t on = 0;
            y_scalar(q, q + strlen(q), 0, out, sizeof out, &on);
            check("YAML: a character that does not fit is dropped with the rest", "aaa", out);
        }
    }

    t_xhx_all();
    t_intern_blob();
    t_intern_blob_full();
    t_dl_all();
    t_xmux_all();
    t_fm_all();
    t_hy2_all();
    t_hy2_sub_all();
    t_qp_all();
    t_qp_node();

    printf("\n%d checks passed", g_pass);
    if (g_fail) {
        printf(", %d FAILED\n", g_fail);
        return 1;
    }
    printf("\n");
    return 0;
}
