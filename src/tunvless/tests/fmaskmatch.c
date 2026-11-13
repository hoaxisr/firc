#include <stdio.h>
#include <string.h>
#include "unit.h"
#include "fmask.h"

static char why[128];
static struct fm_cfg cfg;
static char jb[16384];

static int parse(const char *j) {
    fm_cfg_free(&cfg);
    why[0] = '\0';
    return fm_parse(j, strlen(j), &cfg, why, sizeof why);
}

static void ok_parse(const char *what, const char *j) {
    check(what, 0, parse(j));
    if (why[0]) printf("     why: %s\n", why);
}

static void bad_parse(const char *what, const char *j, const char *want) {
    char w[160];
    check(what, -1, parse(j));
    snprintf(w, sizeof w, "%s: why", what);
    check_str(w, want, why);
}

static const char *frag(const char *settings) {
    snprintf(jb, sizeof jb, "{\"tcp\":[{\"type\":\"fragment\",\"settings\":%s}]}", settings);
    return jb;
}

static const char *hc(const char *settings) {
    snprintf(jb, sizeof jb, "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":%s}]}", settings);
    return jb;
}

static const char *hc1(const char *item) {
    char s[8192];
    snprintf(s, sizeof s, "{\"clients\":[[%s]]}", item);
    return hc(s);
}

static const char *filt(const char *settings) {
    snprintf(jb, sizeof jb, "{\"tcp\":[{\"type\":\"filter\",\"settings\":%s}]}", settings);
    return jb;
}

static size_t compact(const char *j, char *out, size_t cap) { return fm_compact(j, strlen(j), out, cap); }

static void t_compact(void) {
    /* catches: whitespace dropped inside strings, or no size cap */
    static char out[8192], big[5000];
    size_t n = compact(" { \"tcp\" : [ {\"type\":\"fragment\"} ] } ", out, sizeof out);
    check("compact: length", 29, (long)n);
    out[n < sizeof out ? n : 0] = '\0';
    check_str("compact: text", "{\"tcp\":[{\"type\":\"fragment\"}]}", out);
    n = compact("{ \"a\" : \" a\\\"b \" }", out, sizeof out);
    out[n < sizeof out ? n : 0] = '\0';
    check_str("compact: string kept as written", "{\"a\":\" a\\\"b \"}", out);
    check("compact: broken array", 0, (long)compact("{\"tcp\":[}", out, sizeof out));
    check("compact: empty", 0, (long)compact("", out, sizeof out));
    check("compact: two values", 0, (long)compact("{} {}", out, sizeof out));
    check("compact: trailing comma", 0, (long)compact("[1,]", out, sizeof out));
    check("compact: leading zero", 0, (long)compact("{\"a\":01}", out, sizeof out));
    check("compact: control byte in string", 0, (long)compact("[\"a\x01\"]", out, sizeof out));
    check("compact: bad escape", 0, (long)compact("[\"\\x\"]", out, sizeof out));
    check("compact: short cap", 0, (long)compact("[1, 2]", out, 4));
    check("compact: exact cap", 5, (long)compact("[1, 2]", out, 5));
    memcpy(big, "[\"", 2);
    memset(big + 2, 'a', 2044);
    memcpy(big + 2046, "\"]", 3);
    check("compact: 2048 bytes", 2048, (long)compact(big, out, sizeof out));
    memcpy(big, "[\"", 2);
    memset(big + 2, 'a', 2045);
    memcpy(big + 2047, "\"]", 3);
    check("compact: 2049 bytes", 0, (long)compact(big, out, sizeof out));
    bad_parse("parse: 2049 bytes compact", big, "over 2048 bytes");
    bad_parse("parse: not json", "{\"tcp\":[}", "does not parse");
    {
        static char huge[200016];
        size_t o = (size_t)sprintf(huge, "{\"udp\":[");
        while (o < 200000) o += (size_t)sprintf(huge + o, "1,");
        sprintf(huge + o, "x");
        bad_parse("parse: large input stops before its end", huge, "over 2048 bytes");
        check("compact: large input", 0, (long)compact(huge, out, sizeof out));
        o = (size_t)sprintf(huge, "{\"udp\":[");
        while (o < 200000) o += (size_t)sprintf(huge + o, "[],");
        sprintf(huge + o, "x");
        bad_parse("parse: many empty arrays stop before the end", huge, "over 2048 bytes");
        o = (size_t)sprintf(huge, "{\"udp\":\"");
        memset(huge + o, 'a', 5000);
        sprintf(huge + o + 5000, "\"x");
        bad_parse("parse: one long string stops before the end", huge, "over 2048 bytes");
    }
    memset(big, ' ', 10);
    memcpy(big + 10, "{\"udp\":\"", 8);
    memset(big + 18, 'a', 2038);
    memcpy(big + 2056, "\"}", 3);
    ok_parse("parse: 2048 bytes compact, padded", big);
    memset(big + 18, 'a', 2039);
    memcpy(big + 2057, "\"}", 3);
    bad_parse("parse: 2049 bytes compact, padded", big, "over 2048 bytes");
}

static void delay_is(const char *what, const char *v, long from, long to) {
    char s[256], w[160];
    snprintf(s, sizeof s, "{\"length\":1,\"delay\":%s}", v);
    snprintf(w, sizeof w, "range %s: parse", what);
    check(w, 0, parse(frag(s)));
    snprintf(w, sizeof w, "range %s: from", what);
    check(w, from, cfg.n == 1 && cfg.m[0].u.frag.n_delay == 1 ? (long)cfg.m[0].u.frag.delay[0].from : -999);
    snprintf(w, sizeof w, "range %s: to", what);
    check(w, to, cfg.n == 1 && cfg.m[0].u.frag.n_delay == 1 ? (long)cfg.m[0].u.frag.delay[0].to : -999);
}

static void length_bad(const char *what, const char *v) {
    char s[256], w[160];
    snprintf(s, sizeof s, "{\"length\":%s}", v);
    snprintf(w, sizeof w, "range %s", what);
    bad_parse(w, frag(s), "fragment: Invalid integer range");
}

static void t_int32range(void) {
    /* catches: no swap, a dash split at the first dash for negatives, or an overflow refused in the string form */
    delay_is("10", "10", 10, 10);
    delay_is("\"10-20\"", "\"10-20\"", 10, 20);
    delay_is("\"20-10\"", "\"20-10\"", 10, 20);
    delay_is("\"-5-10\"", "\"-5-10\"", -5, 10);
    delay_is("\"-10--5\"", "\"-10--5\"", -10, -5);
    delay_is("\"5--3\"", "\"5--3\"", -3, 5);
    delay_is("\"\"", "\"\"", 0, 0);
    delay_is("\"+7\"", "\"+7\"", 7, 7);
    delay_is("\"4294967306\"", "\"4294967306\"", 10, 10);
    delay_is("\"2147483648\"", "\"2147483648\"", -2147483648L, -2147483648L);
    delay_is("\"-2147483649\"", "\"-2147483649\"", 2147483647L, 2147483647L);
    delay_is("2147483647", "2147483647", 2147483647L, 2147483647L);
    delay_is("-2147483648", "-2147483648", -2147483648L, -2147483648L);
    bad_parse("range \"\" as length", frag("{\"length\":\"\"}"), "fragment: last lengths entry min can't be 0");
    length_bad("\" 5\"", "\" 5\"");
    length_bad("\"5-\"", "\"5-\"");
    length_bad("\"-\"", "\"-\"");
    length_bad("\"5-10-3\"", "\"5-10-3\"");
    length_bad("1.5", "1.5");
    length_bad("1e1", "1e1");
    length_bad("\"a\"", "\"a\"");
    length_bad("true", "true");
    length_bad("[1]", "[1]");
    length_bad("4294967306", "4294967306");
    length_bad("2147483648", "2147483648");
    length_bad("\"99999999999999999999\"", "\"99999999999999999999\"");
}

static void pk_is(const char *what, const char *settings, long long from, long long to) {
    char w[160];
    snprintf(w, sizeof w, "packets %s: parse", what);
    check(w, 0, parse(frag(settings)));
    if (cfg.n != 1) return;
    snprintf(w, sizeof w, "packets %s: from", what);
    check(w, 1, cfg.m[0].u.frag.pk_from == from);
    snprintf(w, sizeof w, "packets %s: to", what);
    check(w, 1, cfg.m[0].u.frag.pk_to == to);
}

static const struct fm_frag *F(void) {
    static const struct fm_frag none;
    return cfg.n == 1 && cfg.m[0].kind == FM_FRAGMENT ? &cfg.m[0].u.frag : &none;
}

static void t_fragment_schema(void) {
    /* catches: an empty delays list left empty, the swap applied to packets, or case-sensitive keys */
    pk_is("tlshello", "{\"packets\":\"tlshello\",\"length\":10}", 0, 1);
    pk_is("TLSHello", "{\"packets\":\"TLSHello\",\"length\":10}", 0, 1);
    pk_is("empty", "{\"packets\":\"\",\"length\":10}", 0, 0);
    pk_is("absent", "{\"length\":10}", 0, 0);
    pk_is("2-3", "{\"packets\":\"2-3\",\"length\":10}", 2, 3);
    pk_is("3-1", "{\"packets\":\"3-1\",\"length\":10}", 3, 1);
    pk_is("4294967306", "{\"packets\":\"4294967306\",\"length\":10}", 4294967306LL, 4294967306LL);
    pk_is("-5", "{\"packets\":\"-5\",\"length\":10}", -5, -5);
    pk_is("Packets/LENGTH", "{\"Packets\":\"2-3\",\"LENGTH\":3}", 2, 3);
    check("LENGTH: read", 3, cfg.n == 1 ? (long)F()->len[0].from : -1);
    pk_is("kelvin sign k", "{\"pac\xe2\x84\xaa" "ets\":\"2-3\",\"length\":3}", 2, 3);
    bad_parse("packets 0-3", frag("{\"packets\":\"0-3\",\"length\":10}"), "fragment: PacketsFrom can't be 0");
    bad_parse("packets x", frag("{\"packets\":\"x\",\"length\":10}"), "fragment: Invalid PacketsFrom");
    bad_parse("packets number", frag("{\"packets\":5,\"length\":10}"), "fragment: invalid packets");
    bad_parse("no length", frag("{}"), "fragment: last lengths entry min can't be 0");
    bad_parse("settings null", "{\"tcp\":[{\"type\":\"fragment\",\"settings\":null}]}",
              "fragment: last lengths entry min can't be 0");
    ok_parse("lengths [0,5]", frag("{\"lengths\":[0,5]}"));
    check("lengths [0,5]: n", 2, cfg.n == 1 ? (long)F()->n_len : -1);
    check("lengths [0,5]: second", 5, cfg.n == 1 && F()->n_len == 2 ? (long)F()->len[1].from : -1);
    check("lengths [0,5]: first", 0, cfg.n == 1 && F()->n_len == 2 ? (long)F()->len[0].to : -1);
    bad_parse("lengths [5,0]", frag("{\"lengths\":[5,0]}"), "fragment: last lengths entry min can't be 0");
    bad_parse("lengths [-1-5]", frag("{\"lengths\":[\"-1-5\"]}"), "fragment: lengths min below 0");
    bad_parse("lengths [-1,0]", frag("{\"lengths\":[-1,0]}"), "fragment: last lengths entry min can't be 0");
    bad_parse("length -1-5", frag("{\"length\":\"-1-5\"}"), "fragment: lengths min below 0");
    ok_parse("lengths over length", frag("{\"length\":0,\"lengths\":[7]}"));
    check("lengths over length: value", 7, cfg.n == 1 ? (long)F()->len[0].from : -1);
    ok_parse("lengths null falls back", frag("{\"lengths\":[3],\"lengths\":null,\"length\":2}"));
    check("lengths null falls back: value", 2, cfg.n == 1 ? (long)F()->len[0].from : -1);
    ok_parse("delay absent", frag("{\"length\":1}"));
    check("delay absent: n", 1, cfg.n == 1 ? (long)F()->n_delay : -1);
    check("delay absent: 0", 0, cfg.n == 1 ? (long)(F()->delay[0].from | F()->delay[0].to) : -1);
    ok_parse("delays empty", frag("{\"length\":1,\"delays\":[],\"delay\":\"5-6\",\"maxSplit\":\"2\"}"));
    check("delays empty: n", 1, cfg.n == 1 ? (long)F()->n_delay : -1);
    check("delays empty: from", 5, cfg.n == 1 ? (long)F()->delay[0].from : -1);
    check("delays empty: to", 6, cfg.n == 1 ? (long)F()->delay[0].to : -1);
    check("maxSplit: from", 2, cfg.n == 1 ? (long)F()->split.from : -1);
    check("maxSplit: to", 2, cfg.n == 1 ? (long)F()->split.to : -1);
    ok_parse("delays list", frag("{\"length\":1,\"delay\":9,\"delays\":[1,\"3-2\"]}"));
    check("delays list: n", 2, cfg.n == 1 ? (long)F()->n_delay : -1);
    check("delays list: second from", 2, cfg.n == 1 && F()->n_delay == 2 ? (long)F()->delay[1].from : -1);
    ok_parse("duplicate key: last wins", frag("{\"length\":5,\"length\":3}"));
    check("duplicate key: value", 3, cfg.n == 1 ? (long)F()->len[0].from : -1);
    bad_parse("duplicate key: earlier refused", frag("{\"length\":\"x\",\"length\":5}"), "fragment: Invalid integer range");
    bad_parse("duplicate key: null last", frag("{\"length\":5,\"length\":null}"),
              "fragment: last lengths entry min can't be 0");
    ok_parse("unknown keys ignored", frag("{\"length\":1,\"zzz\":[1,{}]}"));
}

static const struct fm_hc_item *item0(void) {
    if (cfg.n != 1 || cfg.m[0].kind != FM_HEADER || cfg.m[0].u.hc.n_cl < 1 || cfg.m[0].u.hc.cl[0].n < 1) return NULL;
    return &cfg.m[0].u.hc.cl[0].it[0];
}

static void bytes_are(const char *what, const char *item, const char *hex) {
    char w[160], got[160];
    const struct fm_hc_item *it;
    snprintf(w, sizeof w, "bytes %s: parse", what);
    check(w, 0, parse(hc1(item)));
    it = item0();
    got[0] = '\0';
    if (it)
        for (size_t i = 0; i < it->packet_n && i < 70; i++) sprintf(got + i * 2, "%02x", it->packet[i]);
    snprintf(w, sizeof w, "bytes %s: value", what);
    check_str(w, hex, got);
}

static void t_bytes(void) {
    /* catches: the base64 form of the default type refused, or \u escapes not turned into UTF-8 */
    bytes_are("array", "{\"type\":\"\",\"packet\":[1,2,255]}", "0102ff");
    bytes_are("no type, array", "{\"packet\":[1,2,255]}", "0102ff");
    bytes_are("no type, base64", "{\"type\":\"\",\"packet\":\"AQL/\"}", "0102ff");
    bytes_are("array type, base64", "{\"type\":\"array\",\"packet\":\"AQL/\"}", "0102ff");
    bytes_are("str", "{\"type\":\"str\",\"packet\":\"GET\\r\\n\"}", "4745540d0a");
    bytes_are("hex", "{\"type\":\"hex\",\"packet\":\"0102ff\"}", "0102ff");
    bytes_are("HEX upper", "{\"type\":\"HEX\",\"packet\":\"0102FF\"}", "0102ff");
    bytes_are("base64", "{\"type\":\"base64\",\"packet\":\"AQL/\"}", "0102ff");
    bytes_are("base64 non-zero tail bits", "{\"packet\":\"AR==\"}", "01");
    bytes_are("base64 newline skipped", "{\"packet\":\"A\\nQ==\"}", "01");
    bytes_are("array null element", "{\"packet\":[null,1]}", "0001");
    bytes_are("null", "{\"packet\":null}", "");
    bytes_are("hex null", "{\"type\":\"hex\",\"packet\":null}", "");
    bytes_are("str \\u00e9", "{\"type\":\"str\",\"packet\":\"\\u00e9\"}", "c3a9");
    bytes_are("str raw e-acute", "{\"type\":\"str\",\"packet\":\"\xc3\xa9\"}", "c3a9");
    bytes_are("str surrogate pair", "{\"type\":\"str\",\"packet\":\"\\ud83d\\ude00\"}", "f09f9880");
    bytes_are("str lone surrogate", "{\"type\":\"str\",\"packet\":\"\\ud800x\"}", "efbfbd78");
    bytes_are("str lone low surrogate", "{\"type\":\"str\",\"packet\":\"\\udc00\"}", "efbfbd");
    bytes_are("str two low surrogates", "{\"type\":\"str\",\"packet\":\"\\udc00\\udc00\"}", "efbfbdefbfbd");
    bytes_are("str invalid utf-8", "{\"type\":\"str\",\"packet\":\"\xff" "a\"}", "efbfbd61");
    bytes_are("str escapes", "{\"type\":\"str\",\"packet\":\"\\/\\b\\f\\t\\\\\\\"\"}", "2f080c095c22");
    bad_parse("bytes [256]", hc1("{\"packet\":[256]}"), "header-custom: invalid packet");
    bad_parse("bytes [-1]", hc1("{\"packet\":[-1]}"), "header-custom: invalid packet");
    bad_parse("bytes [1.0]", hc1("{\"packet\":[1.0]}"), "header-custom: invalid packet");
    bad_parse("bytes number", hc1("{\"packet\":5}"), "header-custom: invalid packet");
    bad_parse("bytes base64 unpadded", hc1("{\"packet\":\"AQ\"}"), "header-custom: invalid packet");
    bad_parse("bytes hex 0g", hc1("{\"type\":\"hex\",\"packet\":\"0g\"}"), "header-custom: invalid packet");
    bad_parse("bytes hex odd", hc1("{\"type\":\"hex\",\"packet\":\"012\"}"), "header-custom: invalid packet");
    bad_parse("bytes str not a string", hc1("{\"type\":\"str\",\"packet\":[1]}"), "header-custom: invalid packet");
    bad_parse("bytes base64 bad", hc1("{\"type\":\"base64\",\"packet\":\"A*==\"}"), "header-custom: invalid packet");
    bad_parse("bytes type bogus", hc1("{\"type\":\"bogus\",\"packet\":[1]}"), "header-custom: unknown type");
    bad_parse("bytes type bogus, no packet", hc1("{\"type\":\"bogus\"}"), "header-custom: unknown type");
    bad_parse("bytes str, no packet", hc1("{\"type\":\"str\",\"rand\":4}"), "header-custom: invalid packet");
    bad_parse("bytes hex, no packet", hc1("{\"type\":\"hex\"}"), "header-custom: invalid packet");
}

static void t_item_kinds(void) {
    /* catches: packet presence judged after decoding, or a capture without a kind accepted */
    const struct fm_hc_item *it;
    bad_parse("kinds packet+rand", hc1("{\"packet\":[1],\"rand\":2}"), "header-custom: exactly one item kind must be set");
    bad_parse("kinds rand+reuse", hc1("{\"rand\":1,\"reuse\":\"v\"}"), "header-custom: exactly one item kind must be set");
    bad_parse("kinds null packet+reuse", hc1("{\"packet\":null,\"reuse\":\"v\"}"),
              "header-custom: exactly one item kind must be set");
    bad_parse("kinds capture alone", hc1("{\"capture\":\"x\"}"), "header-custom: exactly one item kind must be set");
    bad_parse("kinds capture, rand 0", hc1("{\"rand\":0,\"capture\":\"x\"}"),
              "header-custom: exactly one item kind must be set");
    ok_parse("kinds null packet + capture", hc1("{\"packet\":null,\"capture\":\"x\"}"));
    it = item0();
    check_str("kinds null packet + capture: name", "x", it && it->capture ? it->capture : "");
    ok_parse("kinds delay only", hc1("{\"delay\":5}"));
    it = item0();
    check("kinds delay only: delay", 5, it ? (long)it->delay.to : -1);
    check("kinds delay only: no packet", 0, it ? (long)it->packet_n : -1);
    ok_parse("kinds rand -1 alone", hc1("{\"rand\":-1}"));
    bad_parse("kinds bad capture name", hc1("{\"capture\":\"1x\",\"packet\":[1]}"), "header-custom: invalid variable name");
    bad_parse("kinds bad reuse name", hc1("{\"reuse\":\"a-b\"}"), "header-custom: invalid variable name");
    bad_parse("kinds rand over int32", hc1("{\"rand\":2147483648}"), "header-custom: invalid rand");
    bad_parse("randRange 0-256", hc1("{\"randRange\":\"0-256\",\"rand\":1}"), "header-custom: invalid randRange");
    bad_parse("randRange -1-5", hc1("{\"randRange\":\"-1-5\",\"rand\":1}"), "header-custom: invalid randRange");
    bad_parse("randRange 256-0", hc1("{\"randRange\":\"256-0\",\"rand\":1}"), "header-custom: invalid randRange");
    ok_parse("randRange absent", hc1("{\"rand\":1}"));
    it = item0();
    check("randRange absent: min", 0, it ? it->rmin : -1);
    check("randRange absent: max", 255, it ? it->rmax : -1);
    check("randRange absent: rand", 1, it ? it->rand : -1);
    ok_parse("randRange 7-3", hc1("{\"randRange\":\"7-3\",\"rand\":1}"));
    it = item0();
    check("randRange 7-3: min", 3, it ? it->rmin : -1);
    check("randRange 7-3: max", 7, it ? it->rmax : -1);
    ok_parse("randRange null after value", hc1("{\"randRange\":\"5-6\",\"randRange\":null,\"rand\":1}"));
    it = item0();
    check("randRange null after value: min", 0, it ? it->rmin : -1);
    check("randRange null after value: max", 255, it ? it->rmax : -1);
    ok_parse("null sequence and item", hc("{\"clients\":[null,[null]]}"));
    check("null sequence: two clients", 2, cfg.n == 1 ? (long)cfg.m[0].u.hc.n_cl : -1);
    check("null sequence: first empty", 0, cfg.n == 1 && cfg.m[0].u.hc.n_cl == 2 ? (long)cfg.m[0].u.hc.cl[0].n : -1);
    check("null item: one item", 1, cfg.n == 1 && cfg.m[0].u.hc.n_cl == 2 ? (long)cfg.m[0].u.hc.cl[1].n : -1);
    ok_parse("errors kept", hc("{\"errors\":[[{\"packet\":[1]}],[]],\"servers\":[[{\"rand\":1}]]}"));
    check("errors kept: n", 2, cfg.n == 1 ? (long)cfg.m[0].u.hc.n_er : -1);
    check("servers kept: n", 1, cfg.n == 1 ? (long)cfg.m[0].u.hc.n_sv : -1);
    bad_parse("kinds checked in errors", hc("{\"errors\":[[{\"capture\":\"x\"}]]}"),
              "header-custom: exactly one item kind must be set");
    bad_parse("settings not an object", hc("5"), "header-custom: invalid settings");
}

static void t_transform(void) {
    /* catches: an unknown op accepted, or u64 read through a double */
    char deep[4096];
    size_t o = 0;
    ok_parse("transform be16", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{\"u64\":4660}]}}"));
    check("transform be16: expr set", 1, item0() && item0()->expr != NULL);
    ok_parse("transform u64 max", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{\"u64\":18446744073709551615}]}}"));
    bad_parse("transform u64 2^64", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{\"u64\":18446744073709551616}]}}"),
              "header-custom: invalid u64");
    bad_parse("transform op empty", hc1("{\"transform\":{\"op\":\"\",\"args\":[{\"u64\":1}]}}"),
              "header-custom: transform op is required");
    bad_parse("transform op absent", hc1("{\"transform\":{\"args\":[{\"u64\":1}]}}"),
              "header-custom: transform op is required");
    bad_parse("transform args empty", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[]}}"),
              "header-custom: transform args are required");
    bad_parse("transform two values", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{\"u64\":1,\"bytes\":[1]}]}}"),
              "header-custom: transform arg must set exactly one value");
    bad_parse("transform no value", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{}]}}"),
              "header-custom: transform arg must set exactly one value");
    ok_parse("transform u64 null + bytes", hc1("{\"transform\":{\"op\":\"concat\",\"args\":[{\"u64\":null,\"bytes\":[1]}]}}"));
    ok_parse("transform bytes null", hc1("{\"transform\":{\"op\":\"concat\",\"args\":[{\"bytes\":null}]}}"));
    bad_parse("transform u64 -1", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{\"u64\":-1}]}}"),
              "header-custom: invalid u64");
    bad_parse("transform u64 1.0", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{\"u64\":1.0}]}}"),
              "header-custom: invalid u64");
    bad_parse("transform u64 string", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{\"u64\":\"1\"}]}}"),
              "header-custom: invalid u64");
    bad_parse("transform bytes bad", hc1("{\"transform\":{\"op\":\"concat\",\"args\":[{\"type\":\"hex\",\"bytes\":\"0\"}]}}"),
              "header-custom: invalid bytes");
    bad_parse("transform op nope", hc1("{\"transform\":{\"op\":\"nope\",\"args\":[{\"u64\":1}]}}"),
              "header-custom: unsupported expr op: nope");
    bad_parse("transform op BE16", hc1("{\"transform\":{\"op\":\"BE16\",\"args\":[{\"u64\":1}]}}"),
              "header-custom: unsupported expr op: BE16");
    bad_parse("transform nested nope",
              hc1("{\"transform\":{\"op\":\"concat\",\"args\":[{\"transform\":{\"op\":\"nope\",\"args\":[{\"u64\":1}]}}]}}"),
              "header-custom: unsupported expr op: nope");
    bad_parse("transform arg bad reuse", hc1("{\"transform\":{\"op\":\"be16\",\"args\":[{\"reuse\":\"1a\"}]}}"),
              "header-custom: invalid variable name");
    ok_parse("transform every op",
             hc1("{\"transform\":{\"op\":\"concat\",\"args\":["
                 "{\"transform\":{\"op\":\"slice\",\"args\":[{\"bytes\":[1]},{\"u64\":0},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"xor16\",\"args\":[{\"u64\":1},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"xor32\",\"args\":[{\"u64\":1},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"be32\",\"args\":[{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"le16\",\"args\":[{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"le32\",\"args\":[{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"le64\",\"args\":[{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"pad\",\"args\":[{\"bytes\":[1]},{\"u64\":4},{\"bytes\":[0]}]}},"
                 "{\"transform\":{\"op\":\"truncate\",\"args\":[{\"bytes\":[1]},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"add\",\"args\":[{\"u64\":1},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"sub\",\"args\":[{\"u64\":1},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"and\",\"args\":[{\"u64\":1},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"or\",\"args\":[{\"u64\":1},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"shl\",\"args\":[{\"u64\":1},{\"u64\":1}]}},"
                 "{\"transform\":{\"op\":\"shr\",\"args\":[{\"u64\":1},{\"metadata\":\"local_port\"}]}}]}}"));
    for (int depth = 8; depth <= 9; depth++) {
        o = (size_t)sprintf(deep, "{");
        for (int i = 0; i < depth; i++) o += (size_t)sprintf(deep + o, "\"transform\":{\"op\":\"concat\",\"args\":[{");
        o += (size_t)sprintf(deep + o, "\"bytes\":[1]");
        for (int i = 0; i < depth; i++) o += (size_t)sprintf(deep + o, "}]}");
        sprintf(deep + o, "}");
        if (depth == 8) ok_parse("transform depth 8", hc1(deep));
        else bad_parse("transform depth 9", hc1(deep), "too deep");
    }
    o = (size_t)sprintf(deep, "{\"udp\":");
    for (int i = 0; i < 31; i++) deep[o++] = '[';
    for (int i = 0; i < 31; i++) deep[o++] = ']';
    sprintf(deep + o, "}");
    ok_parse("json depth 32", deep);
    o = (size_t)sprintf(deep, "{\"udp\":");
    for (int i = 0; i < 32; i++) deep[o++] = '[';
    for (int i = 0; i < 32; i++) deep[o++] = ']';
    sprintf(deep + o, "}");
    bad_parse("json depth 33", deep, "too deep");
}

static void t_servers_measurable(void) {
    /* catches: measurability checked on clients, or variable sizes not carried across sequences */
    ok_parse("servers be16 metadata", hc("{\"servers\":[[{\"transform\":{\"op\":\"be16\",\"args\":[{\"metadata\":\"remote_port\"}]}}]]}"));
    bad_parse("servers concat metadata",
              hc("{\"servers\":[[{\"transform\":{\"op\":\"concat\",\"args\":[{\"metadata\":\"remote_port\"}]}}]]}"),
              "header-custom: metadata not implemented: remote_port");
    ok_parse("clients concat metadata",
             hc("{\"clients\":[[{\"transform\":{\"op\":\"concat\",\"args\":[{\"metadata\":\"remote_port\"}]}}]]}"));
    ok_parse("errors concat metadata",
             hc("{\"errors\":[[{\"transform\":{\"op\":\"concat\",\"args\":[{\"metadata\":\"remote_port\"}]}}]]}"));
    bad_parse("servers unknown reuse", hc("{\"servers\":[[{\"reuse\":\"v\"}]]}"), "header-custom: unknown variable: v");
    ok_parse("clients unknown reuse", hc("{\"clients\":[[{\"reuse\":\"v\"}]]}"));
    ok_parse("servers reuse of client capture",
             hc("{\"clients\":[[{\"rand\":4,\"capture\":\"v\"}]],\"servers\":[[{\"reuse\":\"v\"}]]}"));
    bad_parse("servers reuse of a later client capture",
              hc("{\"clients\":[[{\"rand\":1}],[{\"rand\":1,\"capture\":\"v\"}]],\"servers\":[[{\"reuse\":\"v\"}]]}"),
              "header-custom: unknown variable: v");
    ok_parse("servers reuse after the clients run out",
             hc("{\"clients\":[[{\"rand\":1,\"capture\":\"v\"}]],\"servers\":[[{\"rand\":1}],[{\"reuse\":\"v\"}]]}"));
    ok_parse("servers reuse of an earlier server capture",
             hc("{\"servers\":[[{\"rand\":2,\"capture\":\"a\"}],[{\"transform\":{\"op\":\"concat\",\"args\":[{\"reuse\":\"a\"}]}}]]}"));
    ok_parse("servers reuse in the same sequence", hc("{\"servers\":[[{\"rand\":2,\"capture\":\"a\"},{\"reuse\":\"a\"}]]}"));
    bad_parse("servers reuse before its capture", hc("{\"servers\":[[{\"reuse\":\"a\"},{\"rand\":2,\"capture\":\"a\"}]]}"),
              "header-custom: unknown variable: a");
    bad_parse("servers slice length not u64",
              hc("{\"servers\":[[{\"transform\":{\"op\":\"slice\",\"args\":[{\"bytes\":[1]},{\"u64\":0},{\"bytes\":[1]}]}}]]}"),
              "header-custom: slice length must be u64");
    bad_parse("servers slice two args",
              hc("{\"servers\":[[{\"transform\":{\"op\":\"slice\",\"args\":[{\"bytes\":[1]},{\"u64\":0}]}}]]}"),
              "header-custom: slice expects 3 args");
    ok_parse("servers pad literal",
             hc("{\"servers\":[[{\"transform\":{\"op\":\"pad\",\"args\":[{\"metadata\":\"x\"},{\"u64\":4},{\"bytes\":[0]}]}}]]}"));
    bad_parse("servers pad length from metadata",
              hc("{\"servers\":[[{\"transform\":{\"op\":\"pad\",\"args\":[{\"bytes\":[1]},{\"metadata\":\"x\"},{\"bytes\":[0]}]}}]]}"),
              "header-custom: pad length must be u64");
    bad_parse("servers truncate length from expr",
              hc("{\"servers\":[[{\"transform\":{\"op\":\"truncate\",\"args\":[{\"bytes\":[1]},"
                 "{\"transform\":{\"op\":\"add\",\"args\":[{\"u64\":1},{\"u64\":0}]}}]}}]]}"),
              "header-custom: truncate length must be u64");
    bad_parse("servers top-level add", hc("{\"servers\":[[{\"transform\":{\"op\":\"add\",\"args\":[{\"u64\":1},{\"u64\":1}]}}]]}"),
              "header-custom: expr size is not bytes for op: add");
    bad_parse("servers concat u64", hc("{\"servers\":[[{\"transform\":{\"op\":\"concat\",\"args\":[{\"u64\":1}]}}]]}"),
              "header-custom: u64 arg has no byte width");
    bad_parse("servers concat of unknown var",
              hc("{\"servers\":[[{\"transform\":{\"op\":\"concat\",\"args\":[{\"bytes\":[1]},{\"reuse\":\"q\"}]}}]]}"),
              "header-custom: unknown variable: q");
    ok_parse("servers be32 of unknown var",
             hc("{\"servers\":[[{\"transform\":{\"op\":\"be32\",\"args\":[{\"reuse\":\"q\"}]}}]]}"));
}

static const char *sd_of(const char *settings) {
    static char out[512];
    size_t k;
    snprintf(jb, sizeof jb, "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":%s}]}", settings);
    if (parse(jb)) {
        snprintf(out, sizeof out, "!%s", why);
        return out;
    }
    if (cfg.n != 1 || cfg.m[0].kind != FM_SUDOKU) return "(not one sudoku)";
    const struct fm_sd *s = &cfg.m[0].u.sd;
    k = (size_t)snprintf(out, sizeof out, "ascii=%u pat=", (unsigned)s->ascii);
    for (size_t i = 0; i < s->n_pat && k < sizeof out; i++)
        k += (size_t)snprintf(out + k, sizeof out - k, "%s\"%s\"", i ? "," : "", s->pat[i]);
    if (k < sizeof out) k += (size_t)snprintf(out + k, sizeof out - k, " pad=%u/%u pw=", s->pmin, s->pmax);
    for (size_t i = 0; i < s->pw_n && k < sizeof out; i++)
        k += (size_t)snprintf(out + k, sizeof out - k, "%s%02x", i ? " " : "", s->pw[i]);
    return out;
}

#define SD_ENT "ascii=0 pat=\"\" pad=0/0 pw="
#define SD_ASC "ascii=1 pat=\"\" pad=0/0 pw="
#define SD_T(t) "ascii=0 pat=\"" t "\" pad=0/0 pw="
#define SD_PAD(a, b) "ascii=0 pat=\"\" pad=" a "/" b " pw="

static void t_sd_defaults(void) {
    /* catches: absent settings refused, or no entropy pattern */
    ok_parse("sd defaults: no settings", "{\"tcp\":[{\"type\":\"sudoku\"}]}");
    check("sd defaults: kind", FM_SUDOKU, cfg.n == 1 ? (long)cfg.m[0].kind : -1);
    check_str("sd defaults: settings null", SD_ENT, sd_of("null"));
    check_str("sd defaults: settings {}", SD_ENT, sd_of("{}"));
    check_str("sd defaults: settings array", "!sudoku: invalid settings", sd_of("[]"));
}

static void t_sd_ascii_mode(void) {
    /* catches: ASCII-only trimming, a case-sensitive mode, or the trimmed value in the text */
    check_str("sd mode: empty", SD_ENT, sd_of("{\"ascii\":\"\"}"));
    check_str("sd mode: entropy", SD_ENT, sd_of("{\"ascii\":\"entropy\"}"));
    check_str("sd mode: prefer_entropy", SD_ENT, sd_of("{\"ascii\":\"prefer_entropy\"}"));
    check_str("sd mode: spaced Prefer_Entropy", SD_ENT, sd_of("{\"ascii\":\" Prefer_Entropy \"}"));
    check_str("sd mode: ascii", SD_ASC, sd_of("{\"ascii\":\"ascii\"}"));
    check_str("sd mode: prefer_ascii", SD_ASC, sd_of("{\"ascii\":\"prefer_ascii\"}"));
    check_str("sd mode: dotted capital I", SD_ASC, sd_of("{\"ascii\":\"ASC\\u0130\\u0130\"}"));
    check_str("sd mode: ideographic space", SD_ASC, sd_of("{\"ascii\":\" ascii\\u3000\"}"));
    check_str("sd mode: next line", SD_ASC, sd_of("{\"ascii\":\"ascii\\u0085\"}"));
    check_str("sd mode: leading space", SD_ASC, sd_of("{\"ascii\":\" ascii\"}"));
    check_str("sd mode: long s", "!sudoku: invalid sudoku ascii mode: a\xc5\xbf" "cii",
              sd_of("{\"ascii\":\"a\\u017fcii\"}"));
    check_str("sd mode: zero width space", "!sudoku: invalid sudoku ascii mode: entropy\xe2\x80\x8b",
              sd_of("{\"ascii\":\"entropy\\u200b\"}"));
    check_str("sd mode: raw value", "!sudoku: invalid sudoku ascii mode:  xx ", sd_of("{\"ascii\":\" xx \"}"));
    check_str("sd mode: xx", "!sudoku: invalid sudoku ascii mode: xx", sd_of("{\"ascii\":\"xx\"}"));
    check_str("sd mode: number", "!sudoku: invalid ascii", sd_of("{\"ascii\":1}"));
}

static void t_sd_custom_table(void) {
    /* catches: length counted in runes, the checks reordered, or inner tabs removed */
    check_str("sd table: spaced", SD_T("xpxvvpvv"), sd_of("{\"customTable\":\"xp xv vp vv\"}"));
    check_str("sd table: upper", SD_T("xpxvvpvv"), sd_of("{\"customTable\":\"XPXVVPVV\"}"));
    check_str("sd table: unicode trim", SD_T("xpxvvpvv"), sd_of("{\"customTable\":\" xpxvvpvv\\u3000\"}"));
    check_str("sd table: e acute", "!sudoku: customTable must be 8 chars, got 9",
              sd_of("{\"customTable\":\"xpxvvpv\\u00e9\"}"));
    check_str("sd table: trailing tab", "!sudoku: customTable must be 8 chars, got 7",
              sd_of("{\"customTable\":\"xpxvvpv\\t\"}"));
    check_str("sd table: zero width space", "!sudoku: customTable must be 8 chars, got 10",
              sd_of("{\"customTable\":\"xpxvvpv\\u200b\"}"));
    check_str("sd table: A", "!sudoku: customTable has invalid char 'a'", sd_of("{\"customTable\":\"xpxvvpvA\"}"));
    check_str("sd table: inner tab", "!sudoku: customTable has invalid char '\\t'",
              sd_of("{\"customTable\":\"xpx\\tvpvv\"}"));
    check_str("sd table: NUL", "!sudoku: customTable has invalid char '\\x00'",
              sd_of("{\"customTable\":\"xpxvvpv\\u0000\"}"));
    check_str("sd table: quote", "!sudoku: customTable has invalid char '\\''", sd_of("{\"customTable\":\"xpxvv'vv\"}"));
    check_str("sd table: dotted capital I", "!sudoku: customTable has invalid char 'i'",
              sd_of("{\"customTable\":\"xpxvvpv\\u0130\"}"));
    check_str("sd table: e acute in 8 bytes", "!sudoku: customTable has invalid char '\xc3\xa9'",
              sd_of("{\"customTable\":\"xpxvvp\\u00e9\"}"));
    check_str("sd table: counts", "!sudoku: customTable must contain exactly 2 x, 2 p and 4 v",
              sd_of("{\"customTable\":\"xxxvvpvv\"}"));
    check_str("sd table: blank", SD_ENT, sd_of("{\"customTable\":\"  \"}"));
    check_str("sd table: number", "!sudoku: invalid customTable", sd_of("{\"customTable\":1}"));
}

static void t_sd_tables_list(void) {
    /* catches: ascii mode validating tables, de-dup before normalizing, or the legacy list ignored */
    check_str("sd tables: listed, de-duplicated", "ascii=0 pat=\"xpxvvpvv\",\"\",\"vxpvxvvp\" pad=0/0 pw=",
              sd_of("{\"customTables\":[\"xpxvvpvv\",\" XPXVVPVV \",\"\",\"vxpvxvvp\"]}"));
    check_str("sd tables: later duplicate", "ascii=0 pat=\"xpxvvpvv\",\"vxpvxvvp\" pad=0/0 pw=",
              sd_of("{\"customTables\":[\"xpxvvpvv\",\"vxpvxvvp\",\"xpxvvpvv\"]}"));
    check_str("sd tables: customTable ignored", SD_T("xpxvvpvv"),
              sd_of("{\"customTable\":\"bad\",\"customTables\":[\"xpxvvpvv\"]}"));
    check_str("sd tables: empty takes legacy", SD_T("vxpvxvvp"),
              sd_of("{\"customTables\":[],\"custom_tables\":[\"vxpvxvvp\"]}"));
    check_str("sd tables: ascii mode skips them", SD_ASC,
              sd_of("{\"ascii\":\"ascii\",\"customTables\":[\"bad\"],\"customTable\":\"bad\"}"));
    check_str("sd tables: bad", "!sudoku: customTable must be 8 chars, got 3", sd_of("{\"customTables\":[\"bad\"]}"));
    check_str("sd tables: a string", "!sudoku: invalid customTables", sd_of("{\"customTables\":\"x\"}"));
    check_str("sd tables: a number inside", "!sudoku: invalid customTables", sd_of("{\"customTables\":[5]}"));
    check_str("sd tables: null entry", "ascii=0 pat=\"\",\"xpxvvpvv\" pad=0/0 pw=",
              sd_of("{\"customTables\":[null,\"xpxvvpvv\"]}"));
    check_str("sd tables: null after a list", SD_ENT, sd_of("{\"customTables\":[\"a\"],\"customTables\":null}"));
    check_str("sd tables: folded key", SD_T("vxpvxvvp"), sd_of("{\"customtables\":[\"vxpvxvvp\"]}"));
}

static void t_sd_legacy(void) {
    /* catches: legacy used after trimming, read when camel is non-zero, or not read when camel is 0 */
    check_str("sd legacy: custom_table alone", SD_T("vxpvxvvp"), sd_of("{\"custom_table\":\"vxpvxvvp\"}"));
    check_str("sd legacy: blank customTable wins", SD_ENT,
              sd_of("{\"customTable\":\"  \",\"custom_table\":\"vxpvxvvp\"}"));
    check_str("sd legacy: string null keeps the earlier", "!sudoku: customTable must be 8 chars, got 1",
              sd_of("{\"customTable\":\"a\",\"customTable\":null}"));
    check_str("sd legacy: padding_min/max", SD_PAD("40", "50"), sd_of("{\"padding_min\":40,\"padding_max\":50}"));
    check_str("sd legacy: paddingMin wins", SD_PAD("10", "10"), sd_of("{\"paddingMin\":10,\"padding_min\":40}"));
    check_str("sd legacy: paddingMin 0", SD_PAD("40", "40"), sd_of("{\"paddingMin\":0,\"padding_min\":40}"));
    check_str("sd legacy: bad padding_min", "!sudoku: invalid padding_min", sd_of("{\"padding_min\":-1}"));
}

static void t_sd_padding(void) {
    static const char *const bad[] = {"-1", "1.0", "1e2", "4294967296", "\"5\"", "-0", "true"};
    char what[64], js[64];
    /* catches: pmax not raised to pmin, no clamp, or a double parse */
    check_str("sd pad: 150/20", SD_PAD("100", "100"), sd_of("{\"paddingMin\":150,\"paddingMax\":20}"));
    check_str("sd pad: 30/10", SD_PAD("30", "30"), sd_of("{\"paddingMin\":30,\"paddingMax\":10}"));
    check_str("sd pad: max only", SD_PAD("0", "7"), sd_of("{\"paddingMax\":7}"));
    check_str("sd pad: uint32 max", SD_PAD("100", "100"), sd_of("{\"paddingMin\":4294967295}"));
    check_str("sd pad: null keeps the earlier", SD_PAD("5", "5"), sd_of("{\"paddingMin\":5,\"paddingMin\":null}"));
    check_str("sd pad: folded key", SD_PAD("3", "3"), sd_of("{\"PaddingMIN\":3}"));
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        snprintf(what, sizeof what, "sd pad: %s refused", bad[i]);
        snprintf(js, sizeof js, "{\"paddingMin\":%s}", bad[i]);
        check_str(what, "!sudoku: invalid paddingMin", sd_of(js));
    }
    check_str("sd pad: bad max", "!sudoku: invalid paddingMax", sd_of("{\"paddingMax\":101.5}"));
}

static void t_sd_password(void) {
    /* catches: NUL mapped to 0x01, or case-sensitive keys */
    check_str("sd pw: NUL kept", "ascii=0 pat=\"\" pad=0/0 pw=61 00 62", sd_of("{\"password\":\"a\\u0000b\"}"));
    check_str("sd pw: last key wins", "ascii=0 pat=\"\" pad=0/0 pw=79", sd_of("{\"PASSWORD\":\"z\",\"password\":\"y\"}"));
    check_str("sd pw: last key wins, upper", "ascii=0 pat=\"\" pad=0/0 pw=7a",
              sd_of("{\"password\":\"y\",\"PASSWORD\":\"z\"}"));
    check_str("sd pw: null keeps the earlier", "ascii=0 pat=\"\" pad=0/0 pw=61",
              sd_of("{\"password\":\"a\",\"password\":null}"));
    check_str("sd pw: number", "!sudoku: invalid password", sd_of("{\"password\":5}"));
}

static void t_sd_one_per_chain(void) {
    /* catches: stacked sudoku accepted (Vision's room closes for good), or the check counted across main and block */
    bad_parse("sd chain: two apart",
              "{\"tcp\":[{\"type\":\"sudoku\"},{\"type\":\"fragment\",\"settings\":{\"length\":1}},{\"type\":\"sudoku\"}]}",
              "sudoku: more than one sudoku mask is not supported");
    bad_parse("sd chain: two adjacent", "{\"tcp\":[{\"type\":\"sudoku\"},{\"type\":\"Sudoku\"}]}",
              "sudoku: more than one sudoku mask is not supported");
    ok_parse("sd chain: one with a fragment",
             "{\"tcp\":[{\"type\":\"sudoku\"},{\"type\":\"fragment\",\"settings\":{\"length\":1}}]}");
    check("sd chain: one with a fragment, n", 2, (long)cfg.n);
    ok_parse("sd chain: no count kept across parses", "{\"tcp\":[{\"type\":\"sudoku\"}]}");
}

static void t_types(void) {
    /* catches: a case-sensitive type lookup refusing what Xray accepts, a refused type silently skipped, or udp masks validated */
    ok_parse("type sudoku", "{\"tcp\":[{\"type\":\"sudoku\",\"settings\":{}}]}");
    ok_parse("type SUDOKU", "{\"tcp\":[{\"type\":\"SUDOKU\"}]}");
    check("type SUDOKU: kind", FM_SUDOKU, cfg.n == 1 ? (long)cfg.m[0].kind : -1);
    bad_parse("type xmc", "{\"tcp\":[{\"type\":\"xmc\",\"settings\":{\"password\":\"p\"}}]}", "xmc is not supported yet");
    bad_parse("type Xmc", "{\"tcp\":[{\"type\":\"Xmc\"}]}", "xmc is not supported yet");
    ok_parse("type Fragment", "{\"tcp\":[{\"type\":\"Fragment\",\"settings\":{\"length\":1}}]}");
    check("type Fragment: kind", FM_FRAGMENT, cfg.n == 1 ? (long)cfg.m[0].kind : -1);
    ok_parse("type Header-Custom", "{\"tcp\":[{\"type\":\"Header-Custom\"}]}");
    check("type Header-Custom: kind", FM_HEADER, cfg.n == 1 ? (long)cfg.m[0].kind : -1);
    ok_parse("keys TCP/Type/Settings", "{\"TCP\":[{\"Type\":\"fragment\",\"Settings\":{\"length\":1}}]}");
    check("keys TCP/Type/Settings: n", 1, (long)cfg.n);
    bad_parse("type frag", "{\"tcp\":[{\"type\":\"frag\"}]}", "unknown tcp mask type frag");
    bad_parse("type absent", "{\"tcp\":[{\"settings\":{}}]}", "unknown tcp mask type ");
    bad_parse("mask null", "{\"tcp\":[null]}", "unknown tcp mask type ");
    bad_parse("type number", "{\"tcp\":[{\"type\":5}]}", "invalid type");
    bad_parse("mask not an object", "{\"tcp\":[5]}", "invalid tcp");
    bad_parse("tcp object", "{\"tcp\":{}}", "invalid tcp");
    bad_parse("root array", "[]", "invalid finalmask");
    ok_parse("settings null", "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":null}]}");
    ok_parse("filter", "{\"tcp\":[{\"type\":\"filter\"}]}");
    check("filter: n", 1, (long)cfg.n);
    check("filter: kind", FM_FILTER, cfg.n == 1 ? (long)cfg.m[0].kind : -1);
    ok_parse("tcp empty", "{\"tcp\":[]}");
    check("tcp empty: n", 0, (long)cfg.n);
    ok_parse("tcp null", "{\"tcp\":null}");
    check("tcp null: n", 0, (long)cfg.n);
    ok_parse("root null", "null");
    check("root null: n", 0, (long)cfg.n);
    ok_parse("udp not read", "{\"udp\":[{\"type\":\"bogus\"}]}");
    check("udp not read: n", 0, (long)cfg.n);
    ok_parse("quicParams not read", "{\"quicParams\":{\"x\":1},\"tcp\":[]}");
    bad_parse("first error wins", "{\"tcp\":[{\"type\":\"fragment\",\"settings\":{}},{\"type\":\"sudoku\"}]}",
              "fragment: last lengths entry min can't be 0");
    bad_parse("refused type before a later bad one", "{\"tcp\":[{\"type\":\"xmc\"},{\"type\":\"frag\"}]}",
              "xmc is not supported yet");
    bad_parse("refused type after a good one", "{\"tcp\":[{\"type\":\"filter\"},{\"type\":\"xmc\"}]}",
              "xmc is not supported yet");
    check("validate only: ok", 0, fm_parse("{\"tcp\":[{\"type\":\"filter\"}]}", 27, NULL, why, sizeof why));
    check("validate only: refused", -1, fm_parse("{\"tcp\":[{\"type\":\"xmc\"}]}", 24, NULL, why, sizeof why));
    check_str("validate only: why", "xmc is not supported yet", why);
}

static void t_filter(void) {
    static const char *const any[] = {
        "{\"allowedSourceIPs\":[\"zz\",\"10.0.0.300\",\"ext-ip:x\"],\"blockedSourceIPs\":[1,{}]}",
        "{\"allowedSourceIPs\":\"x\"}", "5", "\"x\"", "[1]", "null", "{}",
    };
    char what[64];
    /* catches: filter settings still validated, or a filter mask given settings of its own */
    for (size_t i = 0; i < sizeof any / sizeof *any; i++) {
        snprintf(what, sizeof what, "filter any settings %zu", i);
        ok_parse(what, filt(any[i]));
        snprintf(what, sizeof what, "filter any settings %zu: one bare mask", i);
        check(what, 1, cfg.n == 1 && cfg.m[0].kind == FM_FILTER);
    }
    ok_parse("filter type folded", "{\"tcp\":[{\"type\":\"FiLtEr\",\"settings\":[\"zz\"]}]}");
    check("filter type folded: kind", FM_FILTER, cfg.n == 1 ? (long)cfg.m[0].kind : -1);
}

static void t_order_kept(void) {
    /* catches: the list reversed at parse */
    ok_parse("order", "{\"tcp\":[{\"type\":\"header-custom\",\"settings\":{}},{\"type\":\"fragment\",\"settings\":{\"length\":1}}]}");
    check("order: n", 2, (long)cfg.n);
    check("order: first", FM_HEADER, cfg.n == 2 ? (long)cfg.m[0].kind : -1);
    check("order: second", FM_FRAGMENT, cfg.n == 2 ? (long)cfg.m[1].kind : -1);
}

int main(void) {
    t_compact();
    t_int32range();
    t_fragment_schema();
    t_bytes();
    t_item_kinds();
    t_transform();
    t_servers_measurable();
    t_sd_defaults();
    t_sd_ascii_mode();
    t_sd_custom_table();
    t_sd_tables_list();
    t_sd_legacy();
    t_sd_padding();
    t_sd_password();
    t_sd_one_per_chain();
    t_types();
    t_filter();
    t_order_kept();
    fm_cfg_free(&cfg);
    return unit_done("fmaskmatch");
}
