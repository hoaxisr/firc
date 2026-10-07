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
     * vless_parse_url return -1: an IPv6 literal host (the first colon is inside the
     * brackets, so the port reads as 0) and port 0. Both must still count as skipped. */
    {
        struct vless_node nodes[16];
        struct vless_sub_stats st;
        const char *sub =
            "vless://a@1.2.3.4:443?security=reality&pbk=K&sni=x.com#ok\n"
            "vless://b@[2001:db8::1]:443?security=reality&pbk=K&sni=x.com#ipv6\n"
            "vless://c@5.6.7.8:0?security=reality&pbk=K&sni=x.com#zero-port\n"
            "vless://d@9.9.9.9:443?security=tls#tls\n"
            "hy2://e@10.0.0.1:443#foreign\n";
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
                                           "hy2://u@h:443?x=");
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
            "vless://e@[2001:db8::1]:443?security=none#IPv6\n"
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
        /* The IPv6 literal does not parse and never reaches the usability check, so the
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
        check_n("extra: uplinkDataPlacement=header, skipped", 1, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22sessionPlacement%%22%%3A%%22query%%22%%7D#x", base);
        check_n("extra: sessionPlacement=query, skipped", 1, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22xPaddingMethod%%22%%3A%%22tokenish%%22%%7D#x", base);
        check_n("extra: xPaddingMethod=tokenish, skipped", 1, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22xPaddingObfsMode%%22%%3Atrue%%7D#x", base);
        check_n("extra: xPaddingObfsMode, skipped", 1, vless_parse_url(url, &n));
        snprintf(url, sizeof(url), "%s&extra=%%7B%%22downloadSettings%%22%%3A%%7B%%22address%%22%%3A%%22d.example%%22%%7D%%7D#x", base);
        check_n("extra: downloadSettings, skipped", 1, vless_parse_url(url, &n));
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

        /* A cut inside an escape: a prefix of five or six letters leaves "%D" or "%" at the
         * end, which is dropped rather than shown as text; the 20 whole letters stay. */
        for (int pre = 5; pre <= 6; pre++) {
            char cut[512], want[64];
            snprintf(cut, sizeof(cut), "%.*s", pre, "nodexy");
            snprintf(want, sizeof(want), "%.*s", pre, "nodexy");
            for (int i = 0; i < 70; i++) strcat(cut, "%D0%9F");
            for (int i = 0; i < 20; i++) strcat(want, "\xD0\x9F");
            snprintf(url, sizeof(url),
                     "vless://11111111-2222-3333-4444-555555555555@example.com:8443"
                     "?security=reality&sni=a.example&pbk=k&fp=chrome#%s", cut);
            vless_parse_url(url, &n);
            check(pre == 5 ? "long name cut after \"%D\": the fragment dropped"
                           : "long name cut after \"%\": the fragment dropped", want, n.name);
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

    printf("\n%d checks passed", g_pass);
    if (g_fail) {
        printf(", %d FAILED\n", g_fail);
        return 1;
    }
    printf("\n");
    return 0;
}
