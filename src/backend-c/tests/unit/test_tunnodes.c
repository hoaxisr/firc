#include "greatest.h"
#include "firc/tunnels.h"
#include "firc/tunnodes.h"
#include "vless.h"
#include "vlink.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define U "11111111-2222-3333-4444-555555555555"
#define SUB_A "      - id: aaaaaaaa\n        subscription: { name: P, url: \"https://a.example\" }\n"
#define SUB_B "      - id: bbbbbbbb\n        subscription: { name: Q, url: \"https://b.example\" }\n"

static const char B64_ABC[] =
    "dmxlc3M6Ly8xMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTVAYS5leGFtcGxlOjQ0Mz9zZWN1cml0eT1ub25lI0EK"
    "dmxlc3M6Ly8xMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTVAYi5leGFtcGxlOjQ0Mz9zZWN1cml0eT1ub25lI0IK"
    "dmxlc3M6Ly8xMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTVAYy5leGFtcGxlOjQ0Mz9zZWN1cml0eT1ub25lI0MK";

static const char CLASH_TWO[] =
    "proxies:\n"
    "  - name: NL-1\n    type: vless\n    server: nl1.example\n    port: 443\n    uuid: " U "\n"
    "  - {name: DE-1, type: vless, server: de1.example, port: 8443, uuid: " U "}\n";

static firc_tunnels_t g_cfg;
static firc_tun_nodes_t g_nodes;

static void cleanup(void *ud)
{
    (void)ud;
    firc_tunnels_free(&g_cfg);
    firc_tun_nodes_free(&g_nodes);
    memset(&g_nodes, 0, sizeof g_nodes);
}

static const firc_tunnel_t *tunnel(const char *sources, const char *extra)
{
    char doc[8192];
    snprintf(doc, sizeof doc, "tunnels:\n  - id: t1\n    device: tunvless0\n    sources:\n%s%s", sources, extra);
    firc_tun_err_t e = {0};
    firc_tunnels_free(&g_cfg);
    if (firc_tunnels_load_buffer(&g_cfg, doc, strlen(doc), &e) != FIRC_OK) {
        fprintf(stderr, "config: %s: %s\n", e.where, e.why);
        return NULL;
    }
    return &g_cfg.t[0];
}

static firc_err_t build(const firc_tunnel_t *t, uint32_t mark, const firc_tun_body_t *b, size_t nb)
{
    firc_tun_nodes_free(&g_nodes);
    memset(&g_nodes, 0, sizeof g_nodes);
    return firc_tun_nodes_build(t, mark, b, nb, &g_nodes);
}

static int keys_are(const char *const *want, size_t n)
{
    int ok = g_nodes.n == n;
    for (size_t i = 0; ok && i < n; i++) {
        ok = strcmp(g_nodes.v[i].key, want[i]) == 0;
    }
    if (!ok) {
        fprintf(stderr, "rows:");
        for (size_t i = 0; i < g_nodes.n; i++) {
            fprintf(stderr, " [%s]", g_nodes.v[i].key);
        }
        fprintf(stderr, "\n");
    }
    return ok;
}

static size_t sendable(void)
{
    size_t k = 0;
    for (size_t i = 0; i < g_nodes.n; i++) {
        if (g_nodes.v[i].link != NULL) {
            k++;
        }
    }
    return k;
}

static char *names_body(const char *const *names, size_t n)
{
    size_t cap = n * 300 + 1;
    char *b = malloc(cap);
    size_t off = 0;
    b[0] = 0;
    for (size_t i = 0; i < n; i++) {
        off += (size_t)snprintf(b + off, cap - off, "vless://" U "@h%zu.example:443?security=none#%s\n", i, names[i]);
    }
    return b;
}

TEST a_base64_list_gives_its_nodes_in_order(void)
{
    /* catches: a base64 body not decoded, nodes reordered, or a row without its link, source or new mark */
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:A", "aaaaaaaa:B", "aaaaaaaa:C"};
    ASSERT(keys_are(want, 3));
    ASSERT_EQ(3u, g_nodes.total);
    ASSERT_EQ(3u, g_nodes.matched);
    for (size_t i = 0; i < 3; i++) {
        const firc_tun_node_t *r = &g_nodes.v[i];
        ASSERT_STR_EQ("P", r->source);
        ASSERT(r->is_new && !r->excluded && r->skip_reason[0] == 0);
        ASSERT(r->link != NULL && strncmp(r->link, "vless://" U "@", 45) == 0);
        ASSERT_EQ(strlen(r->link), r->link_len);
    }
    ASSERT_STR_EQ("B", g_nodes.v[1].name);
    ASSERT(strstr(g_nodes.v[1].link, "@b.example:443?") != NULL);
    PASS();
}

TEST a_clash_body_gives_its_two_nodes(void)
{
    /* catches: a Clash YAML subscription not parsed into rows */
    const firc_tunnel_t *t = tunnel(SUB_B, "");
    firc_tun_body_t b = {"https://b.example", 0, CLASH_TWO, sizeof CLASH_TWO - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"bbbbbbbb:NL-1", "bbbbbbbb:DE-1"};
    ASSERT(keys_are(want, 2));
    ASSERT(strstr(g_nodes.v[1].link, "@de1.example:8443?") != NULL);
    PASS();
}

TEST order_pins_its_keys_first(void)
{
    /* catches: order ignored, or ordered rows still flagged new */
    const firc_tunnel_t *t = tunnel(SUB_A, "    order: [\"aaaaaaaa:B\"]\n");
    firc_tun_body_t b = {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:B", "aaaaaaaa:A", "aaaaaaaa:C"};
    ASSERT(keys_are(want, 3));
    ASSERT(!g_nodes.v[0].is_new);
    ASSERT(g_nodes.v[1].is_new && g_nodes.v[2].is_new);
    PASS();
}

TEST an_excluded_node_is_listed_but_not_sent(void)
{
    /* catches: an excluded node sent to tunvless, or dropped from the table */
    const firc_tunnel_t *t = tunnel(SUB_A, "    exclude: [\"aaaaaaaa:C\"]\n");
    firc_tun_body_t b = {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:A", "aaaaaaaa:B", "aaaaaaaa:C"};
    ASSERT(keys_are(want, 3));
    ASSERT(g_nodes.v[2].excluded);
    ASSERT(g_nodes.v[2].link == NULL);
    ASSERT(!g_nodes.v[0].excluded && g_nodes.v[0].link != NULL);
    ASSERT_EQ(2u, sendable());
    PASS();
}

TEST the_filter_keeps_matching_subscription_nodes_ignoring_case(void)
{
    /* catches: the filter ignored, matched case-sensitively, or the counts not 2 of 5 */
    const char *names[] = {"NL Amsterdam", "DE Berlin", "the Netherlands", "US", "FR"};
    char *body = names_body(names, 5);
    const firc_tunnel_t *t = tunnel(SUB_A, "    filter: \"nl|neth\"\n");
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    const char *want[] = {"aaaaaaaa:NL Amsterdam", "aaaaaaaa:the Netherlands"};
    ASSERT(keys_are(want, 2));
    ASSERT_EQ(2u, g_nodes.matched);
    ASSERT_EQ(5u, g_nodes.total);
    PASS();
}

TEST duplicate_names_in_one_source_get_a_number(void)
{
    /* catches: two nodes of one name sharing a key, so order and exclude hit both */
    const char *names[] = {"X", "Y", "X", "X"};
    char *body = names_body(names, 4);
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    const char *want[] = {"aaaaaaaa:X", "aaaaaaaa:Y", "aaaaaaaa:X#2", "aaaaaaaa:X#3"};
    ASSERT(keys_are(want, 4));
    PASS();
}

TEST a_name_with_key_characters_is_encoded(void)
{
    /* catches: a colon, percent or hash in a name making two different names one key */
    const char *names[] = {"a%3Ab%25c%23d", "a%3Ab%25c%23d"};
    char *body = names_body(names, 2);
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    const char *want[] = {"aaaaaaaa:a%3Ab%25c%23d", "aaaaaaaa:a%3Ab%25c%23d#2"};
    ASSERT(keys_are(want, 2));
    ASSERT_STR_EQ("a:b%c#d", g_nodes.v[0].name);
    PASS();
}

TEST a_name_with_control_bytes_gets_a_key_the_config_takes(void)
{
    const char *names[] = {"x", "a%0Ab%09c%7Fd%1F"};
    char *body = names_body(names, 2);
    const firc_tunnel_t *t = tunnel(SUB_A, "    order: [\"aaaaaaaa:a%0Ab%09c%7Fd%1F\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    const char *want[] = {"aaaaaaaa:a%0Ab%09c%7Fd%1F", "aaaaaaaa:x"};
    ASSERT(keys_are(want, 2));
    ASSERT_STR_EQ("a\nb\tc\x7f" "d\x1f", g_nodes.v[0].name);
    PASS();
}

TEST an_ordered_key_its_subscription_no_longer_gives_is_not_listed(void)
{
    /* catches: an ordered key of a renamed node kept as a row on top while its new name lands at the end */
    const char *names[] = {"A", "B", "\xd0\x9b\xd0\xb0\xd1\x82\xd0\xb2\xd0\xb8\xd1\x8f [FAST]"};
    char *body = names_body(names, 3);
    const firc_tunnel_t *t = tunnel(SUB_A, "    order: [\"aaaaaaaa:\xe2\x9a\xa1 \xd0\x9b\xd0\xb0\xd1\x82\xd0\xb2\xd0\xb8\xd1\x8f [FAST]\", \"aaaaaaaa:B\"]\n"
                                           "    exclude: [\"aaaaaaaa:\xe2\x9a\xa1 \xd0\x9b\xd0\xb0\xd1\x82\xd0\xb2\xd0\xb8\xd1\x8f [FAST]\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    const char *want[] = {"aaaaaaaa:B", "aaaaaaaa:A", "aaaaaaaa:\xd0\x9b\xd0\xb0\xd1\x82\xd0\xb2\xd0\xb8\xd1\x8f [FAST]"};
    ASSERT(keys_are(want, 3));
    ASSERT(g_nodes.v[2].is_new && !g_nodes.v[2].excluded);
    ASSERT_EQ(3u, sendable());
    PASS();
}

TEST a_node_back_under_its_saved_key_takes_its_place_and_exclusion(void)
{
    /* catches: an unlisted key dropped from order or exclude, so the node coming back lands at the end and is sent */
    const firc_tunnel_t *t = tunnel(SUB_A, "    order: [\"aaaaaaaa:Z\", \"aaaaaaaa:C\"]\n    exclude: [\"aaaaaaaa:Z\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *gone[] = {"aaaaaaaa:C", "aaaaaaaa:A", "aaaaaaaa:B"};
    ASSERT(keys_are(gone, 3));
    const char *names[] = {"A", "B", "C", "Z"};
    char *body = names_body(names, 4);
    firc_tun_body_t back = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &back, 1));
    free(body);
    const char *want[] = {"aaaaaaaa:Z", "aaaaaaaa:C", "aaaaaaaa:A", "aaaaaaaa:B"};
    ASSERT(keys_are(want, 4));
    ASSERT(!g_nodes.v[0].is_new && g_nodes.v[0].excluded && g_nodes.v[0].link == NULL);
    ASSERT_EQ(3u, sendable());
    PASS();
}

TEST a_link_key_its_link_no_longer_names_gives_no_row(void)
{
    /* catches: a key of an edited link kept as a missing row for good */
    const firc_tunnel_t *t = tunnel("      - id: cccccccc\n        link: \"vless://" U "@g.example:443?security=none#Germany\"\n",
                                    "    order: [\"cccccccc:Estonia\", \"cccccccc:Germany\"]\n"
                                    "    exclude: [\"cccccccc:Estonia\"]\n");
    ASSERT(t != NULL);
    ASSERT_EQ(FIRC_OK, build(t, 0, NULL, 0));
    const char *want[] = {"cccccccc:Germany"};
    ASSERT(keys_are(want, 1));
    ASSERT_EQ(1u, sendable());
    PASS();
}

TEST a_bracketed_ipv6_link_source_is_one_node(void)
{
    /* catches: a link source with a bracketed IPv6 host dropped, mis-keyed, or sent with another host */
    const firc_tunnel_t *t = tunnel("      - id: cccccccc\n        link: \"vless://" U "@[2001:db8::7]:8443?security=reality&pbk=K&sni=x.com#n\"\n", "");
    ASSERT(t != NULL);
    ASSERT_EQ(FIRC_OK, build(t, 0, NULL, 0));
    const char *want[] = {"cccccccc:n"};
    ASSERT(keys_are(want, 1));
    ASSERT_EQ(1u, g_nodes.total);
    ASSERT(g_nodes.v[0].link != NULL);
    struct vless_node m;
    ASSERT_EQ(0, vless_parse_url(g_nodes.v[0].link, &m));
    ASSERT_STR_EQ("2001:db8::7", m.host);
    ASSERT_EQ(8443, m.port);
    PASS();
}

TEST a_link_source_counts_whatever_the_filter(void)
{
    /* catches: the filter applied to a manual link, or link sources not listed first */
    const firc_tunnel_t *t = tunnel(SUB_B "      - id: cccccccc\n        link: \"vless://" U "@m.example:443?security=none#zz-mine\"\n",
                                    "    filter: \"^nl\"\n");
    firc_tun_body_t b = {"https://b.example", 0, CLASH_TWO, sizeof CLASH_TWO - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"cccccccc:zz-mine", "bbbbbbbb:NL-1"};
    ASSERT(keys_are(want, 2));
    ASSERT_STR_EQ("link", g_nodes.v[0].source);
    ASSERT(g_nodes.v[0].link != NULL);
    ASSERT_EQ(2u, g_nodes.matched);
    ASSERT_EQ(3u, g_nodes.total);
    PASS();
}

TEST at_most_256_nodes_are_sent(void)
{
    /* catches: more than 256 nodes sent, the first 256 not the ones kept, rows past the cap dropped, or total cut */
    size_t cap = 300 * 120 + 1, off = 0;
    char *body = malloc(cap);
    for (int i = 0; i < 300; i++) {
        off += (size_t)snprintf(body + off, cap - off, "vless://" U "@h.example:443?security=none#n%d\n", i);
    }
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, off, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    ASSERT_EQ(256u, sendable());
    ASSERT_EQ(300u, g_nodes.total);
    ASSERT_STR_EQ("aaaaaaaa:n0", g_nodes.v[0].key);
    ASSERT_STR_EQ("aaaaaaaa:n255", g_nodes.v[255].key);
    ASSERT_EQ(300u, g_nodes.n);
    ASSERT(!g_nodes.v[255].over_cap && g_nodes.v[255].link != NULL);
    ASSERT_STR_EQ("aaaaaaaa:n256", g_nodes.v[256].key);
    ASSERT(g_nodes.v[256].over_cap && g_nodes.v[256].link == NULL);
    ASSERT(g_nodes.v[299].over_cap);
    PASS();
}

TEST the_body_of_another_mark_is_not_used(void)
{
    /* catches: a body fetched through another uplink used for this tunnel */
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0x00050000u, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    ASSERT_EQ(0u, g_nodes.n);
    ASSERT_EQ(FIRC_OK, build(t, 0x00050000u, &b, 1));
    ASSERT_EQ(3u, g_nodes.n);
    firc_tun_body_t other = {"https://other.example", 0, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &other, 1));
    ASSERT_EQ(0u, g_nodes.n);
    PASS();
}

#define SUB_H "      - id: aaaaaaaa\n        subscription: { name: P, url: \"https://a.example\", headers: { X-HWID: \"\" } }\n"

/* Catches: a body fetched with other headers used for this subscription, or its own one missed. */
TEST the_body_of_other_headers_is_not_used(void)
{
    const firc_tunnel_t *t = tunnel(SUB_H, "");
    ASSERT(t != NULL);
    uint64_t sig = firc_tun_sub_headers_sig(&t->src[0].sub);
    firc_tun_body_t plain = {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &plain, 1));
    ASSERT_EQ(0u, g_nodes.n);
    firc_tun_body_t own = {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, sig};
    ASSERT_EQ(FIRC_OK, build(t, 0, &own, 1));
    ASSERT_EQ(3u, g_nodes.n);
    PASS();
}

#define SINKS                                                                                       \
    "vless://" U "@0.0.0.0:1?security=none#Please%20turn%20on%20HWID%01\n"                          \
    "vless://" U "@real.example:1?security=none#Second\n"

/* Catches: a sink node not counted, a real node counted as one, or the first name kept with its control byte. */
TEST nodes_at_a_sink_are_counted_with_the_first_name(void)
{
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, SINKS, sizeof SINKS - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    ASSERT_EQ(2u, g_nodes.seen);
    ASSERT_EQ(2u, g_nodes.sinks);
    ASSERT_STR_EQ("Please turn on HWID", g_nodes.sink_name);
    static const char mixed[] = SINKS "vless://" U "@a.example:443?security=none#Real\n";
    firc_tun_body_t m = {"https://a.example", 0, mixed, sizeof mixed - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &m, 1));
    ASSERT_EQ(3u, g_nodes.seen);
    ASSERT_EQ(2u, g_nodes.sinks);
    static const char six[] = "proxies:\n  - {name: Six, type: vless, server: \"::\", port: 443, uuid: " U "}\n";
    firc_tun_body_t s6 = {"https://a.example", 0, six, sizeof six - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &s6, 1));
    ASSERT_EQ(1u, g_nodes.seen);
    ASSERT_EQ(1u, g_nodes.sinks);
    ASSERT_STR_EQ("Six", g_nodes.sink_name);
    PASS();
}

#define DL_EXTRA(addr)                                                                              \
    "type=xhttp&security=none&path=%2Fx&extra=%7B%22downloadSettings%22%3A%7B%22address%22%3A%22" addr \
    "%22%2C%22port%22%3A443%2C%22network%22%3A%22xhttp%22%7D%7D"

/* catches: the sink count blind to the block, or the block lost in the row */
TEST a_download_block_at_a_sink_counts_as_one(void)
{
    static const char body[] = "vless://" U "@stub.example:443?" DL_EXTRA("0.0.0.0") "#Stub\n"
                               "vless://" U "@real.example:443?security=none#Real\n";
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, sizeof body - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    ASSERT_EQ(2u, g_nodes.seen);
    ASSERT_EQ(1u, g_nodes.sinks);
    ASSERT_STR_EQ("Stub", g_nodes.sink_name);
    const char *want[] = {"aaaaaaaa:Real", "aaaaaaaa:Stub"};
    ASSERT(keys_are(want, 2));
    ASSERT(g_nodes.v[1].link == NULL);
    ASSERT_STR_EQ("downloadSettings: 0.0.0.0: nobody to answer", g_nodes.v[1].skip_reason);
    PASS();
}

/* catches: a block without a port told as a subscription stub */
TEST a_download_block_without_a_port_is_no_stub(void)
{
    static const char body[] = "vless://" U "@m.example:443?type=xhttp&security=none&path=%2Fx&extra="
                               "%7B%22downloadSettings%22%3A%7B%22address%22%3A%22d.example%22%2C%22network%22%3A%22xhttp%22%7D%7D#NoPort\n";
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, sizeof body - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    ASSERT_EQ(1u, g_nodes.seen);
    ASSERT_EQ(0u, g_nodes.sinks);
    ASSERT_STR_EQ("downloadSettings: no port", g_nodes.v[0].skip_reason);
    PASS();
}

/* catches: the sink count blind to the block, or the block lost in the row */
TEST a_node_with_a_download_block_is_sent_with_it(void)
{
    static const char body[] = "vless://" U "@m.example:443?" DL_EXTRA("d.example") "#Dl\n";
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, sizeof body - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    ASSERT_EQ(1u, g_nodes.n);
    ASSERT(g_nodes.v[0].link != NULL);
    ASSERT_EQ(0u, g_nodes.sinks);
    struct vless_node n;
    memset(&n, 0, sizeof n);
    ASSERT_EQ(0, vless_parse_url(g_nodes.v[0].link, &n));
    ASSERT(vless_dl(&n) != NULL);
    ASSERT_STR_EQ("d.example", vless_dl(&n)->host);
    PASS();
}

TEST a_node_the_parser_skips_is_listed_with_its_reason(void)
{
    /* catches: a skipped node missing from the table, sent, or listed without a reason */
    static const char body[] = "vless://" U "@a.example:443?security=none#ok\n"
                               "vless://" U "@b.example:443?type=kcp#bad\n";
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, sizeof body - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:ok", "aaaaaaaa:bad"};
    ASSERT(keys_are(want, 2));
    ASSERT(g_nodes.v[1].link == NULL);
    ASSERT(g_nodes.v[1].skip_reason[0] != 0);
    ASSERT_EQ(1u, g_nodes.total);
    PASS();
}

/* catches: the xmux conflict not reaching the node row, or the node sent */
TEST an_xmux_conflict_is_a_named_skip(void)
{
    static const char body[] = "vless://" U "@a.example:443?security=none#ok\n"
                               "vless://" U "@b.example:443?type=xhttp&security=none&path=%2Fx&extra="
                               "%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A4%2C%22maxConnections%22%3A2%7D%7D#both\n";
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, sizeof body - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:ok", "aaaaaaaa:both"};
    ASSERT(keys_are(want, 2));
    ASSERT(g_nodes.v[1].link == NULL);
    ASSERT_STR_EQ("xhttp: maxConnections cannot be specified together with maxConcurrency", g_nodes.v[1].skip_reason);
    PASS();
}

TEST an_ipv6_server_is_sent_as_a_bracketed_link(void)
{
    /* catches: a node with an IPv6 server dropped, or its host written without brackets */
    static const char body[] = "proxies:\n"
                               "  - {name: six, type: vless, server: \"2001:db8::1\", port: 443, uuid: " U "}\n"
                               "  - {name: four, type: vless, server: 192.0.2.1, port: 443, uuid: " U "}\n";
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, sizeof body - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:six", "aaaaaaaa:four"};
    ASSERT(keys_are(want, 2));
    ASSERT(g_nodes.v[0].skip_reason[0] == 0 && g_nodes.v[1].skip_reason[0] == 0);
    ASSERT(g_nodes.v[0].link != NULL && strncmp(g_nodes.v[0].link, "vless://" U "@[2001:db8::1]:443?", 8 + 36 + 19) == 0);
    ASSERT(g_nodes.v[1].link != NULL);
    ASSERT_EQ(2u, g_nodes.total);
    PASS();
}

TEST a_long_name_is_cut_to_100_bytes(void)
{
    /* catches: a row name longer than the name tunvless reports in its events */
    char name[130];
    memset(name, 'q', 120);
    name[120] = 0;
    const char *names[] = {name};
    char *body = names_body(names, 1);
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    ASSERT_EQ(1u, g_nodes.n);
    ASSERT_EQ(100u, strlen(g_nodes.v[0].name));
    ASSERT(strstr(g_nodes.v[0].link, "#qqqq") != NULL);
    ASSERT_EQ(100u, strlen(strchr(g_nodes.v[0].link, '#') + 1));
    PASS();
}

TEST insecure_is_set_per_tunnel_for_each_build(void)
{
    /* catches: one tunnel's insecure flag leaking into the next build */
    static const char body[] = "vless://" U "@a.example:443?security=tls&sni=a.example&allowInsecure=1#tls\n";
    firc_tun_body_t b = {"https://a.example", 0, body, sizeof body - 1, 0};
    const firc_tunnel_t *t = tunnel(SUB_A, "    advanced: { insecure: true }\n");
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    ASSERT_EQ(1u, sendable());
    t = tunnel(SUB_A, "");
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    ASSERT_EQ(0u, sendable());
    ASSERT_EQ(1u, g_nodes.n);
    ASSERT(g_nodes.v[0].skip_reason[0] != 0);
    PASS();
}

TEST a_link_source_that_does_not_parse_is_listed_with_a_reason(void)
{
    /* catches: a broken manual link dropped silently or sent */
    const firc_tunnel_t *t = tunnel("      - id: cccccccc\n        link: \"vless://" U "@m.example:443?type=kcp#mine\"\n", "");
    ASSERT_EQ(FIRC_OK, build(t, 0, NULL, 0));
    const char *want[] = {"cccccccc:mine"};
    ASSERT(keys_are(want, 1));
    ASSERT(g_nodes.v[0].link == NULL);
    ASSERT(g_nodes.v[0].skip_reason[0] != 0);
    ASSERT_EQ(0u, g_nodes.total);
    PASS();
}

TEST a_twin_name_keeps_its_number_when_one_is_skipped(void)
{
    /* catches: duplicate numbers given after skipped rows move, so a node turning usable swaps keys with its twin */
    static const char body[] = "vless://" U "@a.example:443?type=kcp#X\n"
                               "vless://" U "@b.example:443?security=none#X\n";
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, sizeof body - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:X#2", "aaaaaaaa:X"};
    ASSERT(keys_are(want, 2));
    ASSERT(strstr(g_nodes.v[0].link, "@b.example:") != NULL);
    ASSERT(g_nodes.v[1].link == NULL && g_nodes.v[1].skip_reason[0] != 0);
    PASS();
}

TEST two_long_names_of_hashes_keep_distinct_short_keys(void)
{
    /* catches: a truncated key leaving no room for #2, so two nodes share a key or it exceeds 191 bytes */
    char name[101];
    memset(name, '#', 100);
    name[100] = 0;
    const char *names[] = {name, name};
    char *body = names_body(names, 2);
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    char want0[200] = "aaaaaaaa:", want1[200];
    for (int i = 0; i < 58; i++) {
        strcat(want0, "%23");
    }
    snprintf(want1, sizeof want1, "%s#2", want0);
    const char *want[] = {want0, want1};
    ASSERT(keys_are(want, 2));
    ASSERT(strlen(g_nodes.v[1].key) <= 191);
    ASSERT_EQ(100u, strlen(g_nodes.v[0].name));
    PASS();
}

TEST link_sources_keep_their_config_order(void)
{
    /* catches: link sources reordered, e.g. by their ids */
    const firc_tunnel_t *t = tunnel("      - id: cccccccc\n        link: \"vless://" U "@c.example:443?security=none#one\"\n"
                                    "      - id: aaaaaaaa\n        link: \"vless://" U "@a.example:443?security=none#two\"\n"
                                    "      - id: bbbbbbbb\n        link: \"vless://" U "@b.example:443?security=none#three\"\n",
                                    "");
    ASSERT_EQ(FIRC_OK, build(t, 0, NULL, 0));
    const char *want[] = {"cccccccc:one", "aaaaaaaa:two", "bbbbbbbb:three"};
    ASSERT(keys_are(want, 3));
    PASS();
}

TEST subscriptions_keep_their_config_order(void)
{
    /* catches: subscriptions reordered, e.g. by id or by the order of the bodies */
    const firc_tunnel_t *t = tunnel(SUB_B SUB_A, "");
    firc_tun_body_t b[] = {{"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 0},
                           {"https://b.example", 0, CLASH_TWO, sizeof CLASH_TWO - 1, 0}};
    ASSERT_EQ(FIRC_OK, build(t, 0, b, 2));
    const char *want[] = {"bbbbbbbb:NL-1", "bbbbbbbb:DE-1", "aaaaaaaa:A", "aaaaaaaa:B", "aaaaaaaa:C"};
    ASSERT(keys_are(want, 5));
    PASS();
}

TEST a_key_repeated_in_order_counts_once(void)
{
    /* catches: a repeated order entry listing a node twice */
    const firc_tunnel_t *t = tunnel(SUB_A, "    order: [\"aaaaaaaa:B\", \"aaaaaaaa:Z\", \"aaaaaaaa:B\", \"aaaaaaaa:Z\"]\n");
    firc_tun_body_t b = {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:B", "aaaaaaaa:A", "aaaaaaaa:C"};
    ASSERT(keys_are(want, 3));
    PASS();
}

TEST a_body_reads_at_most_1024_nodes(void)
{
    /* catches: the node array sized by the body alone, so a hostile body allocates without bound */
    size_t cap = 1100 * 120 + 1, off = 0;
    char *body = malloc(cap);
    for (int i = 0; i < 1100; i++) {
        off += (size_t)snprintf(body + off, cap - off, "vless://" U "@h.example:443?security=none#n%d\n", i);
    }
    const firc_tunnel_t *t = tunnel(SUB_A, "");
    firc_tun_body_t b = {"https://a.example", 0, body, off, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    ASSERT_EQ(1024u, g_nodes.total);
    ASSERT_EQ(1100u, g_nodes.n);
    ASSERT_STR_EQ("aaaaaaaa:n1024", g_nodes.v[1024].key);
    ASSERT_STR_EQ("more nodes than fit", g_nodes.v[1024].skip_reason);
    size_t big = 5u * 4000000u;
    char *junk = malloc(big + 16);
    memcpy(junk, "vless://x\n", 10);
    for (size_t i = 10; i + 5 <= big; i += 5) {
        memcpy(junk + i, "vless", 5);
    }
    firc_tun_body_t j = {"https://a.example", 0, junk, big, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &j, 1));
    free(junk);
    ASSERT_EQ(0u, g_nodes.total);
    PASS();
}

static int flat_and_unique(void)
{
    for (size_t i = 0; i < g_nodes.n; i++) {
        if (g_nodes.v[i].is_new) {
            return 0;
        }
        for (size_t j = 0; j < i; j++) {
            if (strcmp(g_nodes.v[i].key, g_nodes.v[j].key) == 0) {
                return 0;
            }
        }
    }
    return 1;
}

TEST a_reversed_order_lists_every_node_once(void)
{
    /* catches: an emitted node blanking its key in the sorted index, so later order keys miss and nodes repeat */
    const firc_tunnel_t *t = tunnel(SUB_A, "    order: [\"aaaaaaaa:C\", \"aaaaaaaa:B\", \"aaaaaaaa:A\"]\n");
    firc_tun_body_t b = {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    const char *want[] = {"aaaaaaaa:C", "aaaaaaaa:B", "aaaaaaaa:A"};
    ASSERT(keys_are(want, 3));
    ASSERT(flat_and_unique());
    ASSERT_EQ(3u, sendable());
    PASS();
}

TEST ten_nodes_in_reverse_order_keep_the_saved_order(void)
{
    /* catches: a partial fix of the index, leaving some of ten reversed keys missed or repeated */
    const char *names[] = {"n0", "n1", "n2", "n3", "n4", "n5", "n6", "n7", "n8", "n9"};
    char *body = names_body(names, 10);
    char extra[512] = "    order: [";
    char want_keys[10][16];
    const char *want[10];
    for (int i = 0; i < 10; i++) {
        snprintf(want_keys[i], sizeof want_keys[i], "aaaaaaaa:n%d", 9 - i);
        want[i] = want_keys[i];
        size_t off = strlen(extra);
        snprintf(extra + off, sizeof extra - off, "%s\"%s\"", i ? ", " : "", want_keys[i]);
    }
    strcat(extra, "]\n");
    const firc_tunnel_t *t = tunnel(SUB_A, extra);
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    ASSERT_EQ(FIRC_OK, build(t, 0, &b, 1));
    free(body);
    ASSERT(keys_are(want, 10));
    ASSERT(flat_and_unique());
    PASS();
}

static firc_tunnel_t *mutable_tunnel(const char *sources, const char *extra)
{
    return tunnel(sources, extra) != NULL ? &g_cfg.t[0] : NULL;
}

static int list_is(char *const *got, size_t n, const char *const *want, size_t n_want)
{
    int ok = n == n_want;
    for (size_t i = 0; ok && i < n; i++) {
        ok = strcmp(got[i], want[i]) == 0;
    }
    if (!ok) {
        fprintf(stderr, "keys:");
        for (size_t i = 0; i < n; i++) {
            fprintf(stderr, " [%s]", got[i]);
        }
        fprintf(stderr, "\n");
    }
    return ok;
}

TEST a_prune_drops_a_renamed_nodes_key_from_order_and_exclude(void)
{
    /* catches: a key its body no longer gives kept in order or exclude, or a key the body gives dropped */
    const char *names[] = {"A", "B", "C new"};
    char *body = names_body(names, 3);
    firc_tunnel_t *t = mutable_tunnel(SUB_A, "    order: [\"aaaaaaaa:C\", \"aaaaaaaa:B\"]\n"
                                             "    exclude: [\"aaaaaaaa:C\", \"aaaaaaaa:A\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_tun_nodes_prune(t, 0, &b, 1, &dropped));
    free(body);
    ASSERT_EQ_FMT((size_t)2, dropped, "%zu");
    const char *order[] = {"aaaaaaaa:B"};
    const char *exclude[] = {"aaaaaaaa:A"};
    ASSERT(list_is(t->order, t->n_order, order, 1));
    ASSERT(list_is(t->exclude, t->n_exclude, exclude, 1));
    PASS();
}

TEST a_filter_hidden_key_its_body_gives_survives_a_prune(void)
{
    /* catches: a prune that judges keys by the filtered rows, losing the pin of a node the filter hides */
    const char *names[] = {"A", "H"};
    char *body = names_body(names, 2);
    firc_tunnel_t *t = mutable_tunnel(SUB_A, "    filter: \"^A$\"\n    order: [\"aaaaaaaa:H\", \"aaaaaaaa:A\"]\n"
                                             "    exclude: [\"aaaaaaaa:H\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_tun_nodes_prune(t, 0, &b, 1, &dropped));
    free(body);
    ASSERT_EQ_FMT((size_t)0, dropped, "%zu");
    const char *order[] = {"aaaaaaaa:H", "aaaaaaaa:A"};
    const char *exclude[] = {"aaaaaaaa:H"};
    ASSERT(list_is(t->order, t->n_order, order, 2));
    ASSERT(list_is(t->exclude, t->n_exclude, exclude, 1));
    PASS();
}

TEST a_filter_hidden_key_its_body_no_longer_gives_is_dropped(void)
{
    /* catches: keeping any key the filter would hide, so a removed node's pin stays for good */
    const char *names[] = {"A", "H2"};
    char *body = names_body(names, 2);
    firc_tunnel_t *t = mutable_tunnel(SUB_A, "    filter: \"^A$\"\n    order: [\"aaaaaaaa:H\", \"aaaaaaaa:A\"]\n"
                                             "    exclude: [\"aaaaaaaa:H\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_tun_nodes_prune(t, 0, &b, 1, &dropped));
    free(body);
    ASSERT_EQ_FMT((size_t)2, dropped, "%zu");
    const char *order[] = {"aaaaaaaa:A"};
    ASSERT(list_is(t->order, t->n_order, order, 1));
    ASSERT_EQ_FMT((size_t)0, t->n_exclude, "%zu");
    PASS();
}

TEST a_subscription_without_its_body_keeps_its_keys(void)
{
    /* catches: a never-fetched subscription, or one held under another mark or headers, read as giving no node */
    firc_tunnel_t *t = mutable_tunnel(SUB_A SUB_B, "    order: [\"aaaaaaaa:Z\", \"bbbbbbbb:Z\"]\n"
                                                   "    exclude: [\"bbbbbbbb:Z\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b[] = {{"https://a.example", 7, B64_ABC, sizeof B64_ABC - 1, 0},
                           {"https://a.example", 0, B64_ABC, sizeof B64_ABC - 1, 5}};
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_tun_nodes_prune(t, 0, b, 2, &dropped));
    ASSERT_EQ_FMT((size_t)0, dropped, "%zu");
    const char *order[] = {"aaaaaaaa:Z", "bbbbbbbb:Z"};
    const char *exclude[] = {"bbbbbbbb:Z"};
    ASSERT(list_is(t->order, t->n_order, order, 2));
    ASSERT(list_is(t->exclude, t->n_exclude, exclude, 1));
    ASSERT_EQ(FIRC_OK, firc_tun_nodes_prune(t, 7, b, 2, &dropped));
    ASSERT_EQ_FMT((size_t)1, dropped, "%zu");
    const char *order2[] = {"bbbbbbbb:Z"};
    ASSERT(list_is(t->order, t->n_order, order2, 1));
    PASS();
}

TEST a_link_sources_dead_key_is_dropped(void)
{
    /* catches: a link source treated as unknown, so the key of its old name stays */
    firc_tunnel_t *t = mutable_tunnel(
        "      - id: 0000000a\n        link: \"vless://" U "@a.example:443?security=none#a\"\n",
        "    order: [\"0000000a:old\", \"0000000a:a\"]\n    exclude: [\"0000000a:old\"]\n");
    ASSERT(t != NULL);
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_tun_nodes_prune(t, 0, NULL, 0, &dropped));
    ASSERT_EQ_FMT((size_t)2, dropped, "%zu");
    const char *order[] = {"0000000a:a"};
    ASSERT(list_is(t->order, t->n_order, order, 1));
    ASSERT_EQ_FMT((size_t)0, t->n_exclude, "%zu");
    PASS();
}

TEST a_prune_numbers_twins_as_the_table_does(void)
{
    /* catches: twin numbers re-derived from the unfiltered or usable rows only, dropping a live #2 or keeping a dead #3 */
    const char *names[] = {"X", "Y", "X"};
    char *body = names_body(names, 3);
    firc_tunnel_t *t = mutable_tunnel(SUB_A, "    filter: \"^Y$\"\n"
                                             "    order: [\"aaaaaaaa:X#3\", \"aaaaaaaa:X#2\", \"aaaaaaaa:Y\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, strlen(body), 0};
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_tun_nodes_prune(t, 0, &b, 1, &dropped));
    free(body);
    ASSERT_EQ_FMT((size_t)1, dropped, "%zu");
    const char *order[] = {"aaaaaaaa:X#2", "aaaaaaaa:Y"};
    ASSERT(list_is(t->order, t->n_order, order, 2));
    PASS();
}

TEST a_source_past_the_row_cap_keeps_its_keys(void)
{
    /* catches: rows cut at the table's cap read as nodes the body no longer gives */
    size_t cap = 2100 * 120 + 1, off = 0;
    char *body = malloc(cap);
    for (int i = 0; i < 2100; i++) {
        off += (size_t)snprintf(body + off, cap - off, "vless://" U "@h.example:443?security=none#n%d\n", i);
    }
    firc_tunnel_t *t = mutable_tunnel(SUB_A, "    order: [\"aaaaaaaa:n2099\", \"aaaaaaaa:gone\"]\n");
    ASSERT(t != NULL);
    firc_tun_body_t b = {"https://a.example", 0, body, off, 0};
    size_t dropped = 99;
    ASSERT_EQ(FIRC_OK, firc_tun_nodes_prune(t, 0, &b, 1, &dropped));
    free(body);
    ASSERT_EQ_FMT((size_t)0, dropped, "%zu");
    ASSERT_EQ_FMT((size_t)2, t->n_order, "%zu");
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    GREATEST_SET_TEARDOWN_CB(cleanup, NULL);
    RUN_TEST(a_base64_list_gives_its_nodes_in_order);
    RUN_TEST(a_clash_body_gives_its_two_nodes);
    RUN_TEST(order_pins_its_keys_first);
    RUN_TEST(an_excluded_node_is_listed_but_not_sent);
    RUN_TEST(the_filter_keeps_matching_subscription_nodes_ignoring_case);
    RUN_TEST(duplicate_names_in_one_source_get_a_number);
    RUN_TEST(a_name_with_key_characters_is_encoded);
    RUN_TEST(a_name_with_control_bytes_gets_a_key_the_config_takes);
    RUN_TEST(an_ordered_key_its_subscription_no_longer_gives_is_not_listed);
    RUN_TEST(a_node_back_under_its_saved_key_takes_its_place_and_exclusion);
    RUN_TEST(a_link_key_its_link_no_longer_names_gives_no_row);
    RUN_TEST(a_link_source_counts_whatever_the_filter);
    RUN_TEST(at_most_256_nodes_are_sent);
    RUN_TEST(the_body_of_another_mark_is_not_used);
    RUN_TEST(the_body_of_other_headers_is_not_used);
    RUN_TEST(a_node_the_parser_skips_is_listed_with_its_reason);
    RUN_TEST(an_xmux_conflict_is_a_named_skip);
    RUN_TEST(a_download_block_at_a_sink_counts_as_one);
    RUN_TEST(a_download_block_without_a_port_is_no_stub);
    RUN_TEST(a_node_with_a_download_block_is_sent_with_it);
    RUN_TEST(an_ipv6_server_is_sent_as_a_bracketed_link);
    RUN_TEST(a_bracketed_ipv6_link_source_is_one_node);
    RUN_TEST(a_long_name_is_cut_to_100_bytes);
    RUN_TEST(insecure_is_set_per_tunnel_for_each_build);
    RUN_TEST(a_link_source_that_does_not_parse_is_listed_with_a_reason);
    RUN_TEST(a_twin_name_keeps_its_number_when_one_is_skipped);
    RUN_TEST(two_long_names_of_hashes_keep_distinct_short_keys);
    RUN_TEST(link_sources_keep_their_config_order);
    RUN_TEST(subscriptions_keep_their_config_order);
    RUN_TEST(a_key_repeated_in_order_counts_once);
    RUN_TEST(nodes_at_a_sink_are_counted_with_the_first_name);
    RUN_TEST(a_body_reads_at_most_1024_nodes);
    RUN_TEST(a_reversed_order_lists_every_node_once);
    RUN_TEST(a_prune_drops_a_renamed_nodes_key_from_order_and_exclude);
    RUN_TEST(a_filter_hidden_key_its_body_gives_survives_a_prune);
    RUN_TEST(a_filter_hidden_key_its_body_no_longer_gives_is_dropped);
    RUN_TEST(a_subscription_without_its_body_keeps_its_keys);
    RUN_TEST(a_link_sources_dead_key_is_dropped);
    RUN_TEST(a_prune_numbers_twins_as_the_table_does);
    RUN_TEST(a_source_past_the_row_cap_keeps_its_keys);
    RUN_TEST(ten_nodes_in_reverse_order_keep_the_saved_order);
    GREATEST_MAIN_END();
}
