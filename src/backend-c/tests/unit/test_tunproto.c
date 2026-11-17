#include "greatest.h"
#include "firc/tunproto.h"
#include "firc/log.h"
#include <string.h>

typedef struct {
    int n;
    char line[4][FIRC_TUN_LINE_MAX];
    size_t len[4];
} got_t;

static void collect(const char *line, size_t len, void *ud)
{
    got_t *g = ud;
    if (g->n < 4) {
        memcpy(g->line[g->n], line, len);
        g->line[g->n][len] = 0;
        g->len[g->n] = len;
    }
    g->n++;
}

static size_t feed(firc_tun_lines_t *l, got_t *g, const char *s, size_t n)
{
    return firc_tun_lines_feed(l, s, n, collect, g);
}

static firc_tev_t parse(const char *s)
{
    firc_tev_t e;
    memset(&e, 0xAA, sizeof(e));
    firc_tun_event_parse(s, strlen(s), &e);
    return e;
}

TEST two_lines_one_call(void)
{
    /* catches: only the first line of a read handled */
    firc_tun_lines_t l = {0};
    got_t g = {0};
    ASSERT_EQ(0, feed(&l, &g, "a\nb\n", 4));
    ASSERT_EQ(2, g.n);
    ASSERT_STR_EQ("a", g.line[0]);
    ASSERT_STR_EQ("b", g.line[1]);
    PASS();
}

TEST line_split_across_reads(void)
{
    /* catches: a line split across reads delivered as two */
    firc_tun_lines_t l = {0};
    got_t g = {0};
    feed(&l, &g, "ab", 2);
    ASSERT_EQ(0, g.n);
    feed(&l, &g, "c\n", 2);
    ASSERT_EQ(1, g.n);
    ASSERT_STR_EQ("abc", g.line[0]);
    PASS();
}

TEST oversize_line_dropped_not_split(void)
{
    /* catches: an oversize line delivered truncated or split in two */
    firc_tun_lines_t l = {0};
    got_t g = {0};
    char big[1500];
    memset(big, 'x', sizeof(big));
    size_t d = feed(&l, &g, big, sizeof(big));
    d += feed(&l, &g, "\nok\n", 4);
    ASSERT_EQ(1, d);
    ASSERT_EQ(1, g.n);
    ASSERT_STR_EQ("ok", g.line[0]);
    PASS();
}

TEST max_length_line_kept_and_next_oversize_dropped(void)
{
    /* catches: an off-by-one at the line limit */
    firc_tun_lines_t l = {0};
    got_t g = {0};
    char b[FIRC_TUN_LINE_MAX + 2];
    memset(b, 'y', FIRC_TUN_LINE_MAX - 1);
    b[FIRC_TUN_LINE_MAX - 1] = '\n';
    ASSERT_EQ(0, feed(&l, &g, b, FIRC_TUN_LINE_MAX));
    ASSERT_EQ(1, g.n);
    ASSERT_EQ(FIRC_TUN_LINE_MAX - 1, g.len[0]);
    memset(b, 'z', FIRC_TUN_LINE_MAX);
    b[FIRC_TUN_LINE_MAX] = '\n';
    ASSERT_EQ(1, feed(&l, &g, b, FIRC_TUN_LINE_MAX + 1));
    ASSERT_EQ(1, g.n);
    PASS();
}

TEST embedded_nul_keeps_full_len(void)
{
    /* catches: strlen used on a line */
    firc_tun_lines_t l = {0};
    got_t g = {0};
    feed(&l, &g, "a\0b\n", 4);
    ASSERT_EQ(1, g.n);
    ASSERT_EQ(3, g.len[0]);
    PASS();
}

TEST parse_active(void)
{
    /* catches: active names not copied in order */
    firc_tev_t e = parse("{\"type\":\"active\",\"nodes\":[\"A\",\"B\"]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT_EQ(2, e.n_active);
    ASSERT_STR_EQ("A", e.active[0]);
    ASSERT_STR_EQ("B", e.active[1]);
    PASS();
}

TEST parse_ready(void)
{
    /* catches: dev not copied */
    firc_tev_t e = parse("{\"type\":\"ready\",\"dev\":\"tunvless0\"}");
    ASSERT_EQ(FIRC_TEV_READY, e.kind);
    ASSERT_STR_EQ("tunvless0", e.dev);
    PASS();
}

TEST parse_node_down(void)
{
    /* catches: node or why swapped or dropped */
    firc_tev_t e = parse("{\"type\":\"node_down\",\"node\":\"NL-3\",\"why\":\"timeout\"}");
    ASSERT_EQ(FIRC_TEV_NODE_DOWN, e.kind);
    ASSERT_STR_EQ("NL-3", e.node);
    ASSERT_STR_EQ("timeout", e.why);
    PASS();
}

TEST parse_node_up(void)
{
    /* catches: node_up not recognised */
    firc_tev_t e = parse("{\"type\":\"node_up\",\"node\":\"NL-3\"}");
    ASSERT_EQ(FIRC_TEV_NODE_UP, e.kind);
    ASSERT_STR_EQ("NL-3", e.node);
    PASS();
}

TEST parse_no_node(void)
{
    /* catches: retry not read */
    firc_tev_t e = parse("{\"type\":\"no_node\",\"retry\":60}");
    ASSERT_EQ(FIRC_TEV_NO_NODE, e.kind);
    ASSERT_EQ(60, e.retry_s);
    PASS();
}

TEST retry_out_of_range_is_bad(void)
{
    /* catches: a negative, huge or mistyped retry accepted */
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"no_node\",\"retry\":-1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"no_node\",\"retry\":86401}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"no_node\",\"retry\":\"60\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"no_node\"}").kind);
    ASSERT_EQ(FIRC_TEV_NO_NODE, parse("{\"type\":\"no_node\",\"retry\":0}").kind);
    ASSERT_EQ(86400, parse("{\"type\":\"no_node\",\"retry\":86400}").retry_s);
    PASS();
}

TEST why_truncated_to_fit(void)
{
    /* catches: an over-long why rejected or overflowing its buffer */
    char s[400];
    char w[201];
    memset(w, 'w', 200);
    w[200] = 0;
    snprintf(s, sizeof(s), "{\"type\":\"node_down\",\"node\":\"N\",\"why\":\"%s\"}", w);
    firc_tev_t e = parse(s);
    ASSERT_EQ(FIRC_TEV_NODE_DOWN, e.kind);
    ASSERT_EQ(159, strlen(e.why));
    ASSERT_EQ('w', e.why[158]);
    PASS();
}

TEST long_node_and_dev_truncated(void)
{
    /* catches: an over-long node or dev rejected or overflowing */
    char s[400];
    char w[201];
    memset(w, 'n', 200);
    w[200] = 0;
    snprintf(s, sizeof(s), "{\"type\":\"node_up\",\"node\":\"%s\"}", w);
    firc_tev_t e = parse(s);
    ASSERT_EQ(FIRC_TEV_NODE_UP, e.kind);
    ASSERT_EQ(127, strlen(e.node));
    snprintf(s, sizeof(s), "{\"type\":\"ready\",\"dev\":\"%s\"}", w);
    e = parse(s);
    ASSERT_EQ(FIRC_TEV_READY, e.kind);
    ASSERT_EQ(15, strlen(e.dev));
    PASS();
}

TEST malformed_lines_are_bad(void)
{
    /* catches: a malformed child line crashing or half-filling the event */
    ASSERT_EQ(FIRC_TEV_BAD, parse("not json").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("[]").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"active\",\"nodes\":\"A\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"active\",\"nodes\":[1]}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"zzz\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":5}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ready\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"node_down\",\"node\":\"N\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"node_up\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"node_up\",\"node\":\"N\"} x").kind);
    PASS();
}

TEST nine_active_names_is_bad_eight_ok(void)
{
    /* catches: a ninth name overflowing the array or the limit off by one */
    ASSERT_EQ(FIRC_TEV_BAD,
              parse("{\"type\":\"active\",\"nodes\":[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\"]}").kind);
    firc_tev_t e = parse("{\"type\":\"active\",\"nodes\":[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\"]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT_EQ(8, e.n_active);
    ASSERT_STR_EQ("8", e.active[7]);
    PASS();
}

TEST parse_nodes_ack_and_pins_full(void)
{
    /* catches: the nodes ack or pins_full read as malformed, or the count not read */
    firc_tev_t e = parse("{\"type\":\"nodes\",\"count\":3}");
    ASSERT_EQ(FIRC_TEV_NODES, e.kind);
    ASSERT_EQ(3, e.count);
    ASSERT_EQ(FIRC_TEV_NODES, parse("{\"type\":\"nodes\",\"count\":0}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"nodes\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"nodes\",\"count\":-1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"nodes\",\"count\":\"3\"}").kind);
    ASSERT_EQ(FIRC_TEV_PINS_FULL, parse("{\"type\":\"pins_full\"}").kind);
    PASS();
}

TEST parse_index_next_to_names(void)
{
    /* catches: the index dropped, swapped between nodes, or a missing index read as node 0 */
    firc_tev_t e = parse("{\"type\":\"node_down\",\"node\":\"N\",\"index\":7,\"why\":\"t\"}");
    ASSERT_EQ(FIRC_TEV_NODE_DOWN, e.kind);
    ASSERT_EQ(7, e.index);
    ASSERT_EQ(-1, e.pos);
    e = parse("{\"type\":\"node_up\",\"node\":\"N\",\"index\":0}");
    ASSERT_EQ(0, e.index);
    e = parse("{\"type\":\"node_up\",\"node\":\"N\"}");
    ASSERT_EQ(FIRC_TEV_NODE_UP, e.kind);
    ASSERT_EQ(-1, e.index);
    e = parse("{\"type\":\"active\",\"nodes\":[\"A\",\"B\"],\"index\":[4,2]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT_EQ(4, e.active_index[0]);
    ASSERT_EQ(2, e.active_index[1]);
    ASSERT_EQ(-1, e.active_pos[0]);
    e = parse("{\"type\":\"active\",\"nodes\":[\"A\"]}");
    ASSERT_EQ(-1, e.active_index[0]);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"node_up\",\"node\":\"N\",\"index\":-1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"node_up\",\"node\":\"N\",\"index\":\"1\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"active\",\"nodes\":[\"A\",\"B\"],\"index\":[1]}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"active\",\"nodes\":[\"A\"],\"index\":[\"1\"]}").kind);
    PASS();
}

TEST active_v6_flags_stay_aligned_with_the_names(void)
{
    firc_tev_t e = parse("{\"type\":\"active\",\"nodes\":[\"A\",\"B\",\"C\"],\"index\":[0,1,2],\"v6\":[false,true,false]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT(!e.active_v6[0]);
    ASSERT(e.active_v6[1]);
    ASSERT(!e.active_v6[2]);
    e = parse("{\"type\":\"active\",\"nodes\":[\"A\",\"B\"]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT(!e.active_v6[0] && !e.active_v6[1]);
    PASS();
}

TEST a_v6_array_of_another_length_is_ignored_whole(void)
{
    firc_tev_t e = parse("{\"type\":\"active\",\"nodes\":[\"A\",\"B\"],\"v6\":[true]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT(!e.active_v6[0] && !e.active_v6[1]);
    e = parse("{\"type\":\"active\",\"nodes\":[\"A\"],\"v6\":[true,true]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT(!e.active_v6[0] && !e.active_v6[1]);
    e = parse("{\"type\":\"active\",\"nodes\":[\"A\",\"B\"],\"v6\":[true,1]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT(!e.active_v6[0] && !e.active_v6[1]);
    PASS();
}

TEST an_empty_active_list_is_no_live_node(void)
{
    /* catches: the empty active list tunvless sends when its last node dies read as malformed */
    firc_tev_t e = parse("{\"type\":\"active\",\"nodes\":[],\"index\":[]}");
    ASSERT_EQ(FIRC_TEV_ACTIVE, e.kind);
    ASSERT_EQ(0, e.n_active);
    PASS();
}

TEST embedded_nul_does_not_read_past_len(void)
{
    /* catches: the parser reading past len */
    char s[] = "{\"type\":\"ready\",\"dev\":\"x\"}\0{\"type\":\"ready\",\"dev\":\"y\"}";
    firc_tev_t e;
    firc_tun_event_parse(s, 5, &e);
    ASSERT_EQ(FIRC_TEV_BAD, e.kind);
    firc_tun_event_parse(s, sizeof(s) - 1, &e);
    ASSERT_EQ(FIRC_TEV_BAD, e.kind);
    PASS();
}

TEST ready_carries_tcp_port_and_absent_reads_as_zero(void)
{
    /* catches: the tcpPort key misspelt, the port not stored, or an absent port left unset */
    firc_tev_t e = parse("{\"type\":\"ready\",\"dev\":\"tunvless3\",\"tcpPort\":3603}");
    ASSERT_EQ(FIRC_TEV_READY, e.kind);
    ASSERT_STR_EQ("tunvless3", e.dev);
    ASSERT_EQ(3603, e.tcp_port);
    e = parse("{\"type\":\"ready\",\"dev\":\"tunvless3\",\"tcpPort\":65535}");
    ASSERT_EQ(FIRC_TEV_READY, e.kind);
    ASSERT_EQ(65535, e.tcp_port);
    e = parse("{\"type\":\"ready\",\"dev\":\"tunvless3\",\"tcpPort\":0}");
    ASSERT_EQ(FIRC_TEV_READY, e.kind);
    ASSERT_EQ(0, e.tcp_port);
    e = parse("{\"type\":\"ready\",\"dev\":\"tunvless3\"}");
    ASSERT_EQ(FIRC_TEV_READY, e.kind);
    ASSERT_EQ(0, e.tcp_port);
    PASS();
}

TEST a_bad_tcp_port_is_bad(void)
{
    /* catches: a negative, oversize, fractional or mistyped port accepted or wrapped into 16 bits */
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ready\",\"dev\":\"t\",\"tcpPort\":-1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ready\",\"dev\":\"t\",\"tcpPort\":65536}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ready\",\"dev\":\"t\",\"tcpPort\":3600.5}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ready\",\"dev\":\"t\",\"tcpPort\":\"3600\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ready\",\"dev\":\"t\",\"tcpPort\":null}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ready\",\"dev\":\"t\",\"tcpPort\":true}").kind);
    PASS();
}

TEST map_and_close_carry_counts(void)
{
    /* catches: the map or close ack unrecognised, its count not read, or a bad count accepted */
    firc_tev_t e = parse("{\"type\":\"map\",\"count\":4096}");
    ASSERT_EQ(FIRC_TEV_MAP, e.kind);
    ASSERT_EQ(4096, e.count);
    e = parse("{\"type\":\"close\",\"count\":2}");
    ASSERT_EQ(FIRC_TEV_CLOSE, e.kind);
    ASSERT_EQ(2, e.count);
    e = parse("{\"type\":\"map\",\"count\":0}");
    ASSERT_EQ(FIRC_TEV_MAP, e.kind);
    ASSERT_EQ(0, e.count);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"map\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"map\",\"count\":-1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"close\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"close\",\"count\":\"2\"}").kind);
    PASS();
}

TEST bytes_carry_two_u32_counts(void)
{
    /* catches: the bytes event unrecognised, rx and tx swapped, the top of the u32 range refused, or a negative, fractional, oversize or missing count accepted */
    firc_tev_t e = parse("{\"type\":\"bytes\",\"rx\":4294967295,\"tx\":7}");
    ASSERT_EQ(FIRC_TEV_BYTES, e.kind);
    ASSERT_EQ(4294967295u, e.rx);
    ASSERT_EQ(7u, e.tx);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"bytes\",\"rx\":4294967296,\"tx\":0}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"bytes\",\"rx\":-1,\"tx\":0}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"bytes\",\"rx\":1.5,\"tx\":0}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"bytes\",\"rx\":1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"bytes\",\"rx\":\"1\",\"tx\":0}").kind);
    PASS();
}

TEST inbound_event_parses(void)
{
    /* catches: the inbound event unrecognised, port or state or why dropped, a missing why not read as empty, or an unknown state accepted */
    firc_tev_t e = parse("{\"type\":\"inbound\",\"port\":1081,\"state\":\"busy\",\"why\":\"Address in use\"}");
    ASSERT_EQ(FIRC_TEV_INBOUND, e.kind);
    ASSERT_EQ(1081, e.ib_port);
    ASSERT_STR_EQ("busy", e.istate);
    ASSERT_STR_EQ("Address in use", e.why);
    e = parse("{\"type\":\"inbound\",\"port\":65535,\"state\":\"no-node\"}");
    ASSERT_EQ(FIRC_TEV_INBOUND, e.kind);
    ASSERT_EQ(65535, e.ib_port);
    ASSERT_STR_EQ("no-node", e.istate);
    ASSERT_STR_EQ("", e.why);
    ASSERT_EQ(FIRC_TEV_INBOUND, parse("{\"type\":\"inbound\",\"port\":1,\"state\":\"up\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":1,\"state\":\"x\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":1,\"state\":\"UP\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":1,\"state\":\"up\",\"why\":5}").kind);
    PASS();
}

TEST inbound_port_must_be_1_to_65535(void)
{
    /* catches: port 0, 65536, a fraction, a negative or a string accepted, or a missing port left as 0 */
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":0,\"state\":\"up\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":65536,\"state\":\"up\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":1.5,\"state\":\"up\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":-1,\"state\":\"up\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"port\":\"80\",\"state\":\"up\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbound\",\"state\":\"up\"}").kind);
    PASS();
}

TEST inbound_why_is_cut_to_its_field(void)
{
    /* catches: an overlong why overrunning the field or the event refused instead of truncated */
    char line[512];
    char why[300];
    memset(why, 'w', sizeof why);
    why[sizeof why - 1] = 0;
    snprintf(line, sizeof line, "{\"type\":\"inbound\",\"port\":9,\"state\":\"up\",\"why\":\"%s\"}", why);
    firc_tev_t e = parse(line);
    ASSERT_EQ(FIRC_TEV_INBOUND, e.kind);
    ASSERT_EQ(159u, strlen(e.why));
    PASS();
}

TEST ibytes_parse_like_bytes(void)
{
    /* catches: the ibytes event unrecognised, rx and tx swapped, port lost, the u32 top refused, or a bad count or port accepted */
    firc_tev_t e = parse("{\"type\":\"ibytes\",\"port\":3128,\"rx\":4294967295,\"tx\":7}");
    ASSERT_EQ(FIRC_TEV_IBYTES, e.kind);
    ASSERT_EQ(3128, e.ib_port);
    ASSERT_EQ(4294967295u, e.rx);
    ASSERT_EQ(7u, e.tx);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ibytes\",\"port\":1,\"rx\":4294967296,\"tx\":0}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ibytes\",\"port\":1,\"rx\":-1,\"tx\":0}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ibytes\",\"port\":1,\"rx\":1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ibytes\",\"port\":0,\"rx\":1,\"tx\":1}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"ibytes\",\"rx\":1,\"tx\":1}").kind);
    PASS();
}

TEST inbounds_ack_has_count(void)
{
    /* catches: the inbounds ack unrecognised, its count not read, or a missing or negative count accepted */
    firc_tev_t e = parse("{\"type\":\"inbounds\",\"count\":3}");
    ASSERT_EQ(FIRC_TEV_INBOUNDS, e.kind);
    ASSERT_EQ(3, e.count);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbounds\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"inbounds\",\"count\":-1}").kind);
    PASS();
}

TEST miss_needs_a_dotted_quad_fake(void)
{
    /* catches: the fake key misspelt, its bytes reversed, or an IPv6, short or garbage fake accepted */
    firc_tev_t e = parse("{\"type\":\"miss\",\"fake\":\"198.18.11.7\"}");
    ASSERT_EQ(FIRC_TEV_MISS, e.kind);
    ASSERT_EQ(198, e.fake[0]);
    ASSERT_EQ(18, e.fake[1]);
    ASSERT_EQ(11, e.fake[2]);
    ASSERT_EQ(7, e.fake[3]);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"miss\",\"fake\":\"::1\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"miss\",\"fake\":\"198.18.11\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"miss\",\"fake\":\"198.18.11.256\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"miss\",\"fake\":\"x\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"miss\",\"fake\":\"\"}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"miss\",\"fake\":3322088199}").kind);
    ASSERT_EQ(FIRC_TEV_BAD, parse("{\"type\":\"miss\"}").kind);
    PASS();
}

static const char *rest_of(const char *s, firc_log_level_t *got)
{
    size_t skip = 99;
    *got = firc_tun_err_level(s, strlen(s), &skip);
    return skip <= strlen(s) ? s + skip : NULL;
}

TEST each_tag_gives_its_level_and_is_cut(void)
{
    /* catches: a tag mapped to the wrong level, left in the relayed text, or a sub-tag cut with it */
    static const struct {
        const char *line;
        firc_log_level_t level;
        const char *text;
    } cases[] = {
        {"tunvless[debug] tun: rx 40", FIRC_LOG_DEBUG, "tun: rx 40"},
        {"tunvless[info]: up", FIRC_LOG_INFO, "up"},
        {"tunvless[warn]: bad option", FIRC_LOG_WARN, "bad option"},
        {"tunvless[warn] tunnel: device x was not created", FIRC_LOG_WARN, "tunnel: device x was not created"},
        {"tunvless[error]: no usable node", FIRC_LOG_ERROR, "no usable node"},
        {"tunvless[error]:no space", FIRC_LOG_ERROR, "no space"},
        {"tunvless[error]:", FIRC_LOG_ERROR, ""},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        firc_log_level_t got;
        const char *rest = rest_of(cases[i].line, &got);
        ASSERT_EQm(cases[i].line, cases[i].level, got);
        ASSERTm(cases[i].line, rest != NULL);
        ASSERT_STR_EQm(cases[i].line, cases[i].text, rest);
    }
    PASS();
}

TEST anything_but_a_whole_tag_is_info_and_kept(void)
{
    /* catches: a prefix of a tag, an unknown level or an untagged line taken as a level, or cut */
    static const char *const lines[] = {
        "tunvless[warn]ing: not a warn tag",
        "tunvless[warn]",
        "tunvless[fatal]: no such level",
        "tunvless[trace] tun: gone",
        "tunvless[Error]: case matters",
        "tunvless: more than 64 routes",
        "tun-stats[0]: 1.0 MB/s",
        " tunvless[warn]: indented",
        "",
    };
    for (size_t i = 0; i < sizeof lines / sizeof lines[0]; i++) {
        firc_log_level_t got;
        const char *rest = rest_of(lines[i], &got);
        ASSERT_EQm(lines[i], FIRC_LOG_INFO, got);
        ASSERT_STR_EQm(lines[i], lines[i], rest);
    }
    PASS();
}

TEST the_tag_is_read_within_len(void)
{
    /* catches: the tag matched past len, where the line has already ended */
    const char s[] = "tunvless[warn]: x";
    size_t skip = 99;
    ASSERT_EQ(FIRC_LOG_INFO, firc_tun_err_level(s, 14, &skip));
    ASSERT_EQ((size_t)0, skip);
    ASSERT_EQ(FIRC_LOG_WARN, firc_tun_err_level(s, 15, &skip));
    ASSERT_EQ((size_t)15, skip);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(two_lines_one_call);
    RUN_TEST(line_split_across_reads);
    RUN_TEST(oversize_line_dropped_not_split);
    RUN_TEST(max_length_line_kept_and_next_oversize_dropped);
    RUN_TEST(embedded_nul_keeps_full_len);
    RUN_TEST(parse_active);
    RUN_TEST(parse_ready);
    RUN_TEST(parse_node_down);
    RUN_TEST(parse_node_up);
    RUN_TEST(parse_no_node);
    RUN_TEST(retry_out_of_range_is_bad);
    RUN_TEST(why_truncated_to_fit);
    RUN_TEST(long_node_and_dev_truncated);
    RUN_TEST(malformed_lines_are_bad);
    RUN_TEST(nine_active_names_is_bad_eight_ok);
    RUN_TEST(embedded_nul_does_not_read_past_len);
    RUN_TEST(parse_nodes_ack_and_pins_full);
    RUN_TEST(parse_index_next_to_names);
    RUN_TEST(active_v6_flags_stay_aligned_with_the_names);
    RUN_TEST(a_v6_array_of_another_length_is_ignored_whole);
    RUN_TEST(an_empty_active_list_is_no_live_node);
    RUN_TEST(ready_carries_tcp_port_and_absent_reads_as_zero);
    RUN_TEST(a_bad_tcp_port_is_bad);
    RUN_TEST(map_and_close_carry_counts);
    RUN_TEST(bytes_carry_two_u32_counts);
    RUN_TEST(inbound_event_parses);
    RUN_TEST(inbound_port_must_be_1_to_65535);
    RUN_TEST(inbound_why_is_cut_to_its_field);
    RUN_TEST(ibytes_parse_like_bytes);
    RUN_TEST(inbounds_ack_has_count);
    RUN_TEST(miss_needs_a_dotted_quad_fake);
    RUN_TEST(each_tag_gives_its_level_and_is_cut);
    RUN_TEST(anything_but_a_whole_tag_is_info_and_kept);
    RUN_TEST(the_tag_is_read_within_len);
    GREATEST_MAIN_END();
}
