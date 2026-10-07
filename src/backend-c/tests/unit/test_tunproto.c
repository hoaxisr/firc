#include "greatest.h"
#include "firc/tunproto.h"
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
    RUN_TEST(an_empty_active_list_is_no_live_node);
    GREATEST_MAIN_END();
}
