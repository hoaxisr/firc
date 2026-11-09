#include "greatest.h"
#include "firc/ktcp.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static void add(firc_ktcp_image_t *im, uint8_t dev, uint8_t f0, uint8_t f1, uint8_t f2, uint8_t f3, uint8_t r0,
                uint8_t r1, uint8_t r2, uint8_t r3)
{
    const uint8_t fake[4] = {f0, f1, f2, f3};
    const firc_ip_t real = {{r0, r1, r2, r3}, 4};
    if (firc_ktcp_image_add(im, dev, fake, &real) != FIRC_OK)
        abort();
}

static void add6(firc_ktcp_image_t *im, uint8_t dev, uint8_t f0, uint8_t f1, uint8_t f2, uint8_t f3, const char *real)
{
    const uint8_t fake[4] = {f0, f1, f2, f3};
    firc_ip_t r = {{0}, 16};
    if (inet_pton(AF_INET6, real, r.b) != 1 || firc_ktcp_image_add(im, dev, fake, &r) != FIRC_OK)
        abort();
}

static bool pair_is(const firc_ktcp_pair_t *p, uint8_t dev, const char *fake, const char *real)
{
    char f[32], r[32];
    snprintf(f, sizeof(f), "%u.%u.%u.%u", p->fake[0], p->fake[1], p->fake[2], p->fake[3]);
    snprintf(r, sizeof(r), "%u.%u.%u.%u", p->real[0], p->real[1], p->real[2], p->real[3]);
    return p->dev == dev && strcmp(f, fake) == 0 && strcmp(r, real) == 0;
}

typedef struct {
    size_t n;
    char call[16][96];
} calls_t;

static void record(uint8_t dev, const uint8_t fake[4], const firc_ip_t *real, void *ud)
{
    calls_t *c = ud;
    if (c->n >= 16)
        return;
    if (real && real->len == 16) {
        char r[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, real->b, r, sizeof(r));
        snprintf(c->call[c->n], sizeof(c->call[0]), "%u %u.%u.%u.%u %s", dev, fake[0], fake[1], fake[2], fake[3], r);
    } else if (real)
        snprintf(c->call[c->n], sizeof(c->call[0]), "%u %u.%u.%u.%u %u.%u.%u.%u", dev, fake[0], fake[1], fake[2],
                 fake[3], real->b[0], real->b[1], real->b[2], real->b[3]);
    else
        snprintf(c->call[c->n], sizeof(c->call[0]), "%u %u.%u.%u.%u -", dev, fake[0], fake[1], fake[2], fake[3]);
    c->n++;
}

static size_t count_of(const char *hay, const char *needle)
{
    size_t n = 0;
    for (const char *p = strstr(hay, needle); p; p = strstr(p + 1, needle))
        n++;
    return n;
}

TEST sort_orders_by_device_then_fake_bytes_and_a_later_duplicate_wins(void)
{
    /* catches: fakes compared as host-order integers, the device ignored, or the earlier duplicate kept */
    firc_ktcp_image_t im = {0};
    add(&im, 2, 198, 18, 0, 1, 1, 0, 0, 1);
    add(&im, 1, 198, 18, 1, 0, 1, 0, 0, 2);
    add(&im, 1, 198, 18, 0, 255, 1, 0, 0, 3);
    add(&im, 2, 198, 18, 0, 1, 1, 0, 0, 4);
    add(&im, 0, 198, 18, 9, 9, 1, 0, 0, 5);
    firc_ktcp_image_sort(&im);
    ASSERT_EQ(4, im.n);
    ASSERT(pair_is(&im.v[0], 0, "198.18.9.9", "1.0.0.5"));
    ASSERT(pair_is(&im.v[1], 1, "198.18.0.255", "1.0.0.3"));
    ASSERT(pair_is(&im.v[2], 1, "198.18.1.0", "1.0.0.2"));
    ASSERT(pair_is(&im.v[3], 2, "198.18.0.1", "1.0.0.4"));
    firc_ktcp_image_free(&im);
    PASS();
}

TEST sort_keeps_the_later_duplicate_across_merged_blocks(void)
{
    /* catches: an unstable sort that keeps an earlier duplicate once the keys span many sorted blocks */
    firc_ktcp_image_t im = {0};
    for (unsigned i = 0; i < 1500; i++) {
        unsigned k = 1499 - i;
        add(&im, (uint8_t)(k % 3), 198, 18, (uint8_t)(k >> 8), (uint8_t)k, 1, (uint8_t)(k >> 8), (uint8_t)k, 0);
    }
    for (unsigned i = 0; i < 1500; i++) {
        unsigned k = (i * 7) % 1500;
        add(&im, (uint8_t)(k % 3), 198, 18, (uint8_t)(k >> 8), (uint8_t)k, 9, (uint8_t)(k >> 8), (uint8_t)k, 0);
    }
    firc_ktcp_image_sort(&im);
    ASSERT_EQ(1500, im.n);
    for (size_t i = 0; i < im.n; i++) {
        const firc_ktcp_pair_t *p = &im.v[i];
        ASSERT_EQ(9, p->real[0]);
        ASSERT_EQ(p->fake[2], p->real[1]);
        ASSERT_EQ(p->fake[3], p->real[2]);
        ASSERT_EQ((p->fake[2] * 256u + p->fake[3]) % 3, p->dev);
        if (i > 0) {
            const firc_ktcp_pair_t *q = &im.v[i - 1];
            ASSERT(q->dev < p->dev || (q->dev == p->dev && memcmp(q->fake, p->fake, 4) < 0));
        }
    }
    firc_ktcp_image_free(&im);
    PASS();
}

TEST diff_orders_entered_changed_left(void)
{
    /* catches: a missed removal, a changed real not emitted, an unchanged pair emitted, or calls out of order */
    firc_ktcp_image_t prev = {0}, next = {0};
    add(&prev, 0, 198, 18, 0, 1, 1, 1, 1, 1);
    add(&prev, 0, 198, 18, 0, 2, 2, 2, 2, 2);
    add(&prev, 1, 198, 18, 0, 1, 3, 3, 3, 3);
    add(&prev, 1, 198, 18, 0, 5, 5, 5, 5, 5);
    add(&next, 0, 198, 18, 0, 1, 1, 1, 1, 1);
    add(&next, 0, 198, 18, 0, 2, 2, 2, 2, 9);
    add(&next, 0, 198, 18, 0, 3, 3, 3, 3, 3);
    add(&next, 1, 198, 18, 0, 5, 5, 5, 5, 5);
    add(&next, 2, 198, 18, 0, 0, 4, 4, 4, 4);
    firc_ktcp_image_sort(&prev);
    firc_ktcp_image_sort(&next);
    calls_t c = {0};
    firc_ktcp_image_diff(&prev, &next, record, &c);
    ASSERT_EQ(4, c.n);
    ASSERT_STR_EQ("0 198.18.0.2 2.2.2.9", c.call[0]);
    ASSERT_STR_EQ("0 198.18.0.3 3.3.3.3", c.call[1]);
    ASSERT_STR_EQ("1 198.18.0.1 -", c.call[2]);
    ASSERT_STR_EQ("2 198.18.0.0 4.4.4.4", c.call[3]);
    memset(&c, 0, sizeof(c));
    firc_ktcp_image_diff(&next, &prev, record, &c);
    ASSERT_EQ(4, c.n);
    ASSERT_STR_EQ("0 198.18.0.2 2.2.2.2", c.call[0]);
    ASSERT_STR_EQ("0 198.18.0.3 -", c.call[1]);
    ASSERT_STR_EQ("1 198.18.0.1 3.3.3.3", c.call[2]);
    ASSERT_STR_EQ("2 198.18.0.0 -", c.call[3]);
    firc_ktcp_image_free(&prev);
    firc_ktcp_image_free(&next);
    PASS();
}

TEST a_device_s_full_set_splits_at_4096_lines(void)
{
    /* catches: an off-by-one at the line cap, a missing mapall, a missing terminator, or another device's pairs */
    firc_ktcp_image_t im = {0};
    add(&im, 6, 198, 18, 200, 1, 6, 6, 6, 6);
    for (unsigned i = 0; i < 8193; i++)
        add(&im, 7, 198, 18, (uint8_t)(i >> 8), (uint8_t)i, 10, 0, (uint8_t)(i >> 8), (uint8_t)i);
    add(&im, 8, 198, 18, 200, 2, 8, 8, 8, 8);
    firc_ktcp_image_sort(&im);
    firc_ktcp_cmds_t out = {0};
    ASSERT_EQ(FIRC_OK, firc_ktcp_map_cmds(&im, 7, true, &out));
    ASSERT_EQ(3, out.n_cmds);
    ASSERT_EQ(4096, out.counts[0]);
    ASSERT_EQ(4096, out.counts[1]);
    ASSERT_EQ(1, out.counts[2]);
    ASSERT_EQ(strlen(out.text), out.len);
    ASSERT_EQ(0, strncmp(out.text, "mapall\n198.18.0.0 10.0.0.0\n198.18.0.1 10.0.0.1\n", 47));
    ASSERT(strstr(out.text, "198.18.15.255 10.0.15.255\n\nmap\n198.18.16.0 10.0.16.0\n") != NULL);
    ASSERT(strstr(out.text, "198.18.31.255 10.0.31.255\n\nmap\n198.18.32.0 10.0.32.0\n\n") != NULL);
    ASSERT_EQ(3, count_of(out.text, "\n\n"));
    ASSERT_EQ(1, count_of(out.text, "mapall\n"));
    ASSERT_EQ(8193 + 3 + 3, count_of(out.text, "\n"));
    ASSERT_EQ(0, count_of(out.text, "198.18.200."));
    size_t tail = strlen("map\n198.18.32.0 10.0.32.0\n\n");
    ASSERT_STR_EQ("map\n198.18.32.0 10.0.32.0\n\n", out.text + out.len - tail);
    firc_ktcp_cmds_free(&out);
    firc_ktcp_image_free(&im);
    PASS();
}

TEST map_cmds_append_and_an_empty_mapall_still_clears(void)
{
    /* catches: out reset or its last command joined by a later call, an empty mapall skipped, or an empty map sent */
    firc_ktcp_image_t im = {0};
    add(&im, 3, 198, 18, 4, 1, 212, 193, 11, 97);
    add(&im, 3, 198, 18, 4, 2, 8, 8, 4, 4);
    firc_ktcp_image_sort(&im);
    firc_ktcp_cmds_t out = {0};
    ASSERT_EQ(FIRC_OK, firc_ktcp_map_cmds(&im, 3, false, &out));
    ASSERT_EQ(FIRC_OK, firc_ktcp_map_cmds(&im, 4, false, &out));
    ASSERT_EQ(FIRC_OK, firc_ktcp_map_cmds(&im, 3, false, &out));
    ASSERT_EQ(FIRC_OK, firc_ktcp_map_cmds(&im, 4, true, &out));
    ASSERT_STR_EQ("map\n198.18.4.1 212.193.11.97\n198.18.4.2 8.8.4.4\n\n"
                  "map\n198.18.4.1 212.193.11.97\n198.18.4.2 8.8.4.4\n\nmapall\n\n",
                  out.text);
    ASSERT_EQ(strlen(out.text), out.len);
    ASSERT_EQ(3, out.n_cmds);
    ASSERT_EQ(2, out.counts[0]);
    ASSERT_EQ(2, out.counts[1]);
    ASSERT_EQ(0, out.counts[2]);
    firc_ktcp_cmds_free(&out);
    firc_ktcp_image_free(&im);
    PASS();
}

TEST close_lists_only_v4_prefixes(void)
{
    /* catches: v6 prefixes sent to a v4-only tunvless, a wrong cidr, or an empty close sent */
    firc_nf_prefix_t p[3] = {
        {.family = 4, .cidr = 24, .addr = {198, 18, 4, 0}},
        {.family = 6, .cidr = 48, .addr = {0xfd, 0x12, 0x34, 0x56}},
        {.family = 4, .cidr = 8, .addr = {10, 0, 0, 0}},
    };
    firc_ktcp_cmds_t out = {0};
    ASSERT_EQ(FIRC_OK, firc_ktcp_close_cmd(&p[1], 1, &out));
    ASSERT_EQ(0, out.n_cmds);
    ASSERT_EQ(0, out.len);
    ASSERT_EQ(FIRC_OK, firc_ktcp_close_cmd(p, 3, &out));
    ASSERT_STR_EQ("close\n198.18.4.0/24\n10.0.0.0/8\n\n", out.text);
    ASSERT_EQ(strlen(out.text), out.len);
    ASSERT_EQ(1, out.n_cmds);
    ASSERT_EQ(2, out.counts[0]);
    firc_ktcp_cmds_free(&out);
    PASS();
}

TEST close_splits_at_4096_prefixes(void)
{
    /* catches: a close list piling past the line cap, or its overflow sent under another command word */
    static firc_nf_prefix_t p[4097];
    for (unsigned i = 0; i < 4097; i++)
        p[i] = (firc_nf_prefix_t){.family = 4, .cidr = 32, .addr = {10, 1, (uint8_t)(i >> 8), (uint8_t)i}};
    firc_ktcp_cmds_t out = {0};
    ASSERT_EQ(FIRC_OK, firc_ktcp_close_cmd(p, 4097, &out));
    ASSERT_EQ(2, out.n_cmds);
    ASSERT_EQ(4096, out.counts[0]);
    ASSERT_EQ(1, out.counts[1]);
    ASSERT_EQ(0, strncmp(out.text, "close\n10.1.0.0/32\n10.1.0.1/32\n", 30));
    size_t tail = strlen("10.1.15.255/32\n\nclose\n10.1.16.0/32\n\n");
    ASSERT_STR_EQ("10.1.15.255/32\n\nclose\n10.1.16.0/32\n\n", out.text + out.len - tail);
    firc_ktcp_cmds_free(&out);
    PASS();
}

TEST firc_ktcp_line_opens_a_new_map_at_the_4097th_line(void)
{
    /* catches: delta lines piling past the line cap into one command that tunvless would cut and ack short */
    firc_ktcp_cmds_t out = {0};
    const firc_ip_t real = {{212, 193, 11, 97}, 4};
    for (unsigned i = 0; i < 4097; i++) {
        const uint8_t fake[4] = {198, 18, (uint8_t)(i >> 8), (uint8_t)i};
        ASSERT_EQ(FIRC_OK, firc_ktcp_line(&out, fake, i % 2 ? NULL : &real));
    }
    ASSERT_EQ(2, out.n_cmds);
    ASSERT_EQ(4096, out.counts[0]);
    ASSERT_EQ(1, out.counts[1]);
    ASSERT_EQ(strlen(out.text), out.len);
    ASSERT_EQ(0, strncmp(out.text, "map\n198.18.0.0 212.193.11.97\n198.18.0.1 -\n198.18.0.2 212.193.11.97\n", 67));
    ASSERT(strstr(out.text, "198.18.15.255 -\n\nmap\n198.18.16.0 212.193.11.97\n\n") != NULL);
    ASSERT_EQ(2, count_of(out.text, "\n\n"));
    ASSERT_EQ(4097 + 2 + 2, count_of(out.text, "\n"));
    firc_ktcp_cmds_free(&out);
    PASS();
}

/* Catches: a v6 real written as dotted bytes, cut at 4 bytes, or its text overflowing the line buffer. */
TEST a_v6_real_is_written_as_its_text(void)
{
    firc_ktcp_cmds_t out = {0};
    const uint8_t fake[4] = {198, 18, 1, 2};
    firc_ip_t r = {{0}, 16};
    ASSERT_EQ(1, inet_pton(AF_INET6, "2a02:e00:ffec:4b8::1", r.b));
    ASSERT_EQ(FIRC_OK, firc_ktcp_line(&out, fake, &r));
    ASSERT_STR_EQ("map\n198.18.1.2 2a02:e00:ffec:4b8::1\n\n", out.text);
    firc_ktcp_cmds_free(&out);
    firc_ktcp_image_t im = {0};
    add6(&im, 5, 198, 18, 1, 3, "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff");
    firc_ktcp_image_sort(&im);
    ASSERT_EQ(FIRC_OK, firc_ktcp_map_cmds(&im, 5, true, &out));
    ASSERT_STR_EQ("mapall\n198.18.1.3 2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff\n\n", out.text);
    firc_ktcp_cmds_free(&out);
    firc_ktcp_image_free(&im);
    PASS();
}

/* Catches: a diff comparing four bytes of the real, so a v6 real that begins like the old v4 one is no change. */
TEST a_real_moving_from_v6_to_v4_is_a_change(void)
{
    firc_ktcp_image_t prev = {0}, next = {0};
    add6(&prev, 1, 198, 18, 0, 1, "5d:b8d8:2200::");
    add(&next, 1, 198, 18, 0, 1, 0, 93, 184, 216);
    add6(&prev, 1, 198, 18, 0, 2, "2001:db8::1");
    add6(&next, 1, 198, 18, 0, 2, "2001:db8::1");
    add6(&next, 1, 198, 18, 0, 3, "2001:db8::2");
    firc_ktcp_image_sort(&prev);
    firc_ktcp_image_sort(&next);
    calls_t c = {0};
    firc_ktcp_image_diff(&prev, &next, record, &c);
    ASSERT_EQ(2, c.n);
    ASSERT_STR_EQ("1 198.18.0.1 0.93.184.216", c.call[0]);
    ASSERT_STR_EQ("1 198.18.0.3 2001:db8::2", c.call[1]);
    memset(&c, 0, sizeof(c));
    firc_ktcp_image_diff(&next, &prev, record, &c);
    ASSERT_EQ(2, c.n);
    ASSERT_STR_EQ("1 198.18.0.1 5d:b8d8:2200::", c.call[0]);
    ASSERT_STR_EQ("1 198.18.0.3 -", c.call[1]);
    firc_ktcp_image_free(&prev);
    firc_ktcp_image_free(&next);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv)
{
    GREATEST_MAIN_BEGIN();
    RUN_TEST(sort_orders_by_device_then_fake_bytes_and_a_later_duplicate_wins);
    RUN_TEST(sort_keeps_the_later_duplicate_across_merged_blocks);
    RUN_TEST(diff_orders_entered_changed_left);
    RUN_TEST(a_device_s_full_set_splits_at_4096_lines);
    RUN_TEST(map_cmds_append_and_an_empty_mapall_still_clears);
    RUN_TEST(close_lists_only_v4_prefixes);
    RUN_TEST(close_splits_at_4096_prefixes);
    RUN_TEST(firc_ktcp_line_opens_a_new_map_at_the_4097th_line);
    RUN_TEST(a_v6_real_is_written_as_its_text);
    RUN_TEST(a_real_moving_from_v6_to_v4_is_a_change);
    GREATEST_MAIN_END();
}
