#include "greatest.h"

#include <errno.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fake_setnl.h"
#include "firc/setnl.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define H16(v) (uint8_t)((v) & 0xff), (uint8_t)(((v) >> 8) & 0xff)
#define H32(v) H16((v) & 0xffff), H16(((v) >> 16) & 0xffff)
#else
#define H16(v) (uint8_t)(((v) >> 8) & 0xff), (uint8_t)((v) & 0xff)
#define H32(v) H16(((v) >> 16) & 0xffff), H16((v) & 0xffff)
#endif
#define NLHDR(len, type, flags) H32(len), H16(type), H16(flags), 0, 0, 0, 0, 0, 0, 0, 0
#define NFGEN 2, 0, 0, 0
#define ATTR(len, type) H16(len), H16(type)
#define PROTO6 ATTR(5, 1), 6, 0, 0, 0
#define NAME(type, a, b, c, d) ATTR(9, type), a, b, c, d, 0, 0, 0, 0

typedef struct {
    fake_setnl_t *kernel;
    firc_setnl_t *s;
} fx_t;

static bool up(fx_t *f) {
    f->kernel = fake_setnl_start(&f->s);
    return f->kernel != NULL;
}

static void down(fx_t *f) {
    firc_setnl_free(f->s);
    fake_setnl_stop(f->kernel);
}

static firc_nf_prefix_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t cidr) {
    firc_nf_prefix_t p;
    memset(&p, 0, sizeof(p));
    p.family = 4;
    p.cidr = cidr;
    p.addr[0] = a;
    p.addr[1] = b;
    p.addr[2] = c;
    p.addr[3] = d;
    return p;
}

static firc_nf_prefix_t v6_2001_db8(uint8_t cidr) {
    firc_nf_prefix_t p;
    memset(&p, 0, sizeof(p));
    p.family = 6;
    p.cidr = cidr;
    p.addr[0] = 0x20;
    p.addr[1] = 0x01;
    p.addr[2] = 0x0d;
    p.addr[3] = 0xb8;
    return p;
}

static firc_nf_prefix_t *many(size_t n) {
    firc_nf_prefix_t *v = calloc(n, sizeof(*v));
    for (size_t i = 0; i < n; i++) {
        v[i] = v4((uint8_t)(10 + (i >> 16)), (uint8_t)((i >> 8) & 0xff), (uint8_t)(i & 0xff), 0, 24);
    }
    return v;
}

static int same_bytes(fake_setnl_t *k, uint8_t cmd, uint8_t *want, size_t want_len) {
    const uint8_t *got = NULL;
    size_t len = 0;
    if (!fake_setnl_last_datagram(k, cmd, &got, &len)) { return -1; }
    if (len != want_len) { return -2; }
    memcpy(want + 8, got + 8, 4);
    return memcmp(got, want, len) == 0 ? 0 : -3;
}

typedef struct {
    char log[4096];
} steps_t;

static void on_step(const char *what, const char *name, void *ud) {
    steps_t *s = ud;
    size_t at = strlen(s->log);
    snprintf(s->log + at, sizeof(s->log) - at, "%s %s;", what, name);
}

TEST create_is_these_bytes(void) {
    fx_t f;
    ASSERT(up(&f));
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, NULL, 0));
    uint8_t want[] = {NLHDR(92, 0x0602, 0x0205),
                      NFGEN,
                      PROTO6,
                      NAME(2, 'f', 'A', 'T', '4'),
                      ATTR(13, 3), 'h', 'a', 's', 'h', ':', 'n', 'e', 't', 0, 0, 0, 0,
                      ATTR(5, 4), 6, 0, 0, 0,
                      ATTR(5, 5), 2, 0, 0, 0,
                      ATTR(20, 0x8007),
                      ATTR(8, 0x4012), 0, 0, 4, 0,
                      ATTR(8, 0x4013), 0, 0, 4, 0};
    ASSERT_EQ(0, same_bytes(f.kernel, 2, want, sizeof(want)));
    down(&f);
    PASS();
}

TEST add_v4_is_these_bytes(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t p = v4(10, 1, 0, 0, 16);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &p, 1));
    uint8_t want[] = {NLHDR(64, 0x0609, 0x0005),
                      NFGEN,
                      PROTO6,
                      NAME(2, 'f', 'A', 'T', '4'),
                      ATTR(24, 0x8007),
                      ATTR(12, 0x8001),
                      ATTR(8, 0x4001), 10, 1, 0, 0,
                      ATTR(5, 3), 16, 0, 0, 0};
    ASSERT_EQ(0, same_bytes(f.kernel, 9, want, sizeof(want)));
    down(&f);
    PASS();
}

TEST add_v6_is_these_bytes(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t p = v6_2001_db8(32);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS6", "fAT6", 6, &p, 1));
    uint8_t want[] = {NLHDR(76, 0x0609, 0x0005),
                      NFGEN,
                      PROTO6,
                      NAME(2, 'f', 'A', 'T', '6'),
                      ATTR(36, 0x8007),
                      ATTR(24, 0x8001),
                      ATTR(20, 0x4002), 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      ATTR(5, 3), 32, 0, 0, 0};
    ASSERT_EQ(0, same_bytes(f.kernel, 9, want, sizeof(want)));
    down(&f);
    PASS();
}

TEST swap_is_these_bytes(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fAS4", 4);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, NULL, 0));
    uint8_t want[] = {NLHDR(52, 0x0606, 0x0005), NFGEN, PROTO6, NAME(2, 'f', 'A', 'T', '4'),
                      NAME(3, 'f', 'A', 'S', '4')};
    ASSERT_EQ(0, same_bytes(f.kernel, 6, want, sizeof(want)));
    down(&f);
    PASS();
}

TEST rename_is_these_bytes(void) {
    fx_t f;
    ASSERT(up(&f));
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, NULL, 0));
    uint8_t want[] = {NLHDR(52, 0x0605, 0x0005), NFGEN, PROTO6, NAME(2, 'f', 'A', 'T', '4'),
                      NAME(3, 'f', 'A', 'S', '4')};
    ASSERT_EQ(0, same_bytes(f.kernel, 5, want, sizeof(want)));
    down(&f);
    PASS();
}

TEST destroy_is_these_bytes(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fAS4", 4);
    ASSERT_EQ(FIRC_OK, firc_setnl_destroy(f.s, "fAS4"));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAS4"));
    uint8_t want[] = {NLHDR(40, 0x0603, 0x0005), NFGEN, PROTO6, NAME(2, 'f', 'A', 'S', '4')};
    ASSERT_EQ(0, same_bytes(f.kernel, 3, want, sizeof(want)));
    down(&f);
    PASS();
}

static void collect(const char *name, void *ud) {
    steps_t *s = ud;
    size_t at = strlen(s->log);
    snprintf(s->log + at, sizeof(s->log) - at, "%s;", name);
}

TEST list_names_is_these_bytes(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fAS4", 4);
    fake_setnl_plant(f.kernel, "_NDM_X", 6);
    steps_t seen = {""};
    ASSERT_EQ(FIRC_OK, firc_setnl_names(f.s, collect, &seen));
    ASSERT_STR_EQ("fAS4;_NDM_X;", seen.log);
    uint8_t want[] = {NLHDR(36, 0x0607, 0x0301), NFGEN, PROTO6, ATTR(8, 0x4006), 0, 0, 0, 2};
    ASSERT_EQ(0, same_bytes(f.kernel, 7, want, sizeof(want)));
    down(&f);
    PASS();
}

TEST a_first_replace_leaves_one_live_set_with_every_prefix(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t v[3] = {v4(10, 1, 0, 0, 16), v4(192, 168, 7, 0, 24), v4(8, 8, 8, 8, 32)};
    steps_t steps = {""};
    fake_setnl_on_step(f.kernel, on_step, &steps);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, v, 3));
    ASSERT_EQ_FMT((size_t)1, fake_setnl_sets(f.kernel), "%zu");
    ASSERT_EQ_FMT((size_t)3, fake_setnl_count(f.kernel, "fAS4"), "%zu");
    for (size_t i = 0; i < 3; i++) { ASSERT(fake_setnl_contains(f.kernel, "fAS4", &v[i])); }
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    ASSERT_STR_EQ("protocol ;type ;type ;destroy fAT4;create fAT4;add fAT4;add fAT4;add fAT4;swap fAT4;"
                  "rename fAT4;",
                  steps.log);
    down(&f);
    PASS();
}

TEST a_second_replace_swaps_and_drops_the_old_members(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t a = v4(10, 1, 0, 0, 16), b = v4(10, 2, 0, 0, 16), c = v4(10, 3, 0, 0, 16);
    firc_nf_prefix_t ab[2] = {a, b}, bc[2] = {b, c};
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, ab, 2));
    fake_setnl_reference(f.kernel, "fAS4", true);
    steps_t steps = {""};
    fake_setnl_on_step(f.kernel, on_step, &steps);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, bc, 2));
    ASSERT_STR_EQ("destroy fAT4;create fAT4;add fAT4;add fAT4;swap fAT4;destroy fAT4;", steps.log);
    ASSERT_EQ_FMT((size_t)2, fake_setnl_count(f.kernel, "fAS4"), "%zu");
    ASSERT_FALSE(fake_setnl_contains(f.kernel, "fAS4", &a));
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &b));
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &c));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    ASSERT_EQ_FMT((size_t)1, fake_setnl_sets(f.kernel), "%zu");
    down(&f);
    PASS();
}

TEST a_replace_writes_the_probed_revision_and_family(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_set_revision(f.kernel, 6, 4);
    firc_setnl_caps_t caps;
    ASSERT_EQ(FIRC_OK, firc_setnl_probe(f.s, &caps));
    ASSERT(caps.has_type);
    ASSERT_EQ(6, caps.rev4);
    ASSERT_EQ(4, caps.rev6);
    firc_nf_prefix_t p = v6_2001_db8(32);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS6", "fAT6", 6, &p, 1));
    fake_setnl_meta_t m;
    ASSERT(fake_setnl_meta(f.kernel, "fAS6", &m));
    ASSERT_STR_EQ("hash:net", m.type);
    ASSERT_EQ(4, m.revision);
    ASSERT_EQ(10, m.family);
    ASSERT(fake_setnl_contains(f.kernel, "fAS6", &p));
    down(&f);
    PASS();
}

TEST a_replace_of_many_prefixes_batches_its_adds(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t *v = many(5000);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, v, 5000));
    ASSERT_EQ_FMT((size_t)5000, fake_setnl_count(f.kernel, "fAS4"), "%zu");
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &v[0]));
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &v[4999]));
    ASSERT(fake_setnl_sends(f.kernel) > 1);
    ASSERT(fake_setnl_sends(f.kernel) < 100);
    ASSERT(fake_setnl_largest_send(f.kernel) <= 32768);
    const uint8_t *d = NULL;
    size_t len = 0;
    ASSERT(fake_setnl_last_datagram(f.kernel, 9, &d, &len));
    int left = (int)len, msgs = 0, acked = 0;
    const struct nlmsghdr *h = (const struct nlmsghdr *)d;
    bool last_acked = false;
    while (mnl_nlmsg_ok(h, left)) {
        msgs++;
        last_acked = (h->nlmsg_flags & NLM_F_ACK) != 0;
        acked += last_acked ? 1 : 0;
        h = mnl_nlmsg_next(h, &left);
    }
    ASSERT(msgs > 1);
    ASSERT_EQ(1, acked);
    ASSERT(last_acked);
    free(v);
    down(&f);
    PASS();
}

TEST a_large_set_asks_for_room(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t *v = many(100000);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, v, 100000));
    fake_setnl_meta_t m;
    ASSERT(fake_setnl_meta(f.kernel, "fAS4", &m));
    ASSERT_EQ_FMT(100000u, m.maxelem, "%u");
    ASSERT_EQ_FMT(65536u, m.hashsize, "%u");
    ASSERT_EQ_FMT((size_t)100000, fake_setnl_count(f.kernel, "fAS4"), "%zu");
    free(v);
    down(&f);
    PASS();
}

TEST a_failed_add_leaves_the_live_set_and_the_handle_usable(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t a = v4(10, 1, 0, 0, 16);
    firc_nf_prefix_t bcd[3] = {v4(10, 2, 0, 0, 16), v4(10, 3, 0, 0, 16), v4(10, 4, 0, 0, 16)};
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &a, 1));
    fake_setnl_fail_add_at(f.kernel, 2, EINVAL);
    ASSERT(firc_setnl_replace(f.s, "fAS4", "fAT4", 4, bcd, 3) != FIRC_OK);
    ASSERT_EQ_FMT((size_t)1, fake_setnl_count(f.kernel, "fAS4"), "%zu");
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &a));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, bcd, 3));
    ASSERT_EQ_FMT((size_t)3, fake_setnl_count(f.kernel, "fAS4"), "%zu");
    ASSERT_FALSE(fake_setnl_contains(f.kernel, "fAS4", &a));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    down(&f);
    PASS();
}

TEST the_first_failed_add_of_a_datagram_is_the_error(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t bcd[3] = {v4(10, 2, 0, 0, 16), v4(10, 3, 0, 0, 16), v4(10, 4, 0, 0, 16)};
    fake_setnl_fail_add_at(f.kernel, 1, ENOMEM);
    fake_setnl_fail_add_also(f.kernel, 2, EEXIST);
    ASSERT_EQ(FIRC_ERR_NOMEM, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, bcd, 3));
    down(&f);
    PASS();
}

TEST a_leftover_scratch_is_replaced_not_reused(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fAT4", 6);
    firc_nf_prefix_t p = v4(10, 1, 0, 0, 16);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &p, 1));
    fake_setnl_meta_t m;
    ASSERT(fake_setnl_meta(f.kernel, "fAS4", &m));
    ASSERT_EQ(2, m.family);
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &p));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    down(&f);
    PASS();
}

static void busy_scratch_at_swap(const char *what, const char *name, void *ud) {
    if (strcmp(what, "swap") == 0 && strcmp(name, "fAT4") == 0) { fake_setnl_reference(ud, "fAT4", true); }
}

TEST a_scratch_busy_after_the_swap_still_leaves_the_new_live_set(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t a = v4(10, 1, 0, 0, 16), b = v4(10, 2, 0, 0, 16);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &a, 1));
    fake_setnl_on_step(f.kernel, busy_scratch_at_swap, f.kernel);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &b, 1));
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &b));
    ASSERT_FALSE(fake_setnl_contains(f.kernel, "fAS4", &a));
    ASSERT(fake_setnl_contains(f.kernel, "fAT4", &a));
    down(&f);
    PASS();
}

TEST a_create_that_fails_after_making_the_set_leaves_no_scratch(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t a = v4(10, 1, 0, 0, 16), b = v4(10, 2, 0, 0, 16);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &a, 1));
    fake_setnl_fail_next(f.kernel, IPSET_CMD_CREATE, ENOMEM, true);
    ASSERT_EQ(FIRC_ERR_NOMEM, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &b, 1));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &a));
    ASSERT_EQ_FMT((size_t)1, fake_setnl_count(f.kernel, "fAS4"), "%zu");
    down(&f);
    PASS();
}

TEST a_swap_the_kernel_calls_busy_is_again_and_leaves_live(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t a = v4(10, 1, 0, 0, 16), b = v4(10, 2, 0, 0, 16);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &a, 1));
    fake_setnl_fail_next(f.kernel, IPSET_CMD_SWAP, EBUSY, false);
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &b, 1));
    ASSERT(fake_setnl_contains(f.kernel, "fAS4", &a));
    ASSERT_FALSE(fake_setnl_contains(f.kernel, "fAS4", &b));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    down(&f);
    PASS();
}

TEST a_rename_refused_as_referenced_is_again_and_leaves_no_scratch(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t a = v4(10, 1, 0, 0, 16);
    fake_setnl_fail_next(f.kernel, IPSET_CMD_RENAME, IPSET_ERR_REFERENCED, false);
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &a, 1));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAS4"));
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    down(&f);
    PASS();
}

TEST a_scratch_named_as_the_live_set_is_refused_before_a_send(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fAS4", 4);
    ASSERT_EQ(FIRC_ERR_INVAL, firc_setnl_replace(f.s, "fAS4", "fAS4", 4, NULL, 0));
    ASSERT_EQ_FMT((size_t)0, fake_setnl_messages(f.kernel), "%zu");
    ASSERT(fake_setnl_has(f.kernel, "fAS4"));
    down(&f);
    PASS();
}

TEST a_prefix_of_length_zero_or_the_other_family_is_refused_before_a_send(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t zero[2] = {v4(10, 1, 0, 0, 16), v4(0, 0, 0, 0, 0)};
    firc_nf_prefix_t mixed[2] = {v4(10, 1, 0, 0, 16), v6_2001_db8(32)};
    ASSERT_EQ(FIRC_ERR_INVAL, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, zero, 2));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, mixed, 2));
    ASSERT_EQ_FMT((size_t)0, fake_setnl_messages(f.kernel), "%zu");
    down(&f);
    PASS();
}

TEST an_empty_replace_leaves_an_empty_live_set(void) {
    fx_t f;
    ASSERT(up(&f));
    firc_nf_prefix_t p = v4(10, 1, 0, 0, 16);
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &p, 1));
    ASSERT_EQ(FIRC_OK, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, NULL, 0));
    ASSERT(fake_setnl_has(f.kernel, "fAS4"));
    ASSERT_EQ_FMT((size_t)0, fake_setnl_count(f.kernel, "fAS4"), "%zu");
    ASSERT_FALSE(fake_setnl_has(f.kernel, "fAT4"));
    down(&f);
    PASS();
}

TEST destroying_an_absent_set_is_ok(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "other", 4);
    ASSERT_EQ(FIRC_OK, firc_setnl_destroy(f.s, "fAS4"));
    ASSERT_EQ_FMT((size_t)1, fake_setnl_messages(f.kernel), "%zu");
    ASSERT(fake_setnl_has(f.kernel, "other"));
    down(&f);
    PASS();
}

TEST destroying_a_referenced_set_is_again(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fAS4", 4);
    fake_setnl_reference(f.kernel, "fAS4", true);
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_setnl_destroy(f.s, "fAS4"));
    ASSERT(fake_setnl_has(f.kernel, "fAS4"));
    down(&f);
    PASS();
}

TEST destroying_without_a_name_sends_nothing(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fAS4", 4);
    fake_setnl_plant(f.kernel, "_NDM_X", 4);
    ASSERT_EQ(FIRC_ERR_INVAL, firc_setnl_destroy(f.s, NULL));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_setnl_destroy(f.s, ""));
    ASSERT_EQ_FMT((size_t)0, fake_setnl_messages(f.kernel), "%zu");
    ASSERT_EQ_FMT((size_t)2, fake_setnl_sets(f.kernel), "%zu");
    down(&f);
    PASS();
}

TEST a_sweep_destroys_only_names_with_the_prefix_and_keeps_the_kept(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fircAS4", 4);
    fake_setnl_plant(f.kernel, "fircBS4", 4);
    fake_setnl_plant(f.kernel, "fircBT4", 4);
    fake_setnl_plant(f.kernel, "_NDM_X", 4);
    const char *keep[] = {"fircAS4"};
    size_t destroyed = 0;
    ASSERT_EQ(FIRC_OK, firc_setnl_sweep(f.s, "firc", keep, 1, &destroyed));
    ASSERT_EQ_FMT((size_t)2, destroyed, "%zu");
    ASSERT(fake_setnl_has(f.kernel, "fircAS4"));
    ASSERT(fake_setnl_has(f.kernel, "_NDM_X"));
    ASSERT_EQ_FMT((size_t)2, fake_setnl_sets(f.kernel), "%zu");
    down(&f);
    PASS();
}

TEST a_sweep_without_a_prefix_sends_nothing(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "_NDM_X", 4);
    size_t destroyed = 0;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_setnl_sweep(f.s, "", NULL, 0, &destroyed));
    ASSERT_EQ(FIRC_ERR_INVAL, firc_setnl_sweep(f.s, NULL, NULL, 0, &destroyed));
    ASSERT_EQ_FMT((size_t)0, fake_setnl_messages(f.kernel), "%zu");
    ASSERT(fake_setnl_has(f.kernel, "_NDM_X"));
    down(&f);
    PASS();
}

TEST a_sweep_skips_a_referenced_set_and_says_again(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_plant(f.kernel, "fircAS4", 4);
    fake_setnl_plant(f.kernel, "fircBS4", 4);
    fake_setnl_plant(f.kernel, "fircCS4", 4);
    fake_setnl_reference(f.kernel, "fircAS4", true);
    size_t destroyed = 0;
    ASSERT_EQ(FIRC_ERR_AGAIN, firc_setnl_sweep(f.s, "firc", NULL, 0, &destroyed));
    ASSERT_EQ_FMT((size_t)2, destroyed, "%zu");
    ASSERT(fake_setnl_has(f.kernel, "fircAS4"));
    ASSERT_EQ_FMT((size_t)1, fake_setnl_sets(f.kernel), "%zu");
    down(&f);
    PASS();
}

TEST a_kernel_without_the_type_says_so(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_no_type(f.kernel);
    firc_setnl_caps_t caps = {true, 9, 9};
    ASSERT_EQ(FIRC_OK, firc_setnl_probe(f.s, &caps));
    ASSERT_FALSE(caps.has_type);
    firc_nf_prefix_t p = v4(10, 1, 0, 0, 16);
    ASSERT_EQ(FIRC_ERR_NOSYS, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &p, 1));
    ASSERT_EQ_FMT((size_t)0, fake_setnl_sets(f.kernel), "%zu");
    const uint8_t *d = NULL;
    size_t len = 0;
    ASSERT_FALSE(fake_setnl_last_datagram(f.kernel, 2, &d, &len));
    down(&f);
    PASS();
}

TEST a_kernel_without_ip_set_is_nosys(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_no_subsystem(f.kernel);
    firc_setnl_caps_t caps;
    ASSERT_EQ(FIRC_ERR_NOSYS, firc_setnl_probe(f.s, &caps));
    firc_nf_prefix_t p = v4(10, 1, 0, 0, 16);
    ASSERT_EQ(FIRC_ERR_NOSYS, firc_setnl_replace(f.s, "fAS4", "fAT4", 4, &p, 1));
    down(&f);
    PASS();
}

static int64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

TEST a_kernel_that_never_answers_times_out(void) {
    fx_t f;
    ASSERT(up(&f));
    fake_setnl_never_answer(f.kernel);
    firc_setnl_caps_t caps;
    int64_t t0 = mono_ms();
    alarm(10);
    firc_err_t err = firc_setnl_probe(f.s, &caps);
    alarm(0);
    int64_t took = mono_ms() - t0;
    ASSERT_EQ(FIRC_ERR_TIMEOUT, err);
    ASSERT(took >= 1900);
    ASSERT(took < 4000);
    down(&f);
    PASS();
}

SUITE(setnl) {
    RUN_TEST(create_is_these_bytes);
    RUN_TEST(add_v4_is_these_bytes);
    RUN_TEST(add_v6_is_these_bytes);
    RUN_TEST(swap_is_these_bytes);
    RUN_TEST(rename_is_these_bytes);
    RUN_TEST(destroy_is_these_bytes);
    RUN_TEST(list_names_is_these_bytes);
    RUN_TEST(a_first_replace_leaves_one_live_set_with_every_prefix);
    RUN_TEST(a_second_replace_swaps_and_drops_the_old_members);
    RUN_TEST(a_replace_writes_the_probed_revision_and_family);
    RUN_TEST(a_replace_of_many_prefixes_batches_its_adds);
    RUN_TEST(a_large_set_asks_for_room);
    RUN_TEST(a_failed_add_leaves_the_live_set_and_the_handle_usable);
    RUN_TEST(the_first_failed_add_of_a_datagram_is_the_error);
    RUN_TEST(a_leftover_scratch_is_replaced_not_reused);
    RUN_TEST(a_scratch_busy_after_the_swap_still_leaves_the_new_live_set);
    RUN_TEST(a_create_that_fails_after_making_the_set_leaves_no_scratch);
    RUN_TEST(a_swap_the_kernel_calls_busy_is_again_and_leaves_live);
    RUN_TEST(a_rename_refused_as_referenced_is_again_and_leaves_no_scratch);
    RUN_TEST(a_scratch_named_as_the_live_set_is_refused_before_a_send);
    RUN_TEST(a_prefix_of_length_zero_or_the_other_family_is_refused_before_a_send);
    RUN_TEST(an_empty_replace_leaves_an_empty_live_set);
    RUN_TEST(destroying_an_absent_set_is_ok);
    RUN_TEST(destroying_a_referenced_set_is_again);
    RUN_TEST(destroying_without_a_name_sends_nothing);
    RUN_TEST(a_sweep_destroys_only_names_with_the_prefix_and_keeps_the_kept);
    RUN_TEST(a_sweep_without_a_prefix_sends_nothing);
    RUN_TEST(a_sweep_skips_a_referenced_set_and_says_again);
    RUN_TEST(a_kernel_without_the_type_says_so);
    RUN_TEST(a_kernel_without_ip_set_is_nosys);
    RUN_TEST(a_kernel_that_never_answers_times_out);
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_SUITE(setnl);
    GREATEST_MAIN_END();
}
