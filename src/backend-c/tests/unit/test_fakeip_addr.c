#include "greatest.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "firc/fakeip_addr.h"

/* Formats into the caller's buffer, so two formatted values never share one static buffer. */
static const char *hex(const firc_ip_t *a, char buf[48]) {
    size_t n = 0;
    for (uint8_t i = 0; i < a->len; i++) {
        n += (size_t)snprintf(buf + n, 48 - n, "%s%02x", i ? ":" : "", a->b[i]);
    }
    return buf;
}

static firc_ip_t ip(uint8_t len, const char *bytes) {
    firc_ip_t a = {{0}, len};
    memcpy(a.b, bytes, len);
    return a;
}

/* An address whose bytes past `len` are poisoned: code must neither read nor write them. */
static firc_ip_t ip_poisoned_tail(uint8_t len, const char *bytes) {
    firc_ip_t a = ip(len, bytes);
    memset(a.b + len, 0x5a, sizeof(a.b) - len);
    return a;
}

/* Catches: adding only to the last byte, carrying the wrong way, or a width that stops at 8 bytes. */
TEST addition_carries_towards_the_front_of_the_address(void) {
    char buf[48];

    firc_ip_t v4 = ip(4, "\xc6\x12\x00\xff");
    firc_ip_add(&v4, 1);
    ASSERT_STR_EQ("c6:12:01:00", hex(&v4, buf));

    firc_ip_t v6 = ip(16, "\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff");
    firc_ip_add(&v6, 1);
    ASSERT_STR_EQ("fd:00:00:00:00:00:00:00:00:00:00:00:00:01:00:00", hex(&v6, buf));

    firc_ip_t top = ip(16, "\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff");
    firc_ip_add(&top, 1);
    ASSERT_STR_EQ("00:00:00:00:00:00:01:00:00:00:00:00:00:00:00:00", hex(&top, buf));

    PASS();
}

/* Catches: alignment checked on a fixed width instead of one derived from the prefix. */
TEST alignment_is_judged_over_the_whole_address(void) {
    firc_ip_t v4 = ip(4, "\xc6\x12\x00\x00");
    ASSERT(firc_ip_aligned(&v4, 15));

    firc_ip_t off = ip(4, "\xc6\x13\x00\x00");
    ASSERT_FALSE(firc_ip_aligned(&off, 15));
    ASSERT(firc_ip_aligned(&off, 16));

    firc_ip_t bit = ip(4, "\xc6\x12\x00\x80");
    ASSERT_FALSE(firc_ip_aligned(&bit, 24));
    ASSERT(firc_ip_aligned(&bit, 25));

    firc_ip_t v6 = ip(16, "\xfd\x37\x9a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    ASSERT(firc_ip_aligned(&v6, 48));
    firc_ip_t v6off = ip(16, "\xfd\x37\x9a\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00");
    ASSERT_FALSE(firc_ip_aligned(&v6off, 48));
    ASSERT(firc_ip_aligned(&v6off, 64));

    PASS();
}

/* Catches: the shift folded into a 64-bit count, losing the high bits of a v6 chunk base. */
TEST a_chunk_base_is_the_pool_base_plus_a_shifted_index(void) {
    char buf[48];

    firc_ip_t a = ip(4, "\xc6\x12\x00\x00");
    ASSERT(firc_ip_add_shifted(&a, 1, 8));
    ASSERT_STR_EQ("c6:12:01:00", hex(&a, buf));

    firc_ip_t b = ip(4, "\xc6\x12\x00\x00");
    ASSERT(firc_ip_add_shifted(&b, 3, 6));
    ASSERT_STR_EQ("c6:12:00:c0", hex(&b, buf));

    firc_ip_t c = ip(4, "\xc6\x12\x00\x00");
    ASSERT(firc_ip_add_shifted(&c, 511, 8));
    ASSERT_STR_EQ("c6:13:ff:00", hex(&c, buf));

    firc_ip_t d = ip(16, "\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    ASSERT(firc_ip_add_shifted(&d, 1, 64));
    ASSERT_STR_EQ("fd:00:00:00:00:00:00:01:00:00:00:00:00:00:00:00", hex(&d, buf));

    firc_ip_t e = ip(16, "\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    ASSERT(firc_ip_add_shifted(&e, 65537, 64));
    ASSERT_STR_EQ("fd:00:00:00:00:01:00:01:00:00:00:00:00:00:00:00", hex(&e, buf));

    firc_ip_t top = ip(16, "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff");
    ASSERT_FALSEm("a carry out of the address is reported", firc_ip_add_shifted(&top, 1, 64));
    ASSERT_STR_EQm("and the value is left as it was",
                   "ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff:ff", hex(&top, buf));

    firc_ip_t spill = ip(4, "\xc6\x12\x00\x00");
    ASSERT(firc_ip_add_shifted(&spill, 5, 6));
    ASSERT_STR_EQm("a shifted limb wider than a byte", "c6:12:01:40", hex(&spill, buf));

    firc_ip_t carry = ip(4, "\xc6\x12\x00\xc0");
    ASSERT(firc_ip_add_shifted(&carry, 1, 6));
    ASSERT_STR_EQm("the carry travels out of the byte it started in", "c6:12:01:00",
                   hex(&carry, buf));

    PASS();
}

/* Catches: a delta used as one byte, a carry stopped early or off the top, or a wrong byte shift. */
TEST addition_handles_wide_deltas_deep_carries_and_the_top_of_the_address(void) {
    char buf[48];

    firc_ip_t wide = ip(4, "\x00\x00\x00\x00");
    firc_ip_add(&wide, 0x01020304u);
    ASSERT_STR_EQm("a delta wider than a byte", "01:02:03:04", hex(&wide, buf));

    firc_ip_t ceiling = ip(4, "\xff\xff\xff\xff");
    firc_ip_add(&ceiling, 1);
    ASSERT_STR_EQm("the documented wrap at the address width", "00:00:00:00",
                   hex(&ceiling, buf));

    firc_ip_t top_limb = ip(16, "\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    ASSERT(firc_ip_add_shifted(&top_limb, UINT64_C(1) << 56, 0));
    ASSERT_STR_EQm("the count's top byte is not dropped",
                   "fd:00:00:00:00:00:00:00:01:00:00:00:00:00:00:00", hex(&top_limb, buf));

    firc_ip_t deep = ip(16, "\x00\x00\x00\x00\x00\x00\x12\xff\xff\xff\xff\xff\xff\xff\xff\xff");
    ASSERT(firc_ip_add_shifted(&deep, 1, 0));
    ASSERT_STR_EQm("a carry travelling past the nine bytes of addend",
                   "00:00:00:00:00:00:13:00:00:00:00:00:00:00:00:00", hex(&deep, buf));

    firc_ip_t ninth = ip(16, "\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
    ASSERT(firc_ip_add_shifted(&ninth, UINT64_C(1) << 63, 1));
    ASSERT_STR_EQm("the spill reaches the ninth byte of the addend",
                   "fd:00:00:00:00:00:00:01:00:00:00:00:00:00:00:00", hex(&ninth, buf));

    firc_ip_t above = ip(4, "\xc6\x12\x00\x00");
    ASSERT_FALSEm("an addend entirely above the address is refused",
                  firc_ip_add_shifted(&above, 1, 32));
    ASSERT_STR_EQm("and nothing is written", "c6:12:00:00", hex(&above, buf));

    PASS();
}

/* Catches: a prefix equal to the width refused, one past it accepted, or bytes past `len` read. */
TEST alignment_at_the_width_and_the_bytes_it_is_allowed_to_read(void) {
    firc_ip_t v4 = ip(4, "\xc6\x12\x00\x01");
    ASSERTm("a prefix equal to the width leaves no host bits", firc_ip_aligned(&v4, 32));
    ASSERT_FALSEm("a prefix past the width is refused", firc_ip_aligned(&v4, 33));

    firc_ip_t v6 = ip(16, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01");
    ASSERT(firc_ip_aligned(&v6, 128));
    ASSERT_FALSE(firc_ip_aligned(&v6, 129));

    firc_ip_t tail = ip_poisoned_tail(4, "\xc6\x12\x00\x00");
    ASSERTm("bytes past len are not the address and must not be read",
            firc_ip_aligned(&tail, 24));

    PASS();
}

/* Catches: the family guessed from anything but the text, or a bad or trailing prefix accepted. */
TEST cidr_text_is_parsed_into_an_address_and_a_prefix(void) {
    static const struct {
        const char *text;
        bool ok;
        uint8_t len;
        uint8_t prefix;
        const char *bytes;
    } rows[] = {
        {"198.18.0.0/15", true, 4, 15, "c6:12:00:00"},
        {"0.0.0.0/0", true, 4, 0, "00:00:00:00"},
        {"255.255.255.255/32", true, 4, 32, "ff:ff:ff:ff"},
        {"fd37:9a00::/48", true, 16, 48,
         "fd:37:9a:00:00:00:00:00:00:00:00:00:00:00:00:00"},
        {"::/0", true, 16, 0, "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"},
        {"2606:2800:220:1::/64", true, 16, 64,
         "26:06:28:00:02:20:00:01:00:00:00:00:00:00:00:00"},
        {"198.18.0.0/33", false, 0, 0, NULL},
        {"fd37::/33", true, 16, 33, "fd:37:00:00:00:00:00:00:00:00:00:00:00:00:00:00"},
        {"fd37::/129", false, 0, 0, NULL},
        {"198.18.0.0", false, 0, 0, NULL},
        {"198.18.0.0/", false, 0, 0, NULL},
        {"198.18.0.0/1x", false, 0, 0, NULL},
        {"198.18.0.0/15x", false, 0, 0, NULL},
        {"198.18.0.0/-1", false, 0, 0, NULL},
        {"not-an-address/15", false, 0, 0, NULL},
        {"198.18.0.0.0/15", false, 0, 0, NULL},
        {"/15", false, 0, 0, NULL},
        {"", false, 0, 0, NULL},
        {"198.18.0.0/4294967326", false, 0, 0, NULL},
        {"198.18.0.0/99999999999999999999", false, 0, 0, NULL},
        {"2001:0db8:0000:0000:0000:ffff:192.168.100.228/96", true, 16, 96,
         "20:01:0d:b8:00:00:00:00:00:00:ff:ff:c0:a8:64:e4"},
        {"2001:0db8:0000:0000:0000:ffff:192.168.100.2288/96", false, 0, 0, NULL},
    };

    char buf[48];
    firc_ip_t dummy;
    uint8_t dummy_prefix;
    ASSERT_FALSE(firc_ip_parse_cidr(NULL, &dummy, &dummy_prefix));
    ASSERT_FALSE(firc_ip_parse_cidr("198.18.0.0/15", NULL, &dummy_prefix));
    ASSERT_FALSE(firc_ip_parse_cidr("198.18.0.0/15", &dummy, NULL));

    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        firc_ip_t a;
        uint8_t prefix = 99;
        memset(&a, 0x5a, sizeof(a));
        bool ok = firc_ip_parse_cidr(rows[i].text, &a, &prefix);
        ASSERT_EQm(rows[i].text, rows[i].ok, ok);
        if (!rows[i].ok) {
            firc_ip_t untouched;
            memset(&untouched, 0x5a, sizeof(untouched));
            ASSERT_MEM_EQm(rows[i].text, &untouched, &a, sizeof(a));
            ASSERT_EQ_FMTm(rows[i].text, 99u, (unsigned)prefix, "%u");
            continue;
        }
        ASSERT_EQ_FMTm(rows[i].text, rows[i].len, a.len, "%u");
        ASSERT_EQ_FMTm(rows[i].text, rows[i].prefix, prefix, "%u");
        ASSERT_STR_EQm(rows[i].text, rows[i].bytes, hex(&a, buf));
    }
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(addition_carries_towards_the_front_of_the_address);
    RUN_TEST(alignment_is_judged_over_the_whole_address);
    RUN_TEST(a_chunk_base_is_the_pool_base_plus_a_shifted_index);
    RUN_TEST(addition_handles_wide_deltas_deep_carries_and_the_top_of_the_address);
    RUN_TEST(alignment_at_the_width_and_the_bytes_it_is_allowed_to_read);
    RUN_TEST(cidr_text_is_parsed_into_an_address_and_a_prefix);
    GREATEST_MAIN_END();
}
