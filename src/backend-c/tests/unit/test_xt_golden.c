#include "greatest.h"

#include <stdlib.h>
#include <string.h>

#include "xt_golden.h"
#include "../../src/xtables/abi.h"

enum { K_TARGET_OFFSET = 88, K_NEXT_OFFSET = 90, K_FLAGS = 82, K_COMEFROM = 92, K_COUNTERS = 96, K_SRC = 0, K_DST = 4, K_SMSK = 8, K_DMSK = 12, K_V4_HEADER = 112 };

static const firc_ipt_proto_t k_fams[] = {FIRC_IPT_PROTO_IPV4, FIRC_IPT_PROTO_IPV6};

/* Catches: the test printer saying a rule differently from iptables-save, so every nat view in the unit tests would lie. */
TEST the_printer_says_what_iptables_save_said(void) {
    for (size_t i = 0; i < firc_test_xt_n_fixtures; i++) {
        for (size_t f = 0; f < 2; f++) {
            const char *name = firc_test_xt_fixtures[i];
            firc_xt_info_t info;
            uint8_t *blob = NULL;
            ASSERTm(name, firc_test_xt_read(name, k_fams[f], &info, &blob));
            char *got = firc_test_xt_print(k_fams[f], &info, blob);
            char *want = firc_test_xt_read_text(name, k_fams[f]);
            ASSERTm(name, got != NULL && want != NULL);
            ASSERT_STR_EQm(name, want, got);
            free(got);
            free(want);
            free(blob);
        }
    }
    PASS();
}

/* Catches: the loader passing an extension it cannot convert, so a big-endian run compares unconverted bytes. */
TEST an_unknown_extension_is_not_converted(void) {
    size_t len = 0;
    uint8_t *raw = firc_test_xt_raw("firmware", FIRC_IPT_PROTO_IPV4, &len);
    ASSERT(raw != NULL && len > XT_REPLACE_HDR_LEN);
    uint8_t *snat = NULL;
    for (size_t i = XT_REPLACE_HDR_LEN; i + 4 <= len && snat == NULL; i++) {
        if (memcmp(raw + i, "SNAT", 4) == 0) { snat = raw + i; }
    }
    ASSERT(snat != NULL);
    snat[0] = 'X';
    ASSERT_FALSE(firc_test_xt_to_host(FIRC_IPT_PROTO_IPV4, raw + XT_REPLACE_HDR_LEN, (uint32_t)(len - XT_REPLACE_HDR_LEN)));
    free(raw);
    PASS();
}

/* Catches: the comparison seeing counters a kernel write never compares, or missing a changed address. */
TEST same_ignores_counters_and_comefrom_only(void) {
    firc_xt_info_t ai, bi;
    uint8_t *a = NULL, *b = NULL;
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &ai, &a));
    ASSERT(firc_test_xt_read("firmware-firc", FIRC_IPT_PROTO_IPV4, &bi, &b));
    uint32_t last = 0;
    for (uint32_t off = 0; off < bi.size;) {
        last = off;
        uint16_t next;
        memcpy(&next, b + off + K_NEXT_OFFSET, 2);
        off += next;
    }
    ASSERT(last > 0);
    uint32_t at[2] = {0, last};
    for (int k = 0; k < 2; k++) {
        memset(b + at[k] + K_COUNTERS, 0x11, 16);
        b[at[k] + K_COMEFROM] = 0x01;
    }
    ASSERT(firc_test_xt_same(FIRC_IPT_PROTO_IPV4, &ai, a, &bi, b));
    b[last + K_SRC] ^= 0x01;
    ASSERT_FALSE(firc_test_xt_same(FIRC_IPT_PROTO_IPV4, &ai, a, &bi, b));
    b[last + K_SRC] ^= 0x01;
    b[0 + K_SRC] ^= 0x01;
    ASSERT_FALSE(firc_test_xt_same(FIRC_IPT_PROTO_IPV4, &ai, a, &bi, b));
    free(a);
    free(b);
    PASS();
}

/* Catches: the printer losing the order of -s and -d or the goto form, which no captured fixture exercises. */
TEST source_destination_and_goto_print_in_iptables_order(void) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_test_xt_read("tiny", FIRC_IPT_PROTO_IPV4, &info, &blob));
    uint32_t hit = UINT32_MAX;
    for (uint32_t off = 0; off < info.size;) {
        uint16_t toff, next;
        memcpy(&toff, blob + off + K_TARGET_OFFSET, 2);
        memcpy(&next, blob + off + K_NEXT_OFFSET, 2);
        if (blob[off + toff + 2] == '\0' && toff == K_V4_HEADER && next == K_V4_HEADER + XT_STANDARD_TARGET_LEN) {
            int32_t verdict;
            memcpy(&verdict, blob + off + toff + 32, 4);
            if (verdict > 0) { hit = off; }
        }
        off += next;
    }
    ASSERT(hit != UINT32_MAX);
    static const uint8_t src[4] = {10, 0, 0, 0}, smsk[4] = {255, 0, 0, 0};
    static const uint8_t dst[4] = {192, 168, 1, 1}, dmsk[4] = {255, 255, 255, 255};
    memcpy(blob + hit + K_SRC, src, 4);
    memcpy(blob + hit + K_DST, dst, 4);
    memcpy(blob + hit + K_SMSK, smsk, 4);
    memcpy(blob + hit + K_DMSK, dmsk, 4);
    blob[hit + K_FLAGS] = 0x02;
    char *got = firc_test_xt_print(FIRC_IPT_PROTO_IPV4, &info, blob);
    ASSERT(got != NULL);
    ASSERT(strstr(got, "-A POSTROUTING -s 10.0.0.0/8 -d 192.168.1.1/32 -g FIRC_g1\n") != NULL);
    free(got);
    free(blob);
    PASS();
}

/* Catches: a corrupt next_offset or target size sending the loader or printer past the blob or into a loop. */
TEST corrupt_blobs_are_refused_not_followed(void) {
    firc_xt_info_t info;
    uint8_t *blob = NULL;
    ASSERT(firc_test_xt_read("tiny", FIRC_IPT_PROTO_IPV4, &info, &blob));
    uint16_t zero = 0, huge = 0xfff0, small = 40;
    memcpy(blob + K_NEXT_OFFSET, &zero, 2);
    ASSERT(firc_test_xt_print(FIRC_IPT_PROTO_IPV4, &info, blob) == NULL);
    memcpy(blob + K_NEXT_OFFSET, &huge, 2);
    ASSERT(firc_test_xt_print(FIRC_IPT_PROTO_IPV4, &info, blob) == NULL);
    memcpy(blob + K_NEXT_OFFSET, &small, 2);
    ASSERT(firc_test_xt_print(FIRC_IPT_PROTO_IPV4, &info, blob) == NULL);
    free(blob);
    size_t len = 0;
    uint8_t *raw = firc_test_xt_raw("tiny", FIRC_IPT_PROTO_IPV4, &len);
    ASSERT(raw != NULL);
    uint8_t *e = raw + XT_REPLACE_HDR_LEN;
    uint16_t toff;
    memcpy(&toff, e + K_TARGET_OFFSET, 2);
    e[toff] = 0;
    e[toff + 1] = 0;
    ASSERT_FALSE(firc_test_xt_to_host(FIRC_IPT_PROTO_IPV4, e, (uint32_t)(len - XT_REPLACE_HDR_LEN)));
    free(raw);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_printer_says_what_iptables_save_said);
    RUN_TEST(an_unknown_extension_is_not_converted);
    RUN_TEST(source_destination_and_goto_print_in_iptables_order);
    RUN_TEST(corrupt_blobs_are_refused_not_followed);
    RUN_TEST(same_ignores_counters_and_comefrom_only);
    GREATEST_MAIN_END();
}
