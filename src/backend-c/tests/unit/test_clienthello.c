#include "greatest.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "firc/clienthello.h"

static size_t hello_ex(uint8_t *out, size_t cap, const char *sni, uint8_t major, uint8_t minor,
                       bool sni_first);

static size_t hello(uint8_t *out, size_t cap, const char *sni, uint8_t major, uint8_t minor) {
    return hello_ex(out, cap, sni, major, minor, true);
}

/* Builds a TLS record with a ClientHello naming `sni` (no server_name when NULL); returns its length. */
static size_t hello_ex(uint8_t *out, size_t cap, const char *sni, uint8_t major, uint8_t minor,
                       bool sni_first) {
    uint8_t body[1024];
    size_t b = 0;
    body[b++] = 0x03;
    body[b++] = 0x03;
    memset(body + b, 0xab, 32);
    b += 32;
    body[b++] = 0;
    body[b++] = 0;
    body[b++] = 2;
    body[b++] = 0x13;
    body[b++] = 0x01;
    body[b++] = 1;
    body[b++] = 0;

    uint8_t ext[512];
    size_t e = 0;
    if (!sni_first) {
        ext[e++] = 0x00;
        ext[e++] = 0x2b;
        ext[e++] = 0x00;
        ext[e++] = 0x03;
        ext[e++] = 0x02;
        ext[e++] = 0x03;
        ext[e++] = 0x04;
    }
    if (sni != NULL) {
        size_t n = strlen(sni);
        ext[e++] = 0x00;
        ext[e++] = 0x00;
        ext[e++] = (uint8_t)((n + 5) >> 8);
        ext[e++] = (uint8_t)(n + 5);
        ext[e++] = (uint8_t)((n + 3) >> 8);
        ext[e++] = (uint8_t)(n + 3);
        ext[e++] = 0x00;
        ext[e++] = (uint8_t)(n >> 8);
        ext[e++] = (uint8_t)n;
        memcpy(ext + e, sni, n);
        e += n;
    }
    ext[e++] = 0x00;
    ext[e++] = 0x2b;
    ext[e++] = 0x00;
    ext[e++] = 0x03;
    ext[e++] = 0x02;
    ext[e++] = 0x03;
    ext[e++] = 0x04;

    body[b++] = (uint8_t)(e >> 8);
    body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e);
    b += e;

    size_t o = 0;
    out[o++] = 0x16;
    out[o++] = major;
    out[o++] = minor;
    out[o++] = (uint8_t)((b + 4) >> 8);
    out[o++] = (uint8_t)(b + 4);
    out[o++] = 0x01;
    out[o++] = 0;
    out[o++] = (uint8_t)(b >> 8);
    out[o++] = (uint8_t)b;
    memcpy(out + o, body, b);
    o += b;
    (void)cap;
    return o;
}

TEST the_sni_is_read_from_a_client_hello(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "example.com", 0x03, 0x01);
    ASSERT(firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    ASSERT_STR_EQ("example.com", name);
    PASS();
}

/* Catches: the first extension read as the server_name. */
TEST an_sni_after_another_extension_is_found(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello_ex(buf, sizeof(buf), "deep.sub.example.org", 0x03, 0x03, false);
    ASSERT(firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    ASSERT_STR_EQm("stepped over the extension in front of it", "deep.sub.example.org", name);
    PASS();
}

TEST a_hello_without_a_server_name_has_none(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), NULL, 0x03, 0x01);
    ASSERT_FALSEm("no extension, no answer", firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    PASS();
}

/* Catches: a length that points past the buffer followed instead of refused. */
TEST every_truncation_is_refused(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "example.com", 0x03, 0x01);
    for (size_t cut = 0; cut < n; cut++) {
        uint8_t *exact = malloc(cut ? cut : 1);
        ASSERT(exact != NULL);
        memcpy(exact, buf, cut);
        (void)firc_tls_client_hello_sni(exact, cut, name, sizeof(name));
        free(exact);
    }
    PASS();
}

/* Catches: a short capture refused on its outer lengths, or read past what arrived. */
TEST the_outer_lengths_are_what_a_short_capture_looks_like(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "example.com", 0x03, 0x01);

    uint8_t *exact = malloc(n);
    ASSERT(exact != NULL);
    memcpy(exact, buf, n);
    exact[3] = 0xff;
    exact[4] = 0xff;
    bool got = firc_tls_client_hello_sni(exact, n, name, sizeof(name));
    bool right = got && strcmp(name, "example.com") == 0;
    free(exact);
    ASSERTm("a record longer than the capture is still read", right);

    exact = malloc(n);
    ASSERT(exact != NULL);
    memcpy(exact, buf, n);
    exact[6] = 0xff;
    exact[7] = 0xff;
    exact[8] = 0xff;
    got = firc_tls_client_hello_sni(exact, n, name, sizeof(name));
    right = got && strcmp(name, "example.com") == 0;
    free(exact);
    ASSERTm("a handshake longer than the capture is still read", right);
    PASS();
}

/* Catches: a capture cut after the name refused instead of giving the name. */
TEST a_capture_cut_after_the_name_still_gives_it(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello_ex(buf, sizeof(buf), "example.com", 0x03, 0x03, false);

    const uint8_t *at = NULL;
    for (size_t i = 0; i + 11 < n; i++) {
        if (memcmp(buf + i, "example.com", 11) == 0) {
            at = buf + i + 11;
            break;
        }
    }
    ASSERT(at != NULL);
    size_t cut = (size_t)(at - buf);
    ASSERTm("the name is not the last thing in the hello", cut < n);

    uint8_t *exact = malloc(cut);
    ASSERT(exact != NULL);
    memcpy(exact, buf, cut);
    bool got = firc_tls_client_hello_sni(exact, cut, name, sizeof(name));
    bool right = got && strcmp(name, "example.com") == 0;
    free(exact);
    ASSERT(right);
    PASS();
}

/* Catches: a host_name length past its extension read past the record. */
TEST a_name_longer_than_its_extension_is_refused(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "example.com", 0x03, 0x01);

    uint8_t *at = NULL;
    for (size_t i = 0; i + 11 < n; i++) {
        if (memcmp(buf + i, "example.com", 11) == 0) {
            at = buf + i - 2;
            break;
        }
    }
    ASSERT(at != NULL);
    at[0] = 0x00;
    at[1] = 200;

    uint8_t *exact = malloc(n);
    ASSERT(exact != NULL);
    memcpy(exact, buf, n);
    bool got = firc_tls_client_hello_sni(exact, n, name, sizeof(name));
    free(exact);
    ASSERT_FALSEm("a name that runs past its extension is not read", got);
    PASS();
}

TEST only_a_tls_handshake_client_hello_is_read(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "example.com", 0x03, 0x01);

    uint8_t bad[1024];
    memcpy(bad, buf, n);
    bad[0] = 0x17;
    ASSERT_FALSE(firc_tls_client_hello_sni(bad, n, name, sizeof(name)));

    memcpy(bad, buf, n);
    bad[5] = 0x02;
    ASSERT_FALSEm("a ServerHello is not ours to read",
                  firc_tls_client_hello_sni(bad, n, name, sizeof(name)));
    PASS();
}

/* Catches: a host_name longer than the buffer truncated instead of refused. */
TEST a_name_too_long_for_the_buffer_is_refused(void) {
    uint8_t buf[1024];
    char small[8];
    size_t n = hello(buf, sizeof(buf), "example.com", 0x03, 0x01);
    ASSERT_FALSE(firc_tls_client_hello_sni(buf, n, small, sizeof(small)));
    PASS();
}

/* Catches: a name with a NUL or a byte outside the DNS grammar accepted. */
TEST a_name_that_is_not_a_name_is_refused(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "ex\x01mple.com", 0x03, 0x01);
    ASSERT_FALSEm("a control byte is not a host name",
                  firc_tls_client_hello_sni(buf, n, name, sizeof(name)));

    n = hello(buf, sizeof(buf), "", 0x03, 0x01);
    ASSERT_FALSEm("an empty name is not one", firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    PASS();
}

/* Catches: a capture cut inside the name answered with half a name. */
TEST a_capture_cut_inside_the_name_is_a_refusal(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "example.com", 0x03, 0x03);

    const uint8_t *at = NULL;
    for (size_t i = 0; i + 11 < n; i++) {
        if (memcmp(buf + i, "example.com", 11) == 0) {
            at = buf + i;
            break;
        }
    }
    ASSERT(at != NULL);
    size_t name_at = (size_t)(at - buf);

    for (size_t cut = name_at + 1; cut < name_at + 11; cut++) {
        uint8_t *exact = malloc(cut);
        ASSERT(exact != NULL);
        memcpy(exact, buf, cut);
        bool got = firc_tls_client_hello_sni(exact, cut, name, sizeof(name));
        free(exact);
        ASSERT_FALSEm("half a name is a different domain", got);
    }

    for (size_t cut = name_at - 9; cut < name_at; cut++) {
        uint8_t *exact = malloc(cut);
        ASSERT(exact != NULL);
        memcpy(exact, buf, cut);
        bool got = firc_tls_client_hello_sni(exact, cut, name, sizeof(name));
        free(exact);
        ASSERT_FALSEm("a list that did not arrive holds no name", got);
    }
    PASS();
}

TEST a_server_name_extension_without_a_host_name_ends_it(void) {
    uint8_t body[256];
    size_t b = 0;
    body[b++] = 0x03;
    body[b++] = 0x03;
    memset(body + b, 0xcd, 32);
    b += 32;
    body[b++] = 0;
    body[b++] = 0;
    body[b++] = 2;
    body[b++] = 0x13;
    body[b++] = 0x01;
    body[b++] = 1;
    body[b++] = 0;

    uint8_t ext[128];
    size_t e = 0;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x07;
    ext[e++] = 0x00;
    ext[e++] = 0x05;
    ext[e++] = 0x09;
    ext[e++] = 0x00;
    ext[e++] = 0x02;
    ext[e++] = 'x';
    ext[e++] = 'y';
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x10;
    ext[e++] = 0x00;
    ext[e++] = 0x0e;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x0b;
    memcpy(ext + e, "second.test", 11);
    e += 11;

    body[b++] = (uint8_t)(e >> 8);
    body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e);
    b += e;

    uint8_t buf[512];
    size_t at = 0;
    buf[at++] = 0x16;
    buf[at++] = 0x03;
    buf[at++] = 0x01;
    buf[at++] = (uint8_t)((b + 4) >> 8);
    buf[at++] = (uint8_t)(b + 4);
    buf[at++] = 0x01;
    buf[at++] = 0x00;
    buf[at++] = (uint8_t)(b >> 8);
    buf[at++] = (uint8_t)b;
    memcpy(buf + at, body, b);
    at += b;

    char name[256];
    ASSERT_FALSEm("the first server_name is the one that counts",
                  firc_tls_client_hello_sni(buf, at, name, sizeof(name)));
    PASS();
}

/* Catches: an SNI not folded to lower case, so it matches no rule. */
TEST a_name_is_folded_like_a_query(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "EXAMPLE.COM", 0x03, 0x03);
    ASSERT(firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    ASSERT_STR_EQ("example.com", name);

    n = hello(buf, sizeof(buf), "Deep.Sub.Example.Org", 0x03, 0x03);
    ASSERT(firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    ASSERT_STR_EQ("deep.sub.example.org", name);
    PASS();
}

/* Catches: a trailing dot kept, or a second one accepted. */
TEST one_trailing_dot_is_the_root_label(void) {
    uint8_t buf[1024];
    char name[256];
    size_t n = hello(buf, sizeof(buf), "example.com.", 0x03, 0x03);
    ASSERT(firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    ASSERT_STR_EQm("the dot is stripped, not kept", "example.com", name);

    n = hello(buf, sizeof(buf), "example.com..", 0x03, 0x03);
    ASSERT_FALSEm("a second dot is an empty label",
                  firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    PASS();
}

/* Catches: a name exactly the buffer's size written without room for its terminator. */
TEST a_name_needs_room_for_its_terminator(void) {
    uint8_t buf[1024];
    size_t n = hello(buf, sizeof(buf), "example.com", 0x03, 0x03);
    char exactly[12];
    char one_short[11];
    ASSERTm("eleven bytes and a terminator fit in twelve",
            firc_tls_client_hello_sni(buf, n, exactly, sizeof(exactly)));
    ASSERT_STR_EQ("example.com", exactly);
    ASSERT_FALSEm("eleven bytes do not fit in eleven",
                  firc_tls_client_hello_sni(buf, n, one_short, sizeof(one_short)));
    PASS();
}

/* Catches: an inner length reading past the extension that declared it. */
TEST a_nested_length_cannot_reach_past_the_one_that_declared_it(void) {
    uint8_t body[256];
    size_t b = 0;
    body[b++] = 0x03;
    body[b++] = 0x03;
    memset(body + b, 0xcd, 32);
    b += 32;
    body[b++] = 0;
    body[b++] = 0;
    body[b++] = 2;
    body[b++] = 0x13;
    body[b++] = 0x01;
    body[b++] = 1;
    body[b++] = 0;

    uint8_t ext[128];
    size_t e = 0;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x10;
    ext[e++] = 0x00;
    ext[e++] = 0x05;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = 0x0b;
    memcpy(ext + e, "leaked.test", 11);
    e += 11;

    body[b++] = (uint8_t)(e >> 8);
    body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e);
    b += e;

    uint8_t buf[512];
    size_t at = 0;
    buf[at++] = 0x16;
    buf[at++] = 0x03;
    buf[at++] = 0x01;
    buf[at++] = (uint8_t)((b + 4) >> 8);
    buf[at++] = (uint8_t)(b + 4);
    buf[at++] = 0x01;
    buf[at++] = 0x00;
    buf[at++] = (uint8_t)(b >> 8);
    buf[at++] = (uint8_t)b;
    memcpy(buf + at, body, b);
    at += b;

    char name[256];
    uint8_t *exact = malloc(at);
    ASSERT(exact != NULL);
    memcpy(exact, buf, at);
    bool got = firc_tls_client_hello_sni(exact, at, name, sizeof(name));
    bool leaked = got && strcmp(name, "leaked.test") == 0;
    free(exact);
    ASSERT_FALSEm("a name from beyond the extension that declared it", leaked);
    ASSERT_FALSEm("a hello whose extension does not contain its list has no name", got);
    PASS();
}

/* Catches: a non-host_name entry read as a name, or ending the list. */
TEST an_entry_that_is_not_a_host_name_is_stepped_over(void) {
    uint8_t body[256];
    size_t b = 0;
    body[b++] = 0x03;
    body[b++] = 0x03;
    memset(body + b, 0xcd, 32);
    b += 32;
    body[b++] = 0;
    body[b++] = 0;
    body[b++] = 2;
    body[b++] = 0x13;
    body[b++] = 0x01;
    body[b++] = 1;
    body[b++] = 0;

    uint8_t list[64];
    size_t l = 0;
    list[l++] = 0x02;
    list[l++] = 0x00;
    list[l++] = 0x0a;
    memcpy(list + l, "other.test", 10);
    l += 10;
    list[l++] = 0x00;
    list[l++] = 0x00;
    list[l++] = 0x0b;
    memcpy(list + l, "example.com", 11);
    l += 11;

    uint8_t ext[128];
    size_t e = 0;
    ext[e++] = 0x00;
    ext[e++] = 0x00;
    ext[e++] = (uint8_t)((l + 2) >> 8);
    ext[e++] = (uint8_t)(l + 2);
    ext[e++] = (uint8_t)(l >> 8);
    ext[e++] = (uint8_t)l;
    memcpy(ext + e, list, l);
    e += l;

    body[b++] = (uint8_t)(e >> 8);
    body[b++] = (uint8_t)e;
    memcpy(body + b, ext, e);
    b += e;

    uint8_t buf[512];
    size_t at = 0;
    buf[at++] = 0x16;
    buf[at++] = 0x03;
    buf[at++] = 0x01;
    buf[at++] = (uint8_t)((b + 4) >> 8);
    buf[at++] = (uint8_t)(b + 4);
    buf[at++] = 0x01;
    buf[at++] = 0x00;
    buf[at++] = (uint8_t)(b >> 8);
    buf[at++] = (uint8_t)b;
    memcpy(buf + at, body, b);
    at += b;

    char name[256];
    ASSERT(firc_tls_client_hello_sni(buf, at, name, sizeof(name)));
    ASSERT_STR_EQm("the entry before it was stepped over, not read", "example.com", name);
    PASS();
}

/* Catches: a name outside the rule grammar accepted. */
TEST a_name_the_matchers_could_not_match_is_refused(void) {
    uint8_t buf[2048];
    char name[512];
    char long_name[300];

    memset(long_name, 'a', sizeof(long_name));
    for (size_t i = 60; i < 254; i += 60) { long_name[i] = '.'; }
    long_name[254] = '\0';
    size_t n = hello(buf, sizeof(buf), long_name, 0x03, 0x03);
    ASSERT_FALSEm("254 bytes is more than a name can be",
                  firc_tls_client_hello_sni(buf, n, name, sizeof(name)));

    char one_label[80];
    memset(one_label, 'b', 64);
    one_label[64] = '\0';
    n = hello(buf, sizeof(buf), one_label, 0x03, 0x03);
    ASSERT_FALSEm("64 bytes is more than a label can be",
                  firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    one_label[63] = '\0';
    n = hello(buf, sizeof(buf), one_label, 0x03, 0x03);
    ASSERTm("63 is not", firc_tls_client_hello_sni(buf, n, name, sizeof(name)));

    long_name[253] = '\0';
    n = hello(buf, sizeof(buf), long_name, 0x03, 0x03);
    ASSERTm("253 is what a name can be", firc_tls_client_hello_sni(buf, n, name, sizeof(name)));

    n = hello(buf, sizeof(buf), ".", 0x03, 0x03);
    ASSERT_FALSEm("the root on its own is not a name to report",
                  firc_tls_client_hello_sni(buf, n, name, sizeof(name)));

    n = hello(buf, sizeof(buf), ".example.com", 0x03, 0x03);
    ASSERT_FALSEm("a name does not start with a dot",
                  firc_tls_client_hello_sni(buf, n, name, sizeof(name)));

    n = hello(buf, sizeof(buf), "ex..ample.com", 0x03, 0x03);
    ASSERT_FALSEm("an empty label is not one",
                  firc_tls_client_hello_sni(buf, n, name, sizeof(name)));

    n = hello(buf, sizeof(buf), "_acme-challenge.example.com", 0x03, 0x03);
    ASSERTm("an underscore is a byte firc's rules accept",
            firc_tls_client_hello_sni(buf, n, name, sizeof(name)));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(the_sni_is_read_from_a_client_hello);
    RUN_TEST(an_sni_after_another_extension_is_found);
    RUN_TEST(a_hello_without_a_server_name_has_none);
    RUN_TEST(every_truncation_is_refused);
    RUN_TEST(the_outer_lengths_are_what_a_short_capture_looks_like);
    RUN_TEST(a_capture_cut_after_the_name_still_gives_it);
    RUN_TEST(a_capture_cut_inside_the_name_is_a_refusal);
    RUN_TEST(a_server_name_extension_without_a_host_name_ends_it);
    RUN_TEST(a_name_is_folded_like_a_query);
    RUN_TEST(one_trailing_dot_is_the_root_label);
    RUN_TEST(a_name_needs_room_for_its_terminator);
    RUN_TEST(a_nested_length_cannot_reach_past_the_one_that_declared_it);
    RUN_TEST(an_entry_that_is_not_a_host_name_is_stepped_over);
    RUN_TEST(a_name_the_matchers_could_not_match_is_refused);
    RUN_TEST(a_name_longer_than_its_extension_is_refused);
    RUN_TEST(only_a_tls_handshake_client_hello_is_read);
    RUN_TEST(a_name_too_long_for_the_buffer_is_refused);
    RUN_TEST(a_name_that_is_not_a_name_is_refused);
    GREATEST_MAIN_END();
}
