#include "greatest.h"

#include <stdio.h>
#include <string.h>

#include "firc/jwt.h"

static const uint8_t SECRET[] = "0123456789abcdef0123456789abcdef";
#define SECRET_LEN (sizeof(SECRET) - 1)

TEST sign_matches_vector(void) {
    firc_jwt_claims_t claims = {0};
    snprintf(claims.sub, sizeof(claims.sub), "admin");
    snprintf(claims.iss, sizeof(claims.iss), "firc");
    claims.iat = 1700000000;
    claims.exp = 2331200000;

    char token[FIRC_JWT_MAX_TOKEN];
    ASSERT_EQ(FIRC_OK, firc_jwt_sign(&claims, SECRET, SECRET_LEN, token, sizeof(token)));
    ASSERT_STR_EQ(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsImlzcyI6ImZpcmMiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6"
        "MjMzMTIwMDAwMH0."
        "7uyMcqz_NcC_N9Eg3D4_FojrhGbgJbvFTYWv30_4gco",
        token);
    PASS();
}

TEST sign_matches_vector_zero_iat(void) {
    firc_jwt_claims_t claims = {0};
    snprintf(claims.sub, sizeof(claims.sub), "user2");
    snprintf(claims.iss, sizeof(claims.iss), "firc");
    claims.iat = 0;
    claims.exp = 630720000;

    char token[FIRC_JWT_MAX_TOKEN];
    ASSERT_EQ(FIRC_OK, firc_jwt_sign(&claims, SECRET, SECRET_LEN, token, sizeof(token)));
    ASSERT_STR_EQ(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJ1c2VyMiIsImlzcyI6ImZpcmMiLCJpYXQiOjAsImV4cCI6NjMwNzIwMDAwfQ."
        "BGgvS4y0AAGXoBopr5_Lp3aCiazicCe4gVaH56DOhTA",
        token);
    PASS();
}

TEST verify_known_good_token(void) {
    const char *token_in =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsImlzcyI6ImZpcmMiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6"
        "MjMzMTIwMDAwMH0."
        "7uyMcqz_NcC_N9Eg3D4_FojrhGbgJbvFTYWv30_4gco";
    firc_jwt_claims_t claims;
    ASSERT_EQ(FIRC_OK, firc_jwt_parse_and_verify(token_in, SECRET, SECRET_LEN, &claims));
    ASSERT_STR_EQ("admin", claims.sub);
    ASSERT_STR_EQ("firc", claims.iss);
    ASSERT_EQ(1700000000, claims.iat);
    ASSERT_EQ(2331200000, claims.exp);
    PASS();
}

TEST verify_rejects_tampered_signature(void) {
    const char *tampered =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsImlzcyI6ImZpcmMiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6"
        "MjMzMTIwMDAwMH0."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    firc_jwt_claims_t claims;
    ASSERT_EQ(FIRC_ERR_INVAL, firc_jwt_parse_and_verify(tampered, SECRET, SECRET_LEN, &claims));
    PASS();
}

TEST verify_rejects_wrong_secret(void) {
    const char *token_in =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsImlzcyI6ImZpcmMiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6"
        "MjMzMTIwMDAwMH0."
        "7uyMcqz_NcC_N9Eg3D4_FojrhGbgJbvFTYWv30_4gco";
    firc_jwt_claims_t claims;
    ASSERT_EQ(FIRC_ERR_INVAL,
             firc_jwt_parse_and_verify(token_in, (const uint8_t *)"wrong", 5, &claims));
    PASS();
}

TEST parse_unverified_reads_claims_without_secret(void) {
    const char *token_in =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiJhZG1pbiIsImlzcyI6ImZpcmMiLCJpYXQiOjE3MDAwMDAwMDAsImV4cCI6"
        "MjMzMTIwMDAwMH0."
        "7uyMcqz_NcC_N9Eg3D4_FojrhGbgJbvFTYWv30_4gco";
    firc_jwt_claims_t claims;
    ASSERT_EQ(FIRC_OK, firc_jwt_parse_unverified(token_in, &claims));
    ASSERT_STR_EQ("admin", claims.sub);
    PASS();
}

TEST malformed_token_rejected(void) {
    firc_jwt_claims_t claims;
    ASSERT_EQ(FIRC_ERR_PROTO, firc_jwt_parse_unverified("not.a.jwt.token", &claims));
    ASSERT_EQ(FIRC_ERR_PROTO, firc_jwt_parse_unverified("onlyonepart", &claims));
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char **argv) {
    GREATEST_MAIN_BEGIN();
    RUN_TEST(sign_matches_vector);
    RUN_TEST(sign_matches_vector_zero_iat);
    RUN_TEST(verify_known_good_token);
    RUN_TEST(verify_rejects_tampered_signature);
    RUN_TEST(verify_rejects_wrong_secret);
    RUN_TEST(parse_unverified_reads_claims_without_secret);
    RUN_TEST(malformed_token_rejected);
    GREATEST_MAIN_END();
}
