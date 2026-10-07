/* Certificates and signatures for the security=tls tests; why a separate file: tests/certgen.c.
 * No crypto library types here. */
#ifndef STEER_TESTS_CERTGEN_H
#define STEER_TESTS_CERTGEN_H
#include <stddef.h>

struct tcg_key;

/* A new ECDSA P-256 key; NULL on failure. */
struct tcg_key *tcg_key_new(void);
void tcg_key_free(struct tcg_key *k);

/* Issue a certificate for CN (and O, if not NULL) with the key subj. issuer_der == NULL —
 * self-signed (ikey is not needed); otherwise that certificate is the issuer and ikey signs. */
int tcg_issue(struct tcg_key *subj, const char *cn, const char *org, int is_ca,
              struct tcg_key *ikey, const unsigned char *issuer_der, size_t issuer_n,
              unsigned char *der, size_t cap, size_t *der_n);
int tcg_der_to_pem(const unsigned char *der, size_t n, char *pem, size_t cap);
/* ECDSA signature over a ready SHA-256 digest, DER (r, s). */
int tcg_sign_sha256(struct tcg_key *k, const unsigned char digest[32],
                    unsigned char *sig, size_t cap, size_t *sig_n);
/* How many certificates of the PEM blocks in the text parse; text between blocks is skipped. */
int tcg_count_pem_certs(const char *pem, size_t n);

#endif
