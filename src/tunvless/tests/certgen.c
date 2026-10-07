/* Certificates and signatures for the tests — something the program itself does not and should
 * not have.
 *
 * The program only VERIFIES X.509 (src/lib/scrypto.c). The security=tls tests (tests/vlessmatch.c)
 * need the other half too: issue a root and leaves on the spot, valid from the current time (a
 * certificate frozen in the repository would one day expire and fail the test for no fault of
 * its own), and sign CertificateVerify as the server. That is wolfCrypt built for the tests with
 * the extra WOLFSSL_CERT_GEN option (Makefile, STEER_WOLFSSL_DEFS); the program's options
 * (build/wolfssl/user_settings.h) have no certificate generation.
 *
 * A SEPARATE FILE, NOT CODE INSIDE THE TEST, for the same reason only scrypto.c sees wolfSSL in
 * the program: the tests include program sources whole, and wolfSSL headers next to them would put
 * its macros and names into one translation unit with ours. The interface here has no library
 * type at all, like the crypto layer.
 *
 * Keys are ECDSA P-256: RSA generation takes seconds and would add nothing to what is tested. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/asn.h>

#include "certgen.h"

#if !defined(WOLFSSL_CERT_GEN)
#error "tests/certgen.c needs WOLFSSL_CERT_GEN (Makefile, STEER_WOLFSSL_DEFS)"
#endif

struct tcg_key {
    ecc_key k;
};

static WC_RNG g_rng;
static int g_rng_ok;

static WC_RNG *rng(void) {
    if (!g_rng_ok && wc_InitRng(&g_rng) == 0) g_rng_ok = 1;
    return g_rng_ok ? &g_rng : NULL;
}

struct tcg_key *tcg_key_new(void) {
    struct tcg_key *k = calloc(1, sizeof(*k));
    if (!k || !rng()) { free(k); return NULL; }
    if (wc_ecc_init(&k->k) != 0) { free(k); return NULL; }
    if (wc_ecc_make_key_ex(rng(), 32, &k->k, ECC_SECP256R1) != 0) {
        wc_ecc_free(&k->k);
        free(k);
        return NULL;
    }
    return k;
}

void tcg_key_free(struct tcg_key *k) {
    if (!k) return;
    wc_ecc_free(&k->k);
    free(k);
}

int tcg_issue(struct tcg_key *subj, const char *cn, const char *org, int is_ca,
              struct tcg_key *ikey, const unsigned char *issuer_der, size_t issuer_n,
              unsigned char *der, size_t cap, size_t *der_n) {
    Cert *c = calloc(1, sizeof(*c));
    int rc = -1;
    if (!c || !rng()) goto out;
    if (wc_InitCert(c) != 0) goto out;
    snprintf(c->subject.commonName, sizeof(c->subject.commonName), "%s", cn);
    if (org) snprintf(c->subject.org, sizeof(c->subject.org), "%s", org);
    c->isCA = is_ca ? 1 : 0;
    c->sigType = CTC_SHA256wECDSA;
    /* Validity from the current time: wolfSSL sets the start to now, the end daysValid later. */
    c->daysValid = 365 * 5;
#ifdef WOLFSSL_CERT_EXT
    if (wc_SetSubjectKeyIdFromPublicKey(c, NULL, &subj->k) != 0) goto out;
    if (is_ca) c->keyUsage = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN;
#endif
    if (issuer_der) {
        /* Issued by another certificate: the name and (with CERT_EXT) the key id come from it. */
        if (wc_SetIssuerBuffer(c, issuer_der, (int)issuer_n) != 0) goto out;
#ifdef WOLFSSL_CERT_EXT
        if (wc_SetAuthKeyIdFromCert(c, issuer_der, (int)issuer_n) != 0) goto out;
#endif
    }
    int n = wc_MakeCert(c, der, (word32)cap, NULL, &subj->k, rng());
    if (n < 0) goto out;
    n = wc_SignCert(c->bodySz, c->sigType, der, (word32)cap, NULL, ikey ? &ikey->k : &subj->k, rng());
    if (n < 0) goto out;
    *der_n = (size_t)n;
    rc = 0;
out:
    free(c);
    return rc;
}

int tcg_der_to_pem(const unsigned char *der, size_t n, char *pem, size_t cap) {
    int r = wc_DerToPem(der, (word32)n, (byte *)pem, (word32)(cap - 1), CERT_TYPE);
    if (r <= 0) return -1;
    pem[r] = '\0';
    return 0;
}

int tcg_sign_sha256(struct tcg_key *k, const unsigned char digest[32],
                    unsigned char *sig, size_t cap, size_t *sig_n) {
    word32 sn = (word32)cap;
    if (!rng() || wc_ecc_sign_hash(digest, 32, sig, &sn, rng(), &k->k) != 0) return -1;
    *sig_n = sn;
    return 0;
}

int tcg_count_pem_certs(const char *pem, size_t n) {
    static const char B[] = "-----BEGIN CERTIFICATE-----", E[] = "-----END CERTIFICATE-----";
    int count = 0;
    const char *p = pem, *end = pem + n;
    unsigned char *der = malloc(8192);
    if (!der) return -1;
    while (p < end) {
        const char *b = strstr(p, B);
        if (!b) break;
        const char *e = strstr(b, E);
        if (!e) break;
        e += sizeof(E) - 1;
        /* Each block on its own: only the block is parsed, text around it (the Android format:
         * `openssl x509 -text` output before the PEM) is not. */
        int dn = wc_CertPemToDer((const unsigned char *)b, (int)(e - b), der, 8192, CERT_TYPE);
        if (dn > 0) {
            DecodedCert dc;
            wc_InitDecodedCert(&dc, der, (word32)dn, NULL);
            if (wc_ParseCert(&dc, CERT_TYPE, NO_VERIFY, NULL) == 0) count++;
            wc_FreeDecodedCert(&dc);
        }
        p = e;
    }
    free(der);
    return count;
}
