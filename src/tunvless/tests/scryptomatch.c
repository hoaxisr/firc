/* The primitives layer (src/lib/scrypto.c) against known vectors. Without them a change of the
 * crypto library would be checked only by a handshake with a live server.
 *
 * Why vectors and not "the handshake worked": a crypto bug does not look like a bug. A Reality
 * server does not reject a wrong authenticator, it silently serves its cover site; a wrong X25519
 * gives a handshake that does not complete, with no hint why. So every primitive of the layer is
 * checked here against published vectors (RFC and NIST), and chain and signature verification
 * against certificates and signatures issued by OpenSSL (tests/scrypto-pki.h), independently of
 * the library under test.
 *
 * Vectors:
 *   SHA-256/384/512   — FIPS 180-4 ("abc" and the two-block example), plus a context clone midway;
 *   HMAC              — RFC 4231, cases 1 and 2; an empty key (Python's hmac);
 *   HKDF              — RFC 5869, cases 1 and 3 (with salt, and without salt and info);
 *   AES-GCM           — the GCM specification (McGrew–Viega), cases 2, 4, 14 and 16;
 *   ChaCha20-Poly1305 — RFC 8439 §2.8.2;
 *   X25519            — RFC 7748 §5.2 (unclamped scalar), §5.2 iterations, §6.1 (Alice and Bob);
 *                      a secret with zero first and last bytes (Go's crypto/ecdh);
 *   AES-256-CTR       — NIST SP 800-38A F.5.5, whole and in pieces of different lengths;
 *   MD5, SHA-1, SHA-224 — RFC 1321 and FIPS 180-4 ("abc", empty string); HMAC-MD5 and HMAC-SHA1 —
 *                      RFC 2202, case 1; HKDF-SHA1 — RFC 5869, case 4;
 *   AES, one block    — FIPS 197, appendix C.1 and C.3, both directions;
 *   ML-KEM-768, ML-DSA-65 — values from Go (tests/scrypto-pq.h); encapsulation with fixed
 *                      randomness from circl, the implicit-rejection secret from Go (inline).
 * Plus what vectors do not catch: IN-PLACE operation at TLS record sizes (up to 16401 bytes, a
 * size at which the tag once broke), rejection of a tampered tag and AAD, the zero X25519 secret
 * of a small-order point, no temporary intermediates left behind after a chain check, and
 * parallel checks from several threads.
 *
 * Needs the real library, so it runs in `make crypto-test`. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>

#include "scrypto.h"
#include "unit.h"
#include "scrypto-pki.h"

static size_t unhex(const char *s, unsigned char *out, size_t cap) {
    size_t n = 0;
    for (; s[0] && s[1]; s += 2) {
        unsigned hi, lo;
        if (sscanf(s, "%1x%1x", &hi, &lo) != 2 || n >= cap) break;
        out[n++] = (unsigned char)(hi << 4 | lo);
    }
    return n;
}

static void check_bytes(const char *what, const char *want_hex, const unsigned char *got, size_t n) {
    unsigned char want[512];
    size_t wn = unhex(want_hex, want, sizeof(want));
    if (wn != n) { check(what, (long)wn, (long)n); return; }
    check_mem(what, want, got, n);
}

/* ---- hashes, HMAC, HKDF ---------------------------------------------------------------------- */

static void test_hash(void) {
    unsigned char out[64];
    const char *abc = "abc";
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    check("SHA-256(abc): return code", 0, sc_hash(SC_SHA256, abc, 3, out));
    check_bytes("SHA-256(abc)", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", out, 32);
    sc_hash(SC_SHA256, two, strlen(two), out);
    check_bytes("SHA-256(two-block)", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", out, 32);
    sc_hash(SC_SHA256, "", 0, out);
    check_bytes("SHA-256(empty)", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", out, 32);
    sc_hash(SC_SHA384, abc, 3, out);
    check_bytes("SHA-384(abc)", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                "8086072ba1e7cc2358baeca134c825a7", out, 48);
    sc_hash(SC_SHA512, abc, 3, out);
    check_bytes("SHA-512(abc)", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f", out, 64);

    /* A clone midway is exactly what the TLS 1.3 transcript does: take a hash and go on. */
    static const enum sc_hash hs[] = { SC_SHA256, SC_SHA384 };
    for (size_t i = 0; i < 2; i++) {
        struct sc_hash_ctx a, b;
        unsigned char w[64], x[64], y[64];
        sc_hash(hs[i], abc, 3, w);
        sc_hash_init(&a, hs[i]);
        sc_hash_update(&a, "ab", 2);
        check(hs[i] == SC_SHA256 ? "SHA-256 clone: return code" : "SHA-384 clone: return code", 0, sc_hash_clone(&b, &a));
        sc_hash_update(&a, "c", 1);
        sc_hash_update(&b, "c", 1);
        sc_hash_final(&a, x);
        sc_hash_final(&b, y);
        check_mem(hs[i] == SC_SHA256 ? "SHA-256 clone: the original goes on" : "SHA-384 clone: the original goes on",
                  w, x, sc_hash_len(hs[i]));
        check_mem(hs[i] == SC_SHA256 ? "SHA-256 clone: the copy is independent" : "SHA-384 clone: the copy is independent",
                  w, y, sc_hash_len(hs[i]));
        sc_hash_free(&a);
        sc_hash_free(&b);
    }
    check("hash length of an unknown algorithm is 0", 0, (long)sc_hash_len((enum sc_hash)9));
}

static void test_hmac(void) {
    unsigned char key[20], out[64];
    memset(key, 0x0b, sizeof(key));
    const char *hi = "Hi There";
    check("HMAC-SHA256 RFC 4231 #1: return code", 0, sc_hmac(SC_SHA256, key, 20, hi, 8, out));
    check_bytes("HMAC-SHA256 RFC 4231 #1", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", out, 32);
    sc_hmac(SC_SHA384, key, 20, hi, 8, out);
    check_bytes("HMAC-SHA384 RFC 4231 #1", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c"
                "faea9ea9076ede7f4af152e8b2fa9cb6", out, 48);
    sc_hmac(SC_SHA512, key, 20, hi, 8, out);
    check_bytes("HMAC-SHA512 RFC 4231 #1", "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", out, 64);
    const char *q = "what do ya want for nothing?";
    sc_hmac(SC_SHA256, "Jefe", 4, q, strlen(q), out);
    check_bytes("HMAC-SHA256 RFC 4231 #2", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", out, 32);
    unsigned char two[32];
    check("HMAC in two pieces: return code", 0,
          sc_hmac2(SC_SHA256, "Jefe", 4, q, 10, q + 10, strlen(q) - 10, two));
    check_mem("HMAC in two pieces = in one", out, two, 32);
    /* An empty key is legal (scrypto.c hands wolfSSL a dummy pointer); value from Python's hmac. */
    check("HMAC with an empty key: return code", 0,
          sc_hmac(SC_SHA256, NULL, 0, "Beauty is truth", 15, out));
    check_bytes("HMAC-SHA256 with an empty key",
                "b3cda0832b90c5646f9d49ae89c5fccc28d5143c8c7d18c3a9627dec875ebd45", out, 32);
}

static void test_hkdf(void) {
    unsigned char ikm[22], salt[13], info[10], prk[64], okm[42];
    memset(ikm, 0x0b, sizeof(ikm));
    for (unsigned i = 0; i < sizeof(salt); i++) salt[i] = (unsigned char)i;
    for (unsigned i = 0; i < sizeof(info); i++) info[i] = (unsigned char)(0xf0 + i);

    check("HKDF #1 extract: return code", 0, sc_hkdf_extract(SC_SHA256, salt, 13, ikm, 22, prk));
    check_bytes("HKDF #1 PRK", "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", prk, 32);
    check("HKDF #1 expand: return code", 0, sc_hkdf_expand(SC_SHA256, prk, 32, info, 10, okm, 42));
    check_bytes("HKDF #1 OKM", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865", okm, 42);
    memset(okm, 0, sizeof(okm));
    sc_hkdf(SC_SHA256, salt, 13, ikm, 22, info, 10, okm, 42);
    check_bytes("HKDF #1 in one call", "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                "34007208d5b887185865", okm, 42);

    /* No salt and no info: the case the "derived" step of TLS 1.3 relies on. */
    sc_hkdf_extract(SC_SHA256, NULL, 0, ikm, 22, prk);
    check_bytes("HKDF #3 PRK (no salt)", "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", prk, 32);
    sc_hkdf_expand(SC_SHA256, prk, 32, NULL, 0, okm, 42);
    check_bytes("HKDF #3 OKM (no info)", "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
                "9d201395faa4b61a96c8", okm, 42);
    static unsigned char big[255 * 32 + 1];
    check("HKDF: output longer than 255 blocks rejected", SC_EINVAL,
          sc_hkdf_expand(SC_SHA256, prk, 32, NULL, 0, big, sizeof(big)));
    check("HKDF: output of exactly 255 blocks accepted", 0,
          sc_hkdf_expand(SC_SHA256, prk, 32, NULL, 0, big, sizeof(big) - 1));
}

/* ---- AEAD ------------------------------------------------------------------------------------ */

struct gcm_case {
    const char *name, *key, *iv, *p, *a, *c, *t;
};

static void aead_case(const char *name, enum sc_aead_alg alg, const char *key_hex, const char *iv_hex,
                      const char *p_hex, const char *a_hex, const char *c_hex, const char *t_hex) {
    unsigned char key[32], iv[12], p[128], a[64], buf[128], tag[16];
    char what[96];
    unhex(key_hex, key, sizeof(key));
    unhex(iv_hex, iv, sizeof(iv));
    size_t pn = unhex(p_hex, p, sizeof(p)), an = unhex(a_hex, a, sizeof(a));
    struct sc_aead k;
    snprintf(what, sizeof(what), "%s: set key", name);
    check(what, 0, sc_aead_setkey(&k, alg, key));
    memcpy(buf, p, pn);
    snprintf(what, sizeof(what), "%s: in-place encryption", name);
    check(what, 0, sc_aead_seal(&k, iv, a, an, buf, pn, tag));
    snprintf(what, sizeof(what), "%s: ciphertext", name);
    check_bytes(what, c_hex, buf, pn);
    snprintf(what, sizeof(what), "%s: tag", name);
    check_bytes(what, t_hex, tag, 16);
    snprintf(what, sizeof(what), "%s: decryption", name);
    check(what, 0, sc_aead_open(&k, iv, a, an, buf, pn, tag));
    snprintf(what, sizeof(what), "%s: plaintext restored", name);
    check_mem(what, p, buf, pn);
    /* A tampered tag and AAD must fail with SC_EAUTH ("does not match"), not a generic error. */
    unsigned char bad[16];
    memcpy(bad, tag, 16);
    bad[3] ^= 0x40;
    sc_aead_seal(&k, iv, a, an, buf, pn, tag);
    snprintf(what, sizeof(what), "%s: tampered tag gives SC_EAUTH", name);
    check(what, SC_EAUTH, sc_aead_open(&k, iv, a, an, buf, pn, bad));
    if (an) {
        sc_aead_seal(&k, iv, a, an, buf, pn, tag);
        a[0] ^= 1;
        snprintf(what, sizeof(what), "%s: tampered AAD gives SC_EAUTH", name);
        check(what, SC_EAUTH, sc_aead_open(&k, iv, a, an, buf, pn, tag));
    }
    sc_aead_free(&k);
}

static void test_aead(void) {
    aead_case("AES-128-GCM #2", SC_AES128_GCM, "00000000000000000000000000000000", "000000000000000000000000",
              "00000000000000000000000000000000", "", "0388dace60b6a392f328c2b971b2fe78",
              "ab6e47d42cec13bdf53a67b21257bddf");
    aead_case("AES-128-GCM #4", SC_AES128_GCM, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
              "b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa05"
              "1ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47");
    aead_case("AES-256-GCM #14", SC_AES256_GCM,
              "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000",
              "00000000000000000000000000000000", "", "cea7403d4d606b6e074ec5d3baf39d18",
              "d0d1c8a799996bf0265b98b5d48ab919");
    aead_case("AES-256-GCM #16", SC_AES256_GCM,
              "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
              "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
              "b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
              "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
              "c5f61e6393ba7a0abcc9f662", "76fc6ece0f4e1768cddf8853bb2d551b");
    /* RFC 8439 §2.8.2: "Ladies and Gentlemen of the class of '99...". */
    aead_case("ChaCha20-Poly1305 RFC 8439", SC_CHACHA20_POLY1305,
              "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", "070000004041424344454647",
              "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920"
              "636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c207375"
              "6e73637265656e20776f756c642062652069742e", "50515253c0c1c2c3c4c5c6c7",
              "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b"
              "1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
              "3ff4def08e4b7a9de576d26586cec64b6116", "1ae10b594f09e26a7e902ecbd0600691");

    /* In place at TLS record sizes, with the tag RIGHT AFTER the ciphertext in the same buffer,
     * the way tls13.c lays out a record. 16401 is a size at which the tag once did not match. */
    static const size_t sizes[] = { 0, 1, 15, 16, 17, 300, 1439, 4096, 8203, 16384, 16401 };
    static const enum sc_aead_alg algs[] = { SC_AES128_GCM, SC_AES256_GCM, SC_CHACHA20_POLY1305 };
    static const char *names[] = { "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305" };
    static unsigned char buf[16401 + 16], orig[16401];
    for (size_t a = 0; a < 3; a++) {
        unsigned char key[32], nonce[12], aad[5] = { 0x17, 0x03, 0x03, 0, 0 };
        for (int i = 0; i < 32; i++) key[i] = (unsigned char)(0xA5 ^ i);
        for (int i = 0; i < 12; i++) nonce[i] = (unsigned char)(0x5A + i);
        struct sc_aead k;
        sc_aead_setkey(&k, algs[a], key);
        int ok = 1, enc = 1;
        for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
            size_t n = sizes[s];
            for (size_t i = 0; i < n; i++) orig[i] = buf[i] = (unsigned char)(i * 31 + 7);
            nonce[11] = (unsigned char)s;
            if (sc_aead_seal(&k, nonce, aad, 5, buf, n, buf + n) != 0) ok = 0;
            /* The round trip passes even when seal and open both skip the same bytes, so: every
             * block of the ciphertext, the short last one too, differs from the plaintext. */
            for (size_t i = 0; i < n; i += 16)
                if (!memcmp(buf + i, orig + i, n - i < 16 ? n - i : 16)) enc = 0;
            unsigned char tag[16];
            memcpy(tag, buf + n, 16);
            if (sc_aead_open(&k, nonce, aad, 5, buf, n, tag) != 0) ok = 0;
            if (n && memcmp(buf, orig, n) != 0) ok = 0;
            if (memcmp(buf + n, tag, 16) != 0) ok = 0;     /* decryption leaves the tag alone */
        }
        char what[80];
        snprintf(what, sizeof(what), "%s: in place at TLS record sizes up to 16401", names[a]);
        check(what, 1, ok);
        snprintf(what, sizeof(what), "%s: every block encrypted at those sizes", names[a]);
        check(what, 1, enc);
        sc_aead_free(&k);
    }
    struct sc_aead none = { 0 };
    unsigned char n12[12] = { 0 }, t16[16];
    check("AEAD without a key gives SC_EINVAL", SC_EINVAL, sc_aead_seal(&none, n12, NULL, 0, t16, 0, t16));
}

/* ---- AES-256-CTR ----------------------------------------------------------------------------- */

static void test_aesctr(void) {
    unsigned char key[32], iv[16], p[64], buf[64], part[64];
    unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4", key, 32);
    unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", iv, 16);
    unhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
          "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", p, 64);
    const char *c = "601ec313775789a5b7a7f504bbf3d228f443e3ca4d62b59aca84e990cacaf5c5"
                    "2b0930daa23de94ce87017ba2d84988ddfc9c58db67aada613c2dd08457941a6";
    struct sc_aesctr x;
    check("AES-256-CTR: init", 0, sc_aesctr_init(&x, key, iv));
    check("AES-256-CTR: encryption", 0, sc_aesctr_xor(&x, p, buf, 64));
    check_bytes("AES-256-CTR SP 800-38A F.5.5", c, buf, 64);
    sc_aesctr_free(&x);

    /* In pieces of 1, 15, 17 and 31: the position inside a block survives the call, so pieces give
     * the keystream of one large call (trvenc.c relies on this). */
    sc_aesctr_init(&x, key, iv);
    static const size_t cuts[] = { 1, 15, 17, 31 };
    size_t off = 0;
    for (size_t i = 0; i < 4; i++) { sc_aesctr_xor(&x, p + off, part + off, cuts[i]); off += cuts[i]; }
    check_bytes("AES-256-CTR in pieces = whole", c, part, 64);
    sc_aesctr_free(&x);

    sc_aesctr_init(&x, key, iv);
    sc_aesctr_xor(&x, buf, buf, 64);                    /* in place, back */
    check_mem("AES-256-CTR: the same keystream decrypts", p, buf, 64);
    sc_aesctr_free(&x);

    /* The carry runs through all 128 bits: the counter is one big-endian number. Each block of
     * keystream is AES of its counter, taken by sc_aes_block (FIPS 197, test_proxy_prims). */
    unsigned char ivmax[16], z[32] = { 0 }, g[32], blk[16], zero_iv[16] = { 0 };
    memset(ivmax, 0xff, 16);
    sc_aesctr_init(&x, key, ivmax);
    sc_aesctr_xor(&x, z, g, 32);
    sc_aesctr_free(&x);
    sc_aes_block(key, 32, 0, ivmax, blk);
    check_mem("AES-256-CTR: from ff..ff, block 1 is counter ff..ff", blk, g, 16);
    sc_aes_block(key, 32, 0, zero_iv, blk);
    check_mem("AES-256-CTR: from ff..ff, block 2 is counter 00..00 (wrap)", blk, g + 16, 16);
    struct sc_aesctr none = { 0 };
    check("AES-256-CTR without init gives SC_EINVAL", SC_EINVAL, sc_aesctr_xor(&none, z, g, 16));
}

/* ---- MD5, SHA-1, SHA-224, one AES block (in the layer, unused in src) ----------------------- */

static void test_proxy_prims(void) {
    unsigned char out[64], key[32], buf[256];
    sc_hash(SC_MD5, "abc", 3, out);
    check_bytes("MD5(abc)", "900150983cd24fb0d6963f7d28e17f72", out, 16);
    sc_hash(SC_MD5, "", 0, out);
    check_bytes("MD5()", "d41d8cd98f00b204e9800998ecf8427e", out, 16);
    sc_hash(SC_SHA1, "abc", 3, out);
    check_bytes("SHA-1(abc)", "a9993e364706816aba3e25717850c26c9cd0d89d", out, 20);
    sc_hash(SC_SHA224, "abc", 3, out);
    check_bytes("SHA-224(abc)", "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7", out, 28);
    check("hash lengths 16, 20, 28", 16 * 10000 + 20 * 100 + 28,
          (long)(sc_hash_len(SC_MD5) * 10000 + sc_hash_len(SC_SHA1) * 100 + sc_hash_len(SC_SHA224)));
    /* A clone midway, the same path as for SHA-256 above. */
    struct sc_hash_ctx a, b;
    sc_hash_init(&a, SC_MD5);
    sc_hash_update(&a, "a", 1);
    check("MD5: clone", 0, sc_hash_clone(&b, &a));
    sc_hash_update(&b, "bc", 2);
    sc_hash_final(&b, out);
    check_bytes("MD5: clone midway", "900150983cd24fb0d6963f7d28e17f72", out, 16);
    sc_hash_free(&a);
    sc_hash_free(&b);

    memset(key, 0x0b, 20);
    sc_hmac(SC_MD5, key, 16, "Hi There", 8, out);
    check_bytes("HMAC-MD5 RFC 2202 #1", "9294727a3638bb1c13f48ef8158bfc9d", out, 16);
    sc_hmac(SC_SHA1, key, 20, "Hi There", 8, out);
    check_bytes("HMAC-SHA1 RFC 2202 #1", "b617318655057264e28bc0b6fb378c8ef146be00", out, 20);
    unsigned char ikm[11], salt[13], info[10];
    memset(ikm, 0x0b, sizeof ikm);
    for (int i = 0; i < 13; i++) salt[i] = (unsigned char)i;
    for (int i = 0; i < 10; i++) info[i] = (unsigned char)(0xf0 + i);
    check("HKDF-SHA1: return code", 0, sc_hkdf(SC_SHA1, salt, 13, ikm, 11, info, 10, buf, 42));
    check_bytes("HKDF-SHA1 RFC 5869 #4",
                "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896",
                buf, 42);

    unsigned char pt[16], ct[16], back[16];
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    unhex("00112233445566778899aabbccddeeff", pt, 16);
    check("AES-128 block: return code", 0, sc_aes_block(key, 16, 0, pt, ct));
    check_bytes("AES-128 FIPS 197 C.1", "69c4e0d86a7b0430d8cdb78070b4c55a", ct, 16);
    sc_aes_block(key, 16, 1, ct, back);
    check_mem("AES-128 block decrypts back", pt, back, 16);
    sc_aes_block(key, 32, 0, pt, ct);
    check_bytes("AES-256 FIPS 197 C.3", "8ea2b7ca516745bfeafc49904b496089", ct, 16);
    sc_aes_block(key, 32, 1, ct, back);
    check_mem("AES-256 block decrypts back", pt, back, 16);
    check("AES block: 24-byte key rejected", SC_EINVAL, sc_aes_block(key, 24, 0, pt, ct));

}

/* ---- X25519 ---------------------------------------------------------------------------------- */

#include "scrypto-pq.h"

/* ML-KEM-768: the key from the seed matches Go's, Go's ciphertext decapsulates to the same
 * secret, our encapsulation agrees with our decapsulation, and a broken key is rejected. */
static void test_mlkem(void) {
    unsigned char ek[SC_MLKEM768_EK], dk[SC_MLKEM768_DK], ss[32], ct[SC_MLKEM768_CT], ss2[32];
    check("ML-KEM: keygen", 0, sc_mlkem768_keygen(ek, dk, KEM_SEED));
    check("ML-KEM: ek matches Go", 0, memcmp(ek, KEM_EK, sizeof ek));
    check("ML-KEM: ek passes the check", 0, sc_mlkem768_ek_check(ek));
    check("ML-KEM: decaps of Go's ciphertext", 0, sc_mlkem768_decaps(ss, dk, KEM_CT));
    check("ML-KEM: secret matches Go", 0, memcmp(ss, KEM_SS, 32));
    unsigned char rnd[32];
    for (int i = 0; i < 32; i++) rnd[i] = (unsigned char)(i * 5 + 1);
    check("ML-KEM: encaps", 0, sc_mlkem768_encaps(ct, ss, ek, rnd));
    /* Deterministic in rnd: circl's EncapsulateTo(ct, ss, m) with the same m gives these. */
    unsigned char h[32];
    sc_hash(SC_SHA256, ct, sizeof ct, h);
    check_bytes("ML-KEM: encaps ciphertext matches circl (its SHA-256)",
                "5c4a45018a4ba853e96a75d1c9d87f7d58cba50a9e804ced49e5ab977c860f6e", h, 32);
    check_bytes("ML-KEM: encaps secret matches circl",
                "84c2b4337af7daaec5c6d2915794a4b7b2de6303e6d850f48510d1a6cec5be36", ss, 32);
    check("ML-KEM: decaps of our ciphertext", 0, sc_mlkem768_decaps(ss2, dk, ct));
    check("ML-KEM: secrets agree", 0, memcmp(ss, ss2, 32));
    /* Implicit rejection: a corrupted ciphertext gives a DIFFERENT secret, not an error. */
    ct[10] ^= 1;
    check("ML-KEM: corrupted ct: return code 0", 0, sc_mlkem768_decaps(ss2, dk, ct));
    check("ML-KEM: corrupted ct: different secret", 1, memcmp(ss, ss2, 32) != 0);
    /* That secret is J(z || ct), z being the second half of the seed: Go's value for Go's
     * ciphertext with the same byte flipped. */
    memcpy(ct, KEM_CT, sizeof ct);
    ct[10] ^= 1;
    sc_mlkem768_decaps(ss2, dk, ct);
    check_bytes("ML-KEM: corrupted Go ciphertext: Go's rejection secret",
                "96f295eb4d00fb0d98913bad878330c3934ce107c527ccf9747857b4138a1b93", ss2, 32);
    /* A coefficient 0xFFF >= q = 3329: Go rejects such a key (FIPS 203, 7.2). */
    unsigned char bad[SC_MLKEM768_EK];
    memcpy(bad, ek, sizeof bad);
    bad[0] = 0xFF; bad[1] |= 0x0F;
    check("ML-KEM: key with a coefficient >= q rejected", SC_EPARSE, sc_mlkem768_ek_check(bad));
    check("ML-KEM: encaps to such a key rejected", SC_EPARSE, sc_mlkem768_encaps(ct, ss, bad, rnd));
}

/* ML-DSA-65: the circl signature verifies, any alteration does not. */
static void test_mldsa(void) {
    check("ML-DSA-65: circl signature verifies", 0, sc_mldsa65_verify(DSA_PK, DSA_MSG, sizeof DSA_MSG, DSA_SIG, sizeof DSA_SIG));
    unsigned char m[32], sg[SC_MLDSA65_SIG];
    memcpy(m, DSA_MSG, 32); m[0] ^= 1;
    check("ML-DSA-65: other message gives SC_ESIG", SC_ESIG, sc_mldsa65_verify(DSA_PK, m, 32, DSA_SIG, sizeof DSA_SIG));
    memcpy(sg, DSA_SIG, sizeof sg); sg[100] ^= 1;
    check("ML-DSA-65: corrupted signature gives SC_ESIG", SC_ESIG, sc_mldsa65_verify(DSA_PK, DSA_MSG, 32, sg, sizeof sg));
    check("ML-DSA-65: short signature gives SC_ESIG", SC_ESIG, sc_mldsa65_verify(DSA_PK, DSA_MSG, 32, DSA_SIG, 100));
}

static void test_x25519(void) {
    unsigned char k[32], u[32], out[32];
    /* §5.2, first vector: the scalar is NOT clamped (a5 in the low byte); the function does it. */
    unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", k, 32);
    unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", u, 32);
    check("X25519 RFC 7748 §5.2: return code", 0, sc_x25519(out, k, u));
    check_bytes("X25519 RFC 7748 §5.2", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", out, 32);

    /* §5.2 iterations: k = u = 9, then k ← X25519(k, u), u ← the old k. */
    unsigned char kk[32] = { 9 }, uu[32] = { 9 }, t[32];
    for (int i = 1; i <= 1000; i++) {
        sc_x25519(t, kk, uu);
        memcpy(uu, kk, 32);
        memcpy(kk, t, 32);
        if (i == 1)
            check_bytes("X25519 RFC 7748: 1 iteration",
                        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", kk, 32);
    }
    check_bytes("X25519 RFC 7748: 1000 iterations",
                "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", kk, 32);

    /* §6.1: the public halves from the private ones, and the shared secret on both sides. */
    unsigned char ap[32], bp[32], apub[32], bpub[32], s1[32], s2[32];
    unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", ap, 32);
    unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bp, 32);
    check("X25519 §6.1: Alice's public key: return code", 0, sc_x25519_base(apub, ap));
    sc_x25519_base(bpub, bp);
    check_bytes("X25519 §6.1: Alice's public key", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", apub, 32);
    check_bytes("X25519 §6.1: Bob's public key", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", bpub, 32);
    sc_x25519(s1, ap, bpub);
    sc_x25519(s2, bp, apub);
    check_bytes("X25519 §6.1: Alice's secret", "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", s1, 32);
    check_mem("X25519 §6.1: Bob's is the same", s1, s2, 32);

    /* A small-order point (u = 0 and u = 1) gives a zero secret: a failure, not a key. */
    unsigned char zero[32] = { 0 }, one[32] = { 1 }, nine[32] = { 9 };
    check("X25519: u = 0 rejected", SC_ECRYPTO, sc_x25519(out, ap, zero));
    check("X25519: u = 1 rejected", SC_ECRYPTO, sc_x25519(out, ap, one));
    /* Only an ALL-zero secret fails: one that starts and ends with a zero byte is a key (scalar
     * and value from Go's crypto/ecdh). */
    unhex("000021aa7794b1ceeb0825425f7c99b6d3f00d2a4764819ebbd8f5122f4c6986", k, 32);
    check("X25519: secret with zero first and last byte accepted", 0, sc_x25519(out, k, nine));
    check_bytes("X25519: secret with zero first and last byte",
                "000edf1da6da6165bf86aa2eaff7952031c8f5e96e8b92d7ab78c765e7706600", out, 32);
}

/* ---- certificates --------------------------------------------------------------------------- */

/* PEM → DER with our own decoder: the test must not check the library with its own function. */
static size_t pem_der(const char *pem, unsigned char *out, size_t cap) {
    static const char *A = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *p = strstr(pem, "-----\n");
    if (!p) return 0;
    p += 6;
    unsigned acc = 0;
    int bits = 0;
    size_t n = 0;
    for (; *p && *p != '-'; p++) {
        const char *q = strchr(A, *p);
        if (!q || !*p) continue;
        acc = (acc << 6) | (unsigned)(q - A);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= cap) return 0;
            out[n++] = (unsigned char)(acc >> bits);
        }
    }
    return n;
}

struct der { unsigned char b[2048]; size_t n; };
static struct der D_LEAF, D_INTER, D_RSALEAF, D_P384, D_FAKECA, D_FAKELEAF, D_EXPIRED;

static struct sc_roots *roots_of(const char *pem) {
    struct sc_roots *r = NULL;
    return sc_roots_load(&r, (const unsigned char *)pem, strlen(pem)) == 0 ? r : NULL;
}

static int chain(struct sc_roots *r, const char *host, int n, ...) {
    const unsigned char *d[8];
    size_t dn[8];
    va_list ap;
    va_start(ap, n);
    for (int i = 0; i < n; i++) { struct der *x = va_arg(ap, struct der *); d[i] = x->b; dn[i] = x->n; }
    va_end(ap);
    return sc_chain_verify(r, d, dn, (size_t)n, host);
}

static void test_sig(void) {
    unsigned char d256[32], d384[48], sig[512];
    sc_hash(SC_SHA256, "steer scrypto", 13, d256);
    sc_hash(SC_SHA384, "steer scrypto", 13, d384);
    struct { const char *name, *hex; struct der *cert; enum sc_sig_alg alg; enum sc_hash h; } v[] = {
        { "ECDSA P-256 SHA-256",      SIG_ECDSA256,  &D_LEAF,    SC_SIG_ECDSA,     SC_SHA256 },
        { "ECDSA P-384 SHA-384",      SIG_ECDSA384,  &D_P384,    SC_SIG_ECDSA,     SC_SHA384 },
        { "RSA PKCS#1 v1.5 SHA-256",  SIG_PKCS1,     &D_RSALEAF, SC_SIG_RSA_PKCS1, SC_SHA256 },
        { "RSA-PSS SHA-256 salt 32",  SIG_PSS256,    &D_RSALEAF, SC_SIG_RSA_PSS,   SC_SHA256 },
        { "RSA-PSS SHA-384 salt 20",  SIG_PSS384S20, &D_RSALEAF, SC_SIG_RSA_PSS,   SC_SHA384 },
        { "RSA-PSS SHA-256 salt 0",   SIG_PSS256S0,  &D_RSALEAF, SC_SIG_RSA_PSS,   SC_SHA256 },
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        size_t sn = unhex(v[i].hex, sig, sizeof(sig));
        const unsigned char *dg = v[i].h == SC_SHA256 ? d256 : d384;
        size_t dn = sc_hash_len(v[i].h);
        char what[96];
        snprintf(what, sizeof(what), "OpenSSL signature %s verifies", v[i].name);
        check(what, 0, sc_cert_verify_sig(v[i].cert->b, v[i].cert->n, v[i].alg, v[i].h, dg, dn, sig, sn));
        sig[sn / 2] ^= 0x10;
        snprintf(what, sizeof(what), "corrupted signature %s gives SC_ESIG", v[i].name);
        check(what, SC_ESIG, sc_cert_verify_sig(v[i].cert->b, v[i].cert->n, v[i].alg, v[i].h, dg, dn, sig, sn));
        /* A wrong digest is a failure, not "close enough": the intact signature over a digest
         * one bit off. (A corrupted RSA signature fails in the padding, before any digest.) */
        sig[sn / 2] ^= 0x10;
        unsigned char other[48];
        memcpy(other, dg, dn);
        other[0] ^= 1;
        snprintf(what, sizeof(what), "%s over another digest gives SC_ESIG", v[i].name);
        check(what, SC_ESIG,
              sc_cert_verify_sig(v[i].cert->b, v[i].cert->n, v[i].alg, v[i].h, other, dn, sig, sn));
    }
    /* Nor is a wrong scheme or key. */
    size_t sn = unhex(SIG_PSS256, sig, sizeof(sig));
    check("PSS signature checked as PKCS#1 v1.5 gives SC_ESIG", SC_ESIG,
          sc_cert_verify_sig(D_RSALEAF.b, D_RSALEAF.n, SC_SIG_RSA_PKCS1, SC_SHA256, d256, 32, sig, sn));
    sn = unhex(SIG_ECDSA256, sig, sizeof(sig));
    check("ECDSA signature with an RSA key rejected", 1,
          sc_cert_verify_sig(D_RSALEAF.b, D_RSALEAF.n, SC_SIG_ECDSA, SC_SHA256, d256, 32, sig, sn) != 0);
    check("wrong digest length gives SC_EINVAL", SC_EINVAL,
          sc_cert_verify_sig(D_LEAF.b, D_LEAF.n, SC_SIG_ECDSA, SC_SHA384, d256, 32, sig, sn));
}

struct worker { struct sc_roots *r; int bad; };

static void *verify_worker(void *arg) {
    struct worker *w = arg;
    for (int i = 0; i < 40; i++) {
        /* A good chain alternates with a leaf without its intermediate: the second must fail even
         * if another thread's temporary intermediate has just been in the store. */
        if (chain(w->r, "good.example", 2, &D_LEAF, &D_INTER) != 0) w->bad++;
        if (chain(w->r, "good.example", 1, &D_LEAF) != SC_ECHAIN) w->bad++;
        if (chain(w->r, "rsa.example", 3, &D_RSALEAF, &D_LEAF, &D_INTER) != 0) w->bad++;
    }
    return NULL;
}

static void test_chain(void) {
    struct sc_roots *r = roots_of(PEM_ROOT);
    check("root store loaded", 1, r != NULL);
    if (!r) return;
    /* On the fresh store, before any check has brought the intermediate along. */
    check("no intermediate: rejected", SC_ECHAIN, chain(r, "good.example", 1, &D_LEAF));
    check("leaf + intermediate, name from SAN", 0, chain(r, "good.example", 2, &D_LEAF, &D_INTER));
    check("name under the wildcard *.wild.example", 0, chain(r, "a.wild.example", 2, &D_LEAF, &D_INTER));
    check("wildcard does not cover wild.example itself", SC_ECHAIN, chain(r, "wild.example", 2, &D_LEAF, &D_INTER));
    check("wildcard does not cover two levels", SC_ECHAIN, chain(r, "a.b.wild.example", 2, &D_LEAF, &D_INTER));
    check("address from SAN IP", 0, chain(r, "192.0.2.7", 2, &D_LEAF, &D_INTER));
    check("other address rejected", SC_ECHAIN, chain(r, "192.0.2.8", 2, &D_LEAF, &D_INTER));
    check("other name rejected", SC_ECHAIN, chain(r, "bad.example", 2, &D_LEAF, &D_INTER));
    check("CN not used as a name when SAN is present", SC_ECHAIN, chain(r, "leaf", 2, &D_LEAF, &D_INTER));
    check("an extra certificate in the chain does no harm", 0,
          chain(r, "good.example", 3, &D_LEAF, &D_RSALEAF, &D_INTER));
    check("temporary intermediates removed after a check", SC_ECHAIN, chain(r, "good.example", 1, &D_LEAF));
    check("leaf directly under the root (P-384)", 0, chain(r, "p384.example", 1, &D_P384));
    check("intermediate without the CA flag rejected", SC_ECHAIN,
          chain(r, "good.example", 3, &D_FAKELEAF, &D_FAKECA, &D_INTER));
    check("expired leaf rejected", SC_ECHAIN, chain(r, "good.example", 2, &D_EXPIRED, &D_INTER));

    /* Parallel checks: the tunnel's connectors verify chains from their own threads. */
    pthread_t th[4];
    struct worker w[4];
    for (int i = 0; i < 4; i++) { w[i].r = r; w[i].bad = 0; pthread_create(&th[i], NULL, verify_worker, &w[i]); }
    int bad = 0;
    for (int i = 0; i < 4; i++) { pthread_join(th[i], NULL); bad += w[i].bad; }
    check("4 threads x 120 checks: no wrong answer", 0, bad);
    sc_roots_free(r);

    r = roots_of(PEM_OTHER);
    check("other root: chain does not verify", SC_ECHAIN, r ? chain(r, "good.example", 2, &D_LEAF, &D_INTER) : -99);
    sc_roots_free(r);

    /* A store with garbage: an entry that does not parse is skipped, the rest load. */
    static char mixed[8192];
    snprintf(mixed, sizeof(mixed), "%s%s%s",
             "-----BEGIN CERTIFICATE-----\nAAAAAAAAAAAAAAAAAAAAAAAA\n-----END CERTIFICATE-----\n",
             PEM_OTHER, PEM_ROOT);
    r = roots_of(mixed);
    check("store with a broken entry: the root still works", 0,
          r ? chain(r, "good.example", 2, &D_LEAF, &D_INTER) : -99);
    sc_roots_free(r);
    r = roots_of("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    check("store without a single root: load fails", 1, r == NULL);
    sc_roots_free(r);
}

int main(void) {
    struct { const char *pem; struct der *d; } all[] = {
        { PEM_LEAF, &D_LEAF }, { PEM_INTER, &D_INTER }, { PEM_RSALEAF, &D_RSALEAF }, { PEM_P384, &D_P384 },
        { PEM_FAKECA, &D_FAKECA }, { PEM_FAKELEAF, &D_FAKELEAF }, { PEM_EXPIRED, &D_EXPIRED },
    };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++)
        all[i].d->n = pem_der(all[i].pem, all[i].d->b, sizeof(all[i].d->b));

    test_hash();
    test_hmac();
    test_hkdf();
    test_aead();
    test_aesctr();
    test_proxy_prims();
    test_x25519();
    test_mlkem();
    test_mldsa();
    test_sig();
    test_chain();
    return unit_done("scryptomatch");
}
