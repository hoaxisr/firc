/* vless_connect failure paths: the descriptor and the keys after each "no".
 *
 * WHAT IS CHECKED. Each failure path of connection setup decides on its own how to clean up:
 * close(fd), transport_close, or nothing when it fails before the socket exists. The choice
 * matters. Once the traffic keys are expanded, the connection holds cipher contexts that
 * transport_close must wipe, and certificate verification allocates on the heap (wolfSSL chain
 * parsing), which the descriptor does not hold. Callers do not clean up either: the spare pool
 * only marks the slot empty, and the node probe returns at once. So a wrong choice leaks on EVERY
 * attempt, and the attempts never stop: the pool refills on every SYN. On every path the test
 * watches three things: the return code, the process descriptors (their count must come back to
 * where it was) and the heap, through LeakSanitizer, checked after each case rather than in one
 * report at exit.
 *
 * Setup lives in the transport (src/proto/transport: transport_open, tr_link_open, security in
 * trsec.c); vless_connect only hands it the node.
 *
 * HOW IT WORKS WITHOUT A NODE OR A NETWORK. TCP setup goes through the g_tcp_dial seam
 * (src/proto/transport/trdial.c). The test hands the client one end of a socketpair and speaks
 * the server half of TLS 1.3 on the other: it parses the ClientHello, takes its key_share,
 * computes X25519, derives the handshake key schedule (RFC 8446 §7.1), sends encrypted
 * EncryptedExtensions, Certificate when needed, and Finished, and checks the client's Finished as
 * a real server would. tests/fake-vless.py speaks only security=none, and tests/run-reality.sh
 * needs sing-box, root and network namespaces.
 *
 * WHY THE SERVER HALF IS IN C, NOT PYTHON. The test is part of `make crypto-test`, and CI also runs
 * it under qemu for other architectures; it needs nothing beyond the crypto library the client is
 * built on. Second, the key schedule must match the client's to the byte: with both halves on
 * the same primitives (the scrypto layer), a mismatch means a bug in our TLS code, not a
 * difference between implementations. The HKDF label and the signature prefix are still built
 * here by separate copies, or a bug in them would agree with itself.
 *
 * security=tls WITH OUR OWN ROOTS. Reality proves itself by an HMAC in the signature field of a
 * temporary certificate: no X.509 chain, no root store. So the Reality cases never reach chain
 * verification, and only security=tls tests it. The TR_ENOH2 path (traffic keys already expanded,
 * so it must close through transport_close) is reachable only after a server check PASSES.
 *
 * So the test issues its own chain: a root and leaves for the SNI name, ECDSA P-256 keys, validity
 * from the current time (a certificate frozen in the repository would one day expire and fail
 * the test for no fault of its own). The root goes to a PEM file whose path reaches the engine
 * through the g_cert_roots seam in src/proto/tls/roots.c. The server half signs CertificateVerify
 * with a real signature over the transcript up to and including Certificate (RFC 8446 §4.4.3,
 * the prefix of 64 spaces and the label), and the client checks it with its own code: a mismatch
 * here means a bug in the engine.
 *
 * Covered this way: full success (handshake, chain, name against sni), the TR_ENOH2 path with
 * its transport_close, a wrong name, no CertificateVerify, a bad signature, a signature algorithm
 * we did not offer, and a self-signed leaf.
 *
 * Certificates are issued by tests/certgen.c on wolfCrypt with WOLFSSL_CERT_GEN (the Makefile
 * builds the tests' library with it; the program's build cannot issue certificates). The
 * Makefile always defines STEER_HAVE_X509WRITE; built by hand without it, the test SKIPS the
 * security=tls cases and says so loudly, since a silent skip would read as a pass.
 */
/* Before any include: the included sources need GNU extensions, and the first header fixes the
 * feature set. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>
#include <stdint.h>

/* Two sources are included whole, not linked, to reach their static seams: g_tcp_dial (trdial.c)
 * and g_cert_roots (roots.c). The VLESS client and the transport layers are linked as separate
 * objects (Makefile). */
#include "../src/proto/transport/trdial.c"
#include "../src/proto/tls/roots.c"
#include "client.h"

#include "scrypto.h"
#include "reality.h"
#if defined(STEER_HAVE_X509WRITE)
# include "certgen.h"
#endif

/* The shared secret with the peer's ephemeral key: the function tls13.c uses, not a copy. A
 * copy of crypto code is a second place where scalar clamping could differ. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);

int run_quiet(const char *const argv[]) { (void)argv; return 0; }

#if defined(__SANITIZE_ADDRESS__)
# include <sanitizer/lsan_interface.h>
# define LEAK_CHECK() __lsan_do_recoverable_leak_check()
#else
/* No sanitizer: the return code and descriptor checks still run, but the test must not stay
 * silent about the heap, since a silent skip reads as a pass. main says so once. */
# define LEAK_CHECK() 0
#endif

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-64s %s\n", what, want == got ? "ok" : "FAIL");
    if (want != got) {
        printf("     want: %ld\n     got:  %ld\n", want, got);
        fails++;
    }
}

static void check_str(const char *what, const char *want, const char *got) {
    int ok = got && strstr(got, want) != NULL;
    printf("%-64s %s\n", what, ok ? "ok" : "FAIL");
    if (!ok) {
        printf("     want substring: %s\n     got:            %s\n", want, got ? got : "(none)");
        fails++;
    }
}

/* Descriptors open in the process. A descriptor leak shows here without any sanitizer; one per
 * attempt on the TR_ENOH2 path (a grpc node with security=reality) reaches RLIMIT_NOFILE within
 * a day of probing. */
static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* ---- server half of TLS 1.3 ----------------------------------------------------
 *
 * Just enough for the client to finish the handshake: one cipher suite (0x1301, AES-128-GCM
 * with SHA-256), one group (X25519), no resumption. */

#define SUITE_HI 0x13
#define SUITE_LO 0x01
#define HLEN 32u                       /* SHA-256: both the transcript hash and the secret size */

struct plan {
    const char *name;
    int no_keyshare;      /* ServerHello without key_share: fails BEFORE key derivation */
    int bad_finished;     /* corrupt the server Finished */
    int cert;             /* 0: send none, 1: a garbage Certificate, 2: a compressed one (0x19) */
    const char *alpn;     /* ALPN string in EncryptedExtensions, or NULL */
    int hangup;           /* close the connection right after ClientHello */
    /* The security=tls path: a real chain issued by the test. `cert` is not read for these
     * cases; `chain` decides what to send. */
    int chain;            /* 0: not the tls path; otherwise the leaf index in g_leaf[] */
    int no_cv;            /* send Certificate and NO CertificateVerify */
    int cv_bad_sig;       /* corrupt a signature byte */
    int cv_bad_alg;       /* sign with a scheme we did not offer (rsa_pkcs1_sha256) */
    /* reality_ok: a Reality temporary certificate with a real HMAC-SHA512 signature over the
     * authkey (the only way to a SUCCESSFUL Reality in this test). upg: after the handshake the
     * server carries data too: traffic keys, the Upgrade request, a 101 answer with the first
     * data in the SAME record, and the client's reply (1: ws, 2: httpupgrade). */
    int reality_ok;
    int upg;
    /* ws with early data (path `?ed=2048`): the client writes "hello" BEFORE reading, and it
     * must go in the request's Sec-WebSocket-Protocol: with Ed > 0 Xray holds the request until
     * the first write. */
    int ed_first;
};

struct srv {
    int fd;
    const struct plan *plan;
    /* Server write keys and record counter. */
    unsigned char key[16], iv[12];
    unsigned char s_hs[HLEN];
    uint64_t seq;
    struct sc_hash_ctx tr;             /* handshake transcript */
    int rc;                            /* != 0: the half broke by itself, not by plan */
    int fin_sent;                      /* the server Finished went out */
    /* Data path (plan.upg): handshake secrets and what the server saw. */
    unsigned char hs[HLEN], c_hs[HLEN];
    int alpn_h11;                      /* the ClientHello ALPN is http/1.1 alone */
    char req[4096];                    /* the Upgrade request as received */
    int got_hello;                     /* the client's "hello" arrived and parsed */
};

/* Static key pair of the Reality server for plan.reality_ok: the node's pbk is its public half. */
static unsigned char g_rs_priv[32], g_rs_pub[32];
/* What the server saw in the ALPN of the last ClientHello (for runs through run_case). */
static volatile int g_seen_h11 = -1;
/* After the last run_case: 1 if the client's Finished came and verifies, 0 if the client sent
 * nothing after its ClientHello, -1 for anything else. */
static int g_cfin = -1;

/* HKDF-Expand-Label from RFC 8446 §7.1. Our own copy, not a call to the static one in tls13.c:
 * the test must compute the label ITSELF, or a bug in the client's wrapper would agree with
 * itself and go unnoticed. */
static int xlabel(const unsigned char *secret, const char *label,
                  const unsigned char *ctx, size_t ctx_n,
                  unsigned char *out, size_t out_n) {
    unsigned char info[128];
    size_t n = 0, ln = strlen(label);
    if (2 + 1 + 6 + ln + 1 + ctx_n > sizeof(info)) return -1;
    info[n++] = (unsigned char)(out_n >> 8);
    info[n++] = (unsigned char)out_n;
    info[n++] = (unsigned char)(6 + ln);
    memcpy(info + n, "tls13 ", 6); n += 6;
    memcpy(info + n, label, ln);    n += ln;
    info[n++] = (unsigned char)ctx_n;
    if (ctx_n) { memcpy(info + n, ctx, ctx_n); n += ctx_n; }
    return sc_hkdf_expand(SC_SHA256, secret, HLEN, info, n, out, out_n);
}

static void tr_snapshot(const struct sc_hash_ctx *tr, unsigned char out[HLEN]) {
    struct sc_hash_ctx c;
    if (sc_hash_clone(&c, tr) != 0) { memset(out, 0, HLEN); return; }
    sc_hash_final(&c, out);
    sc_hash_free(&c);
}

static int wr_all(int fd, const unsigned char *b, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, b + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int rd_all(int fd, unsigned char *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* One record: a five-byte header, then the body. */
static int rd_rec(int fd, unsigned char *type, unsigned char *body, size_t cap, size_t *n) {
    unsigned char h[5];
    if (rd_all(fd, h, 5)) return -1;
    size_t len = ((size_t)h[3] << 8) | h[4];
    if (len > cap) return -1;
    if (rd_all(fd, body, len)) return -1;
    *type = h[0];
    *n = len;
    return 0;
}

/* ---- our own X.509 chain for security=tls -------------------------------------------
 *
 * Three leaves:
 *   LEAF_OK   for the SNI name, signed by the root: the check passes, which is the way to the
 *             TR_ENOH2 path and its transport_close;
 *   LEAF_NAME signed by the same root, for another name: the check must fail on the name, not
 *             pass because "the chain verified";
 *   LEAF_SELF self-signed: the root plays no part, the chain check fails.
 *
 * ECDSA P-256 keys, not RSA: RSA-2048 generation takes seconds and would slow the test with no
 * gain for what is tested. certverify.c accepts both, and the CertificateVerify signature goes
 * through the same sc_cert_verify_sig (tests/scryptomatch.c checks RSA and PSS against OpenSSL
 * signatures).
 *
 * Validity is counted FROM THE CURRENT TIME, not fixed in a string: a frozen certificate expires
 * one day and fails the test for no fault of its own, so it is issued anew on every run.
 */
#if defined(STEER_HAVE_X509WRITE)

#define LEAF_OK   1
#define LEAF_NAME 2
#define LEAF_SELF 3

/* The name the good leaf is issued for, also the node's SNI: the certificate is checked against
 * sni, not host (trsec.c, verify_host). */
#define TLS_SNI "tls.node.invalid"

struct leaf {
    unsigned char der[2048];
    size_t der_n;
    struct tcg_key *key;         /* the leaf's key: it signs CertificateVerify */
};

static struct leaf g_leaf[4];        /* [0] unused: indexes match LEAF_* */
static char g_roots_file[64];
static int g_chain_ready;

/* Root, three leaves and the store file, once per process: certverify.c loads the roots under
 * pthread_once, so a second store in the same process would have no effect, and all cases must
 * run against ONE root set. The name goes in the CN: the test issues no SAN, and the name check
 * must find it there. */
static int chain_build(void) {
    struct tcg_key *root_key = tcg_key_new();
    if (!root_key) return -1;

    static char pem[4096];
    unsigned char root_der[2048];
    size_t root_n = 0;
    if (tcg_issue(root_key, "steer test root", NULL, 1, NULL, NULL, 0,
                  root_der, sizeof(root_der), &root_n) != 0 ||
        tcg_der_to_pem(root_der, root_n, pem, sizeof(pem)) != 0) {
        tcg_key_free(root_key);
        return -1;
    }

    struct { int idx; const char *cn; int self; } want[] = {
        { LEAF_OK,   TLS_SNI,          0 },
        { LEAF_NAME, "other.invalid",  0 },
        { LEAF_SELF, TLS_SNI,          1 },
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(*want); i++) {
        struct leaf *l = &g_leaf[want[i].idx];
        if (!(l->key = tcg_key_new())) { tcg_key_free(root_key); return -1; }
        int rc = want[i].self
            ? tcg_issue(l->key, want[i].cn, NULL, 0, NULL, NULL, 0, l->der, sizeof(l->der), &l->der_n)
            : tcg_issue(l->key, want[i].cn, NULL, 0, root_key, root_der, root_n,
                        l->der, sizeof(l->der), &l->der_n);
        if (rc != 0) { tcg_key_free(root_key); return -1; }
    }
    tcg_key_free(root_key);

    snprintf(g_roots_file, sizeof(g_roots_file), "%s", "/tmp/vlessmatch-roots-XXXXXX");
    int fd = mkstemp(g_roots_file);
    if (fd < 0) return -1;
    size_t pn = strlen(pem);
    int ok = wr_all(fd, (const unsigned char *)pem, pn) == 0;
    close(fd);
    if (!ok) return -1;
    g_chain_ready = 1;
    return 0;
}

static void chain_free(void) {
    for (int i = 1; i <= LEAF_SELF; i++) { tcg_key_free(g_leaf[i].key); g_leaf[i].key = NULL; }
    if (g_roots_file[0]) unlink(g_roots_file);
}

/* A Certificate message with one leaf (RFC 8446 §4.4.2): a context byte, a list with a 3-byte
 * length, holding one entry "3-byte length + DER + 2-byte extensions". The root is left out on
 * purpose: it is already in the store, and the chain must verify without it, or the test would
 * check the server's generosity instead of the verification. */
static size_t cert_msg(const struct leaf *l, unsigned char *out, size_t cap) {
    size_t body = 1 + 3 + 3 + l->der_n + 2;
    if (4 + body > cap) return 0;
    size_t n = 0;
    out[n++] = 0x0B;
    out[n++] = (unsigned char)(body >> 16);
    out[n++] = (unsigned char)(body >> 8);
    out[n++] = (unsigned char)body;
    out[n++] = 0x00;                                     /* certificate_request_context */
    size_t list = 3 + l->der_n + 2;
    out[n++] = (unsigned char)(list >> 16);
    out[n++] = (unsigned char)(list >> 8);
    out[n++] = (unsigned char)list;
    out[n++] = (unsigned char)(l->der_n >> 16);
    out[n++] = (unsigned char)(l->der_n >> 8);
    out[n++] = (unsigned char)l->der_n;
    memcpy(out + n, l->der, l->der_n); n += l->der_n;
    out[n++] = 0x00; out[n++] = 0x00;                    /* extensions: none */
    return n;
}

/* CertificateVerify: a signature over 64 spaces, the label, a zero byte and the transcript hash
 * up to and including Certificate. The prefix is built HERE, not taken from certverify.c: the
 * two halves must reach the same answer independently, or a bug in the prefix would agree with
 * itself. */
static size_t cv_msg(const struct leaf *l, const unsigned char thash[HLEN],
                     const struct plan *pl, unsigned char *out, size_t cap) {
    unsigned char content[64 + 33 + 1 + HLEN];
    size_t cn = 0;
    memset(content, 0x20, 64); cn = 64;
    memcpy(content + cn, "TLS 1.3, server CertificateVerify", 33); cn += 33;
    content[cn++] = 0x00;
    memcpy(content + cn, thash, HLEN); cn += HLEN;

    unsigned char digest[HLEN];
    if (sc_hash(SC_SHA256, content, cn, digest) != 0) return 0;

    /* A DER ECDSA P-256 signature is at most 72 bytes; room to spare. */
    unsigned char sig[160];
    size_t sig_n = 0;
    if (tcg_sign_sha256(l->key, digest, sig, sizeof(sig), &sig_n) != 0) return 0;
    if (pl->cv_bad_sig) sig[sig_n / 2] ^= 0xFF;

    if (4 + 4 + sig_n > cap) return 0;
    size_t n = 0;
    out[n++] = 0x0F;
    out[n++] = 0; out[n++] = 0; out[n++] = (unsigned char)(4 + sig_n);
    /* 0x0403 is ecdsa_secp256r1_sha256, which our signature_algorithms lists. 0x0401 is
     * rsa_pkcs1_sha256, which TLS 1.3 forbids for CertificateVerify, and we do not offer it: a
     * server choosing it must get its own reason, not "bad signature". */
    out[n++] = 0x04; out[n++] = pl->cv_bad_alg ? 0x01 : 0x03;
    out[n++] = (unsigned char)(sig_n >> 8);
    out[n++] = (unsigned char)sig_n;
    memcpy(out + n, sig, sig_n); n += sig_n;
    return n;
}
#endif /* STEER_HAVE_X509WRITE */

/* ClientHello: we need the client's key_share and the session_id, which the server must echo
 * as is. Parsed by extension type, not by offset: reality.c's Hello changes with the browser
 * look. */
static int ch_pick(const unsigned char *b, size_t n, unsigned char pub[32],
                   unsigned char *sid, size_t *sid_n) {
    if (n < 40 || b[0] != 0x01) return -1;
    size_t p = 4 + 2 + 32;
    size_t sn = b[p++];
    if (sn > 32 || p + sn > n) return -1;
    memcpy(sid, b + p, sn);
    *sid_n = sn;
    p += sn;
    if (p + 2 > n) return -1;
    size_t cs = ((size_t)b[p] << 8) | b[p + 1];
    p += 2 + cs;
    if (p >= n) return -1;
    p += 1 + b[p];                                  /* compression_methods */
    if (p + 2 > n) return -1;
    size_t exts = ((size_t)b[p] << 8) | b[p + 1];
    p += 2;
    size_t end = p + exts;
    if (end > n) return -1;
    while (p + 4 <= end) {
        unsigned etype = ((unsigned)b[p] << 8) | b[p + 1];
        size_t elen = ((size_t)b[p + 2] << 8) | b[p + 3];
        p += 4;
        if (p + elen > end) return -1;
        if (etype == 0x0033) {
            /* client_shares: list length (2), then group (2) + length (2) + key. Take X25519
             * (0x001d) specifically: reality.c may offer the post-quantum group, and it comes
             * first in the list. */
            size_t q = 2;
            while (q + 4 <= elen) {
                unsigned grp = ((unsigned)b[p + q] << 8) | b[p + q + 1];
                size_t kn = ((size_t)b[p + q + 2] << 8) | b[p + q + 3];
                if (q + 4 + kn > elen) break;
                if (grp == 0x001d && kn == 32) {
                    memcpy(pub, b + p + q + 4, 32);
                    return 0;
                }
                q += 4 + kn;
            }
        }
        p += elen;
    }
    return -1;
}

/* An encrypted handshake record with one message: the client collects messages across record
 * boundaries, so this is tested too. */
static int send_enc(struct srv *s, const unsigned char *msg, size_t n) {
    unsigned char out[4096];
    if (n + 1 + 16 + 5 > sizeof(out)) return -1;
    size_t total = n + 1 + 16;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)(total >> 8);
    out[4] = (unsigned char)total;
    memcpy(out + 5, msg, n);
    out[5 + n] = 0x16;                              /* the real record type */

    unsigned char nonce[12];
    memcpy(nonce, s->iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(s->seq >> (8 * i));

    /* A one-off key per record: the server half is not about speed. The context goes on the
     * heap: at over a kilobyte it does not belong on this thread's stack. */
    struct sc_aead *g = malloc(sizeof(*g));
    if (!g) return -1;
    int rc = sc_aead_setkey(g, SC_AES128_GCM, s->key);
    if (rc == 0) rc = sc_aead_seal(g, nonce, out, 5, out + 5, n + 1, out + 5 + n + 1);
    sc_aead_free(g);
    free(g);
    if (rc) return -1;
    s->seq++;
    return wr_all(s->fd, out, 5 + total);
}

/* ---- data path after the handshake: ws and httpupgrade (plan.upg) -------------------------
 *
 * Here the server half takes the connection on to data: the application traffic keys (RFC 8446
 * §7.1, from the master secret and the transcript up to the server Finished), the client
 * Finished under the handshake key, the Upgrade request, a 101 answer followed in the SAME record
 * by the first stream data (a ws frame or raw httpupgrade bytes: a remainder the transport must
 * not lose), and whatever the client sends back. Each direction has its own key and counter
 * (struct dir). */
struct dir { struct sc_aead g; unsigned char iv[12]; uint64_t seq; int ready; };

static int dir_set(struct dir *d, const unsigned char secret[HLEN]) {
    unsigned char key[16];
    if (xlabel(secret, "key", NULL, 0, key, 16) || xlabel(secret, "iv", NULL, 0, d->iv, 12)) return -1;
    if (d->ready) sc_aead_free(&d->g);
    d->ready = 0;
    if (sc_aead_setkey(&d->g, SC_AES128_GCM, key)) return -1;
    d->ready = 1;
    d->seq = 0;
    return 0;
}

static void dir_nonce(const struct dir *d, unsigned char n[12]) {
    memcpy(n, d->iv, 12);
    for (int i = 0; i < 8; i++) n[11 - i] ^= (unsigned char)(d->seq >> (8 * i));
}

/* The next record from the client: ChangeCipherSpec is skipped, the rest is decrypted. */
static int rec_open(struct dir *d, int fd, unsigned char *out, size_t cap, size_t *n,
                    unsigned char *inner) {
    for (;;) {
        unsigned char type;
        size_t len;
        if (rd_rec(fd, &type, out, cap, &len)) return -1;
        if (type == 0x14) continue;
        if (type != 0x17 || len < 17) return -1;
        unsigned char hdr[5] = { 0x17, 0x03, 0x03, (unsigned char)(len >> 8), (unsigned char)len };
        unsigned char nonce[12];
        dir_nonce(d, nonce);
        if (sc_aead_open(&d->g, nonce, hdr, 5, out, len - 16, out + len - 16)) return -1;
        d->seq++;
        size_t pt = len - 16;
        while (pt && !out[pt - 1]) pt--;
        if (!pt) return -1;
        *inner = out[--pt];
        *n = pt;
        return 0;
    }
}

static int rec_seal(struct dir *d, int fd, const unsigned char *msg, size_t n) {
    static __thread unsigned char out[5 + 4096 + 17];
    if (n + 17 > 4096 + 17) return -1;
    size_t total = n + 1 + 16;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
    memcpy(out + 5, msg, n);
    out[5 + n] = 0x17;
    unsigned char nonce[12];
    dir_nonce(d, nonce);
    if (sc_aead_seal(&d->g, nonce, out, 5, out + 5, n + 1, out + 5 + n + 1)) return -1;
    d->seq++;
    return wr_all(fd, out, 5 + total);
}

/* The client's Finished (RFC 8446 §4.4.4), checked as a real server checks it: a record under the
 * client handshake key holding an HMAC, keyed by the client finished key, over the transcript up
 * to the server Finished. 1 if it verifies, -1 for anything else. */
static int client_finished(struct srv *s, struct dir *d) {
    unsigned char rec[512], th[HLEN], fkey[HLEN], vd[HLEN], inner;
    size_t n;
    tr_snapshot(&s->tr, th);
    if (dir_set(d, s->c_hs) || rec_open(d, s->fd, rec, sizeof(rec), &n, &inner)) return -1;
    if (inner != 0x16 || n != 4 + HLEN || memcmp(rec, "\x14\x00\x00\x20", 4)) return -1;
    if (xlabel(s->c_hs, "finished", NULL, 0, fkey, HLEN)) return -1;
    if (sc_hmac(SC_SHA256, fkey, HLEN, th, HLEN, vd) != 0) return -1;
    return memcmp(rec + 4, vd, HLEN) ? -1 : 1;
}

/* Sec-WebSocket-Accept (RFC 6455 §1.3): base64 of SHA-1 over the key and the GUID. Computed
 * here, not by tr_ws_accept: the client checks the answer with that function, and a bug in it
 * would agree with itself. */
static int ws_accept(const char *key, char out[29]) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    char in[96];
    unsigned char h[21] = { 0 };                  /* SHA-1 and a zero byte: 7 groups of 3 */
    int n = snprintf(in, sizeof(in), "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", key);
    if (n < 0 || (size_t)n >= sizeof(in) || sc_hash(SC_SHA1, in, (size_t)n, h) != 0) return -1;
    for (int i = 0, o = 0; i < 21; i += 3) {
        unsigned v = ((unsigned)h[i] << 16) | ((unsigned)h[i + 1] << 8) | h[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        out[o++] = T[(v >> 6) & 63];
        out[o++] = i < 18 ? T[v & 63] : '=';
    }
    out[28] = '\0';
    return 0;
}

static int app_phase_dirs(struct srv *s, struct dir *cd, struct dir *sd) {
    unsigned char zeros[HLEN] = {0}, empty[HLEN], derived[HLEN], master[HLEN], th[HLEN];
    unsigned char c_ap[HLEN], s_ap[HLEN];
    if (sc_hash(SC_SHA256, zeros, 0, empty) != 0) return -1;
    if (xlabel(s->hs, "derived", empty, HLEN, derived, HLEN) != 0) return -1;
    if (sc_hkdf_extract(SC_SHA256, derived, HLEN, zeros, HLEN, master) != 0) return -1;
    tr_snapshot(&s->tr, th);
    if (xlabel(master, "c ap traffic", th, HLEN, c_ap, HLEN) != 0) return -1;
    if (xlabel(master, "s ap traffic", th, HLEN, s_ap, HLEN) != 0) return -1;

    static __thread unsigned char buf[16384 + 256];
    size_t n;
    unsigned char inner;
    /* A wrong client Finished ends the connection here, before the Upgrade answer. */
    if (client_finished(s, cd) != 1) return -1;
    if (dir_set(cd, c_ap) || dir_set(sd, s_ap)) return -1;

    size_t rn = 0;
    while (!strstr(s->req, "\r\n\r\n")) {
        if (rec_open(cd, s->fd, buf, sizeof(buf), &n, &inner) || inner != 0x17) return -1;
        if (rn + n >= sizeof(s->req)) return -1;
        memcpy(s->req + rn, buf, n);
        rn += n;
        s->req[rn] = '\0';
    }

    char resp[512];
    int k;
    if (s->plan->upg == 1) {
        char key[32] = "", acc[29];
        const char *kp = strstr(s->req, "\r\nSec-WebSocket-Key: ");
        if (!kp) return -1;
        sscanf(kp + 21, "%31[^\r]", key);
        if (ws_accept(key, acc)) return -1;
        k = snprintf(resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
        resp[k++] = (char)0x82; resp[k++] = 5;           /* server frame: unmasked */
        memcpy(resp + k, "FIRST", 5); k += 5;
    } else {
        k = snprintf(resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\n\r\nFIRST");
    }
    if (rec_seal(sd, s->fd, (const unsigned char *)resp, (size_t)k)) return -1;

    /* ws early data (Ed > 0): the client's "hello" came in the request itself, base64url
     * without `=`. */
    if (s->plan->ed_first) {
        s->got_hello = strstr(s->req, "\r\nSec-WebSocket-Protocol: aGVsbG8\r\n") != NULL;
        return 0;
    }
    if (rec_open(cd, s->fd, buf, sizeof(buf), &n, &inner) || inner != 0x17) return -1;
    if (s->plan->upg == 1) {
        /* 0x82, 0x80|5, the mask, "hello" masked. */
        if (n != 11 || buf[0] != 0x82 || buf[1] != (0x80 | 5)) return -1;
        for (int i = 0; i < 5; i++) buf[6 + i] ^= buf[2 + (i & 3)];
        s->got_hello = !memcmp(buf + 6, "hello", 5);
    } else {
        s->got_hello = n == 5 && !memcmp(buf, "hello", 5);
    }
    return 0;
}

static int app_phase(struct srv *s) {
    struct dir *cd = calloc(1, sizeof(*cd)), *sd = calloc(1, sizeof(*sd));
    int rc = cd && sd ? app_phase_dirs(s, cd, sd) : -1;
    if (cd && cd->ready) sc_aead_free(&cd->g);
    if (sd && sd->ready) sc_aead_free(&sd->g);
    free(cd);
    free(sd);
    return rc;
}

static void *server_half(void *arg) {
    struct srv *s = arg;
    const struct plan *pl = s->plan;
    unsigned char ch[4096];
    unsigned char type;
    size_t ch_n = 0;

    s->rc = -1;
    if (rd_rec(s->fd, &type, ch, sizeof(ch), &ch_n) || type != 0x16) return NULL;
    if (pl->hangup) { s->rc = 0; close(s->fd); s->fd = -1; return NULL; }
    /* ALPN exactly "http/1.1": extension 0x0010 of length 11, list of length 9 (ws and
     * httpupgrade; the other transports send "h2, http/1.1"). All 15 bytes are compared, the
     * name included. */
    static const char H11[] = "\x00\x10\x00\x0b\x00\x09\x08http/1.1";
    s->alpn_h11 = memmem(ch, ch_n, H11, sizeof(H11) - 1) != NULL;
    g_seen_h11 = s->alpn_h11;

    unsigned char cpub[32], sid[32];
    size_t sid_n = 0;
    if (ch_pick(ch, ch_n, cpub, sid, &sid_n)) return NULL;

    unsigned char spriv[32], spub[32];
    if (xc_x25519_keypair(spriv, spub) != 0) return NULL;

    /* ---- ServerHello ---- */
    unsigned char sh[256];
    size_t m = 0;
    sh[m++] = 0x02; m += 3;                          /* length filled in below */
    sh[m++] = 0x03; sh[m++] = 0x03;
    if (xc_random(sh + m, 32) != 0) return NULL;
    m += 32;
    sh[m++] = (unsigned char)sid_n;
    memcpy(sh + m, sid, sid_n); m += sid_n;
    sh[m++] = SUITE_HI; sh[m++] = SUITE_LO;
    sh[m++] = 0x00;                                  /* compression */
    size_t exts_at = m; m += 2;
    sh[m++] = 0x00; sh[m++] = 0x2b; sh[m++] = 0x00; sh[m++] = 0x02;
    sh[m++] = 0x03; sh[m++] = 0x04;                  /* supported_versions: TLS 1.3 */
    if (!pl->no_keyshare) {
        sh[m++] = 0x00; sh[m++] = 0x33; sh[m++] = 0x00; sh[m++] = 0x24;
        sh[m++] = 0x00; sh[m++] = 0x1d; sh[m++] = 0x00; sh[m++] = 0x20;
        memcpy(sh + m, spub, 32); m += 32;
    }
    sh[exts_at]     = (unsigned char)((m - exts_at - 2) >> 8);
    sh[exts_at + 1] = (unsigned char)(m - exts_at - 2);
    sh[1] = (unsigned char)((m - 4) >> 16);
    sh[2] = (unsigned char)((m - 4) >> 8);
    sh[3] = (unsigned char)(m - 4);

    unsigned char rec[5 + 256];
    rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = (unsigned char)(m >> 8); rec[4] = (unsigned char)m;
    memcpy(rec + 5, sh, m);
    if (wr_all(s->fd, rec, 5 + m)) return NULL;

    if (sc_hash_init(&s->tr, SC_SHA256) != 0) return NULL;
    sc_hash_update(&s->tr, ch, ch_n);
    sc_hash_update(&s->tr, sh, m);

    if (pl->no_keyshare) { s->rc = 0; return NULL; }   /* the client stops listening here */

    /* ---- handshake key schedule, RFC 8446 §7.1 ---- */
    unsigned char zeros[HLEN] = {0}, empty[HLEN];
    unsigned char early[HLEN], derived[HLEN], hs[HLEN], ecdhe[32], th[HLEN];
    if (sc_hash(SC_SHA256, zeros, 0, empty) != 0) return NULL;
    if (sc_hkdf_extract(SC_SHA256, NULL, 0, zeros, HLEN, early) != 0) return NULL;
    if (xlabel(early, "derived", empty, HLEN, derived, HLEN) != 0) return NULL;
    if (x25519_shared_ext(spriv, cpub, ecdhe) != 0) return NULL;
    if (sc_hkdf_extract(SC_SHA256, derived, HLEN, ecdhe, 32, hs) != 0) return NULL;
    tr_snapshot(&s->tr, th);
    if (xlabel(hs, "s hs traffic", th, HLEN, s->s_hs, HLEN) != 0) return NULL;
    if (xlabel(hs, "c hs traffic", th, HLEN, s->c_hs, HLEN) != 0) return NULL;
    memcpy(s->hs, hs, HLEN);
    if (xlabel(s->s_hs, "key", NULL, 0, s->key, sizeof(s->key)) != 0) return NULL;
    if (xlabel(s->s_hs, "iv", NULL, 0, s->iv, sizeof(s->iv)) != 0) return NULL;

    /* ---- EncryptedExtensions ---- */
    unsigned char ee[64];
    size_t en = 0;
    ee[en++] = 0x08; en += 3;
    size_t elist_at = en; en += 2;
    if (pl->alpn) {
        size_t pn = strlen(pl->alpn);
        ee[en++] = 0x00; ee[en++] = 0x10;
        ee[en++] = 0x00; ee[en++] = (unsigned char)(3 + pn);
        ee[en++] = 0x00; ee[en++] = (unsigned char)(1 + pn);
        ee[en++] = (unsigned char)pn;
        memcpy(ee + en, pl->alpn, pn); en += pn;
    }
    ee[elist_at]     = (unsigned char)((en - elist_at - 2) >> 8);
    ee[elist_at + 1] = (unsigned char)(en - elist_at - 2);
    ee[1] = 0; ee[2] = (unsigned char)((en - 4) >> 8); ee[3] = (unsigned char)(en - 4);
    if (send_enc(s, ee, en)) return NULL;
    sc_hash_update(&s->tr, ee, en);

#if defined(STEER_HAVE_X509WRITE)
    /* ---- Certificate and CertificateVerify with a real chain (security=tls path) ---- */
    if (pl->chain) {
        const struct leaf *l = &g_leaf[pl->chain];
        unsigned char msg[3072];
        size_t mn = cert_msg(l, msg, sizeof(msg));
        if (!mn) return NULL;
        if (send_enc(s, msg, mn)) return NULL;
        sc_hash_update(&s->tr, msg, mn);

        if (!pl->no_cv) {
            /* The hash is taken AFTER Certificate and BEFORE CertificateVerify: what the
             * server signs per RFC 8446 §4.4.3, and where the client takes its own (tls13.c,
             * message 0x0F). One step off here would give "bad signature" and look like a bug
             * in the engine. */
            unsigned char th_cv[HLEN];
            tr_snapshot(&s->tr, th_cv);
            size_t cn = cv_msg(l, th_cv, pl, msg, sizeof(msg));
            if (!cn) return NULL;
            if (send_enc(s, msg, cn)) return NULL;
            sc_hash_update(&s->tr, msg, cn);
        }
        goto finished;
    }
#endif

    /* ---- Certificate or its compressed form ---- */
    if (pl->cert == 2) {
        /* CompressedCertificate: the client fails on it at once, without waiting for
         * Finished; a compressed certificate means we were handed to the camouflage site. */
        unsigned char cc[16] = { 0x19, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
                                 0x04, 0x01, 0x02, 0x03 };
        s->rc = send_enc(s, cc, 12) ? -1 : 0;
        return NULL;
    }
    if (pl->reality_ok) {
        /* Reality temporary certificate: an Ed25519 key (any 32 bytes: nobody checks it as a
         * key) and the signature field = HMAC-SHA512(authkey, key), where authkey is
         * HKDF-SHA256 of ECDH(server static key, client ephemeral key) with salt Random[0..20)
         * and info "REALITY" (Xray's reality.go; the client half is reality.c). The DER is just
         * what cert_reality_check reads:
         * SEQUENCE { tbs with an Ed25519 SPKI, algid, BIT STRING }. */
        unsigned char shared[32], authkey[32], epub[32], sig[64];
        if (x25519_shared_ext(g_rs_priv, cpub, shared) != 0) return NULL;
        if (sc_hkdf(SC_SHA256, ch + 6, 20, shared, 32, "REALITY", 7, authkey, 32) != 0) return NULL;
        for (int i = 0; i < 32; i++) epub[i] = (unsigned char)(0x40 + i);
        if (sc_hmac(SC_SHA512, authkey, 32, epub, 32, sig) != 0) return NULL;
        static const unsigned char spki[] = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
                                              0x03, 0x21, 0x00 };
        unsigned char der[128];
        size_t dn = 0;
        der[dn++] = 0x30; der[dn++] = 0x78;                  /* Certificate, 120 bytes */
        der[dn++] = 0x30; der[dn++] = 0x2C;                  /* tbsCertificate: SPKI only */
        memcpy(der + dn, spki, sizeof(spki)); dn += sizeof(spki);
        memcpy(der + dn, epub, 32); dn += 32;
        static const unsigned char alg[] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70 };
        memcpy(der + dn, alg, sizeof(alg)); dn += sizeof(alg);
        der[dn++] = 0x03; der[dn++] = 0x41; der[dn++] = 0x00;
        memcpy(der + dn, sig, 64); dn += 64;
        unsigned char cm[256];
        size_t cn = 0, body = 1 + 3 + 3 + dn + 2;
        cm[cn++] = 0x0B;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(body >> 8); cm[cn++] = (unsigned char)body;
        cm[cn++] = 0;                                        /* certificate_request_context */
        size_t list = 3 + dn + 2;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(list >> 8); cm[cn++] = (unsigned char)list;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(dn >> 8); cm[cn++] = (unsigned char)dn;
        memcpy(cm + cn, der, dn); cn += dn;
        cm[cn++] = 0; cm[cn++] = 0;                          /* no entry extensions */
        if (send_enc(s, cm, cn)) return NULL;
        sc_hash_update(&s->tr, cm, cn);
    }
    if (pl->cert == 1) {
        /* The body deliberately parses as no certificate at all: what is tested is not X.509
         * parsing but how a failed check is closed. */
        unsigned char cr[40];
        cr[0] = 0x0B; cr[1] = 0; cr[2] = 0; cr[3] = 32;
        memset(cr + 4, 0xA5, 32);
        if (send_enc(s, cr, 36)) return NULL;
        sc_hash_update(&s->tr, cr, 36);
    }

    /* ---- Finished ---- */
#if defined(STEER_HAVE_X509WRITE)
finished:;
#endif
    unsigned char fkey[HLEN], hash[HLEN], vd[HLEN];
    tr_snapshot(&s->tr, hash);
    if (xlabel(s->s_hs, "finished", NULL, 0, fkey, HLEN) != 0) return NULL;
    if (sc_hmac(SC_SHA256, fkey, HLEN, hash, HLEN, vd) != 0) return NULL;
    if (pl->bad_finished) vd[0] ^= 0xFF;
    unsigned char fin[4 + HLEN];
    fin[0] = 0x14; fin[1] = 0; fin[2] = 0; fin[3] = (unsigned char)HLEN;
    memcpy(fin + 4, vd, HLEN);
    if (send_enc(s, fin, sizeof(fin))) return NULL;
    sc_hash_update(&s->tr, fin, sizeof(fin));
    s->fin_sent = 1;

    if (pl->upg) { s->rc = app_phase(s); return NULL; }
    s->rc = 0;
    return NULL;
}

/* ---- TCP setup seam ------------------------------------------------------------ */

static int g_give_fd = -1;

static int fake_dial(const char *host, uint16_t port, int timeout_s) {
    (void)host; (void)port;
    int fd = g_give_fd;
    g_give_fd = -1;
    if (fd < 0) return TR_ECONNECT;
    /* What tcp_connect does with the winning socket: read and write timeouts. Without them a
     * bug in the server half would hang the test instead of failing it. */
    sock_ready(fd, timeout_s);
    return fd;
}

/* A Reality node over tcp. Reality, not security=tls: the proof here is the temporary
 * certificate's signature over the authkey, so failing the check needs no root store and no
 * X.509 chain, and the ECERT path is reachable without issuing certificates. The pbk is
 * arbitrary: X25519 multiplies any 32 bytes, and the server for this pair is fake anyway. */
static void node_reality(struct vless_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "00000000-0000-0000-0000-000000000001");
    snprintf(n->type, sizeof(n->type), "%s", type);
    snprintf(n->security, sizeof(n->security), "%s", "reality");
    snprintf(n->sni, sizeof(n->sni), "%s", "www.example.com");
    snprintf(n->fp, sizeof(n->fp), "%s", "chrome");
    snprintf(n->pbk, sizeof(n->pbk), "%s", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA");
    snprintf(n->sid, sizeof(n->sid), "%s", "0123456789abcdef");
}

#if defined(STEER_HAVE_X509WRITE)
/* A security=tls node: the proof is the chain to a root and the name, nothing else. pbk and sid
 * are left empty on purpose: plain TLS has none, and reality_build_hello does not read them with
 * .plain = 1 (trsec.c). The name is checked against sni, not host, so sni is the name the good
 * leaf is issued for. */
static void node_tls(struct vless_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "00000000-0000-0000-0000-000000000001");
    snprintf(n->type, sizeof(n->type), "%s", type);
    snprintf(n->security, sizeof(n->security), "%s", "tls");
    snprintf(n->sni, sizeof(n->sni), "%s", TLS_SNI);
    snprintf(n->fp, sizeof(n->fp), "%s", "chrome");
}
#endif

/* One run: make a socket pair, give one end to the client and the other to the server half.
 *
 * ctx_left, if given, receives the number of cipher contexts left EXPANDED in the connection
 * after return. This is the observable form of "there was nothing to free": a failed handshake
 * closes with a plain close(fd), which is safe only while tls13.c expands the traffic contexts
 * as its last step, after all its failure exits. Nothing else guards this link between the two
 * files; the check fails the day the order in tls13.c changes. */
static int run_case(const struct plan *pl, struct vless_node *n, char *reason, size_t rn,
                    int *ctx_left) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -100;

    struct srv s;
    memset(&s, 0, sizeof(s));
    s.fd = sv[1];
    s.plan = pl;

    pthread_t th;
    if (pthread_create(&th, NULL, server_half, &s) != 0) {
        close(sv[0]); close(sv[1]);
        return -101;
    }

    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    if (rc == 0) transport_close(&c);
    g_tcp_dial = NULL;

    if (reason && rn) snprintf(reason, rn, "%s", tls13_verify_reason());
    if (ctx_left) *ctx_left = (c.link.tls.rd.ctx_ready ? 1 : 0) + (c.link.tls.wr.ctx_ready ? 1 : 0) +
                              (c.xh.up.link.tls.rd.ctx_ready ? 1 : 0) +
                              (c.xh.up.link.tls.wr.ctx_ready ? 1 : 0);

    pthread_join(th, NULL);
    /* What the client sent after the server Finished. vless_connect has returned, so a Finished
     * it sent is already in the socket: read without waiting. */
    g_cfin = 0;
    unsigned char b;
    if (s.fd >= 0 && fcntl(s.fd, F_SETFL, O_NONBLOCK) == 0 && recv(s.fd, &b, 1, MSG_PEEK) > 0) {
        struct dir *d = calloc(1, sizeof(*d));
        g_cfin = d && s.fin_sent ? client_finished(&s, d) : -1;
        if (d && d->ready) sc_aead_free(&d->g);
        free(d);
    }
    if (s.fd >= 0) close(s.fd);
    /* The client's end of the pair is closed by vless_connect itself (or by transport_close on
     * success). If it is not, that is the finding, and the caller's descriptor count shows it. */
    return rc;
}

/* A ws or httpupgrade run through to data: setup, the first data after the 101 answer (it came
 * in ONE TLS record with the answer), the client's reply. 0 if all of it worked; *s holds what
 * the server saw. */
static int run_upg(const struct plan *pl, struct vless_node *n, struct srv *s) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -100;
    memset(s, 0, sizeof(*s));
    s->fd = sv[1];
    s->plan = pl;
    pthread_t th;
    if (pthread_create(&th, NULL, server_half, s) != 0) { close(sv[0]); close(sv[1]); return -101; }

    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    g_tcp_dial = NULL;
    if (rc == 0 && pl->ed_first) rc = transport_write(&c, (const unsigned char *)"hello", 5);
    if (rc == 0) {
        static unsigned char buf[VLESS_MIN_RECV_CAP];
        size_t got = 0;
        for (int i = 0; i < 50 && !rc && !got; i++) {
            if (!transport_has_data(&c)) {
                struct pollfd p = { .fd = transport_fd(&c), .events = POLLIN, .revents = 0 };
                if (poll(&p, 1, 3000) <= 0) break;
            }
            rc = transport_read(&c, buf, sizeof(buf), &got);
        }
        if (!rc && (got != 5 || memcmp(buf, "FIRST", 5))) rc = -102;
        if (!rc && !pl->ed_first) rc = transport_write(&c, (const unsigned char *)"hello", 5);
        transport_close(&c);
    }
    pthread_join(th, NULL);
    if (s->fd >= 0) close(s->fd);
    return rc;
}

/* base64url without padding: the form of pbk in a node link. */
static void b64url(const unsigned char *in, size_t n, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        if (i + 1 < n) out[o++] = T[(v >> 6) & 63];
        if (i + 2 < n) out[o++] = T[v & 63];
    }
    out[o] = '\0';
}

/* Does the heap check itself work?
 *
 * A test built WITH the sanitizer but run with ASAN_OPTIONS=detect_leaks=0 would report
 * "nothing left on the heap" on EVERY path: a green test that no longer checks what it was
 * written for. A safeguard that can be turned off by accident must report its own state.
 *
 * The leak is made ON PURPOSE and cleaned up right away. The pointer is hidden by XOR because
 * LeakSanitizer scans the stack and the registers too and would not count a live pointer as a
 * leak. The sanitizer report printed below is part of the check, not a failure. */
static volatile uintptr_t g_hidden;
#define HIDE_MASK ((uintptr_t)0x5a5a5a5a5a5a5a5aULL)

static void heap_check_selftest(void) {
#if defined(__SANITIZE_ADDRESS__)
    void *p = malloc(64);
    if (!p) return;
    memset(p, 0x11, 64);
    g_hidden = (uintptr_t)p ^ HIDE_MASK;
    p = NULL;
    printf("-- an EXPECTED leak report follows: it proves the heap check is on --\n");
    fflush(stdout);
    int seen = LEAK_CHECK();
    printf("-- end of the expected report --\n");
    check("heap check is on (the deliberate leak was seen)", 1, seen);
    free((void *)(g_hidden ^ HIDE_MASK));
    g_hidden = 0;
#endif
}

int main(void) {
    /* The server half writes to a socket the client has already closed: on a failed check the
     * client closes without reading to the end. Without this the test would die of SIGPIPE
     * instead of reporting the result. */
    signal(SIGPIPE, SIG_IGN);
    /* Line by line: a leak still there at exit makes LeakSanitizer end the process before stdio
     * flushes, and a buffered report would lose its last checks. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    /* Without /proc every descriptor check would compare -1 with -1 and pass. */
    check("descriptors can be counted (/proc/self/fd)", 1, fd_count() > 0);

    heap_check_selftest();

    struct vless_node node;
    node_reality(&node, "tcp");

    /* Warm-up. The first handshake brings one-time allocations of the crypto library and the
     * thread start, and without it the first heap check would report them as a leak. The return
     * code shows that the warm-up worked: it must equal that of the first measured case below. */
    {
        struct plan warm = { .name = "warm-up", .cert = 0 };
        char why[256];
        int rc = run_case(&warm, &node, why, sizeof(why), NULL);
        check("warm-up: the handshake reached the certificate check", TLS13_ECERT, rc);
    }

    static const struct plan plans[] = {
        { .name = "server sent no certificate", .cert = 0 },
        { .name = "server certificate does not parse", .cert = 1 },
        { .name = "certificate arrived compressed", .cert = 2 },
        { .name = "ServerHello without key_share", .no_keyshare = 1 },
        { .name = "server Finished does not match", .bad_finished = 1 },
        { .name = "server closed after ClientHello", .hangup = 1 },
    };
    static const int want[] = {
        TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
        TLS13_ENOKEYSHARE, TLS13_EFINISHED, TLS13_ECLOSED,
    };
    /* The failure reason must reach the caller: without it "the node is down" and "the node is
     * not ours" look the same. Checked for the three ECERT paths, the only ones with a reason. */
    static const char *why_want[] = {
        "sent no certificate",
        "cannot parse",
        /* A compressed certificate is reported as "did not accept the key", not as anything
         * about compression, on purpose: a Reality server that accepted the client answers
         * with its temporary certificate and does not compress it, so the camouflage site is
         * answering. The check is here because a literal text ("server compressed its
         * certificate") would send the user after compression, which has nothing to do with
         * it. */
        "did not accept the key",
        "", "", "",
    };

    for (size_t i = 0; i < sizeof(plans) / sizeof(*plans); i++) {
        /* The test's buffer is TWICE the engine's (g_verify_reason[96]): the test must measure
         * the engine, not itself. With equal sizes a cut by the test's own buffer would look
         * like a property of the engine, and the other way round. */
        char what[160], why[256] = "";
        int fd0 = fd_count(), ctx_left = -1;
        int rc = run_case(&plans[i], &node, why, sizeof(why), &ctx_left);

        snprintf(what, sizeof(what), "%s: return code", plans[i].name);
        check(what, want[i], rc);

        if (why_want[i][0]) {
            snprintf(what, sizeof(what), "%s: reason reported", plans[i].name);
            check_str(what, why_want[i], why);
        }

        /* Our Finished goes only to a server that has proved itself (tls13.c). Not after a
         * hangup: the server's end is gone, and there is nothing to read. */
        if (!plans[i].hangup) {
            snprintf(what, sizeof(what), "%s: no client Finished sent", plans[i].name);
            check(what, 0, g_cfin);
        }

        /* Twenty attempts in a row, as on a router, where the spare pool refills on every SYN.
         * A per-attempt leak becomes visible here instead of staying a rounding error. */
        for (int k = 0; k < 20; k++) {
            int again = run_case(&plans[i], &node, NULL, 0, NULL);
            if (again != want[i]) { rc = again; break; }
        }
        snprintf(what, sizeof(what), "%s: twenty more attempts, same code", plans[i].name);
        check(what, want[i], rc);

        snprintf(what, sizeof(what), "%s: no cipher context left expanded", plans[i].name);
        check(what, 0, ctx_left);

        snprintf(what, sizeof(what), "%s: descriptor count restored", plans[i].name);
        check(what, fd0, fd_count());

        snprintf(what, sizeof(what), "%s: nothing left on the heap", plans[i].name);
        check(what, 0, LEAK_CHECK());
    }

    /* ---- a successful Reality, and ws/httpupgrade over it ------------------------------
     *
     * The server answers with a real Reality temporary certificate (an HMAC over the authkey
     * from its static key pair; the node's pbk is the public half), so the handshake SUCCEEDS
     * here and data follows. For tcp only the look is checked: the ALPN is not narrowed to
     * http/1.1. For ws and httpupgrade everything up to data: ALPN http/1.1 alone, the Upgrade
     * request with the path without ed, the 101 answer and the first data in ONE TLS record (the
     * remainder is not lost), and the client's reply arriving (for ws as a masked frame). */
    if (xc_x25519_keypair(g_rs_priv, g_rs_pub) != 0) {
        printf("%-64s %s\n", "Reality server key pair", "FAIL");
        fails++;
    } else {
        /* ws without early data (ed=0: stripped, Ed 0) and with it (ed=2048: the request goes
         * out with the first write, "hello" in Sec-WebSocket-Protocol); httpupgrade with
         * ed=2048: the 101 answer is read lazily, on the first read. */
        static const char *rtype[] = { "tcp", "ws", "httpupgrade", "ws ed" };
        static const char *rpath[] = { "/w?ed=0", "/w?ed=0", "/w?ed=2048", "/w?ed=2048" };
        for (int u = 0; u < 4; u++) {
            struct plan up = { .name = "reality", .reality_ok = 1, .upg = u == 2 ? 2 : u ? 1 : 0,
                               .ed_first = u == 3 };
            struct vless_node rn;
            node_reality(&rn, u == 3 ? "ws" : rtype[u]);
            b64url(g_rs_pub, 32, rn.pbk);
            snprintf(rn.path, sizeof(rn.path), "%s", rpath[u]);
            snprintf(rn.http_host, sizeof(rn.http_host), "%s", "cdn.example");
            char what[160];
            int fd0 = fd_count();
            static struct srv s;
            int rc;
            if (u == 0) {
                g_seen_h11 = -1;
                rc = run_case(&up, &rn, NULL, 0, NULL);
                check("reality: temporary certificate accepted, connection established", 0, rc);
                check("reality: the server verified the client's Finished", 1, g_cfin);
                check("reality + tcp: ALPN is not http/1.1 alone", 0, g_seen_h11);
                check("reality + tcp: descriptor count restored", fd0, fd_count());
                continue;
            }
            rc = run_upg(&up, &rn, &s);
            snprintf(what, sizeof(what), "reality + %s: connected, first data read", rtype[u]);
            check(what, 0, rc);
            snprintf(what, sizeof(what), "reality + %s: ALPN is http/1.1 alone", rtype[u]);
            check(what, 1, s.alpn_h11);
            snprintf(what, sizeof(what), "reality + %s: path without ed, Host from host", rtype[u]);
            check(what, 1, !strncmp(s.req, "GET /w HTTP/1.1\r\nHost: cdn.example\r\n", 36));
            snprintf(what, sizeof(what), u == 3 ? "reality + %s: 'hello' in Sec-WebSocket-Protocol"
                                                : "reality + %s: reply after 101 arrived", rtype[u]);
            check(what, 1, s.got_hello);
            snprintf(what, sizeof(what), "reality + %s: descriptor count restored", rtype[u]);
            check(what, fd0, fd_count());
            snprintf(what, sizeof(what), "reality + %s: nothing left on the heap", rtype[u]);
            check(what, 0, LEAK_CHECK());
        }
    }

    /* ---- security=tls with our own roots -------------------------------------------
     *
     * Here the server check passes on a real X.509 chain, which makes full setup and the
     * TR_ENOH2 path reachable; TR_ENOH2 must close through transport_close, not close(fd). The
     * roots reach the engine through the g_cert_roots seam. There is one store for the whole
     * process: certverify.c loads it under pthread_once, and a second one would have no effect. */
#if defined(STEER_HAVE_X509WRITE)
    if (chain_build() != 0) {
        printf("%-64s %s\n", "issuing our own X.509 chain", "FAIL");
        fails++;
    } else {
        g_cert_roots = g_roots_file;

        /* Warm-up for this half: the first handshake with chain verification loads the root
         * store under pthread_once. It stays on the heap for good by design (see roots_load),
         * and without the warm-up the first heap check would report it as a leak. */
        {
            struct plan warm = { .name = "tls warm-up", .chain = LEAF_OK };
            struct vless_node w;
            node_tls(&w, "tcp");
            int rc = run_case(&warm, &w, NULL, 0, NULL);
            check("tls warm-up: chain verified, connection established", 0, rc);
        }

        static const struct plan tls_plans[] = {
            { .name = "tls: chain verifies",                .chain = LEAF_OK },
            { .name = "tls: server chose http/1.1, not h2", .chain = LEAF_OK, .alpn = "http/1.1" },
            { .name = "tls: leaf issued for another name",  .chain = LEAF_NAME },
            { .name = "tls: self-signed leaf",              .chain = LEAF_SELF },
            { .name = "tls: no CertificateVerify",          .chain = LEAF_OK, .no_cv = 1 },
            { .name = "tls: signature does not verify",     .chain = LEAF_OK, .cv_bad_sig = 1 },
            { .name = "tls: signature scheme not offered",  .chain = LEAF_OK, .cv_bad_alg = 1 },
        };
        /* The ALPN case MUST NOT run on tcp. tcp asks for no ALPN at all (transport.c: tr_tcp
         * has alpn = NULL), so the "server did not choose h2" check is not made there, and on tcp
         * this case would silently pass as a success. */
        static const char *tls_type[] = { "tcp", "grpc", "tcp", "tcp", "tcp", "tcp", "tcp" };
        static const int tls_want[] = {
            0, TR_ENOH2, TLS13_ECERT, TLS13_ECERT,
            TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
        };
        /* Each needle is the END of its reason in certverify.c or tls13.c, so a reason cut short
         * (g_verify_reason in tls13.c is 96 bytes) fails the check. */
        static const char *tls_why[] = {
            "", "",
            "names another host",          /* CERTV_ECHAIN: the name is checked with the chain */
            "does not chain to a root or names another host", /* self-signed: same code */
            "sent no signature",           /* tls13.c tells "no certificate" from "no signature" */
            "bad server signature",        /* CERTV_ESIG */
            "algorithm we did not offer",  /* CERTV_EALG: its own reason, not "bad signature" */
        };
        for (size_t i = 0; i < sizeof(tls_plans) / sizeof(*tls_plans); i++) {
            struct vless_node tn;
            node_tls(&tn, tls_type[i]);
            char what[160], why[256] = "";
            int fd0 = fd_count(), ctx_left = -1;
            int rc = run_case(&tls_plans[i], &tn, why, sizeof(why), &ctx_left);

            snprintf(what, sizeof(what), "%s: return code", tls_plans[i].name);
            check(what, tls_want[i], rc);

            if (tls_why[i][0]) {
                snprintf(what, sizeof(what), "%s: reason reported", tls_plans[i].name);
                check_str(what, tls_why[i], why);
            }

            /* The handshake completes for success and TR_ENOH2 (the ALPN is checked after it):
             * then the server must have a Finished that verifies; otherwise none at all. */
            const int done = tls_want[i] == 0 || tls_want[i] == TR_ENOH2;
            snprintf(what, sizeof(what), done ? "%s: client Finished verifies"
                                              : "%s: no client Finished sent", tls_plans[i].name);
            check(what, done, g_cfin);

            for (int k = 0; k < 20; k++) {
                int again = run_case(&tls_plans[i], &tn, NULL, 0, NULL);
                if (again != tls_want[i]) { rc = again; break; }
            }
            snprintf(what, sizeof(what), "%s: twenty more attempts, same code", tls_plans[i].name);
            check(what, tls_want[i], rc);

            snprintf(what, sizeof(what), "%s: no cipher context left expanded", tls_plans[i].name);
            check(what, 0, ctx_left);

            snprintf(what, sizeof(what), "%s: descriptor count restored", tls_plans[i].name);
            check(what, fd0, fd_count());

            snprintf(what, sizeof(what), "%s: nothing left on the heap", tls_plans[i].name);
            check(what, 0, LEAK_CHECK());
        }
        /* Pins and an explicit opt-out of verification (Xray pinnedPeerCertSha256 /
         * verifyPeerCertByName). The expectations match what a test against an Xray-core 26.9.9
         * server showed: a pinned leaf is accepted WITHOUT chain or name (here a self-signed
         * one), another leaf's fingerprint fails, vcn replaces the name to check, and insecure
         * drops the chain check but not the CertificateVerify signature. */
        {
            static const char HEX[] = "0123456789abcdef";
            char h_ok[65], h_name[65], h_self[65];
            struct { int idx; char *out; } hh[] = { { LEAF_OK, h_ok }, { LEAF_NAME, h_name }, { LEAF_SELF, h_self } };
            for (size_t i = 0; i < 3; i++) {
                unsigned char d[32];
                sc_hash(SC_SHA256, g_leaf[hh[i].idx].der, g_leaf[hh[i].idx].der_n, d);
                for (int k = 0; k < 32; k++) { hh[i].out[2 * k] = HEX[d[k] >> 4]; hh[i].out[2 * k + 1] = HEX[d[k] & 15]; }
                hh[i].out[64] = '\0';
            }
            struct { const char *name; struct plan pl; const char *pcs, *vcn; int ins; int want; } pin[] = {
                { "pcs: pinned self-signed leaf accepted",      { .chain = LEAF_SELF }, h_self, NULL, 0, 0 },
                { "pcs: pinned leaf for another name accepted", { .chain = LEAF_NAME }, h_name, NULL, 0, 0 },
                { "pcs: another leaf's fingerprint is refused", { .chain = LEAF_OK },   h_name, NULL, 0, TLS13_ECERT },
                { "pcs: several fingerprints, match is second", { .chain = LEAF_OK },   NULL,   NULL, 0, 0 },
                { "vcn: the name to check replaces sni",        { .chain = LEAF_NAME }, NULL,   "other.invalid", 0, 0 },
                { "vcn: a wrong name is refused",               { .chain = LEAF_OK },   NULL,   "other.invalid", 0, TLS13_ECERT },
                { "insecure: self-signed leaf accepted",        { .chain = LEAF_SELF }, NULL,   NULL, 1, 0 },
                { "insecure: CertificateVerify signature still checked",
                                                                { .chain = LEAF_OK, .cv_bad_sig = 1 }, NULL, NULL, 1, TLS13_ECERT },
            };
            char two[140];
            snprintf(two, sizeof two, "%s,%s", h_self, h_ok);
            for (size_t i = 0; i < sizeof pin / sizeof *pin; i++) {
                struct vless_node tn;
                node_tls(&tn, "tcp");
                tn.pcs = i == 3 ? two : pin[i].pcs;
                tn.vcn = pin[i].vcn;
                tn.insecure = (uint8_t)pin[i].ins;
                pin[i].pl.name = pin[i].name;
                int fd0 = fd_count(), ctx_left = -1;
                int rc = run_case(&pin[i].pl, &tn, NULL, 0, &ctx_left);
                char what[160];
                snprintf(what, sizeof what, "%s: return code", pin[i].name);
                check(what, pin[i].want, rc);
                snprintf(what, sizeof what, "%s: no fd or cipher context leak", pin[i].name);
                check(what, 0, (fd_count() - fd0) + (ctx_left > 0 ? ctx_left : 0));
                snprintf(what, sizeof what, "%s: nothing left on the heap", pin[i].name);
                check(what, 0, LEAK_CHECK());
            }
        }
        /* ws and httpupgrade over plain TLS with our own chain: as for Reality above, plus a real
         * certificate check. This is the path of nodes behind a CDN. */
        static const char *ttype[] = { "ws", "httpupgrade", "ws ed" };
        for (int u = 1; u <= 3; u++) {
            struct plan up = { .name = "tls", .chain = LEAF_OK, .upg = u == 2 ? 2 : 1, .ed_first = u == 3 };
            struct vless_node tn;
            node_tls(&tn, u == 2 ? "httpupgrade" : "ws");
            snprintf(tn.path, sizeof(tn.path), "%s", u == 1 ? "/w?ed=0" : "/w?ed=2048");
            char what[160];
            int fd0 = fd_count();
            static struct srv s;
            int rc = run_upg(&up, &tn, &s);
            snprintf(what, sizeof(what), "tls + %s: connected, first data read", ttype[u - 1]);
            check(what, 0, rc);
            snprintf(what, sizeof(what), "tls + %s: ALPN is http/1.1 alone", ttype[u - 1]);
            check(what, 1, s.alpn_h11);
            snprintf(what, sizeof(what), "tls + %s: path without ed, Host from sni", ttype[u - 1]);
            check(what, 1, !strncmp(s.req, "GET /w HTTP/1.1\r\nHost: " TLS_SNI "\r\n",
                                    strlen("GET /w HTTP/1.1\r\nHost: " TLS_SNI "\r\n")));
            snprintf(what, sizeof(what), "tls + %s: client's 'hello' arrived", ttype[u - 1]);
            check(what, 1, s.got_hello);
            snprintf(what, sizeof(what), "tls + %s: descriptor count restored", ttype[u - 1]);
            check(what, fd0, fd_count());
            snprintf(what, sizeof(what), "tls + %s: nothing left on the heap", ttype[u - 1]);
            check(what, 0, LEAK_CHECK());
        }
        /* The server behind TLS chose h2, but the upgrade runs over HTTP/1.1: its own code, not
         * "did not agree to HTTP/2". */
        {
            struct plan up = { .name = "tls h2", .chain = LEAF_OK, .alpn = "h2" };
            struct vless_node tn;
            node_tls(&tn, "ws");
            int rc = run_case(&up, &tn, NULL, 0, NULL);
            check("tls + ws: server chose h2, refused with TR_ENOH1", TR_ENOH1, rc);
        }
        g_cert_roots = NULL;
        chain_free();
    }
#else
    printf("\nWARNING: built WITHOUT certificate issuing (no STEER_HAVE_X509WRITE, tests/certgen.c):\n");
    printf("         the security=tls cases are SKIPPED: neither a passing server check\n");
    printf("         nor the TR_ENOH2 path with its transport_close is tested here.\n\n");
#endif

    /* security=none: no TLS at all. It checks the test rather than the client: if the seam
     * handed over a bad socket, success would fail too, and the failure checks above would pass
     * for the wrong reason. */
    {
        struct vless_node plain;
        memset(&plain, 0, sizeof(plain));
        snprintf(plain.host, sizeof(plain.host), "%s", "node.invalid");
        plain.port = 443;
        snprintf(plain.type, sizeof(plain.type), "%s", "tcp");
        snprintf(plain.security, sizeof(plain.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&plain, &c, 3);
        g_tcp_dial = NULL;
        check("security=none over tcp: connection established", 0, rc);
        check("security=none: no TLS set up", 1, c.link.plain);
        if (rc == 0) transport_close(&c);
        /* Closed, not only marked closed: the other end of the pair reads end of stream (the
         * client wrote nothing, and nothing else holds its end). */
        unsigned char b;
        check("security=none: transport_close closed the descriptor", 0,
              recv(sv[1], &b, 1, MSG_DONTWAIT));
        close(sv[1]);
        check("security=none: nothing left on the heap", 0, LEAK_CHECK());
    }

#if !defined(__SANITIZE_ADDRESS__)
    printf("\nWARNING: built WITHOUT AddressSanitizer: the 'nothing left on the heap' checks\n");
    printf("         are vacuous. Return codes and descriptors are checked, the heap is NOT.\n");
#endif
    printf("\n%s\n", fails ? "SOME CHECKS FAILED" : "all checks passed");
    return fails ? 1 : 0;
}
