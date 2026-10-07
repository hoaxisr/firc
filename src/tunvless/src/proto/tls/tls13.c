/* TLS 1.3 handshake and record layer for a ClientHello built by reality.c (plus a minimal TLS 1.2
 * client at the end).
 *
 * Reality is real TLS 1.3 with one twist in authentication: the client proves itself with the
 * authenticator in session_id, and a server that recognised it sends a temporary certificate
 * with an HMAC under the authenticator key in the signature field (certverify.h). The rest is
 * plain RFC 8446: ServerHello brings the server's key_share, traffic keys come from the shared
 * secret, records use AEAD.
 *
 * No chain is checked for Reality: a server that did not recognise us hands the connection to
 * the third-party site it hides behind, whose genuine certificate proves nothing about the
 * server. That is why there is no library TLS stack here: it would insist on chain checks and
 * build its own ClientHello, while ours must look like a browser's (reality.c). Only primitives
 * are needed, through the scrypto layer.
 *
 * Only the needed part of the handshake exists: parse ServerHello, derive keys, check Finished
 * (plus the certificate check for security=tls). Resumption, client certificates,
 * HelloRetryRequest and post-handshake messages are not supported: no node needs them, and
 * each would be code that never runs and so is never tested.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <poll.h>

#include "scrypto.h"
#include "certverify.h"
#include "tls13.h"

/* From reality.c: the same X25519, with the peer key from ServerHello. Shared rather than
 * copied, so clamping and byte order cannot diverge between two copies. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);

/* ---- HKDF-Expand-Label, RFC 8446 §7.1 -------------------------------------- */
/* The label has a strict format: output length, "tls13 " + label, context. One wrong byte
 * gives keys that differ from the server's, which shows up as failing decryption after the
 * handshake. */
static int expand_label(enum sc_hash md,
                        const unsigned char *secret, size_t secret_n,
                        const char *label,
                        const unsigned char *ctx, size_t ctx_n,
                        unsigned char *out, size_t out_n) {
    unsigned char info[512];
    size_t i = 0;
    size_t llen = strlen(label);
    if (6 + llen > 255 || ctx_n > 255 || 4 + 6 + llen + ctx_n > sizeof(info)) return -1;
    info[i++] = (unsigned char)(out_n >> 8);
    info[i++] = (unsigned char)out_n;
    info[i++] = (unsigned char)(6 + llen);
    memcpy(info + i, "tls13 ", 6); i += 6;
    memcpy(info + i, label, llen); i += llen;
    info[i++] = (unsigned char)ctx_n;
    if (ctx_n) { memcpy(info + i, ctx, ctx_n); i += ctx_n; }
    return sc_hkdf_expand(md, secret, secret_n, info, i, out, out_n);
}

static int derive_secret(enum sc_hash md, const unsigned char *secret,
                         const char *label, const unsigned char *thash, size_t hash_n,
                         unsigned char *out) {
    return expand_label(md, secret, hash_n, label, thash, hash_n, out, hash_n);
}

/* ---- transcript ------------------------------------------------------------ */
/* The hash of all handshake messages in order. It enters every key derivation, so any
 * divergence from the server (an extra byte, a missing message) breaks the keys and is caught
 * as a bad Finished.
 *
 * Hash failures are not returned: an initialised SHA-2 context has nothing that can fail (no
 * allocation, no device), and if it ever does, the hash comes out wrong and the handshake fails
 * with TLS13_EFINISHED rather than passing with foreign keys. A failed init leaves the context
 * unset (alg == 0), and every later call on it fails too. */
static void tr_init(struct tls13 *t) {
    sc_hash_init(&t->tr, SC_SHA256);
    sc_hash_init(&t->tr384, SC_SHA384);
}
static void tr_add(struct tls13 *t, const unsigned char *d, size_t n) {
    sc_hash_update(&t->tr, d, n);
    sc_hash_update(&t->tr384, d, n);
}
/* The transcript hash with the algorithm the server chose, on a copy of the context: the
 * transcript goes on after each key derivation. */
static void tr_hash(const struct tls13 *t, unsigned char *out) {
    struct sc_hash_ctx c;
    if (sc_hash_clone(&c, t->hash_n == 48 ? &t->tr384 : &t->tr) != 0) {
        memset(out, 0, t->hash_n == 48 ? 48 : 32);
        return;
    }
    sc_hash_final(&c, out);
    sc_hash_free(&c);
}

/* ---- reading records ------------------------------------------------------- */
/* Reading straight from the descriptor is for the handshake only, which is synchronous by
 * nature. */
static int read_full(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r == 0) return TLS13_ECLOSED;
        if (r < 0) {
            if (errno == EINTR) continue;
            /* The handshake socket is blocking with SO_RCVTIMEO, so EAGAIN here means only
             * that the node did not answer in time: not an I/O error (see TLS13_ETIMEOUT). */
            if (errno == EAGAIN || errno == EWOULDBLOCK) return TLS13_ETIMEOUT;
            return TLS13_EIO;
        }
        got += (size_t)r;
    }
    return 0;
}

/* Records come from the connection buffer. The socket is read in LARGE chunks: one read()
 * takes everything pending (up to 16 KB), and records are served from the buffer without new
 * calls.
 *
 * The data stream passes may_wait = 0: poll first, never block, and leave an incomplete record
 * in the buffer so the loop moves on to other connections. The handshake, which must wait,
 * reads the descriptor directly (read_record_fd). */
/* The remainder moves to the start of the buffer only when the free tail runs short: with
 * medium records (4-8 KB, common with Xray) an unconditional move would memmove kilobytes on
 * every read. The threshold lets one read take a useful chunk rather than a hundred bytes at a
 * time. */
#define RBUF_MIN_FILL 4096

static int rbuf_fill(struct tls13 *t, int may_wait) {
    /* Compact first, then check for overflow: a full buffer with a moved start is not an
     * overflow but room to reclaim. */
    if (t->rbuf_off && sizeof(t->rbuf) - t->rbuf_n < RBUF_MIN_FILL) {
        if (t->rbuf_n > t->rbuf_off)
            memmove(t->rbuf, t->rbuf + t->rbuf_off, t->rbuf_n - t->rbuf_off);
        t->rbuf_n -= t->rbuf_off;
        t->rbuf_off = 0;
    }
    if (t->rbuf_n >= sizeof(t->rbuf)) return TLS13_ETOOBIG;

    if (!may_wait) {
        struct pollfd p = { .fd = t->fd, .events = POLLIN };
        int pr = poll(&p, 1, 0);
        if (pr <= 0 || !(p.revents & POLLIN)) return TLS13_EAGAIN;
    }
    ssize_t r = read(t->fd, t->rbuf + t->rbuf_n, sizeof(t->rbuf) - t->rbuf_n);
    if (r == 0) return TLS13_ECLOSED;
    if (r < 0) {
        if (errno == EINTR) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return TLS13_EAGAIN;
        return TLS13_EIO;
    }
    t->rbuf_n += (size_t)r;
    return 0;
}

/* For the handshake: it waits, and it reads exactly one record at a time, so nothing past its
 * last record leaves the socket before the connection buffer takes over. */
static int read_record_fd(int fd, unsigned char *type, unsigned char *body, size_t cap,
                          size_t *body_n) {
    unsigned char h[5];
    int rc = read_full(fd, h, 5);
    if (rc) return rc;
    size_t len = ((size_t)h[3] << 8) | h[4];
    if (len > cap) return TLS13_ETOOBIG;
    rc = read_full(fd, body, len);
    if (rc) return rc;
    *type = h[0];
    *body_n = len;
    return 0;
}

static int read_record(struct tls13 *t, unsigned char *type, unsigned char **body,
                       size_t *body_n, int may_wait) {
    for (int guard = 0; guard < 64; guard++) {
        size_t have = t->rbuf_n - t->rbuf_off;
        if (have >= 5) {
            const unsigned char *h = t->rbuf + t->rbuf_off;
            size_t len = ((size_t)h[3] << 8) | h[4];
            if (len > TLS13_MAX_REC) return TLS13_EBADREC;
            if (have >= 5 + len) {
                *type = h[0];
                *body = t->rbuf + t->rbuf_off + 5;
                *body_n = len;
                t->rbuf_off += 5 + len;
                return 0;
            }
        }
        int rc = rbuf_fill(t, may_wait);
        if (rc) return rc;
    }
    return TLS13_EAGAIN;
}

/* ---- AEAD ------------------------------------------------------------------ */
/* TLS 1.3 nonce: iv XOR the right-aligned record number. Each direction has its own counter,
 * NEVER reset: a reset repeats a nonce, which voids AEAD entirely. */
static void aead_nonce(const unsigned char iv[12], uint64_t seq, unsigned char out[12]) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++)
        out[11 - i] ^= (unsigned char)(seq >> (8 * i));
}

/* Called once per direction when the traffic keys are ready; every record then uses the
 * ready context. */
int tls13_keys_setup(struct tls13_keys *k) {
    if (k->ctx_ready) return 0;
    enum sc_aead_alg a;
    /* The key length is checked against the algorithm: the caller fills key_n, and a mismatch
     * would mean an AES-256 key expanded from sixteen bytes plus garbage. */
    switch (k->aead) {
        case TLS13_AEAD_AES128: a = SC_AES128_GCM; break;
        case TLS13_AEAD_AES256: a = SC_AES256_GCM; break;
        case TLS13_AEAD_CHACHA: a = SC_CHACHA20_POLY1305; break;
        default: return TLS13_ECRYPTO;
    }
    if (k->key_n != sc_aead_key_len(a)) return TLS13_ECRYPTO;
    if (sc_aead_setkey(&k->ctx, a, k->key) != 0) return TLS13_ECRYPTO;
    k->ctx_ready = 1;
    return 0;
}

void tls13_keys_free(struct tls13_keys *k) {
    if (!k->ctx_ready) return;
    sc_aead_free(&k->ctx);
    k->ctx_ready = 0;
}

/* Safe on a ZEROED struct and when called twice; this is a contract: tr_link_close calls it on
 * every TLS link, including one whose handshake never started. It relies on a zero algorithm or
 * ready flag meaning "empty" for every layer context (sc_hash_free and sc_aead_free then do
 * nothing), and on freeing setting it back to zero. */
void tls13_free(struct tls13 *t) {
    tls13_keys_free(&t->rd);
    tls13_keys_free(&t->wr);
    sc_hash_free(&t->tr);
    sc_hash_free(&t->tr384);
    t->ready = 0;
}

int tls13_aead_open(struct tls13_keys *k, uint64_t seq,
                     const unsigned char *aad, size_t aad_n,
                     unsigned char *buf, size_t n) {
    if (n < 16) return TLS13_EBADREC;
    if (!k->ctx_ready) return TLS13_ESTATE;
    unsigned char nonce[12];
    aead_nonce(k->iv, seq, nonce);
    size_t ct = n - 16;
    /* The tag is COPIED, not read from the same buffer. Decryption runs in place, and the tag
     * sits right after the ciphertext, where an implementation may write while finishing the
     * last partial block. tests/scryptomatch.c checks that wolfCrypt does not, at record sizes
     * up to 16401 bytes, but a 16-byte copy is cheaper than depending on library internals. */
    unsigned char tag[16];
    memcpy(tag, buf + ct, 16);
    int rc = sc_aead_open(&k->ctx, nonce, aad, aad_n, buf, ct, tag);
    return rc == 0 ? 0 : TLS13_EAUTH;
}

int tls13_aead_seal(struct tls13_keys *k, uint64_t seq,
                     const unsigned char *aad, size_t aad_n,
                     unsigned char *buf, size_t n, unsigned char *tag) {
    if (!k->ctx_ready) return TLS13_ESTATE;
    unsigned char nonce[12];
    aead_nonce(k->iv, seq, nonce);
    int rc = sc_aead_seal(&k->ctx, nonce, aad, aad_n, buf, n, tag);
    return rc == 0 ? 0 : TLS13_ECRYPTO;
}

/* The same two operations with a one-time context, for the HANDSHAKE: it handles three or four
 * records per connection, so the key setup cost does not matter, and no context needs freeing
 * on a dozen error paths. Persistent contexts are for the data stream only. */
static int aead_open_once(const struct tls13_keys *src, uint64_t seq,
                          const unsigned char *aad, size_t aad_n,
                          unsigned char *buf, size_t n) {
    struct tls13_keys k = *src;
    k.ctx_ready = 0;
    int rc = tls13_keys_setup(&k);
    if (rc == 0) rc = tls13_aead_open(&k, seq, aad, aad_n, buf, n);
    tls13_keys_free(&k);
    return rc;
}

static int aead_seal_once(const struct tls13_keys *src, uint64_t seq,
                          const unsigned char *aad, size_t aad_n,
                          unsigned char *buf, size_t n, unsigned char *tag) {
    struct tls13_keys k = *src;
    k.ctx_ready = 0;
    int rc = tls13_keys_setup(&k);
    if (rc == 0) rc = tls13_aead_seal(&k, seq, aad, aad_n, buf, n, tag);
    tls13_keys_free(&k);
    return rc;
}

/* ---- handshake ------------------------------------------------------------- */

/* The verification failure is kept PER THREAD, not in struct tls13: the caller turns it into
 * text from the error code alone (transport_strerror), after the link is closed. The thread
 * outlives the close, and connectors in different threads do not overwrite each other's
 * reasons. */
static __thread char g_verify_reason[96];

const char *tls13_verify_reason(void) { return g_verify_reason; }

/* Takes the ClientHello record already sent (for the transcript) and our ephemeral private key.
 *
 * auth->host != NULL turns on the certificate check (security=tls); auth->reality_key, the
 * Reality check. Without either, Certificate and CertificateVerify still enter the transcript
 * but are not parsed.
 *
 * Returns with the traffic keys ready. */
static int handshake(struct tls13 *t, int fd,
                     const unsigned char *client_hello, size_t hello_n,
                     const unsigned char *our_priv,
                     const struct tls13_auth *auth) {
    /* Computed once, so the checks in the parsing loop cannot drift apart. */
    const char *host = auth ? auth->host : NULL;
    const unsigned char *rkey = auth ? auth->reality_key : NULL;
    const int want_cert = (host != NULL) || (rkey != NULL);
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    /* md and H are set after ServerHello: they depend on the cipher suite. */
    enum sc_hash md = SC_SHA256;
    size_t H = 0;

    tr_init(t);
    /* The transcript takes the handshake message without the record header. */
    tr_add(t, client_hello + 5, hello_n - 5);

    unsigned char rec[TLS13_MAX_REC];
    unsigned char type;
    size_t n;

    /* ServerHello. */
    int rc = read_record_fd(fd, &type, rec, sizeof(rec), &n);
    if (rc) return rc;
    if (type != 0x16 || n < 44 || rec[0] != 0x02) return TLS13_EBADREC;
    tr_add(t, rec, n);

    /* The server's key_share is among the extensions. It is found by type 0x33, not by
     * offset: the session_id length and the extension set vary between servers.
     * HS_HDR = 4: message type(1) + length(3). */
    const size_t HS_HDR = 4;
    unsigned char server_pub[32];
    /* X25519MLKEM768 hybrid: the server answers with the ML-KEM ciphertext (1088) and its
     * X25519 half (32). */
    unsigned char kem_ct[SC_MLKEM768_CT];
    int have_pub = 0, have_kem = 0;
    {
        size_t p = HS_HDR + 2 + 32;             /* header + version + random */
        if (p >= n) return TLS13_EBADREC;
        size_t sid_n = rec[p++];
        p += sid_n;
        p += 2;                                 /* cipher_suite */
        p += 1;                                 /* compression */
        if (p + 2 > n) return TLS13_EBADREC;
        size_t exts_n = ((size_t)rec[p] << 8) | rec[p + 1];
        p += 2;
        size_t end = p + exts_n;
        if (end > n) return TLS13_EBADREC;
        while (p + 4 <= end) {
            unsigned etype = ((unsigned)rec[p] << 8) | rec[p + 1];
            size_t elen = ((size_t)rec[p + 2] << 8) | rec[p + 3];
            p += 4;
            if (p + elen > end) break;
            if (etype == 0x0033 && elen >= 4) {
                /* group(2) + length(2) + key. The group is read, not guessed from the length
                 * (X25519: 32 bytes, hybrid: 1120): taking a ciphertext for a public key would
                 * go on with a wrong secret and fail as an AEAD error. */
                unsigned grp = ((unsigned)rec[p] << 8) | rec[p + 1];
                size_t klen = ((size_t)rec[p + 2] << 8) | rec[p + 3];
                if (4 + klen > elen) return TLS13_EBADREC;
                if (grp == 0x001D && klen == 32) {
                    memcpy(server_pub, rec + p + 4, 32);
                    have_pub = 1;
                } else if (grp == 0x11EC && klen == SC_MLKEM768_CT + 32 && auth && auth->mlkem_dk) {
                    memcpy(kem_ct, rec + p + 4, SC_MLKEM768_CT);
                    memcpy(server_pub, rec + p + 4 + SC_MLKEM768_CT, 32);
                    have_pub = have_kem = 1;
                } else return TLS13_ENOKEYSHARE;
            }
            p += elen;
        }
    }
    if (!have_pub) return TLS13_ENOKEYSHARE;
    /* A copy of ServerHello for the ML-DSA check, which signs it too: rec is reused for the
     * following records. Made only when the check is on. */
    unsigned char sh_copy[TLS13_SH_KEEP];
    size_t sh_copy_n = 0;
    if (auth && auth->mldsa_pk) {
        if (n > sizeof(sh_copy)) return TLS13_ETOOBIG;
        memcpy(sh_copy, rec, n);
        sh_copy_n = n;
    }

    /* The cipher suite from ServerHello sets the AEAD and the hash. */
    {
        size_t p = HS_HDR + 2 + 32;
        size_t sid_n = rec[p++];
        p += sid_n;
        unsigned suite = ((unsigned)rec[p] << 8) | rec[p + 1];
        switch (suite) {
            case 0x1301: t->rd.aead = t->wr.aead = TLS13_AEAD_AES128;
                         t->rd.key_n = t->wr.key_n = 16; t->hash_n = 32; break;
            case 0x1302: t->rd.aead = t->wr.aead = TLS13_AEAD_AES256;
                         t->rd.key_n = t->wr.key_n = 32; t->hash_n = 48; break;
            case 0x1303: t->rd.aead = t->wr.aead = TLS13_AEAD_CHACHA;
                         t->rd.key_n = t->wr.key_n = 32; t->hash_n = 32; break;
            default: return TLS13_EBADSUITE;
        }
    }
    H = t->hash_n;
    md = H == 48 ? SC_SHA384 : SC_SHA256;

    /* ECH: did the server accept the inner Hello (RFC 9849, 7.2)? The confirmation is the last
     * eight bytes of ServerHello.random: HKDF-Expand-Label(HKDF-Extract(0, Inner random),
     * "ech accept confirmation", Hash(Inner ‖ ServerHello with those eight bytes zeroed), 8).
     * Accepted: from now on the transcript is built from Inner, not the Outer that was sent
     * (both keys and Finished use it). Not accepted: the handshake stops (TLS13_EECH). The
     * comparison has no early exit: the value is not secret, but the habit is cheaper than an
     * exception. */
    if (auth && auth->ech) {
        struct sc_hash_ctx ic;
        unsigned char ch[48], prk[48], conf[8], zero8[8] = { 0 };
        if (n < 38) return TLS13_EBADREC;
        if (sc_hash_init(&ic, md) != 0) return TLS13_ECRYPTO;
        sc_hash_update(&ic, auth->ech->inner, auth->ech->inner_n);
        sc_hash_update(&ic, rec, 30);
        sc_hash_update(&ic, zero8, 8);
        sc_hash_update(&ic, rec + 38, n - 38);
        int hr = sc_hash_final(&ic, ch);
        sc_hash_free(&ic);
        if (hr != 0 || sc_hkdf_extract(md, NULL, 0, auth->ech->random, 32, prk) != 0 ||
            expand_label(md, prk, H, "ech accept confirmation", ch, H, conf, 8) != 0)
            return TLS13_ECRYPTO;
        unsigned char diff = 0;
        for (int i = 0; i < 8; i++) diff |= (unsigned char)(conf[i] ^ rec[30 + i]);
        if (diff) return TLS13_EECH;
        /* Restart the transcript: Inner, then the real ServerHello. */
        sc_hash_free(&t->tr);
        sc_hash_free(&t->tr384);
        tr_init(t);
        tr_add(t, auth->ech->inner, auth->ech->inner_n);
        tr_add(t, rec, n);
    }

    /* Key schedule, RFC 8446 §7.1. Every step is required, in strict order:
     * early -> handshake -> master, with derive-secret between them. */
    unsigned char zeros[48] = {0};
    unsigned char early[48], derived[48], hs_secret[48], empty_hash[48];
    if (sc_hash(md, zeros, 0, empty_hash) != 0) return TLS13_ECRYPTO;

    if (sc_hkdf_extract(md, NULL, 0, zeros, H, early) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, early, H, "derived", empty_hash, H, derived, H) != 0) return TLS13_ECRYPTO;

    /* The ECDHE input of the schedule is the secret with the server's EPHEMERAL key from
     * ServerHello, not the one computed in reality.c. Mixing them up passes ServerHello and then
     * fails every AEAD (TLS13_EAUTH):
     *
     *   Reality secret = our ephemeral x the server's static key (pbk from the link);
     *                    used ONLY for the authenticator in session_id;
     *   TLS secret     = our ephemeral x the server's ephemeral key (key_share in ServerHello);
     *                    the whole key schedule rests on it.
     *
     * The server serving us VLESS still runs ordinary TLS 1.3 with its ephemeral key, or the
     * stream would not look like real HTTPS.
     *
     * The hybrid secret is mlkem_ss ‖ x25519_ss (draft-ietf-tls-ecdhe-mlkem: ML-KEM first for
     * X25519MLKEM768, the same order as Go and BoringSSL). Plain X25519 is just 32 bytes. */
    unsigned char ecdhe[SC_MLKEM768_SS + 32];
    size_t ecdhe_n = 32;
    if (have_kem) {
        if (getenv("STEER_PQ_TRACE")) fprintf(stderr, "tunvless[pq]: server chose X25519MLKEM768\n");
        if (sc_mlkem768_decaps(ecdhe, auth->mlkem_dk, kem_ct) != 0) return TLS13_ECRYPTO;
        if (x25519_shared_ext(our_priv, server_pub, ecdhe + SC_MLKEM768_SS) != 0) return TLS13_ECRYPTO;
        ecdhe_n = sizeof(ecdhe);
    } else if (x25519_shared_ext(our_priv, server_pub, ecdhe) != 0) return TLS13_ECRYPTO;
    if (sc_hkdf_extract(md, derived, H, ecdhe, ecdhe_n, hs_secret) != 0)
        return TLS13_ECRYPTO;

    unsigned char th[48];
    tr_hash(t, th);
    unsigned char c_hs[48], s_hs[48];
    if (derive_secret(md, hs_secret, "c hs traffic", th, H, c_hs) != 0) return TLS13_ECRYPTO;
    if (derive_secret(md, hs_secret, "s hs traffic", th, H, s_hs) != 0) return TLS13_ECRYPTO;

    struct tls13_keys c_hk = t->wr, s_hk = t->rd;
    if (expand_label(md, c_hs, H, "key", NULL, 0, c_hk.key, c_hk.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, c_hs, H, "iv", NULL, 0, c_hk.iv, 12) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_hs, H, "key", NULL, 0, s_hk.key, s_hk.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_hs, H, "iv", NULL, 0, s_hk.iv, 12) != 0) return TLS13_ECRYPTO;

    /* Encrypted server messages follow. Read up to Finished, adding each to the transcript:
     * Certificate and CertificateVerify must be in the hash even when not checked, or
     * Finished will not match. */
    uint64_t s_seq = 0;
    int got_finished = 0;
    unsigned char server_finished[48];

    /* Handshake messages are assembled ACROSS RECORD BOUNDARIES. A message continued in the
     * next record (long certificate chains: Certificates of 8273 bytes occur) must not be
     * lost, or the transcript diverges, our Finished fails and the server closes the
     * connection, which looks like "the node no longer recognises the client" even with a
     * valid authenticator.
     *
     * One buffer per thread: a thread runs one handshake at a time, and 40 KB per connection
     * would be 2.5 MB at 64 connections. */
    static __thread unsigned char hsbuf[40960];
    size_t hs_have = 0;

    /* Messages the authentication needs. Copied, not kept by pointer: hsbuf shifts as it is
     * parsed, and by check time the old place would hold the next message. The chain can be
     * eight kilobytes or more, so the buffer is as large as hsbuf. */
    static __thread unsigned char certbuf[40960];
    size_t cert_n = 0;
    unsigned char cv_buf[1024];
    size_t cv_n = 0;
    unsigned char cv_transcript[48];
    size_t cv_thash_n = 0;
    g_verify_reason[0] = '\0';

    /* Up to 64 records: a long certificate chain arrives in several. */
    for (int guard = 0; guard < 64 && !got_finished; guard++) {
        rc = read_record_fd(fd, &type, rec, sizeof(rec), &n);
        if (rc) return rc;
        if (type == 0x14) continue;             /* ChangeCipherSpec: ignored in 1.3 */
        if (type != 0x17) return TLS13_EBADREC;

        unsigned char aad[5] = { 0x17, 0x03, 0x03,
                                 (unsigned char)(n >> 8), (unsigned char)n };
        rc = aead_open_once(&s_hk, s_seq++, aad, 5, rec, n);
        if (rc) return rc;
        size_t pt = n - 16;
        /* The last non-zero byte is the real record type (RFC 8446 §5.4). */
        while (pt > 0 && rec[pt - 1] == 0) pt--;
        if (pt == 0) return TLS13_EBADREC;
        unsigned char inner = rec[--pt];
        if (inner != 0x16) continue;            /* not handshake: skip */

        /* Append to what is left from earlier records. */
        if (hs_have + pt > sizeof(hsbuf)) return TLS13_ETOOBIG;
        memcpy(hsbuf + hs_have, rec, pt);
        hs_have += pt;

        /* The buffer may hold several messages, the last one incomplete. */
        size_t p = 0;
        while (p + 4 <= hs_have) {
            unsigned char msg = hsbuf[p];
            size_t mlen = ((size_t)hsbuf[p + 1] << 16) | ((size_t)hsbuf[p + 2] << 8) | hsbuf[p + 3];
            if (p + 4 + mlen > hs_have) break;  /* the rest comes in the next record */
            if (msg == 0x08) {                  /* EncryptedExtensions */
                /* Only ALPN is extracted: no other extension affects us, and parsing more
                 * untrusted bytes is more room for bugs. Body: list length(2), then
                 * type(2) + length(2) + body per extension; ALPN holds list length(2),
                 * length(1), name. */
                const unsigned char *e = hsbuf + p + 4;
                if (mlen >= 2) {
                    size_t total = ((size_t)e[0] << 8) | e[1];
                    if (total + 2 <= mlen) {
                        size_t q = 2;
                        while (q + 4 <= total + 2) {
                            unsigned etype = ((unsigned)e[q] << 8) | e[q + 1];
                            size_t ebody = ((size_t)e[q + 2] << 8) | e[q + 3];
                            if (q + 4 + ebody > total + 2) break;
                            if (etype == 0x0010 && ebody >= 4) {
                                size_t pl = e[q + 6];
                                if (pl && pl < sizeof(t->alpn) && 3 + pl <= ebody) {
                                    memcpy(t->alpn, e + q + 7, pl);
                                    t->alpn[pl] = '\0';
                                }
                            }
                            q += 4 + ebody;
                        }
                    }
                }
            }
            if (want_cert && msg == 0x19) {     /* CompressedCertificate (RFC 8879) */
                /* Its meaning differs by node kind.
                 *
                 * security=tls never sends compress_certificate (reality.c), so a compressed
                 * certificate means a server that compressed unasked; say so.
                 *
                 * Reality does send it (Chrome's look needs it), but a Reality server that
                 * RECOGNISED the client answers with its temporary certificate, uncompressed.
                 * A compressed one comes from the camouflage site instead, which is exactly
                 * "key not recognised"; compression is beside the point for the user. */
                snprintf(g_verify_reason, sizeof(g_verify_reason), "%s",
                         rkey ? cert_verify_strerror(CERTV_ENOTREALITY)
                              : "server sent a compressed certificate without being asked");
                return TLS13_ECERT;
            }
            if (want_cert && msg == 0x0B && cert_n == 0) {   /* Certificate */
                if (mlen > sizeof(certbuf)) return TLS13_ETOOBIG;
                memcpy(certbuf, hsbuf + p + 4, mlen);
                cert_n = mlen;
            }
            if (host && msg == 0x0F && cv_n == 0) {     /* CertificateVerify */
                /* The hash is taken HERE, before tr_add of this message: the server signed
                 * the transcript up to and including Certificate, and a hash cannot be
                 * rolled back later. */
                if (mlen > sizeof(cv_buf)) return TLS13_ETOOBIG;
                tr_hash(t, cv_transcript);
                cv_thash_n = H;
                memcpy(cv_buf, hsbuf + p + 4, mlen);
                cv_n = mlen;
            }
            if (msg == 0x14) {                  /* Finished */
                /* Checked BEFORE it enters the transcript: the server computed it over the
                 * hash of the preceding messages. */
                unsigned char fkey[48], hash[48], want[48];
                tr_hash(t, hash);
                if (expand_label(md, s_hs, H, "finished", NULL, 0, fkey, H) != 0)
                    return TLS13_ECRYPTO;
                if (sc_hmac(md, fkey, H, hash, H, want) != 0) return TLS13_ECRYPTO;
                if (mlen != H || memcmp(hsbuf + p + 4, want, H) != 0) return TLS13_EFINISHED;
                memcpy(server_finished, want, H);
                got_finished = 1;
            }
            tr_add(t, hsbuf + p, 4 + mlen);
            p += 4 + mlen;
        }
        /* Drop what was parsed; move the incomplete rest to the start. */
        if (p) {
            if (hs_have > p) memmove(hsbuf, hsbuf + p, hs_have - p);
            hs_have -= p;
        }
    }
    if (!got_finished) return TLS13_EFINISHED;

    /* Authentication comes AFTER the server's Finished and BEFORE ours.
     *
     * After: Finished proves we share one transcript with the server, so the part signed by
     * CertificateVerify was not swapped on the way. A signature over a transcript we are not
     * yet sure of proves nothing.
     *
     * Before: our Finished is the first thing sent under the session keys, and there is no
     * reason to send it to a peer that has not proved itself. */
    /* Reality: the proof is the signature field of the temporary certificate; the chain plays
     * no part. It runs before the security=tls branch, not instead of it: no setting has both
     * proofs, but the order in code must be unambiguous. */
    if (rkey) {
        if (!cert_n) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "server sent no certificate");
            return TLS13_ECERT;
        }
        int rrc = cert_reality_check(certbuf, cert_n, rkey);
        if (rrc == 0 && auth->mldsa_pk)
            rrc = cert_reality_check_pq(certbuf, cert_n, rkey, auth->mldsa_pk,
                                        client_hello + 5, hello_n - 5, sh_copy, sh_copy_n);
        if (rrc != 0) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "%s", cert_verify_strerror(rrc));
            return TLS13_ECERT;
        }
    }

    if (host) {
        if (!cert_n || !cv_n) {
            /* The handshake completed without proof. Without a PSK (we offer none) a TLS 1.3
             * server must send both, so only a broken or hostile server gets here. Named apart
             * from "the certificate does not verify". */
            snprintf(g_verify_reason, sizeof(g_verify_reason),
                     "server sent no %s", cert_n ? "signature" : "certificate");
            return TLS13_ECERT;
        }
        int vrc = cert_verify_server_ex(certbuf, cert_n, cv_buf, cv_n,
                                        cv_transcript, cv_thash_n, host, auth->roots, auth->policy);
        if (vrc != 0) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "%s",
                     cert_verify_strerror(vrc));
            return TLS13_ECERT;
        }
    }

    /* Our Finished covers the transcript including the server's Finished. */
    unsigned char th2[48], cfkey[48], chash[48], cfin[48];
    tr_hash(t, th2);
    if (expand_label(md, c_hs, H, "finished", NULL, 0, cfkey, H) != 0) return TLS13_ECRYPTO;
    memcpy(chash, th2, H);
    if (sc_hmac(md, cfkey, H, chash, H, cfin) != 0) return TLS13_ECRYPTO;

    /* Send ChangeCipherSpec (middlebox compatibility, as the browser does) and the encrypted
     * Finished. */
    {
        unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        if (write(fd, ccs, 6) != 6) return TLS13_EIO;

        unsigned char pt[96];
        size_t pl = 0;
        pt[pl++] = 0x14;
        pt[pl++] = 0; pt[pl++] = 0; pt[pl++] = (unsigned char)H;
        memcpy(pt + pl, cfin, H); pl += H;
        pt[pl++] = 0x16;                        /* inner type */

        unsigned char out[160];
        size_t total = pl + 16;
        out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
        out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
        memcpy(out + 5, pt, pl);
        if (aead_seal_once(&c_hk, 0, out, 5, out + 5, pl, out + 5 + pl) != 0) return TLS13_ECRYPTO;
        if (write(fd, out, 5 + total) != (ssize_t)(5 + total)) return TLS13_EIO;
    }

    /* Application traffic keys: from the master secret and the full transcript. */
    unsigned char master[48], c_ap[48], s_ap[48];
    if (expand_label(md, hs_secret, H, "derived", empty_hash, H, derived, H) != 0)
        return TLS13_ECRYPTO;
    if (sc_hkdf_extract(md, derived, H, zeros, H, master) != 0) return TLS13_ECRYPTO;
    tr_hash(t, th2);
    if (derive_secret(md, master, "c ap traffic", th2, H, c_ap) != 0) return TLS13_ECRYPTO;
    if (derive_secret(md, master, "s ap traffic", th2, H, s_ap) != 0) return TLS13_ECRYPTO;

    if (expand_label(md, c_ap, H, "key", NULL, 0, t->wr.key, t->wr.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, c_ap, H, "iv", NULL, 0, t->wr.iv, 12) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_ap, H, "key", NULL, 0, t->rd.key, t->rd.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_ap, H, "iv", NULL, 0, t->rd.iv, 12) != 0) return TLS13_ECRYPTO;
    /* Traffic keys never change from here, so the cipher contexts are set up once; the stream
     * then runs without a single setkey. */
    if (tls13_keys_setup(&t->wr) != 0 || tls13_keys_setup(&t->rd) != 0) return TLS13_ECRYPTO;
    t->wr_seq = t->rd_seq = 0;
    t->ready = 1;
    return 0;
}

int tls13_handshake(struct tls13 *t, int fd,
                    const unsigned char *client_hello, size_t hello_n,
                    const unsigned char *our_priv) {
    return handshake(t, fd, client_hello, hello_n, our_priv, NULL);
}

int tls13_handshake_auth(struct tls13 *t, int fd,
                         const unsigned char *client_hello, size_t hello_n,
                         const unsigned char *our_priv,
                         const struct tls13_auth *auth) {
    /* An empty name with the certificate check on is a caller bug, not "nothing to check": a
     * check without a name would pass any valid certificate in the world. */
    if (auth && auth->host && !auth->host[0]) return TLS13_ECERT;
    return handshake(t, fd, client_hello, hello_n, our_priv, auth);
}

int tls13_has_record(const struct tls13 *t) {
    size_t have = t->rbuf_n - t->rbuf_off;
    if (have < 5) return 0;
    const unsigned char *h = t->rbuf + t->rbuf_off;
    size_t len = ((size_t)h[3] << 8) | h[4];
    return have >= 5 + len;
}

size_t tls13_buffered(const struct tls13 *t) {
    return t->rbuf_n - t->rbuf_off;
}

size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap) {
    size_t have = t->rbuf_n - t->rbuf_off;
    if (!have) return 0;
    if (have > cap) have = cap;
    memcpy(out, t->rbuf + t->rbuf_off, have);
    t->rbuf_off += have;
    return have;
}

/* ---- data ------------------------------------------------------------------ */
static int tls12_write(struct tls13 *t, const unsigned char *data, size_t n);

int tls13_write(struct tls13 *t, const unsigned char *data, size_t n) {
    if (!t->ready) return TLS13_ESTATE;
    if (t->v12) return tls12_write(t, data, n);
    while (n) {
        size_t chunk = n > TLS13_MAX_PLAIN ? TLS13_MAX_PLAIN : n;
        unsigned char out[TLS13_MAX_REC + 5];
        size_t total = chunk + 1 + 16;          /* + inner type + tag */
        out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
        out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
        memcpy(out + 5, data, chunk);
        out[5 + chunk] = 0x17;                  /* inner type: application_data */
        if (tls13_aead_seal(&t->wr, t->wr_seq++, out, 5, out + 5, chunk + 1,
                      out + 5 + chunk + 1) != 0)
            return TLS13_ECRYPTO;
        size_t want = 5 + total, sent = 0;
        while (sent < want) {
            ssize_t w = write(t->fd, out + sent, want - sent);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return TLS13_EIO;
            }
            sent += (size_t)w;
        }
        data += chunk;
        n -= chunk;
    }
    return 0;
}

static int tls12_read_rec(struct tls13 *t, unsigned char type, unsigned char *rec, size_t n,
                          const unsigned char **body, size_t *body_n);

/* Read EXACTLY ONE record. It may carry no data: then zero bytes with code 0, a success.
 *
 * "Exactly one" matters. Records without data are common here (ChangeCipherSpec,
 * NewSessionTicket, Vision's empty records), and the socket is blocking with SO_RCVTIMEO: waiting
 * on for data after one stalls a healthy connection until the timeout and then fails it as an
 * I/O error, cutting a download at a random point. Waiting for the socket to become readable is
 * the caller's job: it has poll; this layer has none and must not.
 *
 * Shared by both reads: the plaintext stays WHERE IT IS, in the connection buffer. Only
 * tls13_read copies, because its caller wants its own buffer. */
static int read_one(struct tls13 *t, const unsigned char **body, size_t *body_n) {
    if (!t->ready) return TLS13_ESTATE;
    *body = NULL;
    *body_n = 0;

    /* The record is decrypted IN PLACE in the connection buffer: another copy would move an
     * extra 16 KB through memory per record. */
    unsigned char *rec = NULL;
    unsigned char type;
    size_t n = 0;
    int rc = read_record(t, &type, &rec, &n, 0);
    /* No whole record yet means "nothing for now", not a failure: the caller comes back. */
    if (rc == TLS13_EAGAIN) return 0;
    if (rc) return rc;
    if (t->v12) return tls12_read_rec(t, type, rec, n, body, body_n);
    if (type == 0x14) return 0;                /* ChangeCipherSpec: meaningless in 1.3 */
    if (type != 0x17) return TLS13_EBADREC;

    unsigned char aad[5] = { 0x17, 0x03, 0x03,
                             (unsigned char)(n >> 8), (unsigned char)n };
    rc = tls13_aead_open(&t->rd, t->rd_seq++, aad, 5, rec, n);
    if (rc) return rc;
    size_t pt = n - 16;
    while (pt > 0 && rec[pt - 1] == 0) pt--;
    if (pt == 0) return TLS13_EBADREC;
    unsigned char inner = rec[--pt];

    /* NewSessionTicket and other post-handshake messages arrive as handshake records and are
     * skipped, not treated as errors: resumption is not supported, and failing on them would
     * kill connections soon after they open. */
    if (inner == 0x16) return 0;
    if (inner == 0x15) return TLS13_ECLOSED;   /* alert */
    if (inner != 0x17) return 0;
    if (pt == 0) return 0;                     /* empty record: legitimate Vision padding */

    *body = rec;
    *body_n = pt;
    return 0;
}

int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got) {
    const unsigned char *body = NULL;
    size_t n = 0;
    int rc = read_one(t, &body, &n);
    *got = 0;
    if (rc || !n) return rc;
    if (n > cap) return TLS13_ETOOBIG;
    memcpy(out, body, n);
    *got = n;
    return 0;
}

int tls13_read_ref(struct tls13 *t, const unsigned char **body, size_t *body_n) {
    return read_one(t, body, body_n);
}


/* ==== TLS 1.2 ============================================================================
 *
 * The minimum for tls12_handshake (tls13.h): ECDHE_RSA with X25519, AES_128_GCM_SHA256 or
 * CHACHA20_POLY1305_SHA256, no resumption, no extended master secret (not offered), no
 * certificate check.
 *
 * The nonce works as in 1.3 if iv is kept right: for GCM iv = salt(4) plus eight zeros, so
 * aead_nonce(iv, n) = salt || n, exactly salt || explicit part when the explicit part equals
 * the record number (as we write it). For ChaCha iv is all twelve bytes and
 * nonce = iv XOR number, as in 1.3. When reading, the GCM explicit part is taken from the
 * record: the server may choose it freely. */

#define TLS12_GCM      0xC02F   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
#define TLS12_CHACHA   0xCCA8   /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */

int xc_random(unsigned char *out, size_t n);
int xc_x25519_keypair(unsigned char priv[32], unsigned char pub[32]);

/* PRF TLS 1.2 (RFC 5246 §5): P_SHA256(secret, label || seed). */
static int tls12_prf(const unsigned char *secret, size_t secret_n, const char *label,
                     const unsigned char *seed, size_t seed_n, unsigned char *out, size_t out_n) {
    unsigned char ls[128], a[32], tmp[32];
    size_t ll = strlen(label);
    if (ll + seed_n > sizeof(ls)) return TLS13_ECRYPTO;
    memcpy(ls, label, ll);
    memcpy(ls + ll, seed, seed_n);
    size_t lsn = ll + seed_n;
    /* A(1) = HMAC(secret, label||seed), then A(i) = HMAC(secret, A(i-1)). */
    if (sc_hmac(SC_SHA256, secret, secret_n, ls, lsn, a)) return TLS13_ECRYPTO;
    size_t off = 0;
    while (off < out_n) {
        /* HMAC(secret, A(i) || label || seed), in two pieces without concatenating them. */
        if (sc_hmac2(SC_SHA256, secret, secret_n, a, 32, ls, lsn, tmp)) return TLS13_ECRYPTO;
        size_t take = out_n - off < 32 ? out_n - off : 32;
        memcpy(out + off, tmp, take);
        off += take;
        if (sc_hmac(SC_SHA256, secret, secret_n, a, 32, a)) return TLS13_ECRYPTO;
    }
    return 0;
}

static void put16(unsigned char *p, size_t v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }
static void put24(unsigned char *p, size_t v) {
    p[0] = (unsigned char)(v >> 16); p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)v;
}

static void tls12_aad(unsigned char aad[13], uint64_t seq, unsigned char type, size_t len) {
    for (int i = 0; i < 8; i++) aad[i] = (unsigned char)(seq >> (56 - 8 * i));
    aad[8] = type; aad[9] = 0x03; aad[10] = 0x03;
    put16(aad + 11, len);
}

static int write_all_fd(int fd, const unsigned char *p, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return TLS13_EIO; }
        sent += (size_t)w;
    }
    return 0;
}

/* One encrypted record of the given type, with the persistent context t->wr. */
static int tls12_seal_rec(struct tls13 *t, unsigned char type, const unsigned char *data,
                          size_t chunk, unsigned char *out, size_t *out_n) {
    int gcm = t->wr.aead != TLS13_AEAD_CHACHA;
    size_t ex = gcm ? 8 : 0;
    size_t total = ex + chunk + 16;
    uint64_t seq = t->wr_seq++;
    out[0] = type; out[1] = 0x03; out[2] = 0x03;
    put16(out + 3, total);
    if (gcm) for (int i = 0; i < 8; i++) out[5 + i] = (unsigned char)(seq >> (56 - 8 * i));
    memcpy(out + 5 + ex, data, chunk);
    unsigned char aad[13];
    tls12_aad(aad, seq, type, chunk);
    if (tls13_aead_seal(&t->wr, seq, aad, 13, out + 5 + ex, chunk, out + 5 + ex + chunk) != 0)
        return TLS13_ECRYPTO;
    *out_n = 5 + total;
    return 0;
}

static int tls12_write(struct tls13 *t, const unsigned char *data, size_t n) {
    while (n) {
        size_t chunk = n > TLS13_MAX_PLAIN ? TLS13_MAX_PLAIN : n;
        unsigned char out[TLS13_MAX_REC + 5];
        size_t on = 0;
        int rc = tls12_seal_rec(t, 0x17, data, chunk, out, &on);
        if (rc) return rc;
        rc = write_all_fd(t->fd, out, on);
        if (rc) return rc;
        data += chunk;
        n -= chunk;
    }
    return 0;
}

/* Decrypt a record in place; the plaintext is returned in pt/pt_n. */
static int tls12_open_rec(struct tls13 *t, unsigned char type, unsigned char *rec, size_t n,
                          unsigned char **pt, size_t *pt_n) {
    int gcm = t->rd.aead != TLS13_AEAD_CHACHA;
    size_t ex = gcm ? 8 : 0;
    if (n < ex + 16) return TLS13_EBADREC;
    uint64_t nonce_seq = t->rd_seq;
    if (gcm) {
        nonce_seq = 0;
        for (int i = 0; i < 8; i++) nonce_seq = (nonce_seq << 8) | rec[i];
    }
    size_t len = n - ex - 16;
    unsigned char aad[13];
    tls12_aad(aad, t->rd_seq, type, len);
    int rc = tls13_aead_open(&t->rd, nonce_seq, aad, 13, rec + ex, n - ex);
    if (rc) return rc;
    t->rd_seq++;
    *pt = rec + ex;
    *pt_n = len;
    return 0;
}

static int tls12_read_rec(struct tls13 *t, unsigned char type, unsigned char *rec, size_t n,
                          const unsigned char **body, size_t *body_n) {
    unsigned char *pt;
    size_t pt_n;
    if (type != 0x17 && type != 0x15 && type != 0x16) return TLS13_EBADREC;
    int rc = tls12_open_rec(t, type, rec, n, &pt, &pt_n);
    if (rc) return rc;
    if (type == 0x15) return TLS13_ECLOSED;     /* alert, close_notify included */
    if (type == 0x16) return 0;                 /* HelloRequest and the like: ignored */
    if (!pt_n) return 0;
    *body = pt;
    *body_n = pt_n;
    return 0;
}

int tls12_handshake(struct tls13 *t, int fd, const char *sni) {
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    t->v12 = 1;
    struct sc_hash_ctx tr;
    if (sc_hash_init(&tr, SC_SHA256) != 0) return TLS13_ECRYPTO;
    int rc = TLS13_ESTATE;

    unsigned char cr[32], sr[32], priv[32], pub[32], sid[32];
    if (xc_random(cr, 32) || xc_random(sid, 32) || xc_x25519_keypair(priv, pub))
        { rc = TLS13_ECRYPTO; goto out; }

    /* ---- ClientHello ---- */
    static __thread unsigned char buf[16384];
    size_t sl = strlen(sni);
    if (sl > 200) { rc = TLS13_ETOOBIG; goto out; }
    unsigned char *h = buf + 5, *p = h + 4;
    *p++ = 0x03; *p++ = 0x03;
    memcpy(p, cr, 32); p += 32;
    *p++ = 32; memcpy(p, sid, 32); p += 32;
    /* ChaCha first: much faster on a router without AES acceleration; the server picks by its
     * own order anyway. */
    put16(p, 4); p += 2;
    put16(p, TLS12_CHACHA); p += 2;
    put16(p, TLS12_GCM); p += 2;
    *p++ = 1; *p++ = 0;                             /* no compression */
    unsigned char *ext = p; p += 2;
    /* server_name */
    put16(p, 0x0000); put16(p + 2, sl + 5); put16(p + 4, sl + 3); p[6] = 0; put16(p + 7, sl);
    memcpy(p + 9, sni, sl); p += 9 + sl;
    /* supported_groups: X25519 only */
    put16(p, 0x000a); put16(p + 2, 4); put16(p + 4, 2); put16(p + 6, 0x001d); p += 8;
    /* ec_point_formats: uncompressed */
    put16(p, 0x000b); put16(p + 2, 2); p[4] = 1; p[5] = 0; p += 6;
    /* signature_algorithms: RSA-PSS and PKCS#1. The signature is not checked, but without the
     * list the server may refuse. */
    static const unsigned char sa[] = { 0x08,0x04, 0x08,0x05, 0x08,0x06, 0x04,0x01, 0x05,0x01, 0x06,0x01 };
    put16(p, 0x000d); put16(p + 2, sizeof(sa) + 2); put16(p + 4, sizeof(sa));
    memcpy(p + 6, sa, sizeof(sa)); p += 6 + sizeof(sa);
    /* ALPN: http/1.1 only */
    put16(p, 0x0010); put16(p + 2, 11); put16(p + 4, 9); p[6] = 8; memcpy(p + 7, "http/1.1", 8); p += 15;
    /* renegotiation_info: empty, as every modern client sends it */
    put16(p, 0xff01); put16(p + 2, 1); p[4] = 0; p += 5;
    put16(ext, (size_t)(p - ext - 2));
    size_t hl = (size_t)(p - h);
    h[0] = 0x01; put24(h + 1, hl - 4);
    buf[0] = 0x16; buf[1] = 0x03; buf[2] = 0x01; put16(buf + 3, hl);
    sc_hash_update(&tr, h, hl);
    if ((rc = write_all_fd(fd, buf, 5 + hl))) goto out;

    /* ---- server reply: ServerHello ... ServerHelloDone ---- */
    static __thread unsigned char hs[40960];
    size_t hs_n = 0, off = 0;
    unsigned suite = 0;
    unsigned char spub[32];
    int have_ske = 0, done = 0;
    for (int guard = 0; guard < 64 && !done; guard++) {
        unsigned char type;
        size_t n;
        rc = read_record_fd(fd, &type, buf, sizeof(buf), &n);
        if (rc) goto out;
        if (type == 0x15) { rc = TLS13_ECLOSED; goto out; }
        if (type != 0x16) { rc = TLS13_EBADREC; goto out; }
        if (hs_n + n > sizeof(hs)) { rc = TLS13_ETOOBIG; goto out; }
        memcpy(hs + hs_n, buf, n);
        hs_n += n;
        while (off + 4 <= hs_n) {
            unsigned char mt = hs[off];
            size_t ml = ((size_t)hs[off + 1] << 16) | ((size_t)hs[off + 2] << 8) | hs[off + 3];
            if (off + 4 + ml > hs_n) break;
            const unsigned char *m = hs + off + 4;
            if (mt == 0x02) {                               /* ServerHello */
                if (ml < 38 || m[0] != 3 || m[1] != 3) { rc = TLS13_EBADREC; goto out; }
                memcpy(sr, m + 2, 32);
                size_t q = 34 + 1 + m[34];
                if (q + 3 > ml) { rc = TLS13_EBADREC; goto out; }
                suite = ((unsigned)m[q] << 8) | m[q + 1];
                if (suite != TLS12_GCM && suite != TLS12_CHACHA) { rc = TLS13_EBADSUITE; goto out; }
            } else if (mt == 0x0c) {                        /* ServerKeyExchange */
                if (ml < 4 + 32 || m[0] != 3 || m[1] != 0x00 || m[2] != 0x1d || m[3] != 32)
                    { rc = TLS13_ENOKEYSHARE; goto out; }
                memcpy(spub, m + 4, 32);
                have_ske = 1;
            } else if (mt == 0x0d) {                        /* CertificateRequest: unsupported */
                rc = TLS13_EBADREC; goto out;
            } else if (mt == 0x0e) {                        /* ServerHelloDone */
                done = 1;
            }
            /* Certificate (0x0b) and the rest only enter the transcript. */
            sc_hash_update(&tr, hs + off, 4 + ml);
            off += 4 + ml;
            if (done) break;
        }
    }
    if (!done || !suite || !have_ske) { rc = TLS13_EBADREC; goto out; }

    /* ---- keys ---- */
    unsigned char pms[32], ms[48], seed[64], kb[88];
    if (x25519_shared_ext(priv, spub, pms)) { rc = TLS13_ECRYPTO; goto out; }
    memcpy(seed, cr, 32); memcpy(seed + 32, sr, 32);
    if ((rc = tls12_prf(pms, 32, "master secret", seed, 64, ms, 48))) goto out;
    memcpy(seed, sr, 32); memcpy(seed + 32, cr, 32);
    int chacha = suite == TLS12_CHACHA;
    size_t kn = chacha ? 32 : 16, ivn = chacha ? 12 : 4;
    if ((rc = tls12_prf(ms, 48, "key expansion", seed, 64, kb, 2 * kn + 2 * ivn))) goto out;
    t->wr.aead = t->rd.aead = chacha ? TLS13_AEAD_CHACHA : TLS13_AEAD_AES128;
    t->wr.key_n = t->rd.key_n = kn;
    memcpy(t->wr.key, kb, kn);
    memcpy(t->rd.key, kb + kn, kn);
    memcpy(t->wr.iv, kb + 2 * kn, ivn);         /* for GCM the other eight are zeros (above) */
    memcpy(t->rd.iv, kb + 2 * kn + ivn, ivn);
    if ((rc = tls13_keys_setup(&t->wr)) || (rc = tls13_keys_setup(&t->rd))) goto out;

    /* ---- ClientKeyExchange, ChangeCipherSpec, Finished ---- */
    unsigned char cke[4 + 33];
    cke[0] = 0x10; put24(cke + 1, 33); cke[4] = 32; memcpy(cke + 5, pub, 32);
    sc_hash_update(&tr, cke, sizeof(cke));
    buf[0] = 0x16; buf[1] = 0x03; buf[2] = 0x03; put16(buf + 3, sizeof(cke));
    memcpy(buf + 5, cke, sizeof(cke));
    size_t bn = 5 + sizeof(cke);
    static const unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    memcpy(buf + bn, ccs, 6); bn += 6;

    unsigned char th[32], fin[16];
    struct sc_hash_ctx tc;
    if (sc_hash_clone(&tc, &tr) != 0) { rc = TLS13_ECRYPTO; goto out; }
    sc_hash_final(&tc, th);
    sc_hash_free(&tc);
    fin[0] = 0x14; put24(fin + 1, 12);
    if ((rc = tls12_prf(ms, 48, "client finished", th, 32, fin + 4, 12))) goto out;
    sc_hash_update(&tr, fin, 16);
    size_t fn = 0;
    if ((rc = tls12_seal_rec(t, 0x16, fin, 16, buf + bn, &fn))) goto out;
    bn += fn;
    if ((rc = write_all_fd(fd, buf, bn))) goto out;

    /* ---- the server's ChangeCipherSpec and Finished ---- */
    unsigned char want[12];
    if (sc_hash_clone(&tc, &tr) != 0) { rc = TLS13_ECRYPTO; goto out; }
    sc_hash_final(&tc, th);
    sc_hash_free(&tc);
    if ((rc = tls12_prf(ms, 48, "server finished", th, 32, want, 12))) goto out;
    int got_ccs = 0;
    for (int guard = 0; guard < 8; guard++) {
        unsigned char type;
        size_t n;
        rc = read_record_fd(fd, &type, buf, sizeof(buf), &n);
        if (rc) goto out;
        if (type == 0x15) { rc = TLS13_ECLOSED; goto out; }
        if (type == 0x14) { got_ccs = 1; continue; }
        if (type != 0x16 || !got_ccs) { rc = TLS13_EBADREC; goto out; }
        unsigned char *pt;
        size_t pn;
        if ((rc = tls12_open_rec(t, 0x16, buf, n, &pt, &pn))) goto out;
        if (pn != 16 || pt[0] != 0x14 || memcmp(pt + 4, want, 12)) { rc = TLS13_EFINISHED; goto out; }
        t->ready = 1;
        rc = 0;
        goto out;
    }
    rc = TLS13_EBADREC;
out:
    sc_hash_free(&tr);
    if (rc) { tls13_keys_free(&t->wr); tls13_keys_free(&t->rd); t->ready = 0; }
    return rc;
}
