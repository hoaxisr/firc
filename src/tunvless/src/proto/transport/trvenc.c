/* VLESS encryption (mlkem768x25519plus), client side: an X25519 + ML-KEM-768 handshake and AEAD
 * records over a ready transport. A byte-exact port of Xray-core proxy/vless/encryption
 * (client.go, common.go, xor.go).
 *
 * WHERE IT SITS. Between the transport (tcp/ws/grpc/xhttp... over none/tls/reality) and the
 * VLESS header: in Xray it is `conn = encryption.Handshake(conn)` before the request is written,
 * and the request, the response and the Vision frames all travel inside this layer's records.
 * Same here: transport_open calls tr_venc_open after opening the transport, and transport_write
 * and transport_read then go through this file. The transport itself knows nothing of
 * encryption.
 *
 * ON THE WIRE (1-RTT).
 *   client: iv(16) ‖ relay... ‖ AEAD(length 1232) ‖ AEAD(ML-KEM ek ‖ X25519 pub) ‖ padding;
 *   server: AEAD(ML-KEM ct ‖ X25519 pub) ‖ AEAD(ticket) ‖ AEAD(padding length) ‖ padding;
 * then records: 23 3 3 <length 2> ‖ AEAD(data, aad = header), up to 8192 data bytes per record.
 *
 * KEYS. The relay is a chain of "pre-shared" exchanges with keys of the server known in advance
 * (nfsKey); they give the handshake AEAD. A second, ephemeral exchange (pfsKey = ML-KEM ss ‖
 * X25519 ss) gives forward secrecy. The record keys are blake3.DeriveKey(context, pfsKey ‖
 * nfsKey), and each direction's context is the message that created it (the two differ in
 * length, so the keys differ). The record cipher is AES-256-GCM with hardware AES, otherwise
 * ChaCha20-Poly1305: the client chooses, the server tries both on the first message.
 *
 * MODES. xorpub masks the X25519 key and the ML-KEM ciphertext in the relay with an AES-CTR
 * keystream (key: DeriveKey("VLESS", relay key)). random also masks the five-byte record headers
 * both ways (Xray's XorConn): the stream looks random.
 *
 * 0-RTT. The server issues a ticket (16 bytes, the first two its lifetime in seconds); a client
 * that declared 0rtt resumes with it on the next connection without ML-KEM, sending iv ‖ relay ‖
 * AEAD(ticket) together with the first record. Tickets live in a process-wide table (key: hash of
 * the encryption string). An expired ticket, or one the server forgot, gets noise back: the
 * ticket is dropped and the connection fails with TR_EVENC0RTT (the next one does a full
 * handshake), as in Xray ("new handshake needed").
 *
 * DOES NOT BLOCK THE LOOP. The handshake runs in a connector thread and waits with poll; records
 * are read in the tunnel loop without waiting: no whole record yet means "0 bytes" (a valid
 * outcome, as with HTTP/2).
 *
 * WRITE ROLLBACK. A transport over HTTP/2 may return H2_EWINDOW ("window closed, nothing sent"),
 * and the caller repeats THE SAME bytes. So the write state (nonce counter, header keystream)
 * advances only after a successful send; otherwise the retry would carry a wrong nonce and the
 * server would close the stream. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <pthread.h>

#include "transport.h"
#include "reality.h"
#include "vencp.h"

#define REC_MAX_DATA 8192              /* data per sent record (Xray: no extra copy at the peer) */
#define REC_MAX_LEN  16640             /* max record body length accepted on receive */
#define REC_MIN_LEN  17
/* Raw input: a whole record of the largest accepted size plus room for one transport read,
 * which needs TRANSPORT_MIN_READ_CAP free (raw_fill). */
#define RBUF_CAP     (5 + REC_MAX_LEN + (16384 + 16) + 16)

static const unsigned char MAX_NONCE[12] = { 255,255,255,255,255,255,255,255,255,255,255,255 };

/* The reason of the last failure as text (per thread), like tls13_verify_reason: one code covers
 * a class, but the user needs words ("server answered with noise" and "wrong relay key" call for
 * different fixes). */
static __thread char g_reason[128];
const char *tr_venc_reason(void) { return g_reason; }
static int fail(int rc, const char *why) {
    snprintf(g_reason, sizeof g_reason, "%s", why);
    return rc;
}

/* ---- AEAD and keystream -------------------------------------------------------------------- */

struct v_aead {
    struct sc_aead k;
    unsigned char nonce[12];       /* the last one used (like Xray's AEAD.Nonce) */
    int ok;
};

static void nonce_inc(unsigned char n[12]) {
    for (int i = 11; i >= 0; i--)
        if (++n[i] != 0) break;
}

static void va_free(struct v_aead *a) {
    if (a->ok) sc_aead_free(&a->k);
    a->ok = 0;
}

/* NewAEAD(ctx, key, useAES): the key is blake3.DeriveKey(k, string(ctx), key). */
static int va_init(struct v_aead *a, const void *ctx, size_t ctx_n, const void *key, size_t key_n,
                   int use_aes) {
    unsigned char k[32];
    va_free(a);
    sc_blake3_derive_key(k, 32, ctx, ctx_n, key, key_n);
    memset(a->nonce, 0, 12);
    int rc = sc_aead_setkey(&a->k, use_aes ? SC_AES256_GCM : SC_CHACHA20_POLY1305, k);
    memset(k, 0, sizeof k);
    a->ok = rc == 0;
    return rc;
}

/* Seal/Open like Xray's AEAD wrapper: with nonce == NULL the counter grows BEFORE use, so the
 * first record goes with nonce 1; Xray passes MaxNonce explicitly (the server's relay answer). */
static int va_seal(struct v_aead *a, const unsigned char *fixed, const void *aad, size_t aad_n,
                   unsigned char *buf, size_t n, unsigned char tag[16]) {
    unsigned char nn[12];
    if (fixed) memcpy(nn, fixed, 12); else { nonce_inc(a->nonce); memcpy(nn, a->nonce, 12); }
    return sc_aead_seal(&a->k, nn, aad, aad_n, buf, n, tag);
}
static int va_open(struct v_aead *a, const unsigned char *fixed, const void *aad, size_t aad_n,
                   unsigned char *buf, size_t n, const unsigned char tag[16]) {
    unsigned char nn[12];
    if (fixed) memcpy(nn, fixed, 12); else { nonce_inc(a->nonce); memcpy(nn, a->nonce, 12); }
    return sc_aead_open(&a->k, nn, aad, aad_n, buf, n, tag);
}

/* NewCTR(key, iv): AES-256-CTR, the key is blake3.DeriveKey(k, "VLESS", key) ("so the key is not
 * used as is"), iv is the whole initial counter block. */
static int ctr_new(struct sc_aesctr *c, const void *key, size_t key_n, const unsigned char iv[16]) {
    unsigned char k[32];
    sc_blake3_derive_key(k, 32, "VLESS", 5, key, key_n);
    int rc = sc_aesctr_init(c, k, iv);
    memset(k, 0, sizeof k);
    return rc;
}

/* ---- 0-RTT tickets ------------------------------------------------------------------------- */

/* A process-wide table: connections to one node share one ticket. Key: blake3 of the encryption
 * string (the string itself, which holds keys, is not stored). Few entries: few nodes in a
 * subscription use 0-RTT. */
#define TICKETS 16
static struct ticket {
    int used;
    unsigned char id[32];
    time_t expire;
    unsigned char pfs[64];
    unsigned char ticket[16];
} g_tk[TICKETS];
static pthread_mutex_t g_tk_mu = PTHREAD_MUTEX_INITIALIZER;
static unsigned g_tk_next;

static int tk_get(const unsigned char id[32], unsigned char pfs[64], unsigned char tk[16]) {
    int ok = 0;
    pthread_mutex_lock(&g_tk_mu);
    for (int i = 0; i < TICKETS; i++)
        if (g_tk[i].used && !memcmp(g_tk[i].id, id, 32)) {
            if (time(NULL) < g_tk[i].expire) {
                memcpy(pfs, g_tk[i].pfs, 64);
                memcpy(tk, g_tk[i].ticket, 16);
                ok = 1;
            }
            break;
        }
    pthread_mutex_unlock(&g_tk_mu);
    return ok;
}

static void tk_put(const unsigned char id[32], const unsigned char pfs[64], const unsigned char tk[16],
                   unsigned seconds) {
    pthread_mutex_lock(&g_tk_mu);
    int slot = -1;
    for (int i = 0; i < TICKETS; i++)
        if (g_tk[i].used && !memcmp(g_tk[i].id, id, 32)) { slot = i; break; }
    if (slot < 0) {
        for (int i = 0; i < TICKETS; i++) if (!g_tk[i].used) { slot = i; break; }
        if (slot < 0) slot = (int)(g_tk_next++ % TICKETS);
    }
    g_tk[slot].used = 1;
    memcpy(g_tk[slot].id, id, 32);
    g_tk[slot].expire = time(NULL) + (time_t)seconds;
    memcpy(g_tk[slot].pfs, pfs, 64);
    memcpy(g_tk[slot].ticket, tk, 16);
    pthread_mutex_unlock(&g_tk_mu);
}

/* The server rejected the ticket: expire it only if it is still the one we used (another
 * connection may have got a new one by now). */
static void tk_expire(const unsigned char id[32], const unsigned char pfs[64]) {
    pthread_mutex_lock(&g_tk_mu);
    for (int i = 0; i < TICKETS; i++)
        if (g_tk[i].used && !memcmp(g_tk[i].id, id, 32) && !memcmp(g_tk[i].pfs, pfs, 64))
            g_tk[i].expire = 0;
    pthread_mutex_unlock(&g_tk_mu);
}

/* ---- connection state ---------------------------------------------------------------------- */

enum { RS_PAD = 0, RS_RAND, RS_REC };

struct venc {
    int use_aes, xor2, zero_rtt_try;
    unsigned char united[96];
    struct v_aead wr, rd;
    unsigned char tk_id[32];               /* ticket table key: blake3 of the encryption string */
    unsigned char tk_pfs[64];              /* pfsKey of the ticket in use (for tk_expire) */
    /* Receive. */
    int rs;                                /* RS_PAD, RS_RAND, RS_REC */
    size_t peer_pad;                       /* RS_PAD: server padding length with the tag */
    unsigned char *padbuf;                 /* padding is collected whole: AEAD checks it */
    size_t padbuf_n;
    unsigned char *rbuf;                   /* raw input */
    size_t rlen, rcap;
    size_t pl_off, pl_len;                 /* decrypted, not yet returned (inside rbuf) */
    size_t pl_rec;                         /* bytes of rbuf taken by this plaintext's record */
    int hdr_done;                          /* the current record's header is unmasked */
    int first_rec;                         /* 0-RTT: the first record not yet received */
    /* random mode keystream (XorConn): the next record's header mask is computed ahead, so a
     * write rollback does not move the keystream. */
    struct sc_aesctr out_ctr, in_ctr;
    int have_out_ctr, have_in_ctr;
    unsigned char out_mask[5];
    /* Send. */
    unsigned char *prewrite;               /* 0-RTT: iv ‖ relay ‖ ticket, sent with record 1 */
    size_t prewrite_n;
};

static void enc_free(struct venc *e) {
    if (!e) return;
    va_free(&e->wr);
    va_free(&e->rd);
    if (e->have_out_ctr) sc_aesctr_free(&e->out_ctr);
    if (e->have_in_ctr) sc_aesctr_free(&e->in_ctr);
    memset(e->united, 0, sizeof e->united);
    free(e->rbuf);
    free(e->padbuf);
    free(e->prewrite);
    free(e);
}

static void out_mask_next(struct venc *e) {
    if (!e->xor2) return;
    static const unsigned char z[5] = {0};
    sc_aesctr_xor(&e->out_ctr, z, e->out_mask, 5);
}

/* ---- raw transport I/O ---------------------------------------------------------------------- */

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Read raw input into rbuf until it holds need bytes. block != 0 (handshake): wait with poll up
 * to deadline. Otherwise 0 means "not enough yet" (e->rlen < need); negative: transport failure. */
static int raw_fill(struct transport *t, struct venc *e, size_t need, int block, int64_t deadline) {
    while (e->rlen < need) {
        if (e->rcap - e->rlen < TRANSPORT_MIN_READ_CAP) return TR_EVENC;   /* need too big: a bug */
        size_t got = 0;
        int rc = t->fr->read(t, e->rbuf + e->rlen, e->rcap - e->rlen, &got);
        if (rc) return rc;
        e->rlen += got;
        if (got) continue;
        if (!block) return 0;
        if (transport_has_data(t)) continue;
        int64_t left = deadline - now_ms();
        if (left <= 0) return fail(TR_EVENC, "the server did not answer the handshake");
        struct pollfd p = { .fd = t->link.fd, .events = POLLIN };
        int pr = poll(&p, 1, left > 1000 ? 1000 : (int)left);
        if (pr < 0 && errno != EINTR) return TR_EIO;
    }
    return 0;
}

/* Unmask the next record's header as soon as its five bytes are in the input: right after the
 * previous record is returned, not at the next read. tr_venc_pending must know whether a WHOLE
 * record is in the input, and a masked header has no readable length. Otherwise a record that
 * arrived in one segment with the previous one would sit untouched while the socket is silent,
 * i.e. forever (found in runs against Xray: one 1 MB exchange in ten stalled at the end). */
static void hdr_prepare(struct venc *e) {
    if (e->hdr_done || e->rs != RS_REC || e->rlen < 5) return;
    if (e->xor2) sc_aesctr_xor(&e->in_ctr, e->rbuf, e->rbuf, 5);
    e->hdr_done = 1;
}

static void rb_drop(struct venc *e, size_t n) {
    if (n >= e->rlen) { e->rlen = 0; return; }
    memmove(e->rbuf, e->rbuf + n, e->rlen - n);
    e->rlen -= n;
}

static void sleep_ms(unsigned ms) {
    if (!ms) return;
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* crypto.RandBetween(from, to): [from, to); a difference of 0 or 1 gives from. */
static int64_t rand_between(int64_t from, int64_t to) {
    if (from > to) { int64_t x = from; from = to; to = x; }
    int64_t d = to - from;
    if (d == 0 || d == 1) return from;
    uint64_t r = 0;
    if (xc_random((unsigned char *)&r, sizeof r) != 0) return from;
    return from + (int64_t)(r % (uint64_t)d);
}

/* ---- handshake ------------------------------------------------------------------------------ */

static const uint16_t DEF_LENS[2][3] = { { 100, 111, 1111 }, { 50, 0, 3333 } };
static const uint16_t DEF_GAPS[1][3] = { { 75, 0, 111 } };

/* CreatPadding: padding chunk lengths and the pauses between writes. */
static size_t make_padding(const struct venc_cfg *c, size_t lens[VENC_MAX_PAD], unsigned gaps[VENC_MAX_PAD],
                           size_t *nl, size_t *ng) {
    const uint16_t (*pl)[3] = c->npad_lens ? (const uint16_t (*)[3])c->lens : DEF_LENS;
    size_t npl = c->npad_lens ? c->npad_lens : 2;
    const uint16_t (*pg)[3] = c->npad_lens ? (const uint16_t (*)[3])c->gaps : DEF_GAPS;
    size_t npg = c->npad_lens ? c->npad_gaps : 1;
    size_t total = 0;
    for (size_t i = 0; i < npl; i++) {
        size_t l = 0;
        if (pl[i][0] >= rand_between(0, 100)) l = (size_t)rand_between(pl[i][1], pl[i][2]);
        lens[i] = l;
        total += l;
    }
    for (size_t i = 0; i < npg; i++) {
        unsigned g = 0;
        if (pg[i][0] >= rand_between(0, 100)) g = (unsigned)rand_between(pg[i][1], pg[i][2]);
        gaps[i] = g;
    }
    *nl = npl;
    *ng = npg;
    return total;
}

static int b64url_key(const char *s, size_t n, unsigned char *out, size_t cap) {
    char tmp[1700];
    if (n >= sizeof tmp) return -1;
    memcpy(tmp, s, n);
    tmp[n] = '\0';
    return xc_b64url_decode(tmp, out, cap);
}

int tr_venc_open(struct transport *t, const struct tr_node *node, int timeout_s) {
    struct venc_cfg c;
    const char *why = "";
    if (vencp_parse(node->encryption, &c, &why) != 0) return fail(TR_EVENC, why);

    struct venc *e = calloc(1, sizeof(*e));
    unsigned char (*keys)[1184] = malloc(sizeof(unsigned char[VENC_MAX_KEYS][1184]));
    unsigned char *hello = NULL;
    int rc = TR_EVENC;
    unsigned char nfs[32], iv[16];
    struct v_aead nfs_a;
    memset(&nfs_a, 0, sizeof nfs_a);
    unsigned char mlk_dk[SC_MLKEM768_DK], xpriv[32], xpub[32];
    struct sc_aesctr tmpctr, last;
    int have_tmp = 0, have_last = 0;
    memset(&tmpctr, 0, sizeof tmpctr);
    memset(&last, 0, sizeof last);
    if (!e || !keys) { rc = TR_EIO; goto out; }
    e->rcap = RBUF_CAP;
    e->rbuf = malloc(e->rcap);
    if (!e->rbuf) { rc = TR_EIO; goto out; }
    e->use_aes = xc_cpu_has_aes();
    e->xor2 = c.xor_mode == 2;
    int64_t deadline = now_ms() + (timeout_s > 0 ? timeout_s : 10) * 1000;

    /* Relay keys and their hashes. */
    size_t klen[VENC_MAX_KEYS], relays_len = 0;
    unsigned char h32[VENC_MAX_KEYS][32];
    for (unsigned j = 0; j < c.nkeys; j++) {
        int kl = b64url_key(c.key[j], c.key_len[j], keys[j], 1184);
        if (kl != 32 && kl != 1184) { rc = fail(TR_EVENC, "a key in the encryption string does not parse"); goto out; }
        klen[j] = (size_t)kl;
        sc_blake3_hash(h32[j], keys[j], klen[j]);
        relays_len += kl == 32 ? 32 + 32 : 1088 + 32;
    }
    relays_len -= 32;
    const size_t head_n = 16 + relays_len;

    /* Ticket id: the hash of the whole string. */
    sc_blake3_hash(e->tk_id, node->encryption, strlen(node->encryption));
    unsigned char t_pfs[64], t_tk[16];
    const int zrtt = c.zero_rtt && tk_get(e->tk_id, t_pfs, t_tk);
    if (getenv("STEER_VENC_TRACE"))
        fprintf(stderr, "tunvless[venc]: %s, mode %s, %u keys, cipher %s\n",
                zrtt ? "0-RTT with ticket" : "full handshake",
                c.xor_mode == 2 ? "random" : c.xor_mode == 1 ? "xorpub" : "native", c.nkeys,
                e->use_aes ? "AES-256-GCM" : "ChaCha20-Poly1305");

    const size_t pfs_n = 18 + 1184 + 32 + 16;              /* 1250 */
    size_t plens[VENC_MAX_PAD], nl = 0, ng = 0;
    unsigned pgaps[VENC_MAX_PAD];
    size_t pad_n = 0;
    if (!zrtt) pad_n = make_padding(&c, plens, pgaps, &nl, &ng);
    size_t hello_n = head_n + (zrtt ? 18 + 32 : pfs_n + pad_n);
    hello = calloc(1, hello_n + 1);
    if (!hello) { rc = TR_EIO; goto out; }

    if (xc_random(iv, 16) != 0) { rc = TR_EIO; goto out; }
    memcpy(hello, iv, 16);
    unsigned char *rel = hello + 16;
    for (unsigned j = 0; j < c.nkeys; j++) {
        size_t index = 32;
        if (klen[j] == 32) {
            if (xc_x25519_keypair(xpriv, xpub) != 0) { rc = TR_EIO; goto out; }
            memcpy(rel, xpub, 32);
            if (x25519_shared_ext(xpriv, keys[j], nfs) != 0) { rc = fail(TR_EVENC, "invalid X25519 relay key"); goto out; }
        } else {
            unsigned char rnd[SC_MLKEM768_RND];
            if (xc_random(rnd, sizeof rnd) != 0) { rc = TR_EIO; goto out; }
            if (sc_mlkem768_encaps(rel, nfs, keys[j], rnd) != 0) { rc = fail(TR_EVENC, "invalid ML-KEM relay key"); goto out; }
            index = 1088;
        }
        if (c.xor_mode > 0) {           /* mask with a relay key keystream: looks random */
            if (ctr_new(&tmpctr, keys[j], klen[j], iv) != 0) { rc = TR_EIO; goto out; }
            have_tmp = 1;
            sc_aesctr_xor(&tmpctr, rel, rel, index);
            sc_aesctr_free(&tmpctr);
            have_tmp = 0;
        }
        if (have_last) sc_aesctr_xor(&last, rel, rel, 32);       /* "so relays cannot be swapped" */
        if (j == (unsigned)c.nkeys - 1u) { if (have_last) { sc_aesctr_free(&last); have_last = 0; } break; }
        if (have_last) sc_aesctr_free(&last);
        if (ctr_new(&last, nfs, 32, iv) != 0) { have_last = 0; rc = TR_EIO; goto out; }
        have_last = 1;
        memcpy(rel + index, h32[j + 1], 32);
        sc_aesctr_xor(&last, rel + index, rel + index, 32);
        rel += index + 32;
    }
    if (va_init(&nfs_a, iv, 16, nfs, 32, e->use_aes) != 0) { rc = TR_EIO; goto out; }

    if (zrtt) {
        /* Resume with the ticket: united = the ticket's pfsKey ‖ nfsKey (per connection). */
        memcpy(e->united, t_pfs, 64);
        memcpy(e->united + 64, nfs, 32);
        unsigned char *p = hello + head_n;
        p[0] = 0; p[1] = 32;
        va_seal(&nfs_a, NULL, NULL, 0, p, 2, p + 2);
        memcpy(p + 18, t_tk, 16);
        va_seal(&nfs_a, NULL, NULL, 0, p + 18, 16, p + 34);
        e->prewrite_n = head_n + 18 + 32;
        e->prewrite = malloc(e->prewrite_n);
        if (!e->prewrite) { rc = TR_EIO; goto out; }
        memcpy(e->prewrite, hello, e->prewrite_n);
        if (va_init(&e->wr, p + 18, 32, e->united, 96, e->use_aes) != 0) { rc = TR_EIO; goto out; }
        e->rs = RS_RAND;
        e->first_rec = 1;
        e->zero_rtt_try = 1;
        memcpy(e->tk_pfs, t_pfs, 64);
        if (e->xor2) {
            if (ctr_new(&e->out_ctr, e->united, 96, iv) != 0) { rc = TR_EIO; goto out; }
            e->have_out_ctr = 1;
            out_mask_next(e);
        }
        rc = 0;
        goto out;
    }

    /* Full handshake. */
    unsigned char *pfs = hello + head_n;
    pfs[0] = (unsigned char)((pfs_n - 18) >> 8); pfs[1] = (unsigned char)(pfs_n - 18);
    va_seal(&nfs_a, NULL, NULL, 0, pfs, 2, pfs + 2);
    unsigned char seed[SC_MLKEM768_SEED];
    if (xc_random(seed, sizeof seed) != 0 || xc_x25519_keypair(xpriv, xpub) != 0) { rc = TR_EIO; goto out; }
    unsigned char pfs_pub[1184 + 32];
    if (sc_mlkem768_keygen(pfs_pub, mlk_dk, seed) != 0) { rc = TR_EIO; goto out; }
    memcpy(pfs_pub + 1184, xpub, 32);
    memcpy(pfs + 18, pfs_pub, sizeof pfs_pub);
    va_seal(&nfs_a, NULL, NULL, 0, pfs + 18, sizeof pfs_pub, pfs + 18 + sizeof pfs_pub);

    unsigned char *pad = hello + head_n + pfs_n;
    if (pad_n) {
        pad[0] = (unsigned char)((pad_n - 18) >> 8); pad[1] = (unsigned char)(pad_n - 18);
        va_seal(&nfs_a, NULL, NULL, 0, pad, 2, pad + 2);
        va_seal(&nfs_a, NULL, NULL, 0, pad + 18, pad_n - 34, pad + pad_n - 16);
    }

    /* Send in chunks with pauses: a varying traffic pattern until VLESS takes over. */
    {
        size_t off = 0;
        size_t first = head_n + pfs_n + (nl ? plens[0] : 0);
        for (size_t i = 0; i < nl; i++) {
            size_t l = i == 0 ? first : plens[i];
            if (l) {
                if (off + l > hello_n) { rc = TR_EVENC; goto out; }
                int wr = t->fr->write(t, hello + off, l);
                if (wr) { rc = wr; goto out; }
                off += l;
            }
            if (i < ng) sleep_ms(pgaps[i]);
        }
        if (off != hello_n) { rc = fail(TR_EVENC, "padding chunks do not add up"); goto out; }
    }

    /* Server answer: AEAD(ML-KEM ct ‖ X25519 pub) under the relay key; the record keys derive
     * from pfs + nfs. */
    if ((rc = raw_fill(t, e, 1088 + 32 + 16, 1, deadline)) != 0) goto out;
    if (va_open(&nfs_a, MAX_NONCE, NULL, 0, e->rbuf, 1088 + 32, e->rbuf + 1088 + 32) != 0) {
        rc = fail(TR_EVENC, "cannot decrypt the server answer (wrong relay key?)");
        goto out;
    }
    unsigned char pfs_key[64], srv_pub[1120];
    memcpy(srv_pub, e->rbuf, 1120);
    if (sc_mlkem768_decaps(pfs_key, mlk_dk, srv_pub) != 0 || x25519_shared_ext(xpriv, srv_pub + 1088, pfs_key + 32) != 0) {
        rc = fail(TR_EVENC, "key exchange failed");
        goto out;
    }
    rb_drop(e, 1088 + 32 + 16);
    memcpy(e->united, pfs_key, 64);
    memcpy(e->united + 64, nfs, 32);
    if (va_init(&e->wr, pfs_pub, sizeof pfs_pub, e->united, 96, e->use_aes) != 0 ||
        va_init(&e->rd, srv_pub, sizeof srv_pub, e->united, 96, e->use_aes) != 0) { rc = TR_EIO; goto out; }

    /* Ticket: 16 bytes under AEAD, the first two its lifetime in seconds (0: no ticket). */
    if ((rc = raw_fill(t, e, 32, 1, deadline)) != 0) goto out;
    unsigned char tkt[16];
    memcpy(tkt, e->rbuf, 16);
    if (va_open(&e->rd, NULL, NULL, 0, tkt, 16, e->rbuf + 16) != 0) { rc = fail(TR_EVENCAUTH, "server ticket failed authentication"); goto out; }
    rb_drop(e, 32);
    unsigned secs = ((unsigned)tkt[0] << 8) | tkt[1];
    if (c.zero_rtt && secs > 0) tk_put(e->tk_id, pfs_key, tkt, secs);

    /* The server's padding length; the padding itself is read on the first read (the server
     * sends it without hurry, and our request may go out meanwhile). */
    if ((rc = raw_fill(t, e, 18, 1, deadline)) != 0) goto out;
    unsigned char lb[2];
    memcpy(lb, e->rbuf, 2);
    if (va_open(&e->rd, NULL, NULL, 0, lb, 2, e->rbuf + 2) != 0) { rc = fail(TR_EVENCAUTH, "server padding length failed authentication"); goto out; }
    rb_drop(e, 18);
    e->peer_pad = ((size_t)lb[0] << 8) | lb[1];
    if (e->peer_pad < 16) { rc = fail(TR_EVENC, "server padding is shorter than the AEAD tag"); goto out; }
    e->rs = RS_PAD;
    if (e->xor2) {
        if (ctr_new(&e->out_ctr, e->united, 96, iv) != 0) { rc = TR_EIO; goto out; }
        e->have_out_ctr = 1;
        if (ctr_new(&e->in_ctr, e->united, 96, tkt) != 0) { rc = TR_EIO; goto out; }
        e->have_in_ctr = 1;
        out_mask_next(e);
    }
    rc = 0;

out:
    if (have_tmp) sc_aesctr_free(&tmpctr);
    if (have_last) sc_aesctr_free(&last);
    memset(mlk_dk, 0, sizeof mlk_dk);
    memset(xpriv, 0, sizeof xpriv);
    memset(nfs, 0, sizeof nfs);
    va_free(&nfs_a);
    free(keys);
    free(hello);
    if (rc == 0) { t->enc = e; return 0; }
    enc_free(e);
    return rc;
}

/* ---- records -------------------------------------------------------------------------------- */

int tr_venc_write(struct transport *t, const unsigned char *d, size_t n) {
    struct venc *e = t->enc;
    static __thread unsigned char obuf[5 + REC_MAX_DATA + 16];
    size_t done = 0;
    while (done < n) {
        size_t ch = n - done > REC_MAX_DATA ? REC_MAX_DATA : n - done;
        /* nonce and key are tentative: committed only after the send. */
        const int rekey = !memcmp(e->wr.nonce, MAX_NONCE, 12);
        unsigned char nn[12];
        memcpy(nn, e->wr.nonce, 12);
        nonce_inc(nn);
        unsigned char hdr[5] = { 23, 3, 3, (unsigned char)((ch + 16) >> 8), (unsigned char)(ch + 16) };
        memcpy(obuf, hdr, 5);
        memcpy(obuf + 5, d + done, ch);
        if (sc_aead_seal(&e->wr.k, nn, hdr, 5, obuf + 5, ch, obuf + 5 + ch) != 0) return TR_EVENCAUTH;
        size_t rec_n = 5 + ch + 16;
        unsigned char *send = obuf;
        size_t send_n = rec_n;
        unsigned char *big = NULL;
        if (e->prewrite) {                  /* iv ‖ relay ‖ ticket go with the first record */
            big = malloc(e->prewrite_n + rec_n);
            if (!big) return TR_EIO;
            memcpy(big, e->prewrite, e->prewrite_n);
            memcpy(big + e->prewrite_n, obuf, rec_n);
            send = big;
            send_n = e->prewrite_n + rec_n;
        }
        if (e->xor2) for (int i = 0; i < 5; i++) send[send_n - rec_n + (size_t)i] ^= e->out_mask[i];
        int rc = t->fr->write(t, send, send_n);
        if (rc) {
            free(big);
            /* send holds a masked header, but the state has not moved and obuf is rebuilt on
             * the retry, so nothing is spoiled. After a partial send (done > 0) a retry of the
             * same bytes would repeat the chunks already sent, so that is a hard failure. */
            return done ? TR_EIO : rc;
        }
        free(big);
        /* Sent: commit. */
        if (e->prewrite) { free(e->prewrite); e->prewrite = NULL; e->prewrite_n = 0; }
        memcpy(e->wr.nonce, nn, 12);
        out_mask_next(e);
        if (rekey) {
            /* A record whose nonce wrapped past the maximum is the last under this key: the
             * next key derives from the record itself (context: header ‖ ciphertext ‖ tag, the
             * header unmasked). */
            unsigned char plainrec[5 + REC_MAX_DATA + 16];
            memcpy(plainrec, obuf, rec_n);
            memcpy(plainrec, hdr, 5);
            if (va_init(&e->wr, plainrec, rec_n, e->united, 96, e->use_aes) != 0) return TR_EIO;
        }
        done += ch;
    }
    return 0;
}

/* Parse a record header: the body length, or 0 if it is not an Xray header (DecodeHeader). */
static int hdr_len(const unsigned char h[5]) {
    if (h[0] != 23 || h[1] != 3 || h[2] != 3) return 0;
    int l = (h[3] << 8) | h[4];
    return (l < REC_MIN_LEN || l > REC_MAX_LEN) ? 0 : l;
}

int tr_venc_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    struct venc *e = t->enc;
    *got = 0;
    if (!cap) return 0;
    for (;;) {
        /* 1. Decrypted data not yet returned. */
        if (e->pl_len) {
            size_t k = e->pl_len < cap ? e->pl_len : cap;
            memcpy(d, e->rbuf + e->pl_off, k);
            e->pl_off += k;
            e->pl_len -= k;
            *got = k;
            if (!e->pl_len) { rb_drop(e, e->pl_rec); e->pl_rec = 0; e->hdr_done = 0; hdr_prepare(e); }
            return 0;
        }
        /* 2. Preambles: the server's random 16 bytes (0-RTT) or its padding (1-RTT). */
        if (e->rs == RS_RAND) {
            int rc = raw_fill(t, e, 16, 0, 0);
            if (rc) return rc;
            if (e->rlen < 16) return 0;
            if (va_init(&e->rd, e->rbuf, 16, e->united, 96, e->use_aes) != 0) return TR_EIO;
            if (e->xor2) {
                if (ctr_new(&e->in_ctr, e->united, 96, e->rbuf) != 0) return TR_EIO;
                e->have_in_ctr = 1;
            }
            rb_drop(e, 16);
            e->rs = RS_REC;
            continue;
        }
        if (e->rs == RS_PAD) {
            if (!e->padbuf) { e->padbuf = malloc(e->peer_pad); e->padbuf_n = 0; if (!e->padbuf) return TR_EIO; }
            while (e->padbuf_n < e->peer_pad) {
                if (!e->rlen) {
                    int rc = raw_fill(t, e, 1, 0, 0);
                    if (rc) return rc;
                    if (!e->rlen) return 0;
                }
                size_t take = e->peer_pad - e->padbuf_n;
                if (take > e->rlen) take = e->rlen;
                memcpy(e->padbuf + e->padbuf_n, e->rbuf, take);
                e->padbuf_n += take;
                rb_drop(e, take);
            }
            if (va_open(&e->rd, NULL, NULL, 0, e->padbuf, e->peer_pad - 16, e->padbuf + e->peer_pad - 16) != 0)
                return fail(TR_EVENCAUTH, "server padding failed authentication");
            free(e->padbuf);
            e->padbuf = NULL;
            e->rs = RS_REC;
            continue;
        }
        /* 3. A record: header, body, decryption. */
        int rc = raw_fill(t, e, 5, 0, 0);
        if (rc) return rc;
        if (e->rlen < 5) return 0;
        hdr_prepare(e);
        int l = hdr_len(e->rbuf);
        if (!l) {
            if (e->first_rec && e->zero_rtt_try) {
                tk_expire(e->tk_id, e->tk_pfs);
                return fail(TR_EVENC0RTT, "0-RTT ticket rejected, next connect: full handshake");
            }
            return fail(TR_EVENC, "invalid record header");
        }
        rc = raw_fill(t, e, 5 + (size_t)l, 0, 0);
        if (rc) return rc;
        if (e->rlen < 5 + (size_t)l) return 0;
        unsigned char hdr[5];
        memcpy(hdr, e->rbuf, 5);
        const int rekey = !memcmp(e->rd.nonce, MAX_NONCE, 12);
        unsigned char nn[12];
        memcpy(nn, e->rd.nonce, 12);
        nonce_inc(nn);
        /* A record whose nonce wrapped past the maximum is the last under this key: the next key
         * derives from the record itself (header ‖ ciphertext ‖ tag, header unmasked). Copy it
         * before opening: the body is decrypted in place. */
        unsigned char *rk = NULL;
        if (rekey) {
            rk = malloc(5 + (size_t)l);
            if (!rk) return TR_EIO;
            memcpy(rk, e->rbuf, 5 + (size_t)l);
        }
        if (sc_aead_open(&e->rd.k, nn, hdr, 5, e->rbuf + 5, (size_t)l - 16, e->rbuf + 5 + l - 16) != 0) {
            free(rk);
            return fail(TR_EVENCAUTH, "cannot decrypt a record (keys out of sync)");
        }
        memcpy(e->rd.nonce, nn, 12);
        e->first_rec = 0;
        if (rk) {
            int krc = va_init(&e->rd, rk, 5 + (size_t)l, e->united, 96, e->use_aes);
            free(rk);
            if (krc != 0) return TR_EIO;
        }
        e->pl_off = 5;
        e->pl_len = (size_t)l - 16;
        e->pl_rec = 5 + (size_t)l;
        if (!e->pl_len) { rb_drop(e, e->pl_rec); e->pl_rec = 0; e->hdr_done = 0; hdr_prepare(e); continue; }
    }
}

int tr_venc_pending(const struct transport *t) {
    const struct venc *e = t->enc;
    if (!e) return 0;
    if (e->pl_len) return 1;
    /* A whole record is already in the input: no socket event will come for it. */
    if (e->rs == RS_REC && e->rlen >= 5 && e->hdr_done) {
        int l = hdr_len(e->rbuf);
        return l && e->rlen >= 5 + (size_t)l;
    }
    return 0;
}

void tr_venc_close(struct transport *t) {
    enc_free(t->enc);
    t->enc = NULL;
}
