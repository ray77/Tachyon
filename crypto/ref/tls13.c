#include "tls13.h"
#include "rsa.h"
#include "x25519.h"
#include "ed25519.h"        /* x25519_base_comb */

/* identifiers are prefixed (t13_, T13E_) because the Amiga unity build compiles tls12.c and tls13.c in one unit */
enum {
    T13E_NONE, T13E_ALERT, T13E_RECORD, T13E_VERSION, T13E_SUITE, T13E_HANDSHAKE, T13E_CERT_PARSE, T13E_CERT_CHAIN, T13E_RSA,
    T13E_FINISHED, T13E_DECRYPT, T13E_STATE, T13E_TOOBIG, T13E_RNG, T13E_HRR, T13E_KEYSHARE, T13E_CERTREQ, T13E_SIGALG,
    T13E_CERTVERIFY, T13E_KEYUPDATE
};

const char *tls13_errstr(int e)
{
    static const char *s[] = { "ok", "alert from server", "bad record", "server version not 1.3", "cipher suite not accepted",
        "malformed handshake", "certificate parse", "certificate chain does not verify", "rsa", "finished mismatch",
        "record decrypt", "unexpected message", "message too big", "rng", "HelloRetryRequest not supported",
        "key_share not x25519", "client certificate requested", "signature algorithm not rsa_pss_rsae_sha256",
        "CertificateVerify signature invalid", "KeyUpdate not supported" };
    return (e >= 0 && e < (int)(sizeof s / sizeof s[0])) ? s[e] : "?";
}

static int t13_fail(tls13 *t, int e) { t->error = e; t->state = TLS13_ST_ERROR; return 0; }

static void t13_put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void t13_put24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }
static uint32_t t13_get16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }
static uint32_t t13_get24(const uint8_t *p) { return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2]; }
static uint32_t t13_slen(const char *s) { uint32_t n = 0; while (s[n]) n++; return n; }
static void t13_wipe(uint8_t *p, uint32_t n) { volatile uint8_t *v = p; while (n--) *v++ = 0; }

/* ---- HKDF-SHA256 and the TLS 1.3 key schedule (RFC 8446 7.1) ------------------------ */
static void t13_hkdf_extract(uint8_t prk[32], const uint8_t *salt, uint32_t saltlen, const uint8_t *ikm, uint32_t ikmlen)
{
    uint8_t zero[32] = { 0 };
    if (salt == 0 || saltlen == 0) { salt = zero; saltlen = 32; }
    hmac_sha256(prk, salt, saltlen, ikm, ikmlen);
}

/* HKDF-Expand-Label(secret, label, context, outlen) with outlen <= 32 (one HMAC block); label without "tls13 " */
static void t13_expand_label(const uint8_t secret[32], const char *label, const uint8_t *ctx, uint32_t ctxlen,
                             uint8_t *out, uint32_t outlen)
{
    uint8_t info[2 + 1 + 6 + 16 + 1 + 32], tmp[32], one = 1;
    uint32_t p = 0, ll = t13_slen(label), i;
    hmac_sha256_ctx h;
    t13_put16(info, outlen); p = 2;
    info[p++] = (uint8_t)(6 + ll);
    info[p++] = 't'; info[p++] = 'l'; info[p++] = 's'; info[p++] = '1'; info[p++] = '3'; info[p++] = ' ';
    for (i = 0; i < ll; i++) info[p++] = (uint8_t)label[i];
    info[p++] = (uint8_t)ctxlen;
    for (i = 0; i < ctxlen; i++) info[p++] = ctx[i];
    hmac_sha256_init(&h, secret, 32);
    hmac_sha256_update(&h, info, p);
    hmac_sha256_update(&h, &one, 1);
    hmac_sha256_final(&h, tmp);
    for (i = 0; i < outlen; i++) out[i] = tmp[i];
}

/* Derive-Secret(secret, label, transcript hash) */
static void t13_derive_secret(const uint8_t secret[32], const char *label, const uint8_t th[32], uint8_t out[32])
{
    t13_expand_label(secret, label, th, 32, out, 32);
}

/* installs key and IV derived from a traffic secret on the read or write side; sequence number restarts at 0 */
static void t13_set_traffic_key(tls13 *t, int write, const uint8_t secret[32])
{
    uint8_t key[16];
    t13_expand_label(secret, "key", 0, 0, key, 16);
    if (write) {
        t13_expand_label(secret, "iv", 0, 0, t->wr_iv, 12);
        aes_gcm_set_key(&t->wr, key, 128);
        t->wr_seq_hi = t->wr_seq_lo = 0; t->wr_encrypted = 1;
    } else {
        t13_expand_label(secret, "iv", 0, 0, t->rd_iv, 12);
        aes_gcm_set_key(&t->rd, key, 128);
        t->rd_seq_hi = t->rd_seq_lo = 0; t->rd_encrypted = 1;
    }
    t13_wipe(key, 16);
}

/* transcript hash of everything hashed so far (the running context is left intact) */
static void t13_transcript_hash(const tls13 *t, uint8_t out[32])
{
    sha256_ctx h = t->transcript;
    sha256_final(&h, out);
}

/* ---- record layer (RFC 8446 5): nonce = IV xor seq, AAD = record header, inner content type ---- */
static void t13_nonce(uint8_t nonce[12], const uint8_t iv[12], uint32_t hi, uint32_t lo)
{
    uint32_t i;
    for (i = 0; i < 12; i++) nonce[i] = iv[i];
    nonce[4] ^= (uint8_t)(hi >> 24); nonce[5] ^= (uint8_t)(hi >> 16); nonce[6] ^= (uint8_t)(hi >> 8); nonce[7] ^= (uint8_t)hi;
    nonce[8] ^= (uint8_t)(lo >> 24); nonce[9] ^= (uint8_t)(lo >> 16); nonce[10] ^= (uint8_t)(lo >> 8); nonce[11] ^= (uint8_t)lo;
}

/* appends a record carrying `pt` of content type `type` to t->out, protected if the write side has keys */
static int t13_write_record(tls13 *t, uint8_t type, const uint8_t *pt, uint32_t len)
{
    uint8_t *r = t->out + t->out_len;
    uint32_t i;
    if (len > 16384) return t13_fail(t, T13E_TOOBIG);
    if (!t->wr_encrypted) {
        if (t->out_len + 5 + len > TLS13_OUT_MAX) return t13_fail(t, T13E_TOOBIG);
        r[0] = type; t13_put16(r + 1, 0x0303); t13_put16(r + 3, len);
        for (i = 0; i < len; i++) r[5 + i] = pt[i];
        t->out_len += 5 + len;
    } else {
        uint8_t nonce[12];
        if (t->out_len + 5 + len + 1 + 16 > TLS13_OUT_MAX) return t13_fail(t, T13E_TOOBIG);
        r[0] = 23; t13_put16(r + 1, 0x0303); t13_put16(r + 3, len + 1 + 16);
        for (i = 0; i < len; i++) r[5 + i] = pt[i];
        r[5 + len] = type;                                  /* TLSInnerPlaintext: content || type, no padding */
        t13_nonce(nonce, t->wr_iv, t->wr_seq_hi, t->wr_seq_lo);
        aes_gcm_encrypt(&t->wr, nonce, r, 5, r + 5, len + 1, r + 5, r + 5 + len + 1);
        t->out_len += 5 + len + 1 + 16;
        if (++t->wr_seq_lo == 0) t->wr_seq_hi++;
    }
    return 1;
}

static int t13_write_handshake(tls13 *t, uint8_t type, const uint8_t *body, uint32_t len)
{
    static uint8_t msg[512];
    uint32_t i;
    if (len + 4 > sizeof msg) return t13_fail(t, T13E_TOOBIG);
    msg[0] = type; t13_put24(msg + 1, len);
    for (i = 0; i < len; i++) msg[4 + i] = body[i];
    sha256_update(&t->transcript, msg, 4 + len);
    return t13_write_record(t, 22, msg, 4 + len);
}

/* ---- ClientHello ---------------------------------------------------------------------- */
int tls13_keypair_generate(tls13_keypair *kp, hmac_drbg *rng)
{
    if (!drbg_generate(rng, kp->priv, 32)) return 0;
    x25519_base_comb(kp->pub, kp->priv);
    return 1;
}

int tls13_client_start_kp(tls13 *t, const char *host, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                          const char *now, hmac_drbg *rng, const tls13_keypair *kp)
{
    static uint8_t ch[512];
    uint32_t p = 0, hl = t13_slen(host), ext_start, i;
    for (i = 0; i < sizeof(*t); i++) ((uint8_t *)t)[i] = 0;
    t->host = host; t->root_n = root_n; t->root_n_len = root_n_len; t->root_e = root_e; t->now = now; t->rng = rng;
    t->pins[0].n = root_n; t->pins[0].n_len = root_n_len; t->pins[0].e = root_e; t->npins = 1; t->cert_pin = -1;
    for (i = 0; i < 32; i++) { t->kp.priv[i] = kp->priv[i]; t->kp.pub[i] = kp->pub[i]; }
    if (hl > 255) return t13_fail(t, T13E_TOOBIG);
    if (!drbg_generate(rng, t->client_random, 32)) return t13_fail(t, T13E_RNG);
    sha256_init(&t->transcript);
    t13_put16(ch + p, 0x0303); p += 2;                                  /* legacy_version */
    for (i = 0; i < 32; i++) ch[p + i] = t->client_random[i]; p += 32;
    ch[p++] = 0;                                                        /* legacy_session_id: empty */
    t13_put16(ch + p, 2); p += 2; t13_put16(ch + p, 0x1301); p += 2;    /* TLS_AES_128_GCM_SHA256 */
    ch[p++] = 1; ch[p++] = 0;                                           /* legacy_compression_methods: null */
    ext_start = p; p += 2;
    /* server_name (0) */
    t13_put16(ch + p, 0); p += 2; t13_put16(ch + p, hl + 5); p += 2; t13_put16(ch + p, hl + 3); p += 2; ch[p++] = 0; t13_put16(ch + p, hl); p += 2;
    for (i = 0; i < hl; i++) ch[p + i] = (uint8_t)host[i]; p += hl;
    /* supported_groups (10): x25519 */
    t13_put16(ch + p, 10); p += 2; t13_put16(ch + p, 4); p += 2; t13_put16(ch + p, 2); p += 2; t13_put16(ch + p, 0x001d); p += 2;
    /* signature_algorithms (13): rsa_pss_rsae_sha256 (CertificateVerify), rsa_pkcs1_sha256 (chain) */
    t13_put16(ch + p, 13); p += 2; t13_put16(ch + p, 6); p += 2; t13_put16(ch + p, 4); p += 2; t13_put16(ch + p, 0x0804); p += 2; t13_put16(ch + p, 0x0401); p += 2;
    /* supported_versions (43): 1.3 only */
    t13_put16(ch + p, 43); p += 2; t13_put16(ch + p, 3); p += 2; ch[p++] = 2; t13_put16(ch + p, 0x0304); p += 2;
    /* key_share (51): one x25519 share */
    t13_put16(ch + p, 51); p += 2; t13_put16(ch + p, 38); p += 2; t13_put16(ch + p, 36); p += 2; t13_put16(ch + p, 0x001d); p += 2; t13_put16(ch + p, 32); p += 2;
    for (i = 0; i < 32; i++) ch[p + i] = t->kp.pub[i]; p += 32;
    t13_put16(ch + ext_start, p - ext_start - 2);
    t->state = TLS13_ST_WAIT_SH;
    return t13_write_handshake(t, 1, ch, p);
}

void tls13_set_cert_cache(tls13 *t, x509_cache *cache) { t->cache = cache; t->cert_cached = 0; }

int tls13_add_pin(tls13 *t, const uint8_t *n, uint32_t n_len, uint32_t e)
{
    if (t->npins >= X509_MAX_PINS) return 0;
    t->pins[t->npins].n = n; t->pins[t->npins].n_len = n_len; t->pins[t->npins].e = e; t->npins++;
    return 1;
}

int tls13_client_start(tls13 *t, const char *host, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                       const char *now, hmac_drbg *rng)
{
    tls13_keypair kp;
    int r;
    if (!tls13_keypair_generate(&kp, rng)) { t->error = T13E_RNG; t->state = TLS13_ST_ERROR; return 0; }
    r = tls13_client_start_kp(t, host, root_n, root_n_len, root_e, now, rng, &kp);
    t13_wipe(kp.priv, 32);
    return r;
}

/* ---- server flight ---------------------------------------------------------------------- */
/* SHA-256("HelloRetryRequest"): a ServerHello carrying this random is a HelloRetryRequest */
static const uint8_t t13_hrr_random[32] = {
    0xcf,0x21,0xad,0x74,0xe5,0x9a,0x61,0x11,0xbe,0x1d,0x8c,0x02,0x1e,0x65,0xb8,0x91,
    0xc2,0xa2,0x11,0x16,0x7a,0xbb,0x8c,0x5e,0x07,0x9e,0x09,0xe2,0xc8,0xa8,0x33,0x9c };

static int t13_on_server_hello(tls13 *t, const uint8_t *m, uint32_t mlen)
{
    const uint8_t *b = m + 4; uint32_t len = mlen - 4;
    uint8_t server_pub[32], shared[32], early[32], derived[32], th[32], empty_hash[32], zero[32] = { 0 };
    uint32_t p, end, i, hrr = 0, have_version = 0, have_share = 0, nz = 0;
    if (len < 2 + 32 + 1 + 2 + 1 + 2) return t13_fail(t, T13E_HANDSHAKE);
    if (t13_get16(b) != 0x0303) return t13_fail(t, T13E_VERSION);
    for (i = 0; i < 32; i++) hrr |= b[2 + i] ^ t13_hrr_random[i];
    if (hrr == 0) return t13_fail(t, T13E_HRR);
    if (b[34] != 0) return t13_fail(t, T13E_HANDSHAKE);                 /* must echo our empty legacy_session_id */
    if (t13_get16(b + 35) != 0x1301) return t13_fail(t, T13E_SUITE);
    if (b[37] != 0) return t13_fail(t, T13E_HANDSHAKE);
    p = 38; end = p + 2 + t13_get16(b + p);
    if (end != len) return t13_fail(t, T13E_HANDSHAKE);
    p += 2;
    while (p + 4 <= end) {
        uint32_t et = t13_get16(b + p), el = t13_get16(b + p + 2);
        const uint8_t *e = b + p + 4;
        if (p + 4 + el > end) return t13_fail(t, T13E_HANDSHAKE);
        if (et == 43) {                                                 /* supported_versions: selected_version */
            if (el != 2 || t13_get16(e) != 0x0304) return t13_fail(t, T13E_VERSION);
            have_version = 1;
        } else if (et == 51) {                                          /* key_share: KeyShareEntry */
            if (el != 36 || t13_get16(e) != 0x001d || t13_get16(e + 2) != 32) return t13_fail(t, T13E_KEYSHARE);
            for (i = 0; i < 32; i++) server_pub[i] = e[4 + i];
            have_share = 1;
        } else return t13_fail(t, T13E_HANDSHAKE);                     /* only pre_shared_key could appear, and we offered none */
        p += 4 + el;
    }
    if (p != end || !have_version || !have_share) return t13_fail(t, T13E_VERSION + (have_version ? T13E_KEYSHARE - T13E_VERSION : 0));

    /* ECDHE shared secret; an all-zero result (low-order point) is rejected (RFC 7748 6.1) */
    x25519_ref(shared, t->kp.priv, server_pub);
    for (i = 0; i < 32; i++) nz |= shared[i];
    if (nz == 0) return t13_fail(t, T13E_KEYSHARE);

    sha256_update(&t->transcript, m, mlen);
    t13_transcript_hash(t, th);                                         /* ClientHello..ServerHello */
    sha256(empty_hash, zero, 0);
    /* Early Secret = Extract(0, 0^32); Handshake Secret = Extract(Derive(early, "derived"), shared) */
    t13_hkdf_extract(early, 0, 0, zero, 32);
    t13_derive_secret(early, "derived", empty_hash, derived);
    t13_hkdf_extract(t->hs_secret, derived, 32, shared, 32);
    t13_derive_secret(t->hs_secret, "c hs traffic", th, t->c_hs);
    t13_derive_secret(t->hs_secret, "s hs traffic", th, t->s_hs);
    /* Master Secret = Extract(Derive(handshake, "derived"), 0^32) */
    t13_derive_secret(t->hs_secret, "derived", empty_hash, derived);
    t13_hkdf_extract(t->master_secret, derived, 32, zero, 32);
    t13_wipe(shared, 32); t13_wipe(early, 32); t13_wipe(derived, 32);
    /* the rest of the server flight is protected with the server handshake traffic key */
    t13_set_traffic_key(t, 0, t->s_hs);
    t->state = TLS13_ST_WAIT_EE;
    return 1;
}

static int t13_on_encrypted_extensions(tls13 *t, const uint8_t *m, uint32_t mlen)
{
    const uint8_t *b = m + 4; uint32_t len = mlen - 4, p = 2, end;
    if (len < 2) return t13_fail(t, T13E_HANDSHAKE);
    end = 2 + t13_get16(b);
    if (end != len) return t13_fail(t, T13E_HANDSHAKE);
    while (p + 4 <= end) {                                              /* nothing we offered needs a reply; validate the structure */
        uint32_t el = t13_get16(b + p + 2);
        if (p + 4 + el > end) return t13_fail(t, T13E_HANDSHAKE);
        p += 4 + el;
    }
    if (p != end) return t13_fail(t, T13E_HANDSHAKE);
    sha256_update(&t->transcript, m, mlen);
    t->state = TLS13_ST_WAIT_CERT;
    return 1;
}

/* Certificate (RFC 8446 4.4.2): certificate_request_context (empty for the server), then entries of
 * cert_data<1..2^24-1> extensions<0..2^16-1>. The chain is verified here, before anything else is trusted. */
static int t13_on_certificate(tls13 *t, const uint8_t *m, uint32_t mlen)
{
    const uint8_t *b = m + 4; uint32_t len = mlen - 4, p, end;
    if (len < 4 || b[0] != 0) return t13_fail(t, T13E_HANDSHAKE);
    end = 4 + t13_get24(b + 1);
    if (end != len) return t13_fail(t, T13E_HANDSHAKE);
    p = 4;
    t->chain_len = 0;
    while (p < end) {
        uint32_t cl, el;
        if (p + 3 > end) return t13_fail(t, T13E_HANDSHAKE);
        cl = t13_get24(b + p); p += 3;
        if (cl == 0 || p + cl + 2 > end) return t13_fail(t, T13E_HANDSHAKE);
        if (t->chain_len < 4) {
            if (!x509_parse(&t->chain[t->chain_len], b + p, cl)) return t13_fail(t, T13E_CERT_PARSE);
            t->chain_len++;
        }
        p += cl;
        el = t13_get16(b + p); p += 2;                                 /* per-entry extensions (status_request, SCT): skipped */
        if (p + el > end) return t13_fail(t, T13E_HANDSHAKE);
        p += el;
    }
    if (p != end || t->chain_len == 0) return t13_fail(t, T13E_CERT_PARSE);
    if (x509_cache_match(t->cache, t->pins, t->npins, t->host, t->chain[0].der, t->chain[0].len)) {
        /* this exact leaf was verified against this root for this host before: skip the RSA chain verification,
         * keep the cheap checks (clock, host name); CertificateVerify below still proves possession of the key.
         * The stored prepared key is used only if it is the presented leaf's key (one Montgomery product checks
         * R^2); a corrupted entry falls through to the full verification, which rewrites it. */
        if (!x509_valid_at(&t->chain[0], t->now) || !x509_match_host(&t->chain[0], t->host)) return t13_fail(t, T13E_CERT_CHAIN);
        if (rsa_pub_check(&t->cache->key, t->chain[0].n, t->chain[0].n_len, t->chain[0].e)) {
            t->server_key = t->cache->key;
            t->cert_cached = 1;
        }
    }
    if (!t->cert_cached) {
        if (!x509_verify_chain_pins(t->chain, t->chain_len, t->pins, t->npins, t->host, t->now, &t->cert_pin)) return t13_fail(t, T13E_CERT_CHAIN);
        if (!rsa_pub_set(&t->server_key, t->chain[0].n, t->chain[0].n_len, t->chain[0].e)) return t13_fail(t, T13E_RSA);
        if (t->cache) {
            x509_cache_store(t->cache, t->pins, t->npins, t->host, t->chain[0].der, t->chain[0].len);
            t->cache->key = t->server_key;
        }
    }
    sha256_update(&t->transcript, m, mlen);
    t->state = TLS13_ST_WAIT_CV;
    return 1;
}

/* CertificateVerify (RFC 8446 4.4.3): RSA-PSS over 64 spaces || "TLS 1.3, server CertificateVerify" || 0 || transcript hash */
static int t13_on_certificate_verify(tls13 *t, const uint8_t *m, uint32_t mlen)
{
    static const char ctx[] = "TLS 1.3, server CertificateVerify";
    const uint8_t *b = m + 4; uint32_t len = mlen - 4, siglen, i;
    uint8_t msg[64 + 33 + 1 + 32];
    if (len < 4) return t13_fail(t, T13E_HANDSHAKE);
    if (t13_get16(b) != 0x0804) return t13_fail(t, T13E_SIGALG);
    siglen = t13_get16(b + 2);
    if (4 + siglen != len) return t13_fail(t, T13E_HANDSHAKE);
    for (i = 0; i < 64; i++) msg[i] = 0x20;
    for (i = 0; i < 33; i++) msg[64 + i] = (uint8_t)ctx[i];
    msg[97] = 0;
    t13_transcript_hash(t, msg + 98);                                   /* ClientHello..Certificate */
    if (!rsa_verify_pss_sha256(&t->server_key, msg, sizeof msg, b + 4, siglen)) return t13_fail(t, T13E_CERTVERIFY);
    sha256_update(&t->transcript, m, mlen);
    t->state = TLS13_ST_WAIT_FIN;
    return 1;
}

static int t13_on_finished(tls13 *t, const uint8_t *m, uint32_t mlen)
{
    const uint8_t *b = m + 4; uint32_t len = mlen - 4, i, diff = 0;
    uint8_t fk[32], th[32], mac[32], c_ap[32], s_ap[32];
    if (len != 32) return t13_fail(t, T13E_HANDSHAKE);
    /* server verify_data = HMAC(finished_key(s hs traffic), Transcript-Hash(ClientHello..CertificateVerify)) */
    t13_expand_label(t->s_hs, "finished", 0, 0, fk, 32);
    t13_transcript_hash(t, th);
    hmac_sha256(mac, fk, 32, th, 32);
    for (i = 0; i < 32; i++) diff |= mac[i] ^ b[i];
    if (diff) { t13_wipe(fk, 32); return t13_fail(t, T13E_FINISHED); }
    sha256_update(&t->transcript, m, mlen);
    t13_transcript_hash(t, th);                                         /* ClientHello..server Finished */
    /* application traffic secrets; the server switches to its application key after its Finished */
    t13_derive_secret(t->master_secret, "c ap traffic", th, c_ap);
    t13_derive_secret(t->master_secret, "s ap traffic", th, s_ap);
    t13_set_traffic_key(t, 0, s_ap);
    /* client Finished under the client handshake traffic key, over the same transcript hash */
    t13_set_traffic_key(t, 1, t->c_hs);
    t13_expand_label(t->c_hs, "finished", 0, 0, fk, 32);
    hmac_sha256(mac, fk, 32, th, 32);
    if (!t13_write_handshake(t, 20, mac, 32)) return 0;
    t13_set_traffic_key(t, 1, c_ap);
    t13_wipe(fk, 32); t13_wipe(c_ap, 32); t13_wipe(s_ap, 32);
    t13_wipe(t->hs_secret, 32); t13_wipe(t->c_hs, 32); t13_wipe(t->s_hs, 32); t13_wipe(t->kp.priv, 32);
    t->state = TLS13_ST_CONNECTED;
    return 1;
}

static int t13_on_handshake_msg(tls13 *t, const uint8_t *m, uint32_t mlen)
{
    uint8_t type = m[0];
    if (t->state == TLS13_ST_CONNECTED) {
        if (type == 4) { t->tickets++; return 1; }                      /* NewSessionTicket: counted, no resumption yet */
        if (type == 24) return t13_fail(t, T13E_KEYUPDATE);
        return t13_fail(t, T13E_STATE);
    }
    switch (t->state) {
    case TLS13_ST_WAIT_SH:   if (type != 2) return t13_fail(t, T13E_STATE); return t13_on_server_hello(t, m, mlen);
    case TLS13_ST_WAIT_EE:   if (type != 8) return t13_fail(t, T13E_STATE); return t13_on_encrypted_extensions(t, m, mlen);
    case TLS13_ST_WAIT_CERT: if (type == 13) return t13_fail(t, T13E_CERTREQ);
                             if (type != 11) return t13_fail(t, T13E_STATE); return t13_on_certificate(t, m, mlen);
    case TLS13_ST_WAIT_CV:   if (type != 15) return t13_fail(t, T13E_STATE); return t13_on_certificate_verify(t, m, mlen);
    case TLS13_ST_WAIT_FIN:  if (type != 20) return t13_fail(t, T13E_STATE); return t13_on_finished(t, m, mlen);
    default: return t13_fail(t, T13E_STATE);
    }
}

/* one record's content after decryption (or a plaintext record before the first key) */
static int t13_on_record(tls13 *t, uint8_t type, const uint8_t *pt, uint32_t len)
{
    uint32_t i;
    if (type == 21) {                                                   /* alert: close_notify or fatal, the connection is over */
        if (len >= 2) t->alert = pt[1];
        return t13_fail(t, T13E_ALERT);
    }
    if (type == 20) return t13_fail(t, T13E_STATE);                    /* a protected change_cipher_spec is never legal */
    if (type == 22) {
        if (len == 0) return t13_fail(t, T13E_RECORD);
        if (t->hs_len + len > TLS13_HS_MAX) return t13_fail(t, T13E_TOOBIG);
        for (i = 0; i < len; i++) t->hs[t->hs_len + i] = pt[i];
        t->hs_len += len;
        for (;;) {
            uint32_t mlen;
            if (t->hs_len < 4) break;
            mlen = 4 + t13_get24(t->hs + 1);
            if (mlen > TLS13_HS_MAX) return t13_fail(t, T13E_TOOBIG);
            if (t->hs_len < mlen) break;
            if (!t13_on_handshake_msg(t, t->hs, mlen)) return 0;
            for (i = 0; i < t->hs_len - mlen; i++) t->hs[i] = t->hs[mlen + i];
            t->hs_len -= mlen;
        }
        return 1;
    }
    if (type == 23) {
        if (t->state != TLS13_ST_CONNECTED) return t13_fail(t, T13E_STATE);
        if (t->app_len + len > TLS13_APP_MAX) return t13_fail(t, T13E_TOOBIG);
        for (i = 0; i < len; i++) t->app[t->app_len + i] = pt[i];
        t->app_len += len;
        return 1;
    }
    return t13_fail(t, T13E_RECORD);
}

int tls13_input(tls13 *t, const uint8_t *data, uint32_t len)
{
    uint32_t i;
    if (t->state == TLS13_ST_ERROR) return 0;
    while (len > 0) {
        uint32_t take = len, rlen;
        if (t->in_len + take > TLS13_IN_MAX) take = TLS13_IN_MAX - t->in_len;
        if (take == 0) return t13_fail(t, T13E_TOOBIG);
        for (i = 0; i < take; i++) t->in[t->in_len + i] = data[i];
        t->in_len += take; data += take; len -= take;
        for (;;) {
            uint8_t type;
            uint32_t ver;
            if (t->in_len < 5) break;
            type = t->in[0]; ver = t13_get16(t->in + 1); rlen = t13_get16(t->in + 3);
            if (ver != 0x0303 && !(ver == 0x0301 && !t->rd_encrypted)) return t13_fail(t, T13E_RECORD);
            if (rlen > 16384 + 256) return t13_fail(t, T13E_RECORD);
            if (t->in_len < 5 + rlen) break;
            if (type == 20 || type == 21 || !t->rd_encrypted) {
                /* plaintext: the ServerHello flight before keys exist, a compatibility change_cipher_spec, an alert */
                if (type != 20 && type != 21 && type != 22) return t13_fail(t, T13E_RECORD);
                if (rlen > 16384) return t13_fail(t, T13E_RECORD);
                if (type == 20) {                                       /* middlebox-compatibility change_cipher_spec: dropped */
                    if (t->state == TLS13_ST_CONNECTED || rlen != 1 || t->in[5] != 1) return t13_fail(t, T13E_STATE);
                } else if (!t13_on_record(t, type, t->in + 5, rlen)) return 0;
            } else {
                uint8_t nonce[12], *pt = t->in + 5;
                uint32_t plen;
                if (type != 23 || rlen < 16 + 1) return t13_fail(t, T13E_RECORD);
                plen = rlen - 16;
                t13_nonce(nonce, t->rd_iv, t->rd_seq_hi, t->rd_seq_lo);
                if (!aes_gcm_decrypt(&t->rd, nonce, t->in, 5, pt, plen, pt + plen, pt)) return t13_fail(t, T13E_DECRYPT);
                if (++t->rd_seq_lo == 0) t->rd_seq_hi++;
                while (plen > 0 && pt[plen - 1] == 0) plen--;         /* strip zero padding */
                if (plen == 0) return t13_fail(t, T13E_RECORD);        /* no content type */
                plen--;
                if (!t13_on_record(t, pt[plen], pt, plen)) return 0;
            }
            for (i = 0; i < t->in_len - 5 - rlen; i++) t->in[i] = t->in[5 + rlen + i];
            t->in_len -= 5 + rlen;
        }
    }
    return 1;
}

int tls13_send(tls13 *t, const uint8_t *pt, uint32_t len)
{
    uint32_t take = len < 16384 ? len : 16384;
    if (t->state != TLS13_ST_CONNECTED) { t13_fail(t, T13E_STATE); return -1; }
    if (t->out_len + 5 + take + 1 + 16 > TLS13_OUT_MAX) return 0;
    if (!t13_write_record(t, 23, pt, take)) return -1;
    return (int)take;
}
