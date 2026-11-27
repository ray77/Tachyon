#include "tls12.h"
#include "rsa.h"

enum {
    E_NONE, E_ALERT, E_RECORD, E_VERSION, E_SUITE, E_HANDSHAKE, E_CERT_PARSE, E_CERT_CHAIN, E_RSA, E_FINISHED,
    E_DECRYPT, E_STATE, E_TOOBIG, E_RNG
};

const char *tls12_errstr(int e)
{
    static const char *s[] = { "ok", "alert from server", "bad record", "server version not 1.2", "cipher suite not accepted",
        "malformed handshake", "certificate parse", "certificate chain does not verify", "rsa", "finished mismatch",
        "record decrypt", "unexpected message", "message too big", "rng" };
    return (e >= 0 && e < (int)(sizeof s / sizeof s[0])) ? s[e] : "?";
}

static int fail(tls12 *t, int e) { t->error = e; t->state = TLS_ST_ERROR; return 0; }

static void put16(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }
static uint32_t get16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }
static uint32_t get24(const uint8_t *p) { return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2]; }
static uint32_t tls_slen(const char *s) { uint32_t n = 0; while (s[n]) n++; return n; }

/* ---- PRF (RFC 5246 5): P_SHA256 ----------------------------------------------- */
static void prf(const uint8_t *secret, uint32_t slen_, const char *label, const uint8_t *seed, uint32_t seedlen, uint8_t *out, uint32_t outlen)
{
    uint8_t a[32], tmp[32];
    hmac_sha256_ctx h;
    uint32_t llen = tls_slen(label), i;
    hmac_sha256_init(&h, secret, slen_);
    hmac_sha256_update(&h, (const uint8_t *)label, llen);
    hmac_sha256_update(&h, seed, seedlen);
    hmac_sha256_final(&h, a);                       /* A(1) */
    while (outlen > 0) {
        uint32_t take = outlen < 32 ? outlen : 32;
        hmac_sha256_init(&h, secret, slen_);
        hmac_sha256_update(&h, a, 32);
        hmac_sha256_update(&h, (const uint8_t *)label, llen);
        hmac_sha256_update(&h, seed, seedlen);
        hmac_sha256_final(&h, tmp);
        for (i = 0; i < take; i++) out[i] = tmp[i];
        out += take; outlen -= take;
        hmac_sha256(a, secret, slen_, a, 32);        /* A(i+1) */
    }
}

/* ---- record layer -------------------------------------------------------------- */
static void seq_bytes(uint8_t s[8], uint32_t hi, uint32_t lo)
{
    s[0] = (uint8_t)(hi >> 24); s[1] = (uint8_t)(hi >> 16); s[2] = (uint8_t)(hi >> 8); s[3] = (uint8_t)hi;
    s[4] = (uint8_t)(lo >> 24); s[5] = (uint8_t)(lo >> 16); s[6] = (uint8_t)(lo >> 8); s[7] = (uint8_t)lo;
}

/* appends a record of `type` with plaintext `pt` to t->out, encrypting if the write side is active */
static int write_record(tls12 *t, uint8_t type, const uint8_t *pt, uint32_t len)
{
    uint8_t *r = t->out + t->out_len;
    uint32_t i;
    if (!t->wr_encrypted) {
        if (t->out_len + 5 + len > TLS_OUT_MAX) return fail(t, E_TOOBIG);
        r[0] = type; put16(r + 1, 0x0303); put16(r + 3, len);
        for (i = 0; i < len; i++) r[5 + i] = pt[i];
        t->out_len += 5 + len;
    } else {
        uint8_t nonce[12], ad[13];
        if (t->out_len + 5 + 8 + len + 16 > TLS_OUT_MAX) return fail(t, E_TOOBIG);
        r[0] = type; put16(r + 1, 0x0303); put16(r + 3, 8 + len + 16);
        seq_bytes(r + 5, t->wr_seq_hi, t->wr_seq_lo);              /* explicit nonce = sequence number */
        for (i = 0; i < 4; i++) nonce[i] = t->wr_iv[i];
        for (i = 0; i < 8; i++) nonce[4 + i] = r[5 + i];
        seq_bytes(ad, t->wr_seq_hi, t->wr_seq_lo);
        ad[8] = type; put16(ad + 9, 0x0303); put16(ad + 11, len);
        aes_gcm_encrypt(&t->wr, nonce, ad, 13, pt, len, r + 13, r + 13 + len);
        t->out_len += 5 + 8 + len + 16;
        if (++t->wr_seq_lo == 0) t->wr_seq_hi++;
    }
    return 1;
}

static int write_handshake(tls12 *t, uint8_t type, const uint8_t *body, uint32_t len)
{
    uint8_t hdr[4];
    static uint8_t msg[TLS_HS_MAX];
    uint32_t i;
    if (len + 4 > TLS_HS_MAX) return fail(t, E_TOOBIG);
    hdr[0] = type; put24(hdr + 1, len);
    for (i = 0; i < 4; i++) msg[i] = hdr[i];
    for (i = 0; i < len; i++) msg[4 + i] = body[i];
    sha256_update(&t->transcript, msg, 4 + len);
    return write_record(t, 22, msg, 4 + len);
}

/* ---- ClientHello ---------------------------------------------------------------- */
int tls12_client_start(tls12 *t, const char *host, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                       const char *now, hmac_drbg *rng)
{
    static uint8_t ch[512];
    uint32_t p = 0, hl = tls_slen(host), ext_start;
    uint32_t i;
    for (i = 0; i < sizeof(*t); i++) ((uint8_t *)t)[i] = 0;
    t->host = host; t->root_n = root_n; t->root_n_len = root_n_len; t->root_e = root_e; t->now = now; t->rng = rng;
    if (hl > 255) return fail(t, E_TOOBIG);
    if (!drbg_generate(rng, t->client_random, 32)) return fail(t, E_RNG);
    sha256_init(&t->transcript);
    put16(ch + p, 0x0303); p += 2;
    for (i = 0; i < 32; i++) ch[p + i] = t->client_random[i]; p += 32;
    ch[p++] = 0;                                    /* session id: none */
    put16(ch + p, 2); p += 2; put16(ch + p, 0x009c); p += 2;    /* TLS_RSA_WITH_AES_128_GCM_SHA256 */
    ch[p++] = 1; ch[p++] = 0;                       /* compression: null */
    ext_start = p; p += 2;
    /* server_name */
    put16(ch + p, 0); p += 2; put16(ch + p, hl + 5); p += 2; put16(ch + p, hl + 3); p += 2; ch[p++] = 0; put16(ch + p, hl); p += 2;
    for (i = 0; i < hl; i++) ch[p + i] = (uint8_t)host[i]; p += hl;
    /* signature_algorithms: rsa_pkcs1_sha256 */
    put16(ch + p, 13); p += 2; put16(ch + p, 4); p += 2; put16(ch + p, 2); p += 2; put16(ch + p, 0x0401); p += 2;
    /* renegotiation_info (empty) - some servers insist */
    put16(ch + p, 0xff01); p += 2; put16(ch + p, 1); p += 2; ch[p++] = 0;
    /* extended_master_secret (RFC 7627): binds the master secret to the handshake transcript; used when echoed */
    put16(ch + p, 0x0017); p += 2; put16(ch + p, 0); p += 2;
    put16(ch + ext_start, p - ext_start - 2);
    t->state = TLS_ST_WAIT_SH;
    return write_handshake(t, 1, ch, p);
}

/* ---- server flight ------------------------------------------------------------------ */
static int on_server_hello(tls12 *t, const uint8_t *b, uint32_t len)
{
    uint32_t sid, i;
    if (len < 2 + 32 + 1) return fail(t, E_HANDSHAKE);
    if (get16(b) != 0x0303) return fail(t, E_VERSION);
    for (i = 0; i < 32; i++) t->server_random[i] = b[2 + i];
    sid = b[34];
    if (sid > 32 || len < 35 + sid + 3) return fail(t, E_HANDSHAKE);
    if (get16(b + 35 + sid) != 0x009c) return fail(t, E_SUITE);
    if (b[37 + sid] != 0) return fail(t, E_SUITE);
    /* extensions: only extended_master_secret changes anything for this suite */
    t->ems = 0;
    if (len > 38 + sid + 2) {
        uint32_t p = 38 + sid, end = p + 2 + get16(b + p);
        if (end > len) return fail(t, E_HANDSHAKE);
        p += 2;
        while (p + 4 <= end) {
            uint32_t et = get16(b + p), el = get16(b + p + 2);
            if (p + 4 + el > end) return fail(t, E_HANDSHAKE);
            if (et == 0x0017 && el == 0) t->ems = 1;
            p += 4 + el;
        }
    }
    t->state = TLS_ST_WAIT_CERT;
    return 1;
}

static int on_certificate(tls12 *t, const uint8_t *b, uint32_t len)
{
    uint32_t total, p = 3;
    if (len < 3) return fail(t, E_HANDSHAKE);
    total = get24(b);
    if (total + 3 != len) return fail(t, E_HANDSHAKE);
    t->chain_len = 0;
    while (p < len) {
        uint32_t cl;
        if (p + 3 > len) return fail(t, E_HANDSHAKE);
        cl = get24(b + p); p += 3;
        if (p + cl > len) return fail(t, E_HANDSHAKE);
        if (t->chain_len < 3) {
            if (!x509_parse(&t->chain[t->chain_len], b + p, cl)) return fail(t, E_CERT_PARSE);
            t->chain_len++;
        }
        p += cl;
    }
    if (t->chain_len == 0) return fail(t, E_CERT_PARSE);
    /* self-signed single certificate (test server): the pinned key is the certificate's own key */
    if (!x509_verify_chain(t->chain, t->chain_len, t->root_n, t->root_n_len, t->root_e, t->host, t->now)) return fail(t, E_CERT_CHAIN);
    if (!rsa_pub_set(&t->server_key, t->chain[0].n, t->chain[0].n_len, t->chain[0].e)) return fail(t, E_RSA);
    t->state = TLS_ST_WAIT_SHD;
    return 1;
}

static int on_server_hello_done(tls12 *t, const uint8_t *b, uint32_t len)
{
    static uint8_t pre[48], pad[512], cke[2 + 512], seed[64], fin[12];
    uint32_t klen = (uint32_t)t->server_key.limbs * 2, i;
    uint8_t keyblock[40], hash[32];
    sha256_ctx h;
    if (len != 0 || b == 0) return fail(t, E_HANDSHAKE);
    /* premaster = version || 46 random; PKCS#1 v1.5 type 2 with nonzero random padding */
    pre[0] = 3; pre[1] = 3;
    if (!drbg_generate(t->rng, pre + 2, 46)) return fail(t, E_RNG);
    if (!drbg_generate(t->rng, pad, klen)) return fail(t, E_RNG);
    for (i = 0; i < klen; i++) if (pad[i] == 0) pad[i] = 0x5a;
    put16(cke, klen);
    if (!rsa_encrypt_pkcs1(&t->server_key, pre, 48, pad, cke + 2)) return fail(t, E_RSA);
    if (!write_handshake(t, 16, cke, 2 + klen)) return 0;
    /* master secret and keys; with EMS the seed is the session hash (transcript through ClientKeyExchange) */
    if (t->ems) {
        h = t->transcript; sha256_final(&h, hash);
        prf(pre, 48, "extended master secret", hash, 32, t->master, 48);
    } else {
        for (i = 0; i < 32; i++) { seed[i] = t->client_random[i]; seed[32 + i] = t->server_random[i]; }
        prf(pre, 48, "master secret", seed, 64, t->master, 48);
    }
    for (i = 0; i < 48; i++) pre[i] = 0;
    for (i = 0; i < 32; i++) { seed[i] = t->server_random[i]; seed[32 + i] = t->client_random[i]; }
    prf(t->master, 48, "key expansion", seed, 64, keyblock, 40);
    for (i = 0; i < 16; i++) { t->wr_key[i] = keyblock[i]; t->rd_key[i] = keyblock[16 + i]; }
    for (i = 0; i < 4; i++) { t->wr_iv[i] = keyblock[32 + i]; t->rd_iv[i] = keyblock[36 + i]; }
    aes_gcm_set_key(&t->wr, t->wr_key, 128);
    aes_gcm_set_key(&t->rd, t->rd_key, 128);
    /* ChangeCipherSpec, then Finished under the new keys */
    { uint8_t ccs = 1; if (!write_record(t, 20, &ccs, 1)) return 0; }
    t->wr_encrypted = 1; t->wr_seq_hi = t->wr_seq_lo = 0;
    h = t->transcript; sha256_final(&h, hash);
    prf(t->master, 48, "client finished", hash, 32, fin, 12);
    if (!write_handshake(t, 20, fin, 12)) return 0;
    t->state = TLS_ST_WAIT_CCS;
    return 1;
}

static int on_finished(tls12 *t, const uint8_t *b, uint32_t len)
{
    uint8_t hash[32], fin[12];
    sha256_ctx h;
    uint32_t i, diff = 0;
    if (len != 12) return fail(t, E_HANDSHAKE);
    h = t->transcript; sha256_final(&h, hash);          /* transcript here already includes our Finished */
    prf(t->master, 48, "server finished", hash, 32, fin, 12);
    for (i = 0; i < 12; i++) diff |= fin[i] ^ b[i];
    if (diff) return fail(t, E_FINISHED);
    t->state = TLS_ST_CONNECTED;
    return 1;
}

static int on_handshake_msg(tls12 *t, const uint8_t *m, uint32_t mlen)
{
    uint8_t type = m[0];
    const uint8_t *body = m + 4; uint32_t blen = mlen - 4;
    int r;
    if (type == 0) return 1;                             /* HelloRequest: ignore */
    if (type == 4) return 1;                             /* NewSessionTicket (not stored yet); not part of the Finished hash? it is - but only after Finished */
    switch (t->state) {
    case TLS_ST_WAIT_SH:   if (type != 2) return fail(t, E_STATE); r = on_server_hello(t, body, blen); break;
    case TLS_ST_WAIT_CERT: if (type != 11) return fail(t, E_STATE); r = on_certificate(t, body, blen); break;
    case TLS_ST_WAIT_SHD:  if (type != 14) return fail(t, E_STATE); sha256_update(&t->transcript, m, mlen); return on_server_hello_done(t, body, blen);
    case TLS_ST_WAIT_FIN:  if (type != 20) return fail(t, E_STATE); return on_finished(t, body, blen);
    default: return fail(t, E_STATE);
    }
    if (r) sha256_update(&t->transcript, m, mlen);
    return r;
}

static int on_record(tls12 *t, uint8_t type, const uint8_t *pt, uint32_t len)
{
    uint32_t i;
    if (type == 21) return fail(t, E_ALERT);
    if (type == 20) {
        if (t->state != TLS_ST_WAIT_CCS || len != 1 || pt[0] != 1) return fail(t, E_STATE);
        t->rd_encrypted = 1; t->rd_seq_hi = t->rd_seq_lo = 0;
        t->state = TLS_ST_WAIT_FIN;
        return 1;
    }
    if (type == 22) {
        if (t->hs_len + len > TLS_HS_MAX) return fail(t, E_TOOBIG);
        for (i = 0; i < len; i++) t->hs[t->hs_len + i] = pt[i];
        t->hs_len += len;
        for (;;) {
            uint32_t mlen;
            if (t->hs_len < 4) break;
            mlen = 4 + get24(t->hs + 1);
            if (mlen > TLS_HS_MAX) return fail(t, E_TOOBIG);
            if (t->hs_len < mlen) break;
            if (!on_handshake_msg(t, t->hs, mlen)) return 0;
            for (i = 0; i < t->hs_len - mlen; i++) t->hs[i] = t->hs[mlen + i];
            t->hs_len -= mlen;
            if (t->state == TLS_ST_WAIT_SHD && t->hs_len) { /* certificate chain pointers live in hs: must be consumed before more arrives */ }
        }
        return 1;
    }
    if (type == 23) {
        if (t->state != TLS_ST_CONNECTED) return fail(t, E_STATE);
        if (t->app_len + len > TLS_IN_MAX) return fail(t, E_TOOBIG);
        for (i = 0; i < len; i++) t->app[t->app_len + i] = pt[i];
        t->app_len += len;
        return 1;
    }
    return fail(t, E_RECORD);
}

int tls12_input(tls12 *t, const uint8_t *data, uint32_t len)
{
    uint32_t i;
    if (t->state == TLS_ST_ERROR) return 0;
    while (len > 0) {
        uint32_t take = len, rlen;
        if (t->in_len + take > TLS_IN_MAX) take = TLS_IN_MAX - t->in_len;
        if (take == 0) return fail(t, E_TOOBIG);
        for (i = 0; i < take; i++) t->in[t->in_len + i] = data[i];
        t->in_len += take; data += take; len -= take;
        for (;;) {
            uint8_t type;
            if (t->in_len < 5) break;
            type = t->in[0];
            if (get16(t->in + 1) != 0x0303 && !(type == 22 && get16(t->in + 1) == 0x0301 && t->state == TLS_ST_WAIT_SH)) return fail(t, E_RECORD);
            rlen = get16(t->in + 3);
            if (rlen > 16384 + 2048) return fail(t, E_RECORD);
            if (t->in_len < 5 + rlen) break;
            if (!t->rd_encrypted) {
                if (!on_record(t, type, t->in + 5, rlen)) return 0;
            } else {
                static uint8_t pt[TLS_IN_MAX];
                uint8_t nonce[12], ad[13];
                uint32_t plen;
                if (rlen < 8 + 16) return fail(t, E_RECORD);
                plen = rlen - 8 - 16;
                for (i = 0; i < 4; i++) nonce[i] = t->rd_iv[i];
                for (i = 0; i < 8; i++) nonce[4 + i] = t->in[5 + i];
                seq_bytes(ad, t->rd_seq_hi, t->rd_seq_lo);
                ad[8] = type; put16(ad + 9, 0x0303); put16(ad + 11, plen);
                if (!aes_gcm_decrypt(&t->rd, nonce, ad, 13, t->in + 13, plen, t->in + 13 + plen, pt)) return fail(t, E_DECRYPT);
                if (++t->rd_seq_lo == 0) t->rd_seq_hi++;
                if (!on_record(t, type, pt, plen)) return 0;
            }
            for (i = 0; i < t->in_len - 5 - rlen; i++) t->in[i] = t->in[5 + rlen + i];
            t->in_len -= 5 + rlen;
        }
    }
    return 1;
}

int tls12_send(tls12 *t, const uint8_t *pt, uint32_t len)
{
    uint32_t take = len < 16384 ? len : 16384;
    if (t->state != TLS_ST_CONNECTED) { fail(t, E_STATE); return -1; }
    if (t->out_len + 5 + 8 + take + 16 > TLS_OUT_MAX) return 0;
    if (!write_record(t, 23, pt, take)) return -1;
    return (int)take;
}
