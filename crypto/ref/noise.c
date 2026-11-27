#include "noise.h"
#include "sha256.h"
#include "x25519.h"

static const uint8_t NOISE_PATTERN[32] = "Noise_XX_25519_AESGCM_SHA256\0\0\0\0";

static void make_iv(uint8_t iv[12], uint32_t c)
{
    int i;
    for (i = 0; i < 8; i++) iv[i] = 0;
    iv[8] = (uint8_t)(c >> 24); iv[9] = (uint8_t)(c >> 16); iv[10] = (uint8_t)(c >> 8); iv[11] = (uint8_t)c;
}

void noise_start(noise_hs *n, const uint8_t *header, uint32_t header_len)
{
    int i;
    for (i = 0; i < 32; i++) { n->h[i] = NOISE_PATTERN[i]; n->ck[i] = NOISE_PATTERN[i]; }
    aes_gcm_set_key(&n->k, n->h, 256);
    n->counter = 0;
    noise_mix_hash(n, header, header_len);
}

void noise_mix_hash(noise_hs *n, const uint8_t *data, uint32_t len)
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, n->h, 32);
    sha256_update(&c, data, len);
    sha256_final(&c, n->h);
}

static void extract_expand(const uint8_t salt[32], const uint8_t *ikm, uint32_t ikmlen, uint8_t out[64])
{
    hkdf_sha256(out, 64, salt, 32, ikm, ikmlen, (const uint8_t *)"", 0);
}

static void mix_key_dh(noise_hs *n, const uint8_t dh[32])
{
    uint8_t okm[64];
    int i;
    extract_expand(n->ck, dh, 32, okm);
    for (i = 0; i < 32; i++) n->ck[i] = okm[i];
    aes_gcm_set_key(&n->k, okm + 32, 256);
    n->counter = 0;
}

void noise_mix_key(noise_hs *n, const uint8_t priv[32], const uint8_t pub[32])
{
    uint8_t dh[32];
    x25519_ref(dh, priv, pub);
    mix_key_dh(n, dh);
}

void noise_es_precompute(noise_es_pre *p, const uint8_t client_eph_priv[32], const uint8_t server_static[32])
{
    int i;
    for (i = 0; i < 32; i++) p->server_static[i] = server_static[i];
    x25519_ref(p->dh, client_eph_priv, server_static);
    p->valid = 1;
}

void noise_encrypt(noise_hs *n, const uint8_t *pt, uint32_t len, uint8_t *ct)
{
    uint8_t iv[12];
    make_iv(iv, n->counter++);
    aes_gcm_encrypt(&n->k, iv, n->h, 32, pt, len, ct, ct + len);
    noise_mix_hash(n, ct, len + 16);
}

int noise_decrypt(noise_hs *n, const uint8_t *ct, uint32_t len, uint8_t *pt)
{
    uint8_t iv[12];
    if (len < 16) return 0;
    make_iv(iv, n->counter);
    if (!aes_gcm_decrypt(&n->k, iv, n->h, 32, ct, len - 16, ct + len - 16, pt)) return 0;
    n->counter++;
    noise_mix_hash(n, ct, len);
    return 1;
}

void noise_finish(noise_hs *n, noise_transport *t)
{
    uint8_t okm[64];
    extract_expand(n->ck, (const uint8_t *)"", 0, okm);
    aes_gcm_set_key(&t->write, okm, 256);
    aes_gcm_set_key(&t->read, okm + 32, 256);
    t->write_counter = 0;
    t->read_counter = 0;
}

void noise_transport_encrypt(noise_transport *t, const uint8_t *pt, uint32_t len, uint8_t *ct)
{
    uint8_t iv[12];
    make_iv(iv, t->write_counter++);
    aes_gcm_encrypt(&t->write, iv, (const uint8_t *)"", 0, pt, len, ct, ct + len);
}

int noise_transport_decrypt(noise_transport *t, const uint8_t *ct, uint32_t len, uint8_t *pt)
{
    uint8_t iv[12];
    if (len < 16) return 0;
    make_iv(iv, t->read_counter);
    if (!aes_gcm_decrypt(&t->read, iv, (const uint8_t *)"", 0, ct, len - 16, ct + len - 16, pt)) return 0;
    t->read_counter++;
    return 1;
}

void noise_client_hello(noise_hs *n, const uint8_t *header, uint32_t header_len, const uint8_t client_eph_pub[32])
{
    noise_start(n, header, header_len);
    noise_mix_hash(n, client_eph_pub, 32);
}

int noise_client_finish(noise_hs *n,
                        const uint8_t client_eph_priv[32], const uint8_t client_static_priv[32], const uint8_t client_static_pub[32],
                        const uint8_t server_eph_pub[32], const uint8_t *server_static_ct, uint32_t server_static_ct_len,
                        const uint8_t *cert_ct, uint32_t cert_ct_len,
                        const uint8_t *client_payload, uint32_t client_payload_len,
                        uint8_t server_static_out[32], uint8_t *cert_out,
                        uint8_t client_static_ct_out[48], uint8_t *client_payload_ct_out,
                        noise_transport *t, const noise_es_pre *pre, int *es_used)
{
    uint32_t i, diff = 0;
    if (es_used) *es_used = 0;
    if (server_static_ct_len != 48) return 0;
    noise_mix_hash(n, server_eph_pub, 32);
    noise_mix_key(n, client_eph_priv, server_eph_pub);                 /* ee */
    if (!noise_decrypt(n, server_static_ct, 48, server_static_out)) return 0;
    if (pre && pre->valid) { for (i = 0; i < 32; i++) diff |= (uint32_t)(pre->server_static[i] ^ server_static_out[i]); }
    if (pre && pre->valid && diff == 0) { mix_key_dh(n, pre->dh); if (es_used) *es_used = 1; }   /* es, computed before */
    else noise_mix_key(n, client_eph_priv, server_static_out);                                    /* es */
    if (!noise_decrypt(n, cert_ct, cert_ct_len, cert_out)) return 0;
    noise_encrypt(n, client_static_pub, 32, client_static_ct_out);     /* s */
    noise_mix_key(n, client_static_priv, server_eph_pub);              /* se */
    noise_encrypt(n, client_payload, client_payload_len, client_payload_ct_out);
    noise_finish(n, t);
    return 1;
}

/* ---- certificate cache ------------------------------------------------------------- */
static void noise_u32_be(uint8_t b[4], uint32_t v) { b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; }

void noise_cert_cache_fingerprint(uint8_t fp[32], const uint8_t root_pub[32],
                                  const uint8_t *details, uint32_t details_len, const uint8_t sig[64])
{
    sha256_ctx h; uint8_t b[4];
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)"Tachyon noise cert cache v1", 27);   /* every field length-prefixed */
    noise_u32_be(b, 32); sha256_update(&h, b, 4); sha256_update(&h, root_pub, 32);
    noise_u32_be(b, details_len); sha256_update(&h, b, 4); sha256_update(&h, details, details_len);
    noise_u32_be(b, 64); sha256_update(&h, b, 4); sha256_update(&h, sig, 64);
    sha256_final(&h, fp);
}

int noise_cert_cache_match(const noise_cert_cache *c, const uint8_t root_pub[32],
                           const uint8_t *details, uint32_t details_len, const uint8_t sig[64])
{
    uint8_t fp[32]; uint32_t i, diff = 0;
    if (!c || !c->valid) return 0;
    noise_cert_cache_fingerprint(fp, root_pub, details, details_len, sig);
    for (i = 0; i < 32; i++) diff |= fp[i] ^ c->fp[i];
    return diff == 0;
}

void noise_cert_cache_store(noise_cert_cache *c, const uint8_t root_pub[32],
                            const uint8_t *details, uint32_t details_len, const uint8_t sig[64])
{
    noise_cert_cache_fingerprint(c->fp, root_pub, details, details_len, sig);
    c->valid = 1;
}
