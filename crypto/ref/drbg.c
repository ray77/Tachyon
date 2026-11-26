#include "drbg.h"
#include "sha256.h"

/* HMAC(K, V || provided) over up to one provided block, as in SP 800-90A 10.1.2.2 */
static void hmac_kv(const uint8_t k[32], const uint8_t v[32], uint8_t sep, int with_sep,
                    const uint8_t *data, uint32_t len, uint8_t out[32])
{
    hmac_sha256_ctx h;
    hmac_sha256_init(&h, k, 32);
    hmac_sha256_update(&h, v, 32);
    if (with_sep) hmac_sha256_update(&h, &sep, 1);
    if (len) hmac_sha256_update(&h, data, len);
    hmac_sha256_final(&h, out);
}

static void drbg_update(hmac_drbg *d, const uint8_t *data, uint32_t len)
{
    uint8_t t[32];
    int i;
    hmac_kv(d->k, d->v, 0x00, 1, data, len, t);
    for (i = 0; i < 32; i++) d->k[i] = t[i];
    hmac_kv(d->k, d->v, 0, 0, 0, 0, t);
    for (i = 0; i < 32; i++) d->v[i] = t[i];
    if (len) {
        hmac_kv(d->k, d->v, 0x01, 1, data, len, t);
        for (i = 0; i < 32; i++) d->k[i] = t[i];
        hmac_kv(d->k, d->v, 0, 0, 0, 0, t);
        for (i = 0; i < 32; i++) d->v[i] = t[i];
    }
}

void drbg_instantiate(hmac_drbg *d, const uint8_t *seed, uint32_t len)
{
    int i;
    for (i = 0; i < 32; i++) { d->k[i] = 0x00; d->v[i] = 0x01; }
    drbg_update(d, seed, len);
    d->reseed_counter = 1;
    d->instantiated = 1;
}

void drbg_reseed(hmac_drbg *d, const uint8_t *seed, uint32_t len)
{
    drbg_update(d, seed, len);
    d->reseed_counter = 1;
}

int drbg_generate(hmac_drbg *d, uint8_t *out, uint32_t len)
{
    uint8_t t[32];
    int i;
    if (!d->instantiated) return 0;
    while (len > 0) {
        uint32_t take = len < 32 ? len : 32;
        hmac_kv(d->k, d->v, 0, 0, 0, 0, t);
        for (i = 0; i < 32; i++) d->v[i] = t[i];
        for (i = 0; i < (int)take; i++) out[i] = t[i];
        out += take; len -= take;
    }
    drbg_update(d, 0, 0);
    d->reseed_counter++;
    return 1;
}

void rng_pool_init(rng_pool *p)
{
    int i;
    for (i = 0; i < 32; i++) p->pool[i] = 0;
    p->samples = 0;
}

void rng_add(rng_pool *p, const uint8_t *data, uint32_t len)
{
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, p->pool, 32);
    sha256_update(&c, data, len);
    sha256_final(&c, p->pool);
    p->samples++;
}

void rng_seed_drbg(rng_pool *p, hmac_drbg *d)
{
    uint8_t seed[36];
    int i;
    for (i = 0; i < 32; i++) seed[i] = p->pool[i];
    seed[32] = (uint8_t)(p->samples >> 24); seed[33] = (uint8_t)(p->samples >> 16);
    seed[34] = (uint8_t)(p->samples >> 8); seed[35] = (uint8_t)p->samples;
    if (d->instantiated) drbg_reseed(d, seed, 36); else drbg_instantiate(d, seed, 36);
    /* the pool keeps evolving; what was handed out is no longer recoverable from it */
    rng_add(p, seed + 32, 4);
}
