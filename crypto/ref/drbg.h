/*
 * WhatsA500 / AmigaCrypto - HMAC_DRBG (NIST SP 800-90A, HMAC-SHA-256) with a
 * simple entropy accumulator. Deterministic given its inputs; all randomness
 * comes from what the collector feeds in (docs/RNG.md). No reseed counter
 * limits are enforced here beyond the spec's 2^48 requests, which an A500
 * will not reach.
 */
#ifndef WHATSA500_DRBG_H
#define WHATSA500_DRBG_H

#include <stdint.h>

typedef struct {
    uint8_t k[32];
    uint8_t v[32];
    uint32_t reseed_counter;
    int instantiated;
} hmac_drbg;

/* seed_material = entropy || nonce || personalization (caller concatenates) */
void drbg_instantiate(hmac_drbg *d, const uint8_t *seed, uint32_t len);
void drbg_reseed(hmac_drbg *d, const uint8_t *seed, uint32_t len);
/* Generate without additional input; returns 0 if not instantiated */
int  drbg_generate(hmac_drbg *d, uint8_t *out, uint32_t len);

/* Entropy accumulator: SHA-256 chained pool. rng_add mixes raw samples (timestamps,
 * event data) into the pool; rng_seed_drbg instantiates/reseeds the DRBG from it. */
typedef struct {
    uint8_t pool[32];
    uint32_t samples;
} rng_pool;

void rng_pool_init(rng_pool *p);
void rng_add(rng_pool *p, const uint8_t *data, uint32_t len);
void rng_seed_drbg(rng_pool *p, hmac_drbg *d);

#endif
