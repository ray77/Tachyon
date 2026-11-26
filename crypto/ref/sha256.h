/*
 * WhatsA500 / AmigaCrypto - SHA-256, HMAC-SHA256, HKDF-SHA256 (FIPS 180-4,
 * RFC 2104, RFC 5869). Portable reference; the Noise handshake, Signal and the
 * WhatsApp message layer all build on these.
 */
#ifndef WHATSA500_SHA256_H
#define WHATSA500_SHA256_H

#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint32_t len_lo, len_hi;
    uint8_t buf[64];
    unsigned buflen;
} sha256_ctx;

/* compression function: C reference and (on the target) the assembler version */
void sha256_block_c(uint32_t h[8], const uint8_t *p);
#ifdef FE16_ASM
void sha256_block(__reg("a0") uint32_t *h, __reg("a1") const uint8_t *p);
#else
#define sha256_block sha256_block_c
#endif

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const uint8_t *data, uint32_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(uint8_t out[32], const uint8_t *data, uint32_t len);

typedef struct { sha256_ctx inner; uint8_t opad_key[64]; } hmac_sha256_ctx;
void hmac_sha256_init(hmac_sha256_ctx *c, const uint8_t *key, uint32_t keylen);
void hmac_sha256_update(hmac_sha256_ctx *c, const uint8_t *data, uint32_t len);
void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[32]);
void hmac_sha256(uint8_t out[32], const uint8_t *key, uint32_t keylen, const uint8_t *data, uint32_t len);

/* HKDF-Extract + Expand; out may be up to 255*32 bytes */
void hkdf_sha256(uint8_t *out, uint32_t outlen,
                 const uint8_t *salt, uint32_t saltlen,
                 const uint8_t *ikm, uint32_t ikmlen,
                 const uint8_t *info, uint32_t infolen);

#endif
