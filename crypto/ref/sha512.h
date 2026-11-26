/*
 * WhatsA500 / AmigaCrypto - SHA-512 (FIPS 180-4), portable reference.
 * Implemented with pairs of 32-bit words so that it needs no 64-bit runtime
 * support on the 68000 (vbcc would otherwise call vc.lib helpers).
 */
#ifndef WHATSA500_SHA512_H
#define WHATSA500_SHA512_H

#include <stdint.h>

typedef struct {
    uint32_t h[16];         /* state as hi,lo pairs: h[2i] = high word of H_i */
    uint32_t len_lo, len_hi;/* message length in bytes (64-bit) */
    uint8_t buf[128];
    unsigned buflen;
} sha512_ctx;

void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const uint8_t *data, uint32_t len);
void sha512_final(sha512_ctx *c, uint8_t out[64]);
void sha512(uint8_t out[64], const uint8_t *data, uint32_t len);

#endif
