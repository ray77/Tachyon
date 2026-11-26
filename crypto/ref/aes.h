/*
 * WhatsA500 / AmigaCrypto - AES-128/256 block encryption and AES-GCM
 * (NIST SP 800-38D). Portable reference; the Noise transport encrypts every
 * frame with AES-256-GCM, Signal messages use AES-256-CBC (decrypt needed too).
 */
#ifndef WHATSA500_AES_H
#define WHATSA500_AES_H

#include <stdint.h>
#include "x25519.h"     /* FE16_REG */

typedef struct {
    uint8_t rk[240];        /* expanded key, 16 bytes per round key */
    uint8_t dk[240];        /* equivalent-inverse-cipher round keys (asm decrypt), see aes_prepare_decrypt */
    int rounds;             /* 10 or 14 */
    int dec_ready;
} aes_key;

/* AES key with the GHASH tables for AES-GCM (Shoup, 8-bit, two bytes per step):
 * m[b] = b*H, m8[b] = b*H*x^8, rhi/rlo = reduction of the two bytes shifted out. ~10 KiB. */
typedef struct {
    aes_key k;
    uint8_t h[16];
    uint32_t m[256][4];
    uint32_t m8[256][4];
    uint32_t rhi[256];
    uint32_t rlo[256];
} aes_gcm_key;

void aes_set_key(aes_key *k, const uint8_t *key, int keybits);      /* 128 or 256 */
void aes_prepare_decrypt(aes_key *k);                                /* called lazily by decrypt */
void aes_encrypt_block(const aes_key *k, const uint8_t in[16], uint8_t out[16]);
void aes_decrypt_block(aes_key *k, const uint8_t in[16], uint8_t out[16]);
void aes_encrypt_block_c(const aes_key *k, const uint8_t in[16], uint8_t out[16]);
void aes_decrypt_block_c(const aes_key *k, const uint8_t in[16], uint8_t out[16]);
void aes_gcm_set_key(aes_gcm_key *g, const uint8_t *key, int keybits);

/* GHASH building blocks, exposed for tests: y = (y ^ x) * H */
void ghash_mul_bit(uint8_t y[16], const uint8_t x[16], const uint8_t h[16]);
void ghash_mul_tab_c(uint8_t y[16], const uint8_t x[16], const aes_gcm_key *g);
#ifdef FE16_ASM
void aes_enc_block(FE16_REG("a0") const uint8_t *rk, FE16_REG("a1") const uint8_t *in, FE16_REG("a2") uint8_t *out, FE16_REG("d0") int rounds);
void aes_dec_block(FE16_REG("a0") const uint8_t *dk, FE16_REG("a1") const uint8_t *in, FE16_REG("a2") uint8_t *out, FE16_REG("d0") int rounds);
void ghash_mul_tab(FE16_REG("a0") uint8_t *y, FE16_REG("a1") const uint8_t *x, FE16_REG("a2") const uint32_t *tab);
#endif

/* AES-GCM with a 96-bit IV. Tag is 16 bytes. Returns 1 on success, 0 on tag mismatch
 * (then no plaintext is written). in/out may alias. */
void aes_gcm_encrypt(const aes_gcm_key *g, const uint8_t iv[12],
                     const uint8_t *aad, uint32_t aadlen,
                     const uint8_t *pt, uint32_t len, uint8_t *ct, uint8_t tag[16]);
int  aes_gcm_decrypt(const aes_gcm_key *g, const uint8_t iv[12],
                     const uint8_t *aad, uint32_t aadlen,
                     const uint8_t *ct, uint32_t len, const uint8_t tag[16], uint8_t *pt);

/* AES-CBC without padding (len multiple of 16), PKCS#7 handled by the caller */
void aes_cbc_encrypt(const aes_key *k, const uint8_t iv[16], const uint8_t *in, uint32_t len, uint8_t *out);
void aes_cbc_decrypt(aes_key *k, const uint8_t iv[16], const uint8_t *in, uint32_t len, uint8_t *out);

#endif
