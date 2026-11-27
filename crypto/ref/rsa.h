/*
 * WhatsA500 / AmigaCrypto - RSA public-key operations for the TLS fallback
 * (RSA-2048 key transport, PKCS#1 v1.5 signature verification of the chain).
 * Montgomery arithmetic on 16-bit limbs (little-endian), portable C; the inner
 * product loop is the assembler candidate. Public-key only: no private keys
 * ever live on the Amiga for TLS.
 */
#ifndef WHATSA500_RSA_H
#define WHATSA500_RSA_H

#include <stdint.h>

#define RSA_MAX_LIMBS 256       /* up to 4096-bit moduli */

typedef struct {
    uint16_t n[RSA_MAX_LIMBS];
    uint16_t rr[RSA_MAX_LIMBS];     /* R^2 mod n, R = 2^(16*limbs) */
    uint16_t n0inv;                 /* -n^-1 mod 2^16 */
    uint32_t e;
    int limbs;
} rsa_pub;

/* n_be: modulus big-endian (len bytes, 128..512); returns 0 if n is even or too large */
int  rsa_pub_set(rsa_pub *k, const uint8_t *n_be, uint32_t len, uint32_t e);
/* 1 if a stored key (certificate cache) is the prepared form of (n_be, e): limbs, modulus and exponent compared,
 * n0inv recomputed, R^2 mod n checked with one Montgomery multiplication (0.45 s on the 68000 against 1.9 s for
 * rsa_pub_set). A corrupted entry is reported, not used. */
int  rsa_pub_check(const rsa_pub *k, const uint8_t *n_be, uint32_t len, uint32_t e);
/* out = in^e mod n, both big-endian with limbs*2 bytes; returns 0 if in >= n */
int  rsa_public_op(const rsa_pub *k, const uint8_t *in_be, uint8_t *out_be);
/* PKCS#1 v1.5 signature over SHA-256(msg): 1 if valid */
int  rsa_verify_pkcs1_sha256(const rsa_pub *k, const uint8_t *msg, uint32_t msglen, const uint8_t *sig, uint32_t siglen);
/* RSASSA-PSS (RFC 8017 9.1.2) over SHA-256(msg), MGF1-SHA256, salt length 32 (TLS 1.3 rsa_pss_rsae_sha256
 * CertificateVerify): 1 if valid */
int  rsa_verify_pss_sha256(const rsa_pub *k, const uint8_t *msg, uint32_t msglen, const uint8_t *sig, uint32_t siglen);
/* PKCS#1 v1.5 type-2 encryption; pad must hold limbs*2 - 3 - msglen random nonzero bytes supplied by the caller */
int  rsa_encrypt_pkcs1(const rsa_pub *k, const uint8_t *msg, uint32_t msglen, const uint8_t *pad, uint8_t *out_be);

/* Montgomery product r = a*b*R^-1 mod n (exposed for the assembler comparison) */
void rsa_mont_mul(const rsa_pub *k, const uint16_t *a, const uint16_t *b, uint16_t *r);
void rsa_mont_mul_c(const rsa_pub *k, const uint16_t *a, const uint16_t *b, uint16_t *r);
#ifdef FE16_ASM
#include "x25519.h"
int rsa_mont_mul_asm(FE16_REG("a0") const uint16_t *a, FE16_REG("a1") const uint16_t *b, FE16_REG("a2") const uint16_t *n,
                     FE16_REG("a3") uint16_t *r, FE16_REG("d0") int limbs, FE16_REG("d1") int n0inv);
int rsa_mont_sqr_asm(FE16_REG("a0") const uint16_t *a, FE16_REG("a2") const uint16_t *n,
                     FE16_REG("a3") uint16_t *r, FE16_REG("d0") int limbs, FE16_REG("d1") int n0inv);
#endif

#endif
