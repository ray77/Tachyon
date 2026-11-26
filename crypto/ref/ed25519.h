/*
 * WhatsA500 / AmigaCrypto - Ed25519 signature verification (RFC 8032) and the
 * XEdDSA-style variant used by libsignal/WhatsApp (Curve25519 public key,
 * Edwards sign bit carried in signature[63] bit 7).
 *
 * Verification handles public data only, so these routines are deliberately
 * variable-time. Field arithmetic is the shared fe16 code (x25519.h).
 */
#ifndef WHATSA500_ED25519_H
#define WHATSA500_ED25519_H

#include <stdint.h>
#include "x25519.h"

/* extended twisted Edwards coordinates: x = X/Z, y = Y/Z, T = XY/Z */
typedef struct { fe16 X, Y, Z, T; } ge_p3;

/* group operations (exposed for tests and benchmarks) */
int  ge_frombytes(ge_p3 *P, const uint8_t s[32]);       /* 1 = ok, 0 = not on curve / invalid */
void ge_tobytes(uint8_t s[32], const ge_p3 *P);
void ge_add(ge_p3 *R, const ge_p3 *P, const ge_p3 *Q);
void ge_dbl(ge_p3 *R, const ge_p3 *P);
void ge_neg(ge_p3 *R, const ge_p3 *P);
void ge_scalarmult(ge_p3 *R, const uint8_t k[32], const ge_p3 *P);     /* variable time */
void ge_scalarmult_base(ge_p3 *R, const uint8_t k[32]);                 /* variable time */
void ge_double_scalarmult(ge_p3 *R, const uint8_t a[32], const ge_p3 *A, const uint8_t b[32]); /* R = [a]A + [b]B */

/* scalar arithmetic mod L = 2^252 + 27742317777372353535851937790883648493 */
void sc_reduce(uint8_t r[32], const uint8_t x[64]);   /* r = x mod L */
int  sc_is_canonical(const uint8_t s[32]);             /* 1 if s < L */

/* 1 = valid, 0 = invalid */
int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t pk[32]);

/* libsignal ecc.VerifySignature: pk is a Curve25519 (Montgomery u) public key */
int xeddsa_verify(const uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t pk[32]);

#endif
