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

/* constant-time fixed-base multiplication with the 64x8 comb table (secret scalars) */
void ge_scalarmult_base_ct(ge_p3 *R, const uint8_t k[32]);
/* X25519 public key = clamp(k) * 9, via the Edwards comb and u = (Z+Y)/(Z-Y); constant time */
void x25519_base_comb(uint8_t out[32], const uint8_t scalar[32]);

/* scalar arithmetic mod L = 2^252 + 27742317777372353535851937790883648493 */
void sc_reduce(uint8_t r[32], const uint8_t x[64]);   /* r = x mod L */
int  sc_is_canonical(const uint8_t s[32]);             /* 1 if s < L */
/* s = (a * b + c) mod L; constant time (byte-limb product in 32-bit columns, then sc_reduce) */
void sc_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32], const uint8_t c[32]);

/* 1 = valid, 0 = invalid */
int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t pk[32]);

/* libsignal ecc.VerifySignature: pk is a Curve25519 (Montgomery u) public key */
int xeddsa_verify(const uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t pk[32]);

/* libsignal ecc.CalculateSignature (SignCurve25519.go `sign`, go.mau.fi/libsignal v0.2.3): Ed25519 signature
 * under the clamped Curve25519 private scalar a, A = [a]B taken as is (its sign bit goes into sig[63] bit 7,
 * the verifier rebuilds A from the Montgomery u and that bit). Nonce r = SHA-512(0xFE 0xFF*31 || a || msg ||
 * random) mod L, so `random` (64 bytes from the DRBG) only hedges; the signature is valid for any value.
 * S = r + SHA-512(R || A || msg) * a mod L. Secret-dependent steps are constant time (comb, sc_muladd).
 * Two fixed-base multiplications: ~7 s on the 68000. Verifies with xeddsa_verify under x25519_base_comb(a). */
void xeddsa_sign(uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t priv[32], const uint8_t random[64]);

#endif
