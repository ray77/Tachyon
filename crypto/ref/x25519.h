/*
 * WhatsA500 / AmigaCrypto - X25519 (RFC 7748)
 *
 * Portable reference implementation. Field elements of GF(2^255 - 19) are
 * stored as 16 little-endian limbs of 16 bits (radix 2^16), the natural
 * representation for the 68000's 16x16->32 MULU.W. The reference uses only
 * 32-bit arithmetic so that it is both a correctness oracle on the host and a
 * fair "plain C" baseline on the target (no emulated 64-bit arithmetic).
 *
 * Invariant: every fe16 value is < 2^256 (not necessarily < p). Values are
 * brought to canonical form only when serialised.
 */
#ifndef WHATSA500_X25519_H
#define WHATSA500_X25519_H

#include <stdint.h>

typedef uint16_t fe16[16];

/* vbcc: pass the three pointers in registers (used by the assembler backends) */
#ifdef __VBCC__
#define FE16_REG(r) __reg(r)
#else
#define FE16_REG(r)
#endif

/* field arithmetic (exposed for tests and micro-benchmarks) */
void fe16_frombytes(fe16 h, const uint8_t s[32]);
void fe16_tobytes(uint8_t s[32], const fe16 h);
void fe16_add(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f, FE16_REG("a2") const uint16_t *g);
void fe16_sub(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f, FE16_REG("a2") const uint16_t *g);
void fe16_add_c(fe16 h, const fe16 f, const fe16 g);
void fe16_sub_c(fe16 h, const fe16 f, const fe16 g);
void fe16_mul(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f, FE16_REG("a2") const uint16_t *g);
/* portable C version, always available for comparison (identical results) */
void fe16_mul_c(fe16 h, const fe16 f, const fe16 g);
#ifdef FE16_ASM
/* the two assembler multiplication variants; fe16_mul is an alias of one of them */
void fe16_mul_comba(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f, FE16_REG("a2") const uint16_t *g);
void fe16_mul_kara(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f, FE16_REG("a2") const uint16_t *g);
#endif
void fe16_sqr(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f);
void fe16_sqr_c(fe16 h, const fe16 f);
void fe16_mul121665(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f);
void fe16_mul121665_c(fe16 h, const fe16 f);
void fe16_invert(fe16 h, const fe16 f);
void fe16_cswap(fe16 f, fe16 g, uint16_t swap);

/* X25519: out = scalar * point (u-coordinate), both 32 bytes little-endian */
void x25519_ref(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
/* out = scalar * 9 (base point) */
void x25519_ref_base(uint8_t out[32], const uint8_t scalar[32]);

#endif
