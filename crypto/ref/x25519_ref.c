/*
 * WhatsA500 / AmigaCrypto - X25519 reference, radix 2^16, 32-bit arithmetic only.
 * See x25519.h for the representation and invariants.
 *
 * Constant-time: no secret-dependent branches or memory indices. Note that on a
 * real 68000 MULU.W itself has operand-dependent timing (README); this
 * reference does not try to hide that - the optimised backends must.
 */
#include "x25519.h"

/* p = 2^255 - 19 as 16-bit limbs */
static const uint16_t P[16] = {
    0xFFED, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF,
    0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0x7FFF
};

/* h += 38*c, propagating the carry through all limbs; returns the carry out (0/1
 * for the inputs this file produces). Applied twice after every operation so
 * the result is again < 2^256. */
static uint32_t fe16_fold(fe16 h, uint32_t c)
{
    int i;
    c *= 38;
    for (i = 0; i < 16; i++) {
        c += h[i];
        h[i] = (uint16_t)c;
        c >>= 16;
    }
    return c;
}

void fe16_frombytes(fe16 h, const uint8_t s[32])
{
    int i;
    for (i = 0; i < 16; i++)
        h[i] = (uint16_t)(s[2 * i] | ((uint16_t)s[2 * i + 1] << 8));
    h[15] &= 0x7FFF;            /* RFC 7748: ignore the most significant bit */
}

/* canonical reduction: h < 2^256 = 2p + 38, so at most two subtractions of p */
static void fe16_canon(fe16 h)
{
    int rep, i;
    for (rep = 0; rep < 2; rep++) {
        uint16_t t[16];
        uint32_t b = 0;
        uint16_t keep;
        for (i = 0; i < 16; i++) {
            uint32_t d = (uint32_t)h[i] - P[i] - b;
            t[i] = (uint16_t)d;
            b = d >> 31;        /* borrow */
        }
        keep = (uint16_t)(b - 1);       /* 0xFFFF if h >= p (no borrow), else 0 */
        for (i = 0; i < 16; i++)
            h[i] = (uint16_t)((h[i] & ~keep) | (t[i] & keep));
    }
}

void fe16_tobytes(uint8_t s[32], const fe16 h)
{
    fe16 t;
    int i;
    for (i = 0; i < 16; i++)
        t[i] = h[i];
    fe16_canon(t);
    for (i = 0; i < 16; i++) {
        s[2 * i] = (uint8_t)t[i];
        s[2 * i + 1] = (uint8_t)(t[i] >> 8);
    }
}

void fe16_add_c(fe16 h, const fe16 f, const fe16 g)
{
    uint32_t c = 0;
    int i;
    for (i = 0; i < 16; i++) {
        c += (uint32_t)f[i] + g[i];
        h[i] = (uint16_t)c;
        c >>= 16;
    }
    c = fe16_fold(h, c);
    fe16_fold(h, c);
}

/* h = f - g + 4p  (4p = 2^257 - 76, so the sum is always positive and < 2^259),
 * then folded back below 2^256. The subtraction runs first so that h may alias
 * f or g (all fe16 operations are alias-safe for every argument combination). */
void fe16_sub_c(fe16 h, const fe16 f, const fe16 g)
{
    uint32_t c = 0, b = 0, hi;
    int i;
    /* f - g with borrow chain */
    for (i = 0; i < 16; i++) {
        uint32_t d = (uint32_t)f[i] - g[i] - b;
        h[i] = (uint16_t)d;
        b = d >> 31;
    }
    /* + (2^256 - 76): limb 0 adds 0xFFB4, limbs 1..15 add 0xFFFF */
    for (i = 0; i < 16; i++) {
        c += (uint32_t)h[i] + (i == 0 ? 0xFFB4u : 0xFFFFu);
        h[i] = (uint16_t)c;
        c >>= 16;
    }
    hi = c + 1 - b;             /* multiples of 2^256 still to fold in: 0, 1 or 2 */
    hi = fe16_fold(h, hi);
    fe16_fold(h, hi);
}

void fe16_mul_c(fe16 h, const fe16 f, const fe16 g)
{
    uint16_t r[32];
    uint32_t lo = 0, hi = 0;    /* 64-bit column accumulator as two 32-bit halves */
    uint32_t c;
    int i, k;

    for (k = 0; k < 31; k++) {
        int first = k < 16 ? 0 : k - 15;
        int last = k < 16 ? k : 15;
        for (i = first; i <= last; i++) {
            uint32_t p = (uint32_t)f[i] * g[k - i];
            lo += p;
            hi += (lo < p);
        }
        r[k] = (uint16_t)lo;
        lo = (lo >> 16) | (hi << 16);
        hi >>= 16;
    }
    r[31] = (uint16_t)lo;       /* product < 2^512, so nothing is lost here */

    /* 2^256 = 38 (mod p): h = r_lo + 38 * r_hi */
    c = 0;
    for (i = 0; i < 16; i++) {
        c += (uint32_t)r[i] + (uint32_t)r[i + 16] * 38u;
        h[i] = (uint16_t)c;
        c >>= 16;
    }
    c = fe16_fold(h, c);        /* c < 39 */
    fe16_fold(h, c);
}

void fe16_sqr_c(fe16 h, const fe16 f)
{
    fe16_mul_c(h, f, f);
}

#ifndef FE16_ASM
/* no assembler backend (host build): the C versions are the implementation */
void fe16_mul(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f, FE16_REG("a2") const uint16_t *g)
{
    fe16_mul_c(h, f, g);
}

void fe16_sqr(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f)
{
    fe16_mul_c(h, f, f);
}

void fe16_add(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f, FE16_REG("a2") const uint16_t *g)
{
    fe16_add_c(h, f, g);
}

void fe16_sub(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f, FE16_REG("a2") const uint16_t *g)
{
    fe16_sub_c(h, f, g);
}

void fe16_mul121665(FE16_REG("a0") uint16_t *h, FE16_REG("a1") const uint16_t *f)
{
    fe16_mul121665_c(h, f);
}
#endif

/* h = 121665 * f;  121665 = 2^16 + 56129, so the 2^16 part just shifts a limb up */
void fe16_mul121665_c(fe16 h, const fe16 f)
{
    uint32_t c = 0;
    int i;
    for (i = 0; i < 16; i++) {
        uint32_t t = (uint32_t)f[i] * 56129u + c;
        h[i] = (uint16_t)t;
        c = (t >> 16) + f[i];
    }
    c = fe16_fold(h, c);        /* c < 2^17 */
    fe16_fold(h, c);
}

void fe16_cswap(fe16 f, fe16 g, uint16_t swap)
{
    uint16_t mask = (uint16_t)(0 - swap);
    int i;
    for (i = 0; i < 16; i++) {
        uint16_t t = (uint16_t)(mask & (f[i] ^ g[i]));
        f[i] ^= t;
        g[i] ^= t;
    }
}

static void fe16_sqr_n(fe16 h, const fe16 f, int n)
{
    fe16_sqr(h, f);
    while (--n > 0)
        fe16_sqr(h, h);
}

/* h = f^(p-2) = f^-1, 254 squarings + 11 multiplications */
void fe16_invert(fe16 h, const fe16 z)
{
    fe16 z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t0, t1;

    fe16_sqr(z2, z);                    /* 2 */
    fe16_sqr_n(t1, z2, 2);              /* 8 */
    fe16_mul(z9, t1, z);                /* 9 */
    fe16_mul(z11, z9, z2);              /* 11 */
    fe16_sqr(t0, z11);                  /* 22 */
    fe16_mul(z2_5_0, t0, z9);           /* 2^5 - 1 */
    fe16_sqr_n(t0, z2_5_0, 5);          /* 2^10 - 2^5 */
    fe16_mul(z2_10_0, t0, z2_5_0);      /* 2^10 - 1 */
    fe16_sqr_n(t0, z2_10_0, 10);        /* 2^20 - 2^10 */
    fe16_mul(z2_20_0, t0, z2_10_0);     /* 2^20 - 1 */
    fe16_sqr_n(t0, z2_20_0, 20);        /* 2^40 - 2^20 */
    fe16_mul(t0, t0, z2_20_0);          /* 2^40 - 1 */
    fe16_sqr_n(t0, t0, 10);             /* 2^50 - 2^10 */
    fe16_mul(z2_50_0, t0, z2_10_0);     /* 2^50 - 1 */
    fe16_sqr_n(t0, z2_50_0, 50);        /* 2^100 - 2^50 */
    fe16_mul(z2_100_0, t0, z2_50_0);    /* 2^100 - 1 */
    fe16_sqr_n(t0, z2_100_0, 100);      /* 2^200 - 2^100 */
    fe16_mul(t0, t0, z2_100_0);         /* 2^200 - 1 */
    fe16_sqr_n(t0, t0, 50);             /* 2^250 - 2^50 */
    fe16_mul(t0, t0, z2_50_0);          /* 2^250 - 1 */
    fe16_sqr_n(t0, t0, 5);              /* 2^255 - 2^5 */
    fe16_mul(h, t0, z11);               /* 2^255 - 21 = p - 2 */
}

void x25519_ref(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
    uint8_t k[32];
    fe16 x1, x2, z2, x3, z3, a, aa, b, bb, e, c, d, da, cb, t;
    uint16_t swap = 0;
    int i, bit;

    for (i = 0; i < 32; i++)
        k[i] = scalar[i];
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    fe16_frombytes(x1, point);
    for (i = 0; i < 16; i++) {
        x2[i] = 0; z2[i] = 0; z3[i] = 0;
        x3[i] = x1[i];
    }
    x2[0] = 1;
    z3[0] = 1;

    for (bit = 254; bit >= 0; bit--) {
        uint16_t kt = (uint16_t)((k[bit >> 3] >> (bit & 7)) & 1);
        swap ^= kt;
        fe16_cswap(x2, x3, swap);
        fe16_cswap(z2, z3, swap);
        swap = kt;

        fe16_add(a, x2, z2);            /* A  = x2 + z2 */
        fe16_sqr(aa, a);                /* AA = A^2 */
        fe16_sub(b, x2, z2);            /* B  = x2 - z2 */
        fe16_sqr(bb, b);                /* BB = B^2 */
        fe16_sub(e, aa, bb);            /* E  = AA - BB */
        fe16_add(c, x3, z3);            /* C  = x3 + z3 */
        fe16_sub(d, x3, z3);            /* D  = x3 - z3 */
        fe16_mul(da, d, a);             /* DA = D * A */
        fe16_mul(cb, c, b);             /* CB = C * B */
        fe16_add(t, da, cb);
        fe16_sqr(x3, t);                /* x3 = (DA + CB)^2 */
        fe16_sub(t, da, cb);
        fe16_sqr(t, t);
        fe16_mul(z3, x1, t);            /* z3 = x1 * (DA - CB)^2 */
        fe16_mul(x2, aa, bb);           /* x2 = AA * BB */
        fe16_mul121665(t, e);
        fe16_add(t, aa, t);
        fe16_mul(z2, e, t);             /* z2 = E * (AA + a24 * E) */
    }
    fe16_cswap(x2, x3, swap);
    fe16_cswap(z2, z3, swap);

    fe16_invert(z2, z2);
    fe16_mul(x2, x2, z2);
    fe16_tobytes(out, x2);
}

void x25519_ref_base(uint8_t out[32], const uint8_t scalar[32])
{
    static const uint8_t nine[32] = { 9 };
    x25519_ref(out, scalar, nine);
}
