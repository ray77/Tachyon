/* Ed25519 / XEdDSA verification over the fe16 field arithmetic. See ed25519.h. */
#include "ed25519.h"
#include "sha512.h"

/* curve constants (little-endian byte encodings, verified by tests/ed25519_test.c) */
static const uint8_t D_BYTES[32] = {       /* d = -121665/121666 */
    0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,0xab,0xd8,0x41,0x41,0x4d,0x0a,0x70,0x00,
    0x98,0xe8,0x79,0x77,0x79,0x40,0xc7,0x8c,0x73,0xfe,0x6f,0x2b,0xee,0x6c,0x03,0x52
};
static const uint8_t SQRTM1_BYTES[32] = {  /* sqrt(-1) = 2^((p-1)/4) */
    0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
    0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b
};
/* base point B: y = 4/5, x positive */
static const uint8_t B_BYTES[32] = {
    0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
    0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
};

static void fe16_set(fe16 h, uint16_t v) { int i; for (i = 1; i < 16; i++) h[i] = 0; h[0] = v; }
static void fe16_copy(fe16 h, const fe16 f) { int i; for (i = 0; i < 16; i++) h[i] = f[i]; }
static void fe16_neg(fe16 h, const fe16 f) { fe16 z; fe16_set(z, 0); fe16_sub(h, z, f); }

static int fe16_iszero(const fe16 f)
{
    uint8_t b[32]; int i, acc = 0;
    fe16_tobytes(b, f);
    for (i = 0; i < 32; i++) acc |= b[i];
    return acc == 0;
}
static int fe16_isnegative(const fe16 f) { uint8_t b[32]; fe16_tobytes(b, f); return b[0] & 1; }

static void ed_sqr_n(fe16 h, const fe16 f, int n)
{
    fe16_sqr(h, f);
    while (--n > 0) fe16_sqr(h, h);
}

/* h = z^(2^252 - 3), used for the square root in point decoding */
static void fe16_pow22523(fe16 h, const fe16 z)
{
    fe16 z2, z9, z11, z2_5_0, z2_10_0, z2_20_0, z2_50_0, z2_100_0, t0, t1;
    fe16_sqr(z2, z);
    ed_sqr_n(t1, z2, 2);
    fe16_mul(z9, t1, z);
    fe16_mul(z11, z9, z2);
    fe16_sqr(t0, z11);
    fe16_mul(z2_5_0, t0, z9);
    ed_sqr_n(t0, z2_5_0, 5);
    fe16_mul(z2_10_0, t0, z2_5_0);
    ed_sqr_n(t0, z2_10_0, 10);
    fe16_mul(z2_20_0, t0, z2_10_0);
    ed_sqr_n(t0, z2_20_0, 20);
    fe16_mul(t0, t0, z2_20_0);
    ed_sqr_n(t0, t0, 10);
    fe16_mul(z2_50_0, t0, z2_10_0);
    ed_sqr_n(t0, z2_50_0, 50);
    fe16_mul(z2_100_0, t0, z2_50_0);
    ed_sqr_n(t0, z2_100_0, 100);
    fe16_mul(t0, t0, z2_100_0);
    ed_sqr_n(t0, t0, 50);
    fe16_mul(t0, t0, z2_50_0);          /* 2^250 - 1 */
    ed_sqr_n(t0, t0, 2);              /* 2^252 - 4 */
    fe16_mul(h, t0, z);                 /* 2^252 - 3 */
}

/* ---- group operations ---------------------------------------------------- */

int ge_frombytes(ge_p3 *P, const uint8_t s[32])
{
    fe16 d, sqrtm1, u, v, v3, vxx, check, one;
    int sign = s[31] >> 7;

    fe16_frombytes(d, D_BYTES);
    fe16_frombytes(sqrtm1, SQRTM1_BYTES);
    fe16_set(one, 1);
    fe16_frombytes(P->Y, s);            /* clears bit 255 */
    fe16_set(P->Z, 1);
    fe16_sqr(u, P->Y);
    fe16_mul(v, u, d);
    fe16_sub(u, u, one);                /* u = y^2 - 1 */
    fe16_add(v, v, one);                /* v = d y^2 + 1 */

    fe16_sqr(v3, v);
    fe16_mul(v3, v3, v);                /* v^3 */
    fe16_sqr(P->X, v3);
    fe16_mul(P->X, P->X, v);
    fe16_mul(P->X, P->X, u);            /* u v^7 */
    fe16_pow22523(P->X, P->X);          /* (u v^7)^((p-5)/8) */
    fe16_mul(P->X, P->X, v3);
    fe16_mul(P->X, P->X, u);            /* x = u v^3 (u v^7)^((p-5)/8) */

    fe16_sqr(vxx, P->X);
    fe16_mul(vxx, vxx, v);
    fe16_sub(check, vxx, u);            /* v x^2 - u */
    if (!fe16_iszero(check)) {
        fe16_add(check, vxx, u);        /* v x^2 + u */
        if (!fe16_iszero(check)) return 0;
        fe16_mul(P->X, P->X, sqrtm1);
    }
    if (fe16_iszero(P->X) && sign) return 0;    /* x = 0 with sign bit set is invalid */
    if (fe16_isnegative(P->X) != sign) fe16_neg(P->X, P->X);
    fe16_mul(P->T, P->X, P->Y);
    return 1;
}

void ge_tobytes(uint8_t s[32], const ge_p3 *P)
{
    fe16 zinv, x, y;
    fe16_invert(zinv, P->Z);
    fe16_mul(x, P->X, zinv);
    fe16_mul(y, P->Y, zinv);
    fe16_tobytes(s, y);
    s[31] ^= (uint8_t)(fe16_isnegative(x) << 7);
}

void ge_neg(ge_p3 *R, const ge_p3 *P)
{
    fe16_neg(R->X, P->X);
    fe16_copy(R->Y, P->Y);
    fe16_copy(R->Z, P->Z);
    fe16_neg(R->T, P->T);
}

/* add-2008-hwcd-3 for a = -1 (ref10 ge_add), 9 multiplications */
void ge_add(ge_p3 *R, const ge_p3 *P, const ge_p3 *Q)
{
    fe16 d2, a, b, c, dd, e, f, g, h, t;
    fe16_frombytes(d2, D_BYTES);
    fe16_add(d2, d2, d2);               /* 2d */

    fe16_add(a, P->Y, P->X);
    fe16_add(t, Q->Y, Q->X);
    fe16_mul(a, a, t);                  /* A = (Y1+X1)(Y2+X2) */
    fe16_sub(b, P->Y, P->X);
    fe16_sub(t, Q->Y, Q->X);
    fe16_mul(b, b, t);                  /* B = (Y1-X1)(Y2-X2) */
    fe16_mul(c, P->T, Q->T);
    fe16_mul(c, c, d2);                 /* C = 2d T1 T2 */
    fe16_mul(dd, P->Z, Q->Z);
    fe16_add(dd, dd, dd);               /* D = 2 Z1 Z2 */
    fe16_sub(e, a, b);
    fe16_sub(f, dd, c);
    fe16_add(g, dd, c);
    fe16_add(h, a, b);
    fe16_mul(R->X, e, f);
    fe16_mul(R->Y, g, h);
    fe16_mul(R->T, e, h);
    fe16_mul(R->Z, f, g);
}

/* doubling as in ref10 ge_p2_dbl followed by p1p1 -> p3: 4 squarings, 4 multiplications */
void ge_dbl(ge_p3 *R, const ge_p3 *P)
{
    fe16 xx, yy, b, a, xp, yp, zp, tp;
    fe16_sqr(xx, P->X);
    fe16_sqr(yy, P->Y);
    fe16_sqr(b, P->Z);
    fe16_add(b, b, b);                  /* 2 Z^2 */
    fe16_add(a, P->X, P->Y);
    fe16_sqr(a, a);                     /* (X+Y)^2 */
    fe16_add(yp, yy, xx);
    fe16_sub(zp, yy, xx);
    fe16_sub(xp, a, yp);
    fe16_sub(tp, b, zp);
    fe16_mul(R->X, xp, tp);
    fe16_mul(R->Y, yp, zp);
    fe16_mul(R->Z, zp, tp);
    fe16_mul(R->T, xp, yp);
}

static void ge_identity(ge_p3 *P)
{
    fe16_set(P->X, 0); fe16_set(P->Y, 1); fe16_set(P->Z, 1); fe16_set(P->T, 0);
}

/* simple left-to-right double-and-add, variable time (public inputs only) */
void ge_scalarmult(ge_p3 *R, const uint8_t k[32], const ge_p3 *P)
{
    ge_p3 acc;
    int bit;
    ge_identity(&acc);
    for (bit = 255; bit >= 0; bit--) {
        ge_dbl(&acc, &acc);
        if ((k[bit >> 3] >> (bit & 7)) & 1) ge_add(&acc, &acc, P);
    }
    *R = acc;
}

void ge_scalarmult_base(ge_p3 *R, const uint8_t k[32])
{
    ge_p3 B;
    ge_frombytes(&B, B_BYTES);
    ge_scalarmult(R, k, &B);
}

/* R = [a]A + [b]B, Shamir's trick: one doubling chain, up to two additions per bit */
void ge_double_scalarmult(ge_p3 *R, const uint8_t a[32], const ge_p3 *A, const uint8_t b[32])
{
    ge_p3 B, AB, acc;
    int bit;
    ge_frombytes(&B, B_BYTES);
    ge_add(&AB, A, &B);
    ge_identity(&acc);
    for (bit = 255; bit >= 0; bit--) {
        int ka = (a[bit >> 3] >> (bit & 7)) & 1;
        int kb = (b[bit >> 3] >> (bit & 7)) & 1;
        ge_dbl(&acc, &acc);
        if (ka && kb) ge_add(&acc, &acc, &AB);
        else if (ka)  ge_add(&acc, &acc, A);
        else if (kb)  ge_add(&acc, &acc, &B);
    }
    *R = acc;
}

/* ---- scalar arithmetic mod L ----------------------------------------------- */

static const int32_t L[32] = {
    0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
};

/* TweetNaCl modL with 32-bit signed limbs (all intermediate values stay far below 2^31) */
static void modL(uint8_t r[32], int32_t x[64])
{
    int32_t carry;
    int i, j;
    for (i = 63; i >= 32; i--) {
        carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = (x[j] + 128) >> 8;
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) {
        x[j] += carry - (x[31] >> 4) * L[j];
        carry = x[j] >> 8;
        x[j] &= 255;
    }
    for (j = 0; j < 32; j++) x[j] -= carry * L[j];
    for (i = 0; i < 32; i++) {
        x[i + 1] += x[i] >> 8;
        r[i] = (uint8_t)(x[i] & 255);
    }
}

void sc_reduce(uint8_t r[32], const uint8_t x[64])
{
    int32_t t[64];
    int i;
    for (i = 0; i < 64; i++) t[i] = x[i];
    modL(r, t);
}

int sc_is_canonical(const uint8_t s[32])
{
    int i;
    for (i = 31; i >= 0; i--) {
        if (s[i] < (uint8_t)L[i]) return 1;
        if (s[i] > (uint8_t)L[i]) return 0;
    }
    return 0;   /* s == L */
}

/* ---- signatures ------------------------------------------------------------ */

static int verify_core(const uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t pk[32])
{
    ge_p3 A, negA, R;
    sha512_ctx c;
    uint8_t hash[64], h[32], rcheck[32];
    int i, acc = 0;

    if (!sc_is_canonical(sig + 32)) return 0;
    if (!ge_frombytes(&A, pk)) return 0;

    sha512_init(&c);
    sha512_update(&c, sig, 32);
    sha512_update(&c, pk, 32);
    sha512_update(&c, msg, len);
    sha512_final(&c, hash);
    sc_reduce(h, hash);

    ge_neg(&negA, &A);
    ge_double_scalarmult(&R, h, &negA, sig + 32);  /* R' = [S]B - [h]A */
    ge_tobytes(rcheck, &R);
    for (i = 0; i < 32; i++) acc |= rcheck[i] ^ sig[i];
    return acc == 0;
}

int ed25519_verify(const uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t pk[32])
{
    return verify_core(sig, msg, len, pk);
}

/* libsignal: ed_y = (u - 1) / (u + 1), sign bit of the Edwards x taken from sig[63] bit 7 */
int xeddsa_verify(const uint8_t sig[64], const uint8_t *msg, uint32_t len, const uint8_t pk[32])
{
    fe16 u, one, num, den;
    uint8_t a_ed[32], sig2[64];
    int i;

    fe16_frombytes(u, pk);
    fe16_set(one, 1);
    fe16_sub(num, u, one);
    fe16_add(den, u, one);
    fe16_invert(den, den);              /* u = -1 maps to y = 0, as in libsignal */
    fe16_mul(num, num, den);
    fe16_tobytes(a_ed, num);
    a_ed[31] |= sig[63] & 0x80;

    for (i = 0; i < 64; i++) sig2[i] = sig[i];
    sig2[63] &= 0x7f;
    return verify_core(sig2, msg, len, a_ed);
}
