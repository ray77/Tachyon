#include "rsa.h"
#include "sha256.h"

/* ---- limb helpers (little-endian uint16 arrays of k->limbs) ---------------- */

static int bn_cmp(const uint16_t *a, const uint16_t *b, int n)
{
    int i;
    for (i = n - 1; i >= 0; i--) { if (a[i] > b[i]) return 1; if (a[i] < b[i]) return -1; }
    return 0;
}

static void bn_sub(uint16_t *r, const uint16_t *a, const uint16_t *b, int n)   /* r = a - b, a >= b */
{
    uint32_t borrow = 0; int i;
    for (i = 0; i < n; i++) {
        uint32_t t = (uint32_t)a[i] - b[i] - borrow;
        r[i] = (uint16_t)t; borrow = (t >> 16) & 1;
    }
}

/* r = 2r mod n (r < n) */
static void bn_dbl_mod(uint16_t *r, const uint16_t *n, int limbs)
{
    uint32_t carry = 0; int i;
    for (i = 0; i < limbs; i++) { uint32_t t = ((uint32_t)r[i] << 1) | carry; r[i] = (uint16_t)t; carry = t >> 16; }
    if (carry || bn_cmp(r, n, limbs) >= 0) bn_sub(r, r, n, limbs);
}

/* CIOS Montgomery multiplication with 16-bit limbs; all intermediates fit in 32 bits:
 * t[j] + a[j]*b[i] + carry <= 65535 + 65535^2 + 65535 < 2^32. */
void rsa_mont_mul_c(const rsa_pub *k, const uint16_t *a, const uint16_t *b, uint16_t *r)
{
    uint16_t t[RSA_MAX_LIMBS + 2];
    int limbs = k->limbs, i, j;
    for (i = 0; i <= limbs + 1; i++) t[i] = 0;
    for (i = 0; i < limbs; i++) {
        uint32_t carry = 0, bi = b[i], m;
        for (j = 0; j < limbs; j++) {
            uint32_t s = (uint32_t)t[j] + a[j] * bi + carry;
            t[j] = (uint16_t)s; carry = s >> 16;
        }
        { uint32_t s = (uint32_t)t[limbs] + carry; t[limbs] = (uint16_t)s; t[limbs + 1] = (uint16_t)(s >> 16); }
        m = ((uint32_t)t[0] * k->n0inv) & 0xffff;
        carry = ((uint32_t)t[0] + m * k->n[0]) >> 16;
        for (j = 1; j < limbs; j++) {
            uint32_t s = (uint32_t)t[j] + m * k->n[j] + carry;
            t[j - 1] = (uint16_t)s; carry = s >> 16;
        }
        { uint32_t s = (uint32_t)t[limbs] + carry; t[limbs - 1] = (uint16_t)s; t[limbs] = (uint16_t)(t[limbs + 1] + (s >> 16)); t[limbs + 1] = 0; }
    }
    if (t[limbs] || bn_cmp(t, k->n, limbs) >= 0) bn_sub(r, t, k->n, limbs);
    else for (i = 0; i < limbs; i++) r[i] = t[i];
}

void rsa_mont_mul(const rsa_pub *k, const uint16_t *a, const uint16_t *b, uint16_t *r)
{
    rsa_mont_mul_c(k, a, b, r);
}

int rsa_pub_set(rsa_pub *k, const uint8_t *n_be, uint32_t len, uint32_t e)
{
    int i, limbs;
    uint32_t inv, n0;
    if (len < 128 || len > 2 * RSA_MAX_LIMBS || (len & 1) || !(n_be[len - 1] & 1) || !(n_be[0] & 0x80)) return 0;
    limbs = (int)(len >> 1);
    k->limbs = limbs; k->e = e;
    for (i = 0; i < limbs; i++) k->n[i] = (uint16_t)(((uint16_t)n_be[len - 2 - 2 * i] << 8) | n_be[len - 1 - 2 * i]);
    /* n0inv = -n^-1 mod 2^16 by Newton iteration (n odd) */
    n0 = k->n[0]; inv = 1;
    for (i = 0; i < 5; i++) inv = (inv * (2 - n0 * inv)) & 0xffff;
    k->n0inv = (uint16_t)((0x10000 - inv) & 0xffff);
    /* rr = R^2 mod n: start from R mod n = 2^(16*limbs) - n (n has its top bit set), then double 16*limbs times */
    { uint16_t zero[RSA_MAX_LIMBS]; for (i = 0; i < limbs; i++) zero[i] = 0; bn_sub(k->rr, zero, k->n, limbs); }
    for (i = 0; i < 16 * limbs; i++) bn_dbl_mod(k->rr, k->n, limbs);
    return 1;
}

static void be_to_limbs(uint16_t *x, const uint8_t *be, int limbs)
{
    int i;
    for (i = 0; i < limbs; i++) x[i] = (uint16_t)(((uint16_t)be[2 * limbs - 2 - 2 * i] << 8) | be[2 * limbs - 1 - 2 * i]);
}

static void limbs_to_be(uint8_t *be, const uint16_t *x, int limbs)
{
    int i;
    for (i = 0; i < limbs; i++) { be[2 * limbs - 2 - 2 * i] = (uint8_t)(x[i] >> 8); be[2 * limbs - 1 - 2 * i] = (uint8_t)x[i]; }
}

int rsa_public_op(const rsa_pub *k, const uint8_t *in_be, uint8_t *out_be)
{
    uint16_t x[RSA_MAX_LIMBS], xm[RSA_MAX_LIMBS], acc[RSA_MAX_LIMBS], one[RSA_MAX_LIMBS];
    int limbs = k->limbs, i, bit, started = 0;
    be_to_limbs(x, in_be, limbs);
    if (bn_cmp(x, k->n, limbs) >= 0) return 0;
    rsa_mont_mul(k, x, k->rr, xm);                  /* xm = x*R */
    for (i = 0; i < limbs; i++) one[i] = 0; one[0] = 1;
    rsa_mont_mul(k, one, k->rr, acc);               /* acc = R (Montgomery one) */
    for (bit = 31; bit >= 0; bit--) {               /* left-to-right square and multiply, e is public */
        if (started) rsa_mont_mul(k, acc, acc, acc);
        if ((k->e >> bit) & 1) { rsa_mont_mul(k, acc, xm, acc); started = 1; }
    }
    rsa_mont_mul(k, acc, one, acc);                 /* back from Montgomery form */
    limbs_to_be(out_be, acc, limbs);
    return 1;
}

static const uint8_t SHA256_DIGESTINFO[19] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};

int rsa_verify_pkcs1_sha256(const rsa_pub *k, const uint8_t *msg, uint32_t msglen, const uint8_t *sig, uint32_t siglen)
{
    uint8_t em[2 * RSA_MAX_LIMBS], h[32];
    uint32_t len = (uint32_t)k->limbs * 2, i, diff = 0;
    if (siglen != len) return 0;
    if (!rsa_public_op(k, sig, em)) return 0;
    sha256(h, msg, msglen);
    /* expected: 00 01 FF...FF 00 DigestInfo H ; all bytes compared, no early exit */
    diff |= em[0] ^ 0x00; diff |= em[1] ^ 0x01;
    for (i = 2; i < len - 32 - 19 - 1; i++) diff |= em[i] ^ 0xff;
    diff |= em[len - 32 - 19 - 1] ^ 0x00;
    for (i = 0; i < 19; i++) diff |= em[len - 32 - 19 + i] ^ SHA256_DIGESTINFO[i];
    for (i = 0; i < 32; i++) diff |= em[len - 32 + i] ^ h[i];
    return diff == 0;
}

int rsa_encrypt_pkcs1(const rsa_pub *k, const uint8_t *msg, uint32_t msglen, const uint8_t *pad, uint8_t *out_be)
{
    uint8_t em[2 * RSA_MAX_LIMBS];
    uint32_t len = (uint32_t)k->limbs * 2, i, padlen;
    if (msglen + 11 > len) return 0;
    padlen = len - 3 - msglen;
    em[0] = 0x00; em[1] = 0x02;
    for (i = 0; i < padlen; i++) { if (pad[i] == 0) return 0; em[2 + i] = pad[i]; }
    em[2 + padlen] = 0x00;
    for (i = 0; i < msglen; i++) em[3 + padlen + i] = msg[i];
    return rsa_public_op(k, em, out_be);
}
