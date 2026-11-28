/* AES / GCM / CBC reference. Byte-oriented S-box implementation; the optimised
 * backends (T-tables in Fast RAM, bitsliced Blitter experiment) replace the
 * block function only. See aes.h. */
#include "aes.h"

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};
static uint8_t INV_SBOX[256];
static int inv_ready;

static uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0)); }
static uint8_t gmul(uint8_t a, uint8_t b)
{
    uint8_t r = 0;
    while (b) { if (b & 1) r ^= a; a = xtime(a); b >>= 1; }
    return r;
}

void aes_set_key(aes_key *k, const uint8_t *key, int keybits)
{
    int nk = keybits >> 5, i, total, pos = 0;   /* pos = word index mod nk, kept without division */
    uint8_t rcon = 1;
    k->rounds = nk + 6;
    k->dec_ready = 0;
    total = 16 * (k->rounds + 1);
    for (i = 0; i < 4 * nk; i++) k->rk[i] = key[i];
    for (i = 4 * nk; i < total; i += 4) {
        uint8_t t0 = k->rk[i - 4], t1 = k->rk[i - 3], t2 = k->rk[i - 2], t3 = k->rk[i - 1];
        if (pos == 0) {
            uint8_t u = t0;
            t0 = (uint8_t)(SBOX[t1] ^ rcon); t1 = SBOX[t2]; t2 = SBOX[t3]; t3 = SBOX[u];
            rcon = xtime(rcon);
        } else if (nk > 6 && pos == 4) {
            t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3];
        }
        k->rk[i]     = (uint8_t)(k->rk[i - 4 * nk] ^ t0);
        k->rk[i + 1] = (uint8_t)(k->rk[i - 4 * nk + 1] ^ t1);
        k->rk[i + 2] = (uint8_t)(k->rk[i - 4 * nk + 2] ^ t2);
        k->rk[i + 3] = (uint8_t)(k->rk[i - 4 * nk + 3] ^ t3);
        if (++pos == nk) pos = 0;
    }
    if (!inv_ready) { for (i = 0; i < 256; i++) INV_SBOX[SBOX[i]] = (uint8_t)i; inv_ready = 1; }
}

static void add_round_key(uint8_t s[16], const uint8_t *rk) { int i; for (i = 0; i < 16; i++) s[i] ^= rk[i]; }

void aes_encrypt_block_c(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    int r, i, c;
    for (i = 0; i < 16; i++) s[i] = in[i];
    add_round_key(s, k->rk);
    for (r = 1; r <= k->rounds; r++) {
        /* SubBytes + ShiftRows (column-major state: s[4*col + row]) */
        for (c = 0; c < 4; c++) {
            t[4 * c]     = SBOX[s[4 * c]];
            t[4 * c + 1] = SBOX[s[4 * ((c + 1) & 3) + 1]];
            t[4 * c + 2] = SBOX[s[4 * ((c + 2) & 3) + 2]];
            t[4 * c + 3] = SBOX[s[4 * ((c + 3) & 3) + 3]];
        }
        if (r < k->rounds) {
            for (c = 0; c < 4; c++) {
                uint8_t a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                uint8_t x = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
                s[4 * c]     = (uint8_t)(a0 ^ x ^ xtime((uint8_t)(a0 ^ a1)));
                s[4 * c + 1] = (uint8_t)(a1 ^ x ^ xtime((uint8_t)(a1 ^ a2)));
                s[4 * c + 2] = (uint8_t)(a2 ^ x ^ xtime((uint8_t)(a2 ^ a3)));
                s[4 * c + 3] = (uint8_t)(a3 ^ x ^ xtime((uint8_t)(a3 ^ a0)));
            }
        } else {
            for (i = 0; i < 16; i++) s[i] = t[i];
        }
        add_round_key(s, k->rk + 16 * r);
    }
    for (i = 0; i < 16; i++) out[i] = s[i];
}

void aes_decrypt_block_c(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
    uint8_t s[16], t[16];
    int r, i, c;
    for (i = 0; i < 16; i++) s[i] = in[i];
    add_round_key(s, k->rk + 16 * k->rounds);
    for (r = k->rounds - 1; r >= 0; r--) {
        /* InvShiftRows + InvSubBytes */
        for (c = 0; c < 4; c++) {
            t[4 * c]     = INV_SBOX[s[4 * c]];
            t[4 * ((c + 1) & 3) + 1] = INV_SBOX[s[4 * c + 1]];
            t[4 * ((c + 2) & 3) + 2] = INV_SBOX[s[4 * c + 2]];
            t[4 * ((c + 3) & 3) + 3] = INV_SBOX[s[4 * c + 3]];
        }
        add_round_key(t, k->rk + 16 * r);
        if (r > 0) {
            for (c = 0; c < 4; c++) {
                uint8_t a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                s[4 * c]     = (uint8_t)(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
                s[4 * c + 1] = (uint8_t)(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
                s[4 * c + 2] = (uint8_t)(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
                s[4 * c + 3] = (uint8_t)(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
            }
        } else {
            for (i = 0; i < 16; i++) s[i] = t[i];
        }
    }
    for (i = 0; i < 16; i++) out[i] = s[i];
}

/* Equivalent inverse cipher: dk[i] = InvMixColumns(rk[rounds - i]) for the inner rounds,
 * so the decrypt round has the same shape as the encrypt round (T-table friendly). */
void aes_prepare_decrypt(aes_key *k)
{
    int r, c;
    for (r = 0; r <= k->rounds; r++) {
        const uint8_t *src = k->rk + 16 * (k->rounds - r);
        uint8_t *dst = k->dk + 16 * r;
        for (c = 0; c < 16; c++) dst[c] = src[c];
        if (r == 0 || r == k->rounds) continue;
        for (c = 0; c < 4; c++) {
            uint8_t a0 = dst[4 * c], a1 = dst[4 * c + 1], a2 = dst[4 * c + 2], a3 = dst[4 * c + 3];
            dst[4 * c]     = (uint8_t)(gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9));
            dst[4 * c + 1] = (uint8_t)(gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13));
            dst[4 * c + 2] = (uint8_t)(gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11));
            dst[4 * c + 3] = (uint8_t)(gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14));
        }
    }
    k->dec_ready = 1;
}

void aes_encrypt_block(const aes_key *k, const uint8_t in[16], uint8_t out[16])
{
#ifdef FE16_ASM
    aes_enc_block(k->rk, in, out, k->rounds);
#else
    aes_encrypt_block_c(k, in, out);
#endif
}

void aes_decrypt_block(aes_key *k, const uint8_t in[16], uint8_t out[16])
{
#ifdef FE16_ASM
    if (!k->dec_ready) aes_prepare_decrypt(k);
    aes_dec_block(k->dk, in, out, k->rounds);
#else
    aes_decrypt_block_c(k, in, out);
#endif
}

/* ---- GHASH: multiplication in GF(2^128), bit-reflected as in SP 800-38D ----- */

void ghash_mul_bit(uint8_t y[16], const uint8_t x[16], const uint8_t h[16])
{
    uint8_t z[16] = { 0 }, v[16];
    int i, j;
    for (i = 0; i < 16; i++) v[i] = h[i];
    for (i = 0; i < 16; i++) {
        uint8_t xi = (uint8_t)(y[i] ^ x[i]);
        for (j = 7; j >= 0; j--) {
            int lsb, b;
            if ((xi >> j) & 1)
                for (b = 0; b < 16; b++) z[b] ^= v[b];
            lsb = v[15] & 1;
            for (b = 15; b > 0; b--) v[b] = (uint8_t)((v[b] >> 1) | (v[b - 1] << 7));
            v[0] >>= 1;
            if (lsb) v[0] ^= 0xe1;
        }
    }
    for (i = 0; i < 16; i++) y[i] = z[i];
}

/* Shoup tables. Bit order: bit 31 of word 0 is x^0, bit 0 of word 3 is x^127 (GCM convention),
 * so "multiply by x" is a right shift of the 128-bit big-endian value. */
static void gf_mulx(uint32_t w[4])
{
    uint32_t lsb = w[3] & 1;
    w[3] = (w[3] >> 1) | (w[2] << 31);
    w[2] = (w[2] >> 1) | (w[1] << 31);
    w[1] = (w[1] >> 1) | (w[0] << 31);
    w[0] = (w[0] >> 1) ^ (lsb ? 0xe1000000u : 0);
}

static void ghash_tables(aes_gcm_key *g)
{
    int b, i, j;
    /* rhi[b]: reduction of byte b at positions 128..135 (MSB of b = x^128): x^(128+k) = x^k (1+x+x^2+x^7) */
    for (b = 0; b < 256; b++) {
        uint32_t r = 0;
        for (i = 0; i < 8; i++)
            if (b & (0x80 >> i)) r ^= (0x80000000u >> i) | (0x40000000u >> i) | (0x20000000u >> i) | (0x01000000u >> i);
        g->rhi[b] = r;
        g->rlo[b] = r >> 8;
    }
    for (i = 0; i < 4; i++) g->m[0][i] = 0;
    for (i = 0; i < 4; i++)
        g->m[128][i] = ((uint32_t)g->h[4 * i] << 24) | ((uint32_t)g->h[4 * i + 1] << 16) | ((uint32_t)g->h[4 * i + 2] << 8) | g->h[4 * i + 3];
    for (b = 64; b >= 1; b >>= 1) {        /* m[b] = m[2b] * x */
        for (i = 0; i < 4; i++) g->m[b][i] = g->m[2 * b][i];
        gf_mulx(g->m[b]);
    }
    for (b = 2; b < 256; b <<= 1)
        for (j = 1; j < b; j++)
            for (i = 0; i < 4; i++) g->m[b + j][i] = g->m[b][i] ^ g->m[j][i];
    for (b = 0; b < 256; b++) {            /* m8[b] = m[b] * x^8 = (m[b] >> 8) ^ rhi[low byte] */
        const uint32_t *w = g->m[b];
        g->m8[b][0] = (w[0] >> 8) ^ g->rhi[w[3] & 0xff];
        g->m8[b][1] = (w[1] >> 8) | (w[0] << 24);
        g->m8[b][2] = (w[2] >> 8) | (w[1] << 24);
        g->m8[b][3] = (w[3] >> 8) | (w[2] << 24);
    }
}

/* Same algorithm as _ghash_mul_tab in crypto/m68k/aes.s: Horner over byte pairs,
 * Z = Z * x^16 + m[x_i] + m8[x_{i+1}], i = 14, 12, ..., 0. */
void ghash_mul_tab_c(uint8_t y[16], const uint8_t x[16], const aes_gcm_key *g)
{
    uint8_t t[16];
    uint32_t z[4];
    int i, k;
    for (i = 0; i < 16; i++) t[i] = (uint8_t)(y[i] ^ x[i]);
    for (k = 0; k < 4; k++) z[k] = g->m[t[14]][k] ^ g->m8[t[15]][k];
    for (i = 12; i >= 0; i -= 2) {
        uint32_t red = g->rhi[(z[3] >> 8) & 0xff] ^ g->rlo[z[3] & 0xff];
        z[3] = (z[3] >> 16) | (z[2] << 16);
        z[2] = (z[2] >> 16) | (z[1] << 16);
        z[1] = (z[1] >> 16) | (z[0] << 16);
        z[0] = (z[0] >> 16) ^ red;
        for (k = 0; k < 4; k++) z[k] ^= g->m[t[i]][k] ^ g->m8[t[i + 1]][k];
    }
    for (k = 0; k < 4; k++) {
        y[4 * k] = (uint8_t)(z[k] >> 24); y[4 * k + 1] = (uint8_t)(z[k] >> 16);
        y[4 * k + 2] = (uint8_t)(z[k] >> 8); y[4 * k + 3] = (uint8_t)z[k];
    }
}

static void ghash_block(uint8_t y[16], const uint8_t x[16], const aes_gcm_key *g)
{
#ifdef FE16_ASM
    ghash_mul_tab(y, x, &g->m[0][0]);
#else
    ghash_mul_tab_c(y, x, g);
#endif
}

void aes_gcm_set_key(aes_gcm_key *g, const uint8_t *key, int keybits)
{
    uint8_t zero[16] = { 0 };
    aes_set_key(&g->k, key, keybits);
    aes_encrypt_block(&g->k, zero, g->h);
    ghash_tables(g);
}

/* called every 64 blocks (1 KiB, ~0.25 s on the 68000) of a GHASH or counter run when set: the probe hangs its
 * heartbeat/socket poll here, so a 166 KB frame's decryption (~37 s live) does not leave the line unread */
void (*aes_gcm_yield)(void);

static void ghash_update(uint8_t y[16], const aes_gcm_key *g, const uint8_t *data, uint32_t len)
{
    uint32_t n = 0;
    while (len >= 16) {
        ghash_block(y, data, g);
        data += 16; len -= 16;
        if (aes_gcm_yield && (++n & 63) == 0) aes_gcm_yield();
    }
    if (len > 0) {
        uint8_t last[16] = { 0 };
        uint32_t i;
        for (i = 0; i < len; i++) last[i] = data[i];
        ghash_block(y, last, g);
    }
}

static void put_be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

static void gcm_tag(const aes_gcm_key *g, const uint8_t j0[16],
                    const uint8_t *aad, uint32_t aadlen, const uint8_t *ct, uint32_t len, uint8_t tag[16])
{
    uint8_t y[16] = { 0 }, lens[16] = { 0 }, ej0[16];
    int i;
    ghash_update(y, g, aad, aadlen);
    ghash_update(y, g, ct, len);
    put_be32(lens + 4, aadlen * 8);     /* bit lengths as 64-bit big-endian; high words stay 0 */
    put_be32(lens + 12, len * 8);
    ghash_update(y, g, lens, 16);
    aes_encrypt_block(&g->k, j0, ej0);
    for (i = 0; i < 16; i++) tag[i] = (uint8_t)(y[i] ^ ej0[i]);
}

static void gcm_ctr(const aes_key *k, const uint8_t j0[16], const uint8_t *in, uint32_t len, uint8_t *out)
{
    uint8_t ctr[16], ks[16];
    uint32_t c, i, n = 0;
    for (i = 0; i < 16; i++) ctr[i] = j0[i];
    c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) | ((uint32_t)ctr[14] << 8) | ctr[15];
    while (len > 0) {
        uint32_t take = len < 16 ? len : 16;
        c++;
        if (aes_gcm_yield && (++n & 63) == 0) aes_gcm_yield();
        put_be32(ctr + 12, c);
        aes_encrypt_block(k, ctr, ks);
        for (i = 0; i < take; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
        in += take; out += take; len -= take;
    }
}

void aes_gcm_encrypt(const aes_gcm_key *g, const uint8_t iv[12], const uint8_t *aad, uint32_t aadlen,
                     const uint8_t *pt, uint32_t len, uint8_t *ct, uint8_t tag[16])
{
    uint8_t j0[16];
    int i;
    for (i = 0; i < 12; i++) j0[i] = iv[i];
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    gcm_ctr(&g->k, j0, pt, len, ct);
    gcm_tag(g, j0, aad, aadlen, ct, len, tag);
}

int aes_gcm_decrypt(const aes_gcm_key *g, const uint8_t iv[12], const uint8_t *aad, uint32_t aadlen,
                    const uint8_t *ct, uint32_t len, const uint8_t tag[16], uint8_t *pt)
{
    uint8_t j0[16], t[16];
    int i, diff = 0;
    for (i = 0; i < 12; i++) j0[i] = iv[i];
    j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;
    gcm_tag(g, j0, aad, aadlen, ct, len, t);
    for (i = 0; i < 16; i++) diff |= t[i] ^ tag[i];
    if (diff) return 0;
    gcm_ctr(&g->k, j0, ct, len, pt);
    return 1;
}

void aes_cbc_encrypt(const aes_key *k, const uint8_t iv[16], const uint8_t *in, uint32_t len, uint8_t *out)
{
    uint8_t x[16];
    uint32_t i;
    for (i = 0; i < 16; i++) x[i] = iv[i];
    while (len >= 16) {
        for (i = 0; i < 16; i++) x[i] ^= in[i];
        aes_encrypt_block(k, x, out);
        for (i = 0; i < 16; i++) x[i] = out[i];
        in += 16; out += 16; len -= 16;
    }
}

void aes_cbc_decrypt(aes_key *k, const uint8_t iv[16], const uint8_t *in, uint32_t len, uint8_t *out)
{
    uint8_t prev[16], cur[16], tmp[16];
    uint32_t i;
    for (i = 0; i < 16; i++) prev[i] = iv[i];
    while (len >= 16) {
        for (i = 0; i < 16; i++) cur[i] = in[i];
        aes_decrypt_block(k, cur, tmp);
        for (i = 0; i < 16; i++) { out[i] = (uint8_t)(tmp[i] ^ prev[i]); prev[i] = cur[i]; }
        in += 16; out += 16; len -= 16;
    }
}
