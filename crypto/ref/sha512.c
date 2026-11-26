/* SHA-512 with 32-bit word pairs. See sha512.h. */
#include "sha512.h"

/* round constants, hi word first */
static const uint32_t K[160] = {
    0x428a2f98,0xd728ae22, 0x71374491,0x23ef65cd, 0xb5c0fbcf,0xec4d3b2f, 0xe9b5dba5,0x8189dbbc,
    0x3956c25b,0xf348b538, 0x59f111f1,0xb605d019, 0x923f82a4,0xaf194f9b, 0xab1c5ed5,0xda6d8118,
    0xd807aa98,0xa3030242, 0x12835b01,0x45706fbe, 0x243185be,0x4ee4b28c, 0x550c7dc3,0xd5ffb4e2,
    0x72be5d74,0xf27b896f, 0x80deb1fe,0x3b1696b1, 0x9bdc06a7,0x25c71235, 0xc19bf174,0xcf692694,
    0xe49b69c1,0x9ef14ad2, 0xefbe4786,0x384f25e3, 0x0fc19dc6,0x8b8cd5b5, 0x240ca1cc,0x77ac9c65,
    0x2de92c6f,0x592b0275, 0x4a7484aa,0x6ea6e483, 0x5cb0a9dc,0xbd41fbd4, 0x76f988da,0x831153b5,
    0x983e5152,0xee66dfab, 0xa831c66d,0x2db43210, 0xb00327c8,0x98fb213f, 0xbf597fc7,0xbeef0ee4,
    0xc6e00bf3,0x3da88fc2, 0xd5a79147,0x930aa725, 0x06ca6351,0xe003826f, 0x14292967,0x0a0e6e70,
    0x27b70a85,0x46d22ffc, 0x2e1b2138,0x5c26c926, 0x4d2c6dfc,0x5ac42aed, 0x53380d13,0x9d95b3df,
    0x650a7354,0x8baf63de, 0x766a0abb,0x3c77b2a8, 0x81c2c92e,0x47edaee6, 0x92722c85,0x1482353b,
    0xa2bfe8a1,0x4cf10364, 0xa81a664b,0xbc423001, 0xc24b8b70,0xd0f89791, 0xc76c51a3,0x0654be30,
    0xd192e819,0xd6ef5218, 0xd6990624,0x5565a910, 0xf40e3585,0x5771202a, 0x106aa070,0x32bbd1b8,
    0x19a4c116,0xb8d2d0c8, 0x1e376c08,0x5141ab53, 0x2748774c,0xdf8eeb99, 0x34b0bcb5,0xe19b48a8,
    0x391c0cb3,0xc5c95a63, 0x4ed8aa4a,0xe3418acb, 0x5b9cca4f,0x7763e373, 0x682e6ff3,0xd6b2b8a3,
    0x748f82ee,0x5defb2fc, 0x78a5636f,0x43172f60, 0x84c87814,0xa1f0ab72, 0x8cc70208,0x1a6439ec,
    0x90befffa,0x23631e28, 0xa4506ceb,0xde82bde9, 0xbef9a3f7,0xb2c67915, 0xc67178f2,0xe372532b,
    0xca273ece,0xea26619c, 0xd186b8c7,0x21c0c207, 0xeada7dd6,0xcde0eb1e, 0xf57d4f7f,0xee6ed178,
    0x06f067aa,0x72176fba, 0x0a637dc5,0xa2c898a6, 0x113f9804,0xbef90dae, 0x1b710b35,0x131c471b,
    0x28db77f5,0x23047d84, 0x32caab7b,0x40c72493, 0x3c9ebe0a,0x15c9bebc, 0x431d67c4,0x9c100d4c,
    0x4cc5d4be,0xcb3e42b6, 0x597f299c,0xfc657e2a, 0x5fcb6fab,0x3ad6faec, 0x6c44198c,0x4a475817
};

/* 64-bit helpers on (hi, lo) pairs; macros keep everything in registers */
#define ADD64(rh, rl, ah, al, bh, bl) do { uint32_t _l = (al) + (bl); (rh) = (ah) + (bh) + (_l < (al)); (rl) = _l; } while (0)
/* rotate right by n (1..31): hi' = hi>>n | lo<<(32-n), lo' = lo>>n | hi<<(32-n) */
#define ROTR_LT32(rh, rl, h, l, n) do { (rh) = ((h) >> (n)) | ((l) << (32 - (n))); (rl) = ((l) >> (n)) | ((h) << (32 - (n))); } while (0)
/* rotate right by 32+n: swap halves, then rotate by n */
#define ROTR_GE32(rh, rl, h, l, n) ROTR_LT32(rh, rl, l, h, n)

static void sha512_block(uint32_t h[16], const uint8_t *p)
{
    uint32_t w[160];            /* message schedule, hi/lo pairs */
    uint32_t a_h, a_l, b_h, b_l, c_h, c_l, d_h, d_l, e_h, e_l, f_h, f_l, g_h, g_l, hh_h, hh_l;
    uint32_t t1_h, t1_l, t2_h, t2_l, s_h, s_l, u_h, u_l;
    int i;

    for (i = 0; i < 16; i++) {
        w[2 * i]     = ((uint32_t)p[8 * i] << 24) | ((uint32_t)p[8 * i + 1] << 16) | ((uint32_t)p[8 * i + 2] << 8) | p[8 * i + 3];
        w[2 * i + 1] = ((uint32_t)p[8 * i + 4] << 24) | ((uint32_t)p[8 * i + 5] << 16) | ((uint32_t)p[8 * i + 6] << 8) | p[8 * i + 7];
    }
    for (i = 16; i < 80; i++) {
        uint32_t x_h = w[2 * (i - 15)], x_l = w[2 * (i - 15) + 1];
        uint32_t y_h = w[2 * (i - 2)],  y_l = w[2 * (i - 2) + 1];
        uint32_t r_h, r_l;
        /* sigma0(x) = ROTR1 ^ ROTR8 ^ SHR7 */
        ROTR_LT32(s_h, s_l, x_h, x_l, 1);
        ROTR_LT32(u_h, u_l, x_h, x_l, 8);
        s_h ^= u_h; s_l ^= u_l;
        s_h ^= x_h >> 7; s_l ^= (x_l >> 7) | (x_h << 25);
        /* sigma1(y) = ROTR19 ^ ROTR61 ^ SHR6 */
        ROTR_LT32(t1_h, t1_l, y_h, y_l, 19);
        ROTR_GE32(u_h, u_l, y_h, y_l, 29);
        t1_h ^= u_h; t1_l ^= u_l;
        t1_h ^= y_h >> 6; t1_l ^= (y_l >> 6) | (y_h << 26);
        ADD64(r_h, r_l, w[2 * (i - 16)], w[2 * (i - 16) + 1], s_h, s_l);
        ADD64(r_h, r_l, r_h, r_l, w[2 * (i - 7)], w[2 * (i - 7) + 1]);
        ADD64(r_h, r_l, r_h, r_l, t1_h, t1_l);
        w[2 * i] = r_h; w[2 * i + 1] = r_l;
    }

    a_h = h[0]; a_l = h[1]; b_h = h[2]; b_l = h[3]; c_h = h[4]; c_l = h[5]; d_h = h[6]; d_l = h[7];
    e_h = h[8]; e_l = h[9]; f_h = h[10]; f_l = h[11]; g_h = h[12]; g_l = h[13]; hh_h = h[14]; hh_l = h[15];

    for (i = 0; i < 80; i++) {
        /* T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i];  Sigma1 = ROTR14 ^ ROTR18 ^ ROTR41 */
        ROTR_LT32(s_h, s_l, e_h, e_l, 14);
        ROTR_LT32(u_h, u_l, e_h, e_l, 18);
        s_h ^= u_h; s_l ^= u_l;
        ROTR_GE32(u_h, u_l, e_h, e_l, 9);
        s_h ^= u_h; s_l ^= u_l;
        u_h = (e_h & f_h) ^ (~e_h & g_h);
        u_l = (e_l & f_l) ^ (~e_l & g_l);
        ADD64(t1_h, t1_l, hh_h, hh_l, s_h, s_l);
        ADD64(t1_h, t1_l, t1_h, t1_l, u_h, u_l);
        ADD64(t1_h, t1_l, t1_h, t1_l, K[2 * i], K[2 * i + 1]);
        ADD64(t1_h, t1_l, t1_h, t1_l, w[2 * i], w[2 * i + 1]);
        /* T2 = Sigma0(a) + Maj(a,b,c);  Sigma0 = ROTR28 ^ ROTR34 ^ ROTR39 */
        ROTR_LT32(s_h, s_l, a_h, a_l, 28);
        ROTR_GE32(u_h, u_l, a_h, a_l, 2);
        s_h ^= u_h; s_l ^= u_l;
        ROTR_GE32(u_h, u_l, a_h, a_l, 7);
        s_h ^= u_h; s_l ^= u_l;
        u_h = (a_h & b_h) ^ (a_h & c_h) ^ (b_h & c_h);
        u_l = (a_l & b_l) ^ (a_l & c_l) ^ (b_l & c_l);
        ADD64(t2_h, t2_l, s_h, s_l, u_h, u_l);

        hh_h = g_h; hh_l = g_l; g_h = f_h; g_l = f_l; f_h = e_h; f_l = e_l;
        ADD64(e_h, e_l, d_h, d_l, t1_h, t1_l);
        d_h = c_h; d_l = c_l; c_h = b_h; c_l = b_l; b_h = a_h; b_l = a_l;
        ADD64(a_h, a_l, t1_h, t1_l, t2_h, t2_l);
    }

    ADD64(h[0], h[1], h[0], h[1], a_h, a_l);   ADD64(h[2], h[3], h[2], h[3], b_h, b_l);
    ADD64(h[4], h[5], h[4], h[5], c_h, c_l);   ADD64(h[6], h[7], h[6], h[7], d_h, d_l);
    ADD64(h[8], h[9], h[8], h[9], e_h, e_l);   ADD64(h[10], h[11], h[10], h[11], f_h, f_l);
    ADD64(h[12], h[13], h[12], h[13], g_h, g_l); ADD64(h[14], h[15], h[14], h[15], hh_h, hh_l);
}

void sha512_init(sha512_ctx *c)
{
    static const uint32_t iv[16] = {
        0x6a09e667,0xf3bcc908, 0xbb67ae85,0x84caa73b, 0x3c6ef372,0xfe94f82b, 0xa54ff53a,0x5f1d36f1,
        0x510e527f,0xade682d1, 0x9b05688c,0x2b3e6c1f, 0x1f83d9ab,0xfb41bd6b, 0x5be0cd19,0x137e2179
    };
    int i;
    for (i = 0; i < 16; i++) c->h[i] = iv[i];
    c->len_lo = 0; c->len_hi = 0; c->buflen = 0;
}

void sha512_update(sha512_ctx *c, const uint8_t *data, uint32_t len)
{
    uint32_t old = c->len_lo;
    c->len_lo += len;
    if (c->len_lo < old) c->len_hi++;
    while (len > 0) {
        unsigned take = 128 - c->buflen;
        unsigned i;
        if (take > len) take = (unsigned)len;
        for (i = 0; i < take; i++) c->buf[c->buflen + i] = data[i];
        c->buflen += take; data += take; len -= take;
        if (c->buflen == 128) { sha512_block(c->h, c->buf); c->buflen = 0; }
    }
}

void sha512_final(sha512_ctx *c, uint8_t out[64])
{
    /* bit length as 128-bit big-endian: top 64 bits are zero for our purposes */
    uint32_t bits_lo = c->len_lo << 3;
    uint32_t bits_hi = (c->len_hi << 3) | (c->len_lo >> 29);
    int i;
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 112) {
        while (c->buflen < 128) c->buf[c->buflen++] = 0;
        sha512_block(c->h, c->buf); c->buflen = 0;
    }
    while (c->buflen < 120) c->buf[c->buflen++] = 0;
    c->buf[120] = (uint8_t)(bits_hi >> 24); c->buf[121] = (uint8_t)(bits_hi >> 16);
    c->buf[122] = (uint8_t)(bits_hi >> 8);  c->buf[123] = (uint8_t)bits_hi;
    c->buf[124] = (uint8_t)(bits_lo >> 24); c->buf[125] = (uint8_t)(bits_lo >> 16);
    c->buf[126] = (uint8_t)(bits_lo >> 8);  c->buf[127] = (uint8_t)bits_lo;
    sha512_block(c->h, c->buf);
    for (i = 0; i < 16; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24); out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8); out[4 * i + 3] = (uint8_t)c->h[i];
    }
}

void sha512(uint8_t out[64], const uint8_t *data, uint32_t len)
{
    sha512_ctx c;
    sha512_init(&c);
    sha512_update(&c, data, len);
    sha512_final(&c, out);
}
