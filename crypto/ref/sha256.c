/* SHA-256 / HMAC / HKDF reference. See sha256.h. */
#include "sha256.h"

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

void sha256_block_c(uint32_t h[8], const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)p[4 * i] << 24) | ((uint32_t)p[4 * i + 1] << 16) | ((uint32_t)p[4 * i + 2] << 8) | p[4 * i + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; i++) {
        t1 = hh + (ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = (ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void sha256_init(sha256_ctx *c)
{
    c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85; c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c; c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
    c->len_lo = 0; c->len_hi = 0; c->buflen = 0;
}

void sha256_update(sha256_ctx *c, const uint8_t *data, uint32_t len)
{
    uint32_t old = c->len_lo;
    c->len_lo += len;
    if (c->len_lo < old) c->len_hi++;
    while (len > 0) {
        unsigned take = 64 - c->buflen, i;
        if (take > len) take = (unsigned)len;
        for (i = 0; i < take; i++) c->buf[c->buflen + i] = data[i];
        c->buflen += take; data += take; len -= take;
        if (c->buflen == 64) { sha256_block(c->h, c->buf); c->buflen = 0; }
    }
}

void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint32_t bits_lo = c->len_lo << 3, bits_hi = (c->len_hi << 3) | (c->len_lo >> 29);
    int i;
    c->buf[c->buflen++] = 0x80;
    if (c->buflen > 56) {
        while (c->buflen < 64) c->buf[c->buflen++] = 0;
        sha256_block(c->h, c->buf); c->buflen = 0;
    }
    while (c->buflen < 56) c->buf[c->buflen++] = 0;
    c->buf[56] = (uint8_t)(bits_hi >> 24); c->buf[57] = (uint8_t)(bits_hi >> 16);
    c->buf[58] = (uint8_t)(bits_hi >> 8);  c->buf[59] = (uint8_t)bits_hi;
    c->buf[60] = (uint8_t)(bits_lo >> 24); c->buf[61] = (uint8_t)(bits_lo >> 16);
    c->buf[62] = (uint8_t)(bits_lo >> 8);  c->buf[63] = (uint8_t)bits_lo;
    sha256_block(c->h, c->buf);
    for (i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(c->h[i] >> 24); out[4 * i + 1] = (uint8_t)(c->h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(c->h[i] >> 8); out[4 * i + 3] = (uint8_t)c->h[i];
    }
}

void sha256(uint8_t out[32], const uint8_t *data, uint32_t len)
{
    sha256_ctx c;
    sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
}

void hmac_sha256_init(hmac_sha256_ctx *c, const uint8_t *key, uint32_t keylen)
{
    uint8_t k[64], ipad[64];
    uint32_t i;
    for (i = 0; i < 64; i++) k[i] = 0;
    if (keylen > 64) sha256(k, key, keylen);
    else for (i = 0; i < keylen; i++) k[i] = key[i];
    for (i = 0; i < 64; i++) { ipad[i] = (uint8_t)(k[i] ^ 0x36); c->opad_key[i] = (uint8_t)(k[i] ^ 0x5c); }
    sha256_init(&c->inner);
    sha256_update(&c->inner, ipad, 64);
}

void hmac_sha256_update(hmac_sha256_ctx *c, const uint8_t *data, uint32_t len)
{
    sha256_update(&c->inner, data, len);
}

void hmac_sha256_final(hmac_sha256_ctx *c, uint8_t out[32])
{
    uint8_t ih[32];
    sha256_ctx o;
    sha256_final(&c->inner, ih);
    sha256_init(&o);
    sha256_update(&o, c->opad_key, 64);
    sha256_update(&o, ih, 32);
    sha256_final(&o, out);
}

void hmac_sha256(uint8_t out[32], const uint8_t *key, uint32_t keylen, const uint8_t *data, uint32_t len)
{
    hmac_sha256_ctx c;
    hmac_sha256_init(&c, key, keylen);
    hmac_sha256_update(&c, data, len);
    hmac_sha256_final(&c, out);
}

void hkdf_sha256(uint8_t *out, uint32_t outlen,
                 const uint8_t *salt, uint32_t saltlen,
                 const uint8_t *ikm, uint32_t ikmlen,
                 const uint8_t *info, uint32_t infolen)
{
    uint8_t prk[32], t[32], zero[32] = { 0 };
    uint8_t counter = 1;
    uint32_t done = 0, tlen = 0;
    if (salt == 0 || saltlen == 0) { salt = zero; saltlen = 32; }
    hmac_sha256(prk, salt, saltlen, ikm, ikmlen);
    while (done < outlen) {
        hmac_sha256_ctx c;
        uint32_t take, i;
        hmac_sha256_init(&c, prk, 32);
        if (tlen) hmac_sha256_update(&c, t, tlen);
        hmac_sha256_update(&c, info, infolen);
        hmac_sha256_update(&c, &counter, 1);
        hmac_sha256_final(&c, t);
        tlen = 32;
        take = outlen - done < 32 ? outlen - done : 32;
        for (i = 0; i < take; i++) out[done + i] = t[i];
        done += take;
        counter++;
    }
}
