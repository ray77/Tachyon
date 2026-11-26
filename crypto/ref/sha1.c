#include "sha1.h"

static uint32_t rol(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_block(uint32_t h[5], const uint8_t *p)
{
    uint32_t w[80], a, b, c, d, e, i;
    for (i = 0; i < 16; i++) w[i] = ((uint32_t)p[4*i] << 24) | ((uint32_t)p[4*i+1] << 16) | ((uint32_t)p[4*i+2] << 8) | p[4*i+3];
    for (i = 16; i < 80; i++) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
    for (i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else             { f = b ^ c ^ d; k = 0xca62c1d6; }
        { uint32_t t = rol(a, 5) + f + e + k + w[i]; e = d; d = c; c = rol(b, 30); b = a; a = t; }
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

void sha1(uint8_t out[20], const uint8_t *data, uint32_t len)
{
    uint32_t h[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    uint8_t last[128];
    uint32_t i, rem, total = len, n;
    while (len >= 64) { sha1_block(h, data); data += 64; len -= 64; }
    rem = len;
    for (i = 0; i < rem; i++) last[i] = data[i];
    last[rem++] = 0x80;
    n = rem <= 56 ? 64 : 128;
    for (i = rem; i < n - 8; i++) last[i] = 0;
    for (i = 0; i < 4; i++) last[n - 8 + i] = 0;            /* bit length < 2^32 bits here */
    last[n - 4] = (uint8_t)(total >> 21); last[n - 3] = (uint8_t)(total >> 13); last[n - 2] = (uint8_t)(total >> 5); last[n - 1] = (uint8_t)(total << 3);
    sha1_block(h, last);
    if (n == 128) sha1_block(h, last + 64);
    for (i = 0; i < 5; i++) { out[4*i] = (uint8_t)(h[i] >> 24); out[4*i+1] = (uint8_t)(h[i] >> 16); out[4*i+2] = (uint8_t)(h[i] >> 8); out[4*i+3] = (uint8_t)h[i]; }
}
