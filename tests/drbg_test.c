/* HMAC_DRBG against vectors from tools/hmac_drbg_ref.py (independent implementation of SP 800-90A) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "drbg.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }
static int unhex(uint8_t *out, const char *h, int maxlen)
{
    int n = 0;
    while (h[0] && h[1] && n < maxlen && h[0] != ' ' && h[0] != '\n') {
        unsigned v; char t[3] = { h[0], h[1], 0 };
        v = (unsigned)strtoul(t, 0, 16); out[n++] = (uint8_t)v; h += 2;
    }
    return n;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/vectors/hmac_drbg.txt", "r");
    char line[2048];
    int n = 0, bad = 0;
    if (!f) { printf("FAIL cannot open vector file\n"); return 1; }
    while (fgets(line, sizeof line, f)) {
        uint8_t seed[128], reseed[64], o1[64], o2[64], o3[64], got[64];
        int sl, rl;
        char *p = line, *tok[5]; int i;
        for (i = 0; i < 5; i++) { tok[i] = p; p = strchr(p, ' '); if (p) *p++ = 0; else break; }
        if (i < 4) break;
        sl = unhex(seed, tok[0], 128); rl = unhex(reseed, tok[1], 64);
        unhex(o1, tok[2], 64); unhex(o2, tok[3], 64); unhex(o3, tok[4], 64);
        {
            hmac_drbg d;
            d.instantiated = 0;
            drbg_instantiate(&d, seed, (uint32_t)sl);
            drbg_generate(&d, got, 64); if (memcmp(got, o1, 64)) bad++;
            drbg_generate(&d, got, 64); if (memcmp(got, o2, 64)) bad++;
            drbg_reseed(&d, reseed, (uint32_t)rl);
            drbg_generate(&d, got, 64); if (memcmp(got, o3, 64)) bad++;
        }
        n++;
    }
    fclose(f);
    printf("%s hmac_drbg Python cross-check: %d vectors, %d mismatches\n", bad ? "FAIL" : "PASS", n, bad);
    if (bad) failures++;
    {   /* pool: different inputs give different seeds, same inputs the same; generate refuses uninstantiated */
        rng_pool p1, p2; hmac_drbg d1, d2; uint8_t a[32], b[32];
        const uint8_t s1[4] = { 1, 2, 3, 4 }, s2[4] = { 1, 2, 3, 5 };
        d1.instantiated = 0; d2.instantiated = 0;
        result(drbg_generate(&d1, a, 32) == 0, "generate refuses an uninstantiated DRBG");
        rng_pool_init(&p1); rng_pool_init(&p2);
        rng_add(&p1, s1, 4); rng_add(&p2, s1, 4);
        rng_seed_drbg(&p1, &d1); rng_seed_drbg(&p2, &d2);
        drbg_generate(&d1, a, 32); drbg_generate(&d2, b, 32);
        result(memcmp(a, b, 32) == 0, "pool: identical samples -> identical stream (deterministic)");
        rng_pool_init(&p2); rng_add(&p2, s2, 4); d2.instantiated = 0; rng_seed_drbg(&p2, &d2);
        drbg_generate(&d2, b, 32);
        result(memcmp(a, b, 32) != 0, "pool: one bit of input difference -> different stream");
        rng_add(&p1, s2, 4); rng_seed_drbg(&p1, &d1);    /* reseed path */
        drbg_generate(&d1, b, 32);
        result(memcmp(a, b, 32) != 0, "pool: reseed changes the stream");
    }
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
