/* AES-GCM with the Blitter keystream (crypto/blit/blitgcm.c) through the software Blitter model,
 * against aes_gcm_encrypt/decrypt. ctx.soft_polls simulates how long the chain stays busy, so the
 * deferred GHASH, the CPU-own blocks behind a batch and the partial final batch are all exercised. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "blitgcm.h"

#define MAXLEN 40000
static int failures, cases;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }
static uint32_t st = 1;
static uint8_t rnd8(void) { st = st * 1103515245u + 12345u; return (uint8_t)(st >> 16); }
static void fill(uint8_t *p, uint32_t n) { uint32_t i; for (i = 0; i < n; i++) p[i] = rnd8(); }

static uint8_t arena[BA_ARENA], pt[MAXLEN + 64], ct[MAXLEN + 64], ref[MAXLEN + 64], dec[MAXLEN + 64], aad[64], key[32], iv[12];
static aes_gcm_key gk;
static blitgcm_ctx ctx;
static uint32_t cov_batches, cov_partial, cov_cpu, cov_ghash;

/* one case: encrypt, decrypt, tampered tag; returns 0 on any mismatch and prints the details */
static int one_case(uint32_t len, uint32_t aadlen, int polls, int cpu_blocks)
{
    uint8_t tag[16], rtag[16];
    uint32_t i;
    int ok = 1, r;
    fill(pt, len); fill(iv, 12); fill(aad, aadlen);
    aes_gcm_encrypt(&gk, iv, aad, aadlen, pt, len, ref, rtag);
    ctx.soft_polls = polls; ctx.cpu_blocks = cpu_blocks;
    memset(ct, 0xee, len + 16);
    blitgcm_encrypt(&ctx, iv, aad, aadlen, pt, len, ct, tag);
    cov_batches += ctx.batches; cov_partial += ctx.partial; cov_cpu += ctx.cpu_own; cov_ghash += ctx.ghash_overlap;
    if (memcmp(ct, ref, len)) { ok = 0; for (i = 0; i < len && ct[i] == ref[i]; i++) { } printf("  ciphertext differs from byte %u (len %u aad %u polls %d)\n", i, len, aadlen, polls); }
    if (memcmp(tag, rtag, 16)) { ok = 0; printf("  tag differs (len %u aad %u polls %d)\n", len, aadlen, polls); }
    if (ct[len] != 0xee) { ok = 0; printf("  wrote past the end (len %u)\n", len); }
    memset(dec, 0xee, len + 16);
    r = blitgcm_decrypt(&ctx, iv, aad, aadlen, ct, len, tag, dec);
    cov_batches += ctx.batches; cov_partial += ctx.partial; cov_cpu += ctx.cpu_own; cov_ghash += ctx.ghash_overlap;
    if (r != 1 || memcmp(dec, pt, len)) { ok = 0; printf("  decrypt: r=%d plaintext %s (len %u aad %u polls %d)\n", r, memcmp(dec, pt, len) ? "differs" : "ok", len, aadlen, polls); }
    if (dec[len] != 0xee) { ok = 0; printf("  decrypt wrote past the end (len %u)\n", len); }
    tag[len % 16] ^= 0x40;
    r = blitgcm_decrypt(&ctx, iv, aad, aadlen, ct, len, tag, dec);
    for (i = 0; i < len && dec[i] == 0; i++) ;
    if (r != 0 || i != len) { ok = 0; printf("  tampered tag: r=%d, plaintext zeroed up to %u of %u\n", r, i, len); }
    if (aadlen) { tag[len % 16] ^= 0x40; aad[0] ^= 1; r = blitgcm_decrypt(&ctx, iv, aad, aadlen, ct, len, tag, dec); if (r != 0) { ok = 0; printf("  tampered AAD accepted (len %u)\n", len); } }
    cases++;
    return ok;
}

int main(void)
{
    static const uint32_t lens[] = { 0, 1, 15, 16, 17, 1024, 16383, 16384, 16385, 20000, 24576, 30000, 32768, 40000 };
    static const int polls[] = { 0, 7, 1500, 100000 };
    int bits, li, pi, ai, ok;
    uint32_t i;

    /* counter lanes: the parameterised filler must match ba_ctr_lanes (verified on the hardware) */
    aes_set_key(&gk.k, key, 256);
    {
        static const uint32_t ctrs[4] = { 2, 0x12345677u, 0xfffffc00u, 0xfffffff5u };
        static uint8_t lanes[16384];
        bg_ctr_params p;
        int c;
        ok = 1;
        fill(key, 32); fill(iv, 12);
        aes_set_key(&gk.k, key, 256);
        for (c = 0; c < 4; c++) {
            ba_ctr_lanes(&gk.k, arena, iv, ctrs[c]);
            memcpy(lanes, arena, sizeof lanes);
            memset(arena, 0x5a, sizeof lanes);
            blitgcm_ctr_params(&p, &gk.k, iv, ctrs[c]);
            blitgcm_ctr_fill_c(arena, &p);
            if (memcmp(lanes, arena, sizeof lanes)) ok = 0;
        }
        result(ok, "counter lanes from bg_ctr_params == ba_ctr_lanes (4 counters incl. wraps)");
    }

    for (bits = 256; bits >= 128; bits -= 128) {
        fill(key, 32);
        aes_gcm_set_key(&gk, key, bits);
        result(blitgcm_init(&ctx, &gk, arena, NULL), bits == 256 ? "blitgcm_init AES-256" : "blitgcm_init AES-128");
        for (li = 0; li < (int)(sizeof lens / sizeof lens[0]); li++) {
            char what[96];
            ok = 1;
            for (ai = 0; ai < 2; ai++) {
                int np = lens[li] >= 16384 ? 4 : 1;
                for (pi = 0; pi < np; pi++) ok &= one_case(lens[li], ai ? 20 : 0, polls[pi], 1);
            }
            sprintf(what, "AES-%d-GCM len %u: ciphertext, tag, decrypt, tampered tag/AAD == reference", bits, lens[li]);
            result(ok, what);
        }
        /* chain only, no CPU-own blocks */
        ok = one_case(40000, 20, 1500, 0) & one_case(16384, 0, 0, 0);
        result(ok, "cpu_blocks = 0 (Blitter + GHASH only)");
        /* random lengths */
        ok = 1;
        for (i = 0; i < 12; i++) { uint32_t len = ((uint32_t)rnd8() << 8 | rnd8()) % (MAXLEN + 1); ok &= one_case(len, rnd8() % 33, polls[rnd8() & 3], 1); }
        result(ok, "12 random lengths / AAD lengths / chain latencies");
    }

    /* in place: in == out */
    {
        uint8_t tag[16], rtag[16];
        fill(pt, 40000); fill(iv, 12); fill(aad, 20);
        aes_gcm_encrypt(&gk, iv, aad, 20, pt, 40000, ref, rtag);
        memcpy(ct, pt, 40000);
        ctx.soft_polls = 1500; ctx.cpu_blocks = 1;
        blitgcm_encrypt(&ctx, iv, aad, 20, ct, 40000, ct, tag);
        ok = memcmp(ct, ref, 40000) == 0 && memcmp(tag, rtag, 16) == 0;
        ok &= blitgcm_decrypt(&ctx, iv, aad, 20, ct, 40000, tag, ct) == 1 && memcmp(ct, pt, 40000) == 0;
        ctx.soft_polls = 0;
        memcpy(ct, pt, 40000);
        blitgcm_encrypt(&ctx, iv, aad, 20, ct, 40000, ct, tag);
        ok &= memcmp(ct, ref, 40000) == 0;
        ok &= blitgcm_decrypt(&ctx, iv, aad, 20, ct, 40000, tag, ct) == 1 && memcmp(ct, pt, 40000) == 0;
        result(ok, "in-place encrypt/decrypt (in == out), with and without CPU-own blocks");
    }
    printf("  %d cases; coverage: %u batches, %u partial, %u CPU-own blocks, %u GHASH blocks under the chain\n", cases, cov_batches, cov_partial, cov_cpu, cov_ghash);
    result(cov_batches > 0 && cov_partial > 0 && cov_cpu > 0 && cov_ghash > 0, "all pipeline paths exercised");
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
