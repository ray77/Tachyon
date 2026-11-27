/*
 * WhatsA500 - AES-GCM with the CTR keystream on the Blitter (docs/CUSTOM-CHIPS.md 2c).
 *
 * Library form of the Copper-driven chain proven in bench/blitaes_bench.c: per batch of
 * 1024 blocks (16 KiB) the CPU writes the counter lanes straight into the transposed state
 * (asm, ~20 ms), the Copper drives the Blitter from SBOX to TOUT (14 round sections, one
 * AUD3 flag each), the ciphertext is keystream XOR plaintext (one blit when both buffers
 * are in Chip RAM, otherwise an asm XOR on the CPU). While the chain runs the CPU does
 * GHASH of the previous batch and encrypts its own blocks behind the batch with the
 * T-tables, so the message is split dynamically between Blitter and CPU. Remainder
 * (< 16 KiB or not worth a chain), J0/length block and tag on the CPU.
 *
 * Semantics are those of aes_gcm_encrypt/decrypt (12-byte IV, AAD, 16-byte tag; in/out may
 * alias). One difference: on a tag mismatch blitgcm_decrypt has already written plaintext
 * (it overlaps GHASH with the chain) and therefore zeroes the output before returning 0.
 *
 * Host build: the chain runs through the software Blitter (ba_exec_soft) and the
 * "chain still running" condition is simulated by ctx->soft_polls, so every code path
 * (deferred GHASH, CPU-own blocks, partial batches) is testable in tests/blitgcm_test.c.
 * Amiga build: compile with -DBLITGCM_HW (needs graphics.library open in GfxBase and
 * crypto/m68k/blitgcm.s + blitexec.s linked).
 */
#ifndef WHATSA500_BLITGCM_H
#define WHATSA500_BLITGCM_H
#include <stdint.h>
#include "aes.h"
#include "blitaes.h"

#define BLITGCM_ARENA_BYTES BA_ARENA                    /* Chip RAM, keys/masks/state/temporaries */
#define BLITGCM_COP_BLOCK   88                          /* one Copper block per blit (44 words) */
#define BLITGCM_COP_BYTES   (8 + (BA_NSBOX + 1 + BA_NMIX + 1 + BA_NFINAL + 1 + BA_NTOUT + 1) * BLITGCM_COP_BLOCK)
#define BLITGCM_MIXKEYS     128                         /* MIX entries whose C pointer is a round-key lane */

/* parameters of one batch of counter lanes; built in C, filled by C (host) or asm (68000) */
typedef struct {
    uint16_t cst[12][8];        /* nonce bytes 0..11 XOR key: lane word for row r (bit 7 - r) */
    uint16_t tab[2][26];        /* counter bits 6..31 over 16 blocks for u0 and u0 + 1, key folded in */
    uint16_t klo[6];            /* key masks for counter bits 0..5 */
    uint32_t ctr;               /* counter of block 0 of the batch */
} bg_ctr_params;

typedef struct {
    const aes_gcm_key *g;
    uint8_t *arena;             /* BLITGCM_ARENA_BYTES of Chip RAM */
    uint8_t *cop;               /* BLITGCM_COP_BYTES of Chip RAM (unused on the host) */
    uint32_t chip_lo, chip_hi;  /* [lo, hi): buffers inside are XORed by one blit; default 0..2 MiB on the Amiga */
    int cpu_blocks;             /* 1 (default): the CPU encrypts its own blocks while the chain runs */
    int soft_polls;             /* host model only: number of polls the simulated chain stays busy */
    uint32_t (*now)(void);      /* optional tick source for the statistics below (NULL: off) */
    /* statistics of the last call */
    uint32_t batches, partial, cpu_own, ghash_overlap, timeouts, blit_xor;
    uint32_t t_lanes, t_chain, t_xor, t_tail, t_total;
    /* internal */
    int rnd;
    uint32_t mixkey_base[BLITGCM_MIXKEYS];
    uint16_t *mixkey_word[BLITGCM_MIXKEYS];
    uint16_t *cop_idle, *cop_sbox, *cop_mix, *cop_fin, *cop_tout;
    uint16_t *old_lof, *old_shf;
    uint16_t olddma;
    uint32_t frame, lastv;
    int hw_active;
} blitgcm_ctx;

/* arena and cop must be Chip RAM (any memory on the host); writes key lanes and masks into the arena
 * and builds the Copper lists. Returns 1, or 0 if a pointer is missing. */
int blitgcm_init(blitgcm_ctx *c, const aes_gcm_key *g, uint8_t *arena, uint8_t *cop);

void blitgcm_encrypt(blitgcm_ctx *c, const uint8_t iv[12], const uint8_t *aad, uint32_t aadlen,
                     const uint8_t *pt, uint32_t len, uint8_t *ct, uint8_t tag[16]);
/* returns 1 on success, 0 on tag mismatch (then pt[0..len) is zero) */
int  blitgcm_decrypt(blitgcm_ctx *c, const uint8_t iv[12], const uint8_t *aad, uint32_t aadlen,
                     const uint8_t *ct, uint32_t len, const uint8_t tag[16], uint8_t *pt);

/* counter lanes: parameters and the portable filler (the asm filler is bg_ctr_fill_asm in crypto/m68k/blitgcm.s) */
void blitgcm_ctr_params(bg_ctr_params *p, const aes_key *k, const uint8_t j0[12], uint32_t ctr);
void blitgcm_ctr_fill_c(uint8_t *arena, const bg_ctr_params *p);

#ifdef BLITGCM_HW
void bg_ctr_fill_asm(__reg("a0") uint8_t *arena, __reg("a1") const bg_ctr_params *p);
void bg_xor_asm(__reg("a0") uint8_t *dst, __reg("a1") const uint8_t *ks, __reg("a2") const uint8_t *src, __reg("d0") uint32_t nlongs);
#endif

#endif
