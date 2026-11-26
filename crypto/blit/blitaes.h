/*
 * WhatsA500 - bit-sliced AES on the Blitter (research track, docs/CUSTOM-CHIPS.md).
 * Program from tools/blitaes/gen_blitaes.py (v2: the Blitter also transposes the
 * data into lanes, so the CPU only copies 16 KiB in and out). This file holds the
 * CPU side (constants, round keys) and a software model of the Blitter so the whole
 * construction is testable on the host.
 */
#ifndef WHATSA500_BLITAES_H
#define WHATSA500_BLITAES_H
#include <stdint.h>
#include "aes.h"
#include "blitaes_prog.h"

#define BA_BLOCKS (16 * BA_L)            /* 1024 blocks = 16 KiB per batch */

/* fills KEYS (15 x 128 lane words), KEYPAT (key repeated 8x) and MASKS in the arena */
void ba_setup(const aes_key *k, uint8_t *arena);
/* software Blitter: runs n entries of p; round selects the key lanes */
void ba_exec_soft(uint8_t *arena, const ba_blit *p, int n, int round);
/* full encryption of BA_BLOCKS blocks through the software model; in/out may alias */
void ba_encrypt_soft(const aes_key *k, uint8_t *arena, const uint8_t *in, uint8_t *out);

#endif
