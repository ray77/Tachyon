/*
 * WhatsA500 - bit-sliced AES on the Blitter (research track, docs/CUSTOM-CHIPS.md).
 * The Blitter program comes from tools/blitaes/gen_blitaes.py; this file holds
 * the CPU side (lane packing, round keys, execution) with a software model of
 * the Blitter so the whole construction is testable on the host.
 */
#ifndef WHATSA500_BLITAES_H
#define WHATSA500_BLITAES_H
#include <stdint.h>
#include "aes.h"
#include "blitaes_prog.h"

#define BA_BLOCKS (16 * BA_L)            /* blocks per batch */

/* round key lanes: 15 x 128 words, lane (b,r,c) of round k is 0xFFFF if bit b of rk[16k+4c+r] is set */
void ba_keys(const aes_key *k, uint16_t *keys);
/* pack BA_BLOCKS plaintext blocks (XORed with the whitening key rk[0]) into the STATE lanes */
void ba_pack(const aes_key *k, const uint8_t *in, uint16_t *state);
void ba_unpack(const uint16_t *state, uint8_t *out);
/* run one program section with the software Blitter model (arena = base of the Chip RAM layout) */
void ba_exec_soft(uint8_t *arena, const ba_blit *p, int n, int round);
/* full encryption of BA_BLOCKS blocks through the software model */
void ba_encrypt_soft(const aes_key *k, uint8_t *arena, const uint8_t *in, uint8_t *out);

#endif
