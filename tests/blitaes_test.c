/* Bit-sliced AES Blitter program (v2, Blitter-side transposition) through the software model. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "blitaes.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }

/* the transposition alone must be an involution: TIN then TOUT restores the data */
static void test_transpose(uint8_t *arena, const uint8_t *in)
{
    static uint8_t t[BA_BLOCKS * 16];
    int i, same = 1, changed = 0;
    { aes_key kk; memset(&kk, 0, sizeof kk); kk.rounds = 14; ba_setup(&kk, arena); }   /* masks */
    memcpy(arena + BA_STATE, in, sizeof t);
    ba_exec_soft(arena, ba_prog + BA_SEC_TIN, BA_NTIN, 0);
    for (i = 0; i < (int)sizeof t; i++) if (arena[BA_STATE + i] != in[i]) changed = 1;
    /* lane check: row k=0, q=0, w=0 holds bit 7 of byte 0 of blocks 0, 64, ..., 960 (block j -> bit 15-j) */
    { uint16_t wv = (uint16_t)((arena[0] << 8) | arena[1]); int j, exp0 = 0;
      for (j = 0; j < 16; j++) exp0 |= ((in[(64 * j) * 16] >> 7) & 1) << (15 - j);
      result(wv == exp0, "lane (k=0,q=0,w=0) = bit 7 of byte 0 across blocks 64j, block j at bit 15-j"); }
    ba_exec_soft(arena, ba_prog + BA_SEC_TOUT, BA_NTOUT, 0);
    for (i = 0; i < (int)sizeof t; i++) if (arena[BA_STATE + i] != in[i]) same = 0;
    result(changed, "transposition changes the data");
    result(same, "transpose in + out is the identity");
}

int main(void)
{
    static uint8_t arena[BA_ARENA], in[BA_BLOCKS * 16], out[BA_BLOCKS * 16], want[16], key[32];
    static aes_key k;
    uint32_t st = 1, i;
    int bits, bad, first;
    for (i = 0; i < sizeof in; i++) { st = st * 1103515245u + 12345u; in[i] = (uint8_t)(st >> 16); }
    test_transpose(arena, in);
    for (bits = 128; bits <= 256; bits += 128) {
        for (i = 0; i < 32; i++) { st = st * 1103515245u + 12345u; key[i] = (uint8_t)(st >> 16); }
        memset(in, 0, 16);
        for (i = 0; i < 16; i++) in[16 + i] = (uint8_t)(i * 0x11);
        aes_set_key(&k, key, bits);
        ba_encrypt_soft(&k, arena, in, out);
        bad = 0; first = -1;
        for (i = 0; i < BA_BLOCKS; i++) {
            aes_encrypt_block_c(&k, in + 16 * i, want);
            if (memcmp(out + 16 * i, want, 16)) { bad++; if (first < 0) first = (int)i; }
        }
        printf("  AES-%d: %d of %d blocks wrong\n", bits, bad, BA_BLOCKS);
        if (bad) { printf("  first block %d\n  got  ", first); for (i = 0; i < 16; i++) printf("%02x", out[16 * first + i]); aes_encrypt_block_c(&k, in + 16 * first, want); printf("\n  want "); for (i = 0; i < 16; i++) printf("%02x", want[i]); printf("\n"); }
        result(bad == 0, bits == 128 ? "bit-sliced AES-128 (Blitter program v2, software model) == reference" : "bit-sliced AES-256 == reference");
    }
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
