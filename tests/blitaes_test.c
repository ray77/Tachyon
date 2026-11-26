/* Bit-sliced AES Blitter program through the software Blitter model vs the byte-oriented reference. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "blitaes.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }

int main(void)
{
    static uint8_t arena[BA_ARENA], in[BA_BLOCKS * 16], out[BA_BLOCKS * 16], want[16], key[32];
    static aes_key k;
    uint32_t st = 1, i;
    int bits, bad, first;
    for (bits = 128; bits <= 256; bits += 128) {
        for (i = 0; i < 32; i++) { st = st * 1103515245u + 12345u; key[i] = (uint8_t)(st >> 16); }
        for (i = 0; i < sizeof in; i++) { st = st * 1103515245u + 12345u; in[i] = (uint8_t)(st >> 16); }
        memset(in, 0, 16);                          /* block 0: all zero; block 1: FIPS 197 C.1/C.3 plaintext */
        for (i = 0; i < 16; i++) in[16 + i] = (uint8_t)(i * 0x11);
        aes_set_key(&k, key, bits);
        ba_encrypt_soft(&k, arena, in, out);
        bad = 0; first = -1;
        for (i = 0; i < BA_BLOCKS; i++) {
            aes_encrypt_block_c(&k, in + 16 * i, want);
            if (memcmp(out + 16 * i, want, 16)) { bad++; if (first < 0) first = (int)i; }
        }
        printf("  AES-%d: %d of %d blocks wrong%s", bits, bad, BA_BLOCKS, bad ? "" : "\n");
        if (bad) { printf(", first block %d\n  got  ", first); for (i = 0; i < 16; i++) printf("%02x", out[16 * first + i]); aes_encrypt_block_c(&k, in + 16 * first, want); printf("\n  want "); for (i = 0; i < 16; i++) printf("%02x", want[i]); printf("\n"); }
        result(bad == 0, bits == 128 ? "bit-sliced AES-128 (Blitter program, software model) == reference" : "bit-sliced AES-256 == reference");
    }
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
