/*
 * Tachyon - 8x8 glyph table (ui/font8.h). The Topaz glyphs are copied from the system font at run time; the own
 * symbols below are drawn to sit next to Topaz 8 (6 px wide glyphs with a 1 px gap on the right, cap height 7).
 */
#include "font8.h"

UBYTE font8_glyphs[256][8];
static int font8_is_ready;

static const UBYTE font8_symbols[16][8] = {
    { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 },        /* 0x00 blank */
    { 0x00,0x00,0x02,0x04,0x88,0x50,0x20,0x00 },        /* 0x01 tick */
    { 0x00,0x00,0x05,0x0A,0x94,0xA8,0x50,0x00 },        /* 0x02 double tick */
    { 0x00,0x38,0x44,0x54,0x5C,0x44,0x38,0x00 },        /* 0x03 clock */
    { 0x00,0x3E,0x7E,0xFE,0xFE,0x7E,0x3E,0x00 },        /* 0x04 cap left */
    { 0x00,0x7C,0x7E,0x7F,0x7F,0x7E,0x7C,0x00 },        /* 0x05 cap right */
    { 0x00,0x00,0x38,0x7C,0x7C,0x38,0x00,0x00 },        /* 0x06 dot */
    { 0x00,0x00,0x00,0x7C,0x38,0x10,0x00,0x00 },        /* 0x07 arrow down */
    { 0x00,0x00,0x10,0x38,0x7C,0x00,0x00,0x00 },        /* 0x08 arrow up */
    { 0x00,0x20,0x30,0x38,0x30,0x20,0x00,0x00 },        /* 0x09 arrow right */
    { 0x00,0x00,0x00,0xFF,0x00,0x00,0x00,0x00 },        /* 0x0A horizontal rule */
    { 0x00,0x18,0x18,0x18,0x18,0x00,0x18,0x00 },        /* 0x0B bang */
    { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF },        /* 0x0C block */
    { 0x00,0x00,0x00,0x00,0x00,0x00,0xFE,0xFE },        /* 0x0D underline */
    { 0x00,0x01,0x03,0x07,0x0F,0x00,0x00,0x00 },        /* 0x0E tail left: a bubble corner opening to the left */
    { 0x00,0x80,0xC0,0xE0,0xF0,0x00,0x00,0x00 }         /* 0x0F tail right */
};

void font8_load_symbols(void)
{
    int c, r;
    for (c = 0; c < 16; c++) for (r = 0; r < 8; r++) font8_glyphs[c][r] = font8_symbols[c][r];
    for (c = 16; c < 32; c++) for (r = 0; r < 8; r++) font8_glyphs[c][r] = 0;
}

int font8_load(UBYTE lo, UBYTE hi, const UBYTE *chardata, UWORD modulo, const ULONG *charloc)
{
    int c, r, n = 0;
    font8_load_symbols();
    for (c = 32; c < 256; c++) for (r = 0; r < 8; r++) font8_glyphs[c][r] = 0;
    if (!chardata || !charloc || lo > hi) { font8_is_ready = 0; return 0; }
    for (c = 32; c < 256; c++) {
        ULONG loc, bit, byte, shift;
        int idx = c;
        if (c < lo || c > hi) idx = hi + 1;                 /* the font's default glyph follows tf_HiChar */
        loc = charloc[idx - lo];
        if ((loc & 0xFFFF) == 0) continue;                  /* zero width: blank */
        bit = loc >> 16; byte = bit >> 3; shift = bit & 7;
        for (r = 0; r < 8; r++) {
            const UBYTE *row = chardata + (ULONG)r * modulo + byte;
            if (shift == 0) font8_glyphs[c][r] = row[0];           /* the usual case: byte aligned glyphs */
            else font8_glyphs[c][r] = (UBYTE)((((UWORD)row[0] << 8) | row[1]) >> (8 - shift));
        }
        n++;
    }
    font8_is_ready = n > 0;
    return n;
}

int font8_ready(void) { return font8_is_ready; }
