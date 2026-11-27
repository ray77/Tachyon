/*
 * Tachyon - the 8x8 glyph table the client's own text renderer (ui/ftext.c) and the host renderer use.
 *
 * 256 glyphs of 8 bytes (one byte per row, bit 7 = left pixel). 0x20..0xFF come from the system's Topaz 8 at run
 * time: on the Amiga from the ROM TextFont that ui/screen.c opened (tf_CharData/tf_CharLoc, no font data in the
 * binary), on the host from a table tools/topaz_from_rom.py extracted from the Kickstart ROM. 0x01..0x1F are our
 * own symbols (message status ticks, badge caps, arrows) that Topaz does not have; the graphics.library Text() path
 * cannot draw them, ui/gui.c falls back to ASCII there. Freestanding, no libc.
 */
#ifndef TACHYON_FONT8_H
#define TACHYON_FONT8_H

#include <exec/types.h>

#define F8_TICK      0x01   /* single check mark: sent */
#define F8_DTICK     0x02   /* double check mark: delivered / read */
#define F8_CLOCK     0x03   /* pending */
#define F8_CAP_L     0x04   /* left round cap of a badge pill */
#define F8_CAP_R     0x05   /* right round cap */
#define F8_DOT       0x06   /* bullet (connection state) */
#define F8_ARROW_DN  0x07
#define F8_ARROW_UP  0x08
#define F8_ARROW_RT  0x09
#define F8_HLINE     0x0A   /* horizontal rule through the middle of the cell */
#define F8_BANG      0x0B   /* bold exclamation mark: failed */
#define F8_BLOCK     0x0C   /* full cell (cursor) */
#define F8_ULINE     0x0D   /* underline cursor (overwrite mode) */
#define F8_TAIL_L    0x0E   /* bubble tail pointing left (incoming) */
#define F8_TAIL_R    0x0F   /* bubble tail pointing right (own) */

extern UBYTE font8_glyphs[256][8];

/* Fills the table: the own symbols, then 0x20..0xFF from a TextFont-style description (lo..hi, bit offsets from
 * charloc[i] >> 16, one plane row every `modulo` bytes). Codes outside lo..hi get the glyph of hi + 1 (the font's
 * default) or stay blank. Returns the number of glyphs taken from the font. */
int  font8_load(UBYTE lo, UBYTE hi, const UBYTE *chardata, UWORD modulo, const ULONG *charloc);
void font8_load_symbols(void);          /* only 0x00..0x1F, used by font8_load as well */
int  font8_ready(void);                 /* 1 after a successful font8_load */

#endif
