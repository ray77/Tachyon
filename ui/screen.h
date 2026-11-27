/*
 * Tachyon - the client's screen on Kickstart 1.3: one Intuition custom screen, 640x256 (PAL hires,
 * non-interlaced), 4 bitplanes = 16 colours, no title bar, with one borderless backdrop window the size of
 * the screen that receives the keyboard (IDCMP). Everything is drawn through graphics.library into the
 * window's RastPort, so Intuition, the TCP/IP stack and the CLI keep running underneath; nothing touches
 * the copper lists or the interrupts (docs/UI.md, "Bildschirm").
 *
 * Coordinates are screen pixels, origin top left; the text functions take the top-left corner of the
 * character cell (Topaz 8: 8x8, 80 columns x 32 rows). Pens are 0..15 (scr_set_palette / SCR_PAL_*).
 * Freestanding: no C library; SysBase is read from address 4. Not reentrant - one screen per program.
 */
#ifndef TACHYON_SCREEN_H
#define TACHYON_SCREEN_H

#include <exec/types.h>
#ifndef TACHYON_HOST
#include "amiga13.h"          /* the host build (ui/screen_host.c, -DTACHYON_HOST) has no Amiga structures */
#else
struct Screen; struct Window; struct RastPort;
#endif

#define SCR_W     640
#define SCR_H     256
#define SCR_DEPTH 4

/* scr_open() error codes (0 = ok) */
#define SCR_ERR_INTUITION 1     /* intuition.library V33 did not open */
#define SCR_ERR_GRAPHICS  2     /* graphics.library V33 did not open */
#define SCR_ERR_SCREEN    3     /* OpenScreen failed (Chip RAM: 80 KiB of bitplanes) */
#define SCR_ERR_WINDOW    4     /* OpenWindow failed */

/* scr_wait_key() results */
#define SCR_KEY_TIMEOUT  0          /* nothing within the timeout */
#define SCR_KEY_RAW      0x100      /* 0x100 | raw code: a key without a character (cursor, F-keys, Help...) */
#define SCR_KEY_UP       0x4C       /* raw codes of the cursor keys, returned as SCR_KEY_RAW | code */
#define SCR_KEY_DOWN     0x4D
#define SCR_KEY_RIGHT    0x4E
#define SCR_KEY_LEFT     0x4F
#define SCR_KEY_HELP     0x5F
#define SCR_FOREVER      0xFFFFFFFFUL

/* default palette (12-bit 0RGB words for LoadRGB4): 0 black, 1 background, 2 white, 3 WhatsApp green, ... */
#define SCR_PAL_BLACK  0
#define SCR_PAL_BG     1
#define SCR_PAL_WHITE  2
#define SCR_PAL_GREEN  3
#define SCR_PAL_DKGREEN 4
#define SCR_PAL_TEAL   5
#define SCR_PAL_LTGREY 6
#define SCR_PAL_GREY   7
#define SCR_PAL_DKGREY 8
#define SCR_PAL_RED    9
#define SCR_PAL_YELLOW 10
#define SCR_PAL_BLUE   11
#define SCR_PAL_LTBLUE 12
#define SCR_PAL_ORANGE 13
#define SCR_PAL_BEIGE  14
#define SCR_PAL_LTGREEN 15

int  scr_open(void);                                   /* libraries, screen, window, font, palette, console.device */
void scr_close(void);                                  /* everything in reverse; safe after a failed scr_open */
void scr_set_palette(const UWORD *rgb4, int count);    /* count <= 16 entries 0x0RGB */

void scr_clear(int pen);
void scr_fill(int x, int y, int w, int h, int pen);    /* clipped to the screen; w, h <= 0 draw nothing */
void scr_hline(int x, int y, int w, int pen);
void scr_vline(int x, int y, int h, int pen);
int  scr_text(int x, int y, int pen, const char *s);          /* JAM1: only the glyph pixels; returns the width in px */
int  scr_text_bg(int x, int y, int pen, int bg, const char *s); /* JAM2: cell background in bg */
int  scr_text_width(const char *s);

/* 1-bit module matrix (QR code): w_modules x h_modules, row-major, each row padded to whole bytes, MSB
 * first, 1 = dark. Every module becomes scale x scale pixels in pen_on / pen_off. Fast path: the matrix
 * is expanded into a Chip RAM template and drawn with one BltTemplate; scr_bitmap_1bpp_rects() is the
 * RectFill fallback (also used when no Chip RAM is left). Both return 0 if the area is off screen. */
int  scr_bitmap_1bpp(int x, int y, int w_modules, int h_modules, const UBYTE *bits, int scale, int pen_on, int pen_off);
int  scr_bitmap_1bpp_rects(int x, int y, int w_modules, int h_modules, const UBYTE *bits, int scale, int pen_on, int pen_off);
/* General form: stride = bytes per source row (ui/qr.h: QR_STRIDE 10), scale_x x scale_y pixels per module.
 * PAL hires pixels are about 0.52:1, so a QR module should be 8x4 (docs/UI.md): scale_x 8 writes one byte per
 * module, scale_x 4/2/1 use lookup tables, other widths the generic bit loop. */
int  scr_bitmap_1bpp_ex(int x, int y, int w_modules, int h_modules, const UBYTE *bits, int stride, int scale_x, int scale_y, int pen_on, int pen_off);
int  scr_bitmap_1bpp_rects_ex(int x, int y, int w_modules, int h_modules, const UBYTE *bits, int stride, int scale_x, int scale_y, int pen_on, int pen_off);

/* Waits up to timeout_ticks frames (1/50 s PAL, SCR_FOREVER = no timeout, 0 = poll) for a key press on the
 * window. Returns the character (ASCII: 8 backspace, 9 tab, 13 return, 27 escape, 127 del, 32..126, and
 * the ISO-8859-1 code for umlauts etc. under a national keymap), SCR_KEY_RAW | code for keys without a
 * character, SCR_KEY_TIMEOUT when nothing arrived. Key releases and pure qualifier presses are skipped. */
LONG scr_wait_key(ULONG timeout_ticks);

/* which translation produced the last key: 'V' IDCMP VANILLAKEY (Intuition's keymap), 'C' console.device
 * RawKeyConvert with the system keymap, 'T' the built-in US table (console.device unavailable), 0 none */
int  scr_last_key_source(void);
LONG scr_translate_raw(UWORD code, UWORD qualifier);   /* same translation for a raw code (self-test, replay) */

/* ScrollRaster through the layer: the rows y..y+h-1 of x..x+w-1 move up by dy pixels, the vacated rows get bg.
 * x and w should be multiples of 16 (word-aligned blit). */
void scr_scroll_up(int x, int y, int w, int h, int dy, int bg);
/* The screen's bitplanes for a renderer that writes cells directly (ui/ftext.c, see there why that is safe here):
 * fills planes[0..depth-1] (max entries) and the bytes per row, returns the depth, 0 without a screen. */
int  scr_planes(UBYTE **planes, int max, UWORD *bytes_per_row);
void scr_wait_blit(void);                              /* WaitBlit: before CPU writes into planes a blit may still touch */
/* The IDCMP qualifier of the last key scr_wait_key returned (IEQUALIFIER_* bits: 0x0003 shift, 0x0008 ctrl,
 * 0x0030 alt, 0x00C0 Amiga keys), so Shift+cursor and Amiga+letter can be told apart from the plain key. */
UWORD scr_last_qualifier(void);
#define SCR_QUAL_SHIFT 0x0003
#define SCR_QUAL_CTRL  0x0008
#define SCR_QUAL_ALT   0x0030
#define SCR_QUAL_AMIGA 0x00C0
/* The glyphs of the screen's Topaz 8 (TextFont fields) for ui/font8.c: 1 and the fields, 0 without a font. */
int  scr_font_glyphs(UBYTE *lo, UBYTE *hi, const UBYTE **chardata, UWORD *modulo, const ULONG **charloc);

struct Screen   *scr_screen(void);
struct Window   *scr_window(void);
struct RastPort *scr_rastport(void);
int  scr_font_height(void);                            /* TxHeight of the window RastPort (8 for Topaz 8) */
int  scr_font_width(void);                             /* TxWidth (8) */
int  scr_console_ok(void);                             /* 1 when console.device opened for RawKeyConvert */

#endif
