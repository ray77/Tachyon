/*
 * Tachyon - host implementation of the screen API (ui/screen.h) for rendering and testing the GUI on the Mac:
 * four 640x256 bitplanes in memory exactly like the Amiga screen (80 bytes per row), the scr_* calls draw into
 * them, scr_host_write_ppm writes the picture, scr_host_cell reads a character cell back by matching the glyph
 * table (ui/font8.c) - the host test asserts on text at screen positions. Keys for scr_wait_key come from a queue.
 * Compile with -DTACHYON_HOST -Iui/host (ui/host/exec/types.h) and the generated build/topaz8_font.h.
 */
#ifndef TACHYON_SCREEN_HOST_H
#define TACHYON_SCREEN_HOST_H

#include "screen.h"

int  scr_host_write_ppm(const char *path);                 /* P6, one pixel per plane pixel (640x256) */
int  scr_host_pixel(int x, int y);                         /* pen 0..15 or -1 */
/* the cell at column col (8 px) and pixel row y: fills fg and bg and returns the character whose glyph matches,
 * ' ' for a uniform cell, -1 if the cell is no single glyph on a single background */
int  scr_host_cell(int col, int y, int *fg, int *bg);
/* reads ncols cells into out (NUL terminated; unknown cells as '?'), returns the number of matched cells */
int  scr_host_row(int col, int y, int ncols, char *out);
void scr_host_push_key(LONG key, UWORD qualifier);         /* queue for scr_wait_key */
void scr_host_set_qualifier(UWORD qualifier);              /* for a key passed to gui_pump directly */
void scr_host_set_mouse(WORD x, WORD y);                    /* position for a SCR_KEY_MOUSE passed to gui_pump */
ULONG scr_host_calls(void);                                /* number of scr_* drawing calls so far (cost model) */
ULONG scr_host_chars(void);                                /* characters drawn through scr_text/scr_text_bg */
void scr_host_reset_counters(void);
const char *scr_host_font_source(void);                    /* FONT8_ROM_SOURCE */

#endif
