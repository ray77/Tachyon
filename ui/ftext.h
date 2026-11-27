/*
 * Tachyon - text and fills straight into the four bitplanes (ui/ftext.c), the fast path of the client GUI.
 *
 * Why it is allowed to bypass graphics.library: the client draws into one borderless backdrop window that covers
 * the whole 640x256 custom screen; its layer is a single ClipRect at offset 0/0 on the screen's BitMap, nothing
 * overlaps it (title bar hidden behind it, menus trapped, no other window on the screen, system requesters open on
 * the Workbench screen). So the window RastPort's planes are the screen planes and a cell at column c, row y is the
 * byte y * BytesPerRow + c in every plane - no clipping, no layer lock, no blitter. The only hazard is a blit that
 * graphics.library started and that is still running (RectFill, ScrollRaster return before the blitter is done):
 * callers run scr_wait_blit() once after their last scr_* call and before the first ftext_* write (ui/gui.c does).
 *
 * Measured against Text() in docs/UI.md ("Client-Oberfläche"). All x positions are character columns (8 px),
 * y is a pixel row; everything is clipped to 80 columns and 256 rows. Freestanding.
 */
#ifndef TACHYON_FTEXT_H
#define TACHYON_FTEXT_H

#include <exec/types.h>

#define FTEXT_COLS 80
#define FTEXT_ROWS 256
#define FTEXT_BOLD 1            /* style flag: glyph OR glyph >> 1, like Topaz' BoldSmear */

void ftext_init(UBYTE **planes, int depth, UWORD bytes_per_row);   /* planes[0..depth-1] */
int  ftext_ready(void);

/* n cells of text at column col, pixel row y (8 rows), fg over bg (JAM2) */
void ftext_text(int col, int y, int fg, int bg, const UBYTE *s, int n, int style);
/* ncols cells wide, h pixel rows tall, filled with pen */
void ftext_fill(int col, int y, int ncols, int h, int pen);
/* ncols cells of n chars of text, the remaining cells filled with bg (one call for a whole text field) */
void ftext_field(int col, int y, int ncols, int fg, int bg, const UBYTE *s, int n, int style);
/* moves the rows y..y+h-1 of columns col..col+ncols-1 up by dy pixel rows (CPU copy); the vacated rows get bg */
void ftext_scroll_up(int col, int y, int ncols, int h, int dy, int bg);

#endif
