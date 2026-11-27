/*
 * Tachyon - direct bitplane text renderer (ui/ftext.h).
 *
 * One cell: for every plane p the byte is glyph (fg bit set, bg bit clear), ~glyph (bg set, fg clear), 0xFF or
 * 0x00 (both equal). 8 rows x depth planes = 32 byte stores for Topaz 8 on 4 planes; the glyph row comes from
 * ui/font8.c's table. On the 68000 a cell is ~60 us against Text()'s 400 us per character plus 1.5 ms per call.
 */
#include "ftext.h"
#include "font8.h"

static UBYTE *ft_planes[8];
static int    ft_depth;
static UWORD  ft_bpr;

void ftext_init(UBYTE **planes, int depth, UWORD bytes_per_row)
{
    int p;
    if (depth > 8) depth = 8;
    for (p = 0; p < depth; p++) ft_planes[p] = planes[p];
    ft_depth = depth; ft_bpr = bytes_per_row;
}

int ftext_ready(void) { return ft_depth > 0 && ft_planes[0] != 0 && font8_ready(); }

static int ft_clip(int *col, int *n, int *y, int *h, int *skip_rows, int *skip_cols)
{
    *skip_rows = 0; *skip_cols = 0;
    if (*col < 0) { *skip_cols = -*col; *n += *col; *col = 0; }
    if (*col + *n > FTEXT_COLS) *n = FTEXT_COLS - *col;
    if (*y < 0) { *skip_rows = -*y; *h += *y; *y = 0; }
    if (*y + *h > FTEXT_ROWS) *h = FTEXT_ROWS - *y;
    return *n > 0 && *h > 0 && ft_depth > 0;
}

void ftext_text(int col, int y, int fg, int bg, const UBYTE *s, int n, int style)
{
    int h = 8, skip, skipc, p, i, r;
    ULONG base;
    if (!ft_clip(&col, &n, &y, &h, &skip, &skipc)) return;
    s += skipc;                                        /* columns left of the screen: skip those characters */
    base = (ULONG)y * ft_bpr + (ULONG)col;
    for (p = 0; p < ft_depth; p++) {
        int fb = (fg >> p) & 1, bb = (bg >> p) & 1;
        UBYTE *d = ft_planes[p] + base;
        if (fb == bb) {
            UBYTE v = fb ? 0xFF : 0x00;
            for (r = 0; r < h; r++, d += ft_bpr) for (i = 0; i < n; i++) d[i] = v;
            continue;
        }
        for (i = 0; i < n; i++) {
            const UBYTE *g = font8_glyphs[s[i]] + skip;
            UBYTE *c = d + i;
            if (fb) {
                if (style & FTEXT_BOLD) for (r = 0; r < h; r++, c += ft_bpr) c[0] = (UBYTE)(g[r] | (g[r] >> 1));
                else                    for (r = 0; r < h; r++, c += ft_bpr) c[0] = g[r];
            } else {
                if (style & FTEXT_BOLD) for (r = 0; r < h; r++, c += ft_bpr) c[0] = (UBYTE)~(g[r] | (g[r] >> 1));
                else                    for (r = 0; r < h; r++, c += ft_bpr) c[0] = (UBYTE)~g[r];
            }
        }
    }
}

void ftext_fill(int col, int y, int ncols, int h, int pen)
{
    int skip, skipc, p, i, r;
    ULONG base;
    if (!ft_clip(&col, &ncols, &y, &h, &skip, &skipc)) return;
    base = (ULONG)y * ft_bpr + (ULONG)col;
    for (p = 0; p < ft_depth; p++) {
        UBYTE v = (UBYTE)(((pen >> p) & 1) ? 0xFF : 0x00);
        UBYTE *d = ft_planes[p] + base;
        for (r = 0; r < h; r++, d += ft_bpr) for (i = 0; i < ncols; i++) d[i] = v;
    }
}

void ftext_field(int col, int y, int ncols, int fg, int bg, const UBYTE *s, int n, int style)
{
    if (n > ncols) n = ncols;
    if (n < 0) n = 0;
    if (n) ftext_text(col, y, fg, bg, s, n, style);
    if (ncols > n) ftext_fill(col + n, y, ncols - n, 8, bg);
}

void ftext_scroll_up(int col, int y, int ncols, int h, int dy, int bg)
{
    int skip, skipc, p, i, r;
    if (dy <= 0) return;
    if (dy >= h) { ftext_fill(col, y, ncols, h, bg); return; }
    if (!ft_clip(&col, &ncols, &y, &h, &skip, &skipc)) return;
    for (p = 0; p < ft_depth; p++) {
        UBYTE *d = ft_planes[p] + (ULONG)y * ft_bpr + (ULONG)col;
        const UBYTE *src = d + (ULONG)dy * ft_bpr;
        for (r = 0; r < h - dy; r++, d += ft_bpr, src += ft_bpr) for (i = 0; i < ncols; i++) d[i] = src[i];
    }
    ftext_fill(col, y + h - dy, ncols, dy, bg);
}
