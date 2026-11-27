/*
 * Tachyon - direct bitplane text renderer (ui/ftext.h).
 *
 * One cell: for every plane p the byte is glyph (fg bit set, bg bit clear), ~glyph (bg set, fg clear), 0xFF or
 * 0x00 (both equal). 8 rows x depth planes = 32 byte stores for Topaz 8 on 4 planes. The 8 rows are written with
 * constant displacements (BytesPerRow 80 of the 640-pixel screen, FT_BPR) so vbcc emits move.b (a0)+,(d16,a1)
 * and no loop: the first version with a row loop and the stride in memory took 650 us per cell on the A500
 * (vbcc keeps loop counters on the stack), this one about a fifth of that. Fills and the CPU scroll write longs.
 * Screens with another width fall back to the generic loops.
 */
#include "ftext.h"
#include "font8.h"

#define FT_BPR 80

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

/* n bytes of v from d (any alignment), longs in the middle (long stores 4-aligned: the 68000 only needs even
 * addresses, the host sanitizer wants 4) */
static void fill_row(UBYTE *d, int n, UBYTE v)
{
    if (n >= 8) {
        UWORD w = (UWORD)(((UWORD)v << 8) | v);
        ULONG l = ((ULONG)w << 16) | w;
        while ((ULONG)d & 3) { *d++ = v; n--; }
        while (n >= 4) { *(ULONG *)d = l; d += 4; n -= 4; }
        if (n >= 2) { *(UWORD *)d = w; d += 2; n -= 2; }
    }
    while (n-- > 0) *d++ = v;
}

static void copy_row(UBYTE *d, const UBYTE *s, int n)
{
    if (n >= 8) {
        while ((ULONG)d & 3) { *d++ = *s++; n--; }
        if (((ULONG)s & 3) == 0) { while (n >= 4) { *(ULONG *)d = *(const ULONG *)s; d += 4; s += 4; n -= 4; } }
        else if (((ULONG)s & 1) == 0) { while (n >= 2) { *(UWORD *)d = *(const UWORD *)s; d += 2; s += 2; n -= 2; } }
    }
    while (n-- > 0) *d++ = *s++;
}

#define CELL_COPY(d, g) do { (d)[0] = (g)[0]; (d)[FT_BPR] = (g)[1]; (d)[2 * FT_BPR] = (g)[2]; (d)[3 * FT_BPR] = (g)[3]; \
    (d)[4 * FT_BPR] = (g)[4]; (d)[5 * FT_BPR] = (g)[5]; (d)[6 * FT_BPR] = (g)[6]; (d)[7 * FT_BPR] = (g)[7]; } while (0)
#define CELL_INV(d, g) do { (d)[0] = (UBYTE)~(g)[0]; (d)[FT_BPR] = (UBYTE)~(g)[1]; (d)[2 * FT_BPR] = (UBYTE)~(g)[2]; (d)[3 * FT_BPR] = (UBYTE)~(g)[3]; \
    (d)[4 * FT_BPR] = (UBYTE)~(g)[4]; (d)[5 * FT_BPR] = (UBYTE)~(g)[5]; (d)[6 * FT_BPR] = (UBYTE)~(g)[6]; (d)[7 * FT_BPR] = (UBYTE)~(g)[7]; } while (0)

/* generic (clipped rows, other screen widths, bold) */
static void text_generic(int col, int y, int fg, int bg, const UBYTE *s, int n, int style, int skip, int h)
{
    int p, i, r;
    ULONG base = (ULONG)y * ft_bpr + (ULONG)col;
    for (p = 0; p < ft_depth; p++) {
        int fb = (fg >> p) & 1, bb = (bg >> p) & 1;
        UBYTE *d = ft_planes[p] + base;
        if (fb == bb) { UBYTE v = fb ? 0xFF : 0x00; for (r = 0; r < h; r++, d += ft_bpr) fill_row(d, n, v); continue; }
        for (i = 0; i < n; i++) {
            const UBYTE *g = font8_glyphs[s[i]] + skip;
            UBYTE *c = d + i;
            for (r = 0; r < h; r++, c += ft_bpr) {
                UBYTE v = g[r];
                if (style & FTEXT_BOLD) v |= (UBYTE)(v >> 1);
                c[0] = fb ? v : (UBYTE)~v;
            }
        }
    }
}

void ftext_text(int col, int y, int fg, int bg, const UBYTE *s, int n, int style)
{
    int h = 8, skip, skipc, p, i;
    if (!ft_clip(&col, &n, &y, &h, &skip, &skipc)) return;
    s += skipc;                                        /* columns left of the screen: skip those characters */
    if (h != 8 || ft_bpr != FT_BPR || (style & FTEXT_BOLD)) { text_generic(col, y, fg, bg, s, n, style, skip, h); return; }
    for (p = 0; p < ft_depth; p++) {
        int fb = (fg >> p) & 1, bb = (bg >> p) & 1;
        UBYTE *d = ft_planes[p] + (ULONG)y * FT_BPR + (ULONG)col;
        if (fb == bb) {
            UBYTE v = fb ? 0xFF : 0x00;
            fill_row(d, n, v); fill_row(d + FT_BPR, n, v); fill_row(d + 2 * FT_BPR, n, v); fill_row(d + 3 * FT_BPR, n, v);
            fill_row(d + 4 * FT_BPR, n, v); fill_row(d + 5 * FT_BPR, n, v); fill_row(d + 6 * FT_BPR, n, v); fill_row(d + 7 * FT_BPR, n, v);
        } else if (fb) {
            for (i = 0; i < n; i++, d++) { const UBYTE *g = font8_glyphs[s[i]]; CELL_COPY(d, g); }
        } else {
            for (i = 0; i < n; i++, d++) { const UBYTE *g = font8_glyphs[s[i]]; CELL_INV(d, g); }
        }
    }
}

void ftext_fill(int col, int y, int ncols, int h, int pen)
{
    int skip, skipc, p, r;
    ULONG base;
    if (!ft_clip(&col, &ncols, &y, &h, &skip, &skipc)) return;
    base = (ULONG)y * ft_bpr + (ULONG)col;
    for (p = 0; p < ft_depth; p++) {
        UBYTE v = (UBYTE)(((pen >> p) & 1) ? 0xFF : 0x00);
        UBYTE *d = ft_planes[p] + base;
        for (r = 0; r < h; r++, d += ft_bpr) fill_row(d, ncols, v);
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
    int skip, skipc, p, r;
    if (dy == 0) return;
    if (dy >= h || -dy >= h) { ftext_fill(col, y, ncols, h, bg); return; }
    if (!ft_clip(&col, &ncols, &y, &h, &skip, &skipc)) return;
    if (dy > 0) {
        for (p = 0; p < ft_depth; p++) {
            UBYTE *d = ft_planes[p] + (ULONG)y * ft_bpr + (ULONG)col;
            const UBYTE *src = d + (ULONG)dy * ft_bpr;
            for (r = 0; r < h - dy; r++, d += ft_bpr, src += ft_bpr) copy_row(d, src, ncols);
        }
        ftext_fill(col, y + h - dy, ncols, dy, bg);
    } else {                                            /* down: copy from the bottom row upwards */
        int up = -dy;
        for (p = 0; p < ft_depth; p++) {
            UBYTE *d = ft_planes[p] + (ULONG)(y + h - 1) * ft_bpr + (ULONG)col;
            const UBYTE *src = d - (ULONG)up * ft_bpr;
            for (r = 0; r < h - up; r++, d -= ft_bpr, src -= ft_bpr) copy_row(d, src, ncols);
        }
        ftext_fill(col, y, ncols, up, bg);
    }
}
