/*
 * Tachyon - host screen (ui/screen_host.h): the scr_* API of ui/screen.c on an in-memory 640x256x4 framebuffer.
 * The Amiga Text() path is emulated with the same glyph table the fast renderer uses, so both paths produce the
 * same pixels and the test's cell reader works for either. Call counters stand in for the measured costs on the
 * A500 (1.5 ms per graphics call, 0.4 ms per character through Text()).
 */
#include <stdio.h>
#include <string.h>
#include "screen_host.h"
#include "font8.h"
#include "topaz8_font.h"          /* generated: build/topaz8_font.h (tools/topaz_from_rom.py) */

#define BPR (SCR_W / 8)
static UBYTE  host_planes[SCR_DEPTH][BPR * SCR_H];
static UBYTE *host_plane_ptrs[SCR_DEPTH];
static UWORD  host_palette[16];
static int    host_open;
static UWORD  host_qual;
static WORD   host_mx, host_my;
static ULONG  host_calls, host_chars;
static struct { LONG key; UWORD qual; } host_keys[64];
static int    host_nkeys, host_key_rd;
/* TextFont-style view of the ROM table for font8_load: one row = 224 glyphs * 1 byte */
static UBYTE  host_chardata[8][224];
static ULONG  host_charloc[225];

static const UWORD host_default_palette[16] = {
    0x000, 0x113, 0xFFF, 0x2D6, 0x075, 0x187, 0xCCC, 0x888,
    0x444, 0xD33, 0xFD3, 0x48D, 0x8BE, 0xF93, 0xEED, 0xDFC
};

int scr_open(void)
{
    int p, c, r;
    for (p = 0; p < SCR_DEPTH; p++) { memset(host_planes[p], 0, sizeof host_planes[p]); host_plane_ptrs[p] = host_planes[p]; }
    memcpy(host_palette, host_default_palette, sizeof host_palette);
    for (c = 0; c < 224; c++) { for (r = 0; r < 8; r++) host_chardata[r][c] = font8_rom_glyphs[c][r]; host_charloc[c] = ((ULONG)(c * 8) << 16) | 8; }
    host_charloc[224] = ((ULONG)(('?' - 0x20) * 8) << 16) | 8;       /* the default glyph after tf_HiChar */
    font8_load(0x20, 0xFF, host_chardata[0], 224, host_charloc);
    host_open = 1; host_nkeys = host_key_rd = 0; host_qual = 0;
    return 0;
}

void scr_close(void) { host_open = 0; }
void scr_set_palette(const UWORD *rgb4, int count) { int i; if (count > 16) count = 16; for (i = 0; i < count; i++) host_palette[i] = rgb4[i]; }

static void host_set(int x, int y, int pen)
{
    int p; ULONG o = (ULONG)y * BPR + (ULONG)(x >> 3); UBYTE m = (UBYTE)(0x80 >> (x & 7));
    for (p = 0; p < SCR_DEPTH; p++) { if ((pen >> p) & 1) host_planes[p][o] |= m; else host_planes[p][o] &= (UBYTE)~m; }
}

int scr_host_pixel(int x, int y)
{
    int p, pen = 0; ULONG o; UBYTE m;
    if (x < 0 || y < 0 || x >= SCR_W || y >= SCR_H) return -1;
    o = (ULONG)y * BPR + (ULONG)(x >> 3); m = (UBYTE)(0x80 >> (x & 7));
    for (p = 0; p < SCR_DEPTH; p++) if (host_planes[p][o] & m) pen |= 1 << p;
    return pen;
}

void scr_clear(int pen) { host_calls++; scr_fill(0, 0, SCR_W, SCR_H, pen); host_calls--; host_calls++; }

void scr_fill(int x, int y, int w, int h, int pen)
{
    int x1 = x + w - 1, y1 = y + h - 1, i, j;
    if (!host_open || w <= 0 || h <= 0) return;
    host_calls++;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x1 >= SCR_W) x1 = SCR_W - 1;
    if (y1 >= SCR_H) y1 = SCR_H - 1;
    for (j = y; j <= y1; j++) for (i = x; i <= x1; i++) host_set(i, j, pen);
}
void scr_hline(int x, int y, int w, int pen) { scr_fill(x, y, w, 1, pen); }
void scr_vline(int x, int y, int h, int pen) { scr_fill(x, y, 1, h, pen); }

static int host_text(int x, int y, int pen, int bg, int jam2, const char *s)
{
    int n = (int)strlen(s), i, r, c, drawn = 0;
    if (!host_open || n == 0 || x >= SCR_W || y >= SCR_H || y + 8 <= 0) return 0;
    host_calls++;
    for (i = 0; i < n && x + 8 * i < SCR_W; i++) {
        const UBYTE *g = font8_glyphs[(UBYTE)s[i]];
        host_chars++;
        for (r = 0; r < 8; r++) {
            if (y + r < 0 || y + r >= SCR_H) continue;
            for (c = 0; c < 8; c++) {
                int on = (g[r] >> (7 - c)) & 1;
                if (on) host_set(x + 8 * i + c, y + r, pen); else if (jam2) host_set(x + 8 * i + c, y + r, bg);
            }
        }
        drawn++;
    }
    return drawn * 8;
}
int scr_text(int x, int y, int pen, const char *s) { return host_text(x, y, pen, 0, 0, s); }
int scr_text_bg(int x, int y, int pen, int bg, const char *s) { return host_text(x, y, pen, bg, 1, s); }
int scr_text_width(const char *s) { return 8 * (int)strlen(s); }

int scr_bitmap_1bpp_rects_ex(int x, int y, int wm, int hm, const UBYTE *bits, int stride, int sx, int sy, int on, int off)
{
    int r, c;
    if (!host_open || sx <= 0 || sy <= 0) return 0;
    host_calls++;
    for (r = 0; r < hm; r++) for (c = 0; c < wm; c++) {
        int v = (bits[r * stride + (c >> 3)] >> (7 - (c & 7))) & 1, i, j;
        for (j = 0; j < sy; j++) for (i = 0; i < sx; i++) {
            int px = x + c * sx + i, py = y + r * sy + j;
            if (px >= 0 && py >= 0 && px < SCR_W && py < SCR_H) host_set(px, py, v ? on : off);
        }
    }
    return 1;
}
int scr_bitmap_1bpp_ex(int x, int y, int wm, int hm, const UBYTE *bits, int stride, int sx, int sy, int on, int off)
{ return scr_bitmap_1bpp_rects_ex(x, y, wm, hm, bits, stride, sx, sy, on, off); }
int scr_bitmap_1bpp(int x, int y, int wm, int hm, const UBYTE *bits, int scale, int on, int off)
{ return scr_bitmap_1bpp_rects_ex(x, y, wm, hm, bits, (wm + 7) >> 3, scale, scale, on, off); }
int scr_bitmap_1bpp_rects(int x, int y, int wm, int hm, const UBYTE *bits, int scale, int on, int off)
{ return scr_bitmap_1bpp_rects_ex(x, y, wm, hm, bits, (wm + 7) >> 3, scale, scale, on, off); }

void scr_scroll_up(int x, int y, int w, int h, int dy, int bg)
{
    int r, i, x1 = x + w - 1, y1 = y + h - 1;
    if (!host_open || w <= 0 || h <= 0 || dy == 0) return;
    host_calls++;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x1 >= SCR_W) x1 = SCR_W - 1;
    if (y1 >= SCR_H) y1 = SCR_H - 1;
    if (dy > y1 - y + 1) dy = y1 - y + 1;
    if (dy < -(y1 - y + 1)) dy = -(y1 - y + 1);
    if (dy > 0) {
        for (r = y; r + dy <= y1; r++) for (i = x; i <= x1; i++) host_set(i, r, scr_host_pixel(i, r + dy));
        for (r = y1 - dy + 1; r <= y1; r++) for (i = x; i <= x1; i++) host_set(i, r, bg);
    } else {
        for (r = y1; r + dy >= y; r--) for (i = x; i <= x1; i++) host_set(i, r, scr_host_pixel(i, r + dy));
        for (r = y; r < y - dy; r++) for (i = x; i <= x1; i++) host_set(i, r, bg);
    }
}

void scr_scroll_direct(int x, int y, int w, int h, int dy) { scr_scroll_up(x, y, w, h, dy, 0); }

int scr_planes(UBYTE **planes, int max, UWORD *bpr)
{
    int p, d = SCR_DEPTH < max ? SCR_DEPTH : max;
    if (!host_open) return 0;
    for (p = 0; p < d; p++) planes[p] = host_plane_ptrs[p];
    *bpr = BPR;
    return d;
}
void scr_wait_blit(void) { }
UWORD scr_last_qualifier(void) { return host_qual; }
void  scr_last_mouse(WORD *x, WORD *y) { *x = host_mx; *y = host_my; }
void  scr_host_set_mouse(WORD x, WORD y) { host_mx = x; host_my = y; }
int scr_font_glyphs(UBYTE *lo, UBYTE *hi, const UBYTE **cd, UWORD *modulo, const ULONG **cl)
{ *lo = 0x20; *hi = 0xFF; *cd = host_chardata[0]; *modulo = 224; *cl = host_charloc; return 1; }

LONG scr_wait_key(ULONG timeout_ticks)
{
    (void)timeout_ticks;
    if (host_key_rd < host_nkeys) { host_qual = host_keys[host_key_rd].qual; return host_keys[host_key_rd++].key; }
    host_nkeys = host_key_rd = 0;
    return SCR_KEY_TIMEOUT;
}
int  scr_last_key_source(void) { return 'H'; }
LONG scr_translate_raw(UWORD code, UWORD qualifier) { (void)qualifier; return SCR_KEY_RAW | code; }
struct Screen   *scr_screen(void)   { return 0; }
struct Window   *scr_window(void)   { return 0; }
struct RastPort *scr_rastport(void) { return 0; }
int scr_font_height(void) { return 8; }
int scr_font_width(void)  { return 8; }
int scr_console_ok(void)  { return 0; }

/* ---- host extras ---------------------------------------------------------------------------------- */

void scr_host_push_key(LONG key, UWORD qualifier)
{
    if (host_nkeys < 64) { host_keys[host_nkeys].key = key; host_keys[host_nkeys].qual = qualifier; host_nkeys++; }
}
void scr_host_set_qualifier(UWORD q) { host_qual = q; }
ULONG scr_host_calls(void) { return host_calls; }
ULONG scr_host_chars(void) { return host_chars; }
void scr_host_reset_counters(void) { host_calls = host_chars = 0; }
const char *scr_host_font_source(void) { return FONT8_ROM_SOURCE; }

int scr_host_write_ppm(const char *path)
{
    FILE *f = fopen(path, "wb");
    int x, y;
    if (!f) return -1;
    fprintf(f, "P6\n%d %d\n255\n", SCR_W, SCR_H);
    for (y = 0; y < SCR_H; y++) for (x = 0; x < SCR_W; x++) {
        UWORD c = host_palette[scr_host_pixel(x, y)];
        UBYTE rgb[3];
        rgb[0] = (UBYTE)(((c >> 8) & 15) * 17); rgb[1] = (UBYTE)(((c >> 4) & 15) * 17); rgb[2] = (UBYTE)((c & 15) * 17);
        fwrite(rgb, 1, 3, f);
    }
    fclose(f);
    return 0;
}

int scr_host_cell(int col, int y, int *fg, int *bg)
{
    UBYTE rows[8][8];           /* pens of the 64 pixels */
    int r, c, pa = -1, pb = -1, ch, bold;
    if (col < 0 || col >= 80 || y < 0 || y + 8 > SCR_H) return -1;
    for (r = 0; r < 8; r++) for (c = 0; c < 8; c++) {
        int pen = scr_host_pixel(col * 8 + c, y + r);
        rows[r][c] = (UBYTE)pen;
        if (pa < 0) pa = pen; else if (pen != pa && pb < 0) pb = pen; else if (pen != pa && pen != pb) return -1;
    }
    if (pb < 0) { *fg = *bg = pa; return ' '; }
    /* two pens: find a glyph g with (pixel == A) == g bit, A as fg; or the inverse */
    for (bold = 0; bold < 2; bold++) for (ch = 1; ch < 256; ch++) {
        const UBYTE *g = font8_glyphs[ch];
        int ok_a = 1, ok_b = 1;
        if (ch == F8_BLOCK || ch == ' ') continue;
        for (r = 0; r < 8 && (ok_a || ok_b); r++) for (c = 0; c < 8; c++) {
            UBYTE gr = bold ? (UBYTE)(g[r] | (g[r] >> 1)) : g[r];
            int bit = (gr >> (7 - c)) & 1;
            if ((rows[r][c] == pa) != bit) ok_a = 0;
            if ((rows[r][c] == pb) != bit) ok_b = 0;
        }
        if (ok_a) { *fg = pa; *bg = pb; return ch; }
        if (ok_b) { *fg = pb; *bg = pa; return ch; }
    }
    return -1;
}

int scr_host_row(int col, int y, int ncols, char *out)
{
    int i, fg, bg, n = 0;
    for (i = 0; i < ncols; i++) {
        int ch = scr_host_cell(col + i, y, &fg, &bg);
        if (ch < 0) out[i] = '?'; else { out[i] = (char)(ch < 32 ? '#' : ch); n++; }
    }
    out[ncols] = 0;
    return n;
}
