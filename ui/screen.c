/*
 * Tachyon - the client's screen on Kickstart 1.3 (ui/screen.h).
 *
 * Why an Intuition screen and not a bare copper list: TheWire13, its SANA-II driver, DOS and the CLI keep
 * running while the client is on screen, and graphics.library's VBL server rewrites COP1LC every frame
 * (docs/TOOLCHAIN.md, "Stolperfallen"); an own display would mean taking over the view or the interrupt.
 * OpenScreen gives the 4 bitplanes (80 KiB Chip), the copper list, the colour table and the sprite pointer,
 * and the backdrop window gives keyboard input through the normal input.device -> Intuition -> IDCMP chain.
 * Kickstart 1.3 limits: struct NewScreen only (no SA_/WA_ tags, those are V36), ViewModes HIRES, the screen
 * title bar can only be hidden behind backdrop windows (ShowTitle FALSE), fonts come from the ROM
 * (topaz 8/9) or diskfont.library, and keymap.library does not exist - raw keys are translated by
 * console.device's RawKeyConvert with the system keymap (Preferences / SetMap), fallback: the US table below.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <exec/io.h>
#include <exec/ports.h>
#include <proto/exec.h>
#include "screen.h"

static struct Library  *scr_intui;        /* intuition.library base */
static struct Library  *scr_gfx;          /* graphics.library base */
static struct Screen   *scr_scr;
static struct Window   *scr_win;
static struct RastPort *scr_rp;
static struct TextFont *scr_font;
static struct MsgPort   scr_conport;      /* reply port for the console.device open */
static struct IOStdReq  scr_conreq;
static void            *scr_console;      /* console.device base (io_Device), 0 when unavailable */
static int              scr_key_source;
static UWORD            scr_qual;         /* qualifier of the last key returned (scr_last_qualifier) */

static struct TextAttr scr_topaz8 = { (STRPTR)"topaz.font", 8, FS_NORMAL, FPF_ROMFONT };

static const UWORD scr_default_palette[16] = {
    0x000, 0x113, 0xFFF, 0x2D6, 0x075, 0x187, 0xCCC, 0x888,
    0x444, 0xD33, 0xFD3, 0x48D, 0x8BE, 0xF93, 0xEED, 0xDFC
};

#define Intui scr_intui
#define Gfx   scr_gfx

static int scr_slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

/* ---- open / close ------------------------------------------------------------------------------------ */

static void scr_console_open(void)
{
    LONG sig;
    scr_console = 0;
    sig = AllocSignal(-1);
    if (sig < 0) return;
    scr_conport.mp_Node.ln_Type = NT_MSGPORT; scr_conport.mp_Flags = PA_SIGNAL;
    scr_conport.mp_SigBit = (UBYTE)sig; scr_conport.mp_SigTask = FindTask(0);
    scr_conport.mp_MsgList.lh_Head = (struct Node *)&scr_conport.mp_MsgList.lh_Tail;
    scr_conport.mp_MsgList.lh_Tail = 0;
    scr_conport.mp_MsgList.lh_TailPred = (struct Node *)&scr_conport.mp_MsgList.lh_Head;
    scr_conreq.io_Message.mn_ReplyPort = &scr_conport; scr_conreq.io_Message.mn_Length = sizeof scr_conreq;
    scr_conreq.io_Message.mn_Node.ln_Type = NT_REPLYMSG;
    /* unit CONU_LIBRARY (-1): no console window, only the library-style functions (RawKeyConvert) */
    if (OpenDevice((STRPTR)"console.device", (ULONG)CONU_LIBRARY, (struct IORequest *)&scr_conreq, 0) == 0)
        scr_console = scr_conreq.io_Device;
    else { FreeSignal(sig); scr_conport.mp_SigTask = 0; }
}

static void scr_console_close(void)
{
    if (scr_console) { CloseDevice((struct IORequest *)&scr_conreq); scr_console = 0; }
    if (scr_conport.mp_SigTask) { FreeSignal(scr_conport.mp_SigBit); scr_conport.mp_SigTask = 0; }
}

int scr_open(void)
{
    struct NewScreen ns;
    struct NewWindow nw;
    int i;

    SysBase = *(struct ExecBase **)4L;
    scr_intui = OpenLibrary((STRPTR)"intuition.library", 33);
    if (!scr_intui) return SCR_ERR_INTUITION;
    scr_gfx = OpenLibrary((STRPTR)"graphics.library", 33);
    if (!scr_gfx) { scr_close(); return SCR_ERR_GRAPHICS; }

    ns.LeftEdge = 0; ns.TopEdge = 0; ns.Width = SCR_W; ns.Height = SCR_H; ns.Depth = SCR_DEPTH;
    ns.DetailPen = 0; ns.BlockPen = 1; ns.ViewModes = HIRES; ns.Type = CUSTOMSCREEN | SCREENQUIET;
    ns.Font = &scr_topaz8; ns.DefaultTitle = 0; ns.Gadgets = 0; ns.CustomBitMap = 0;
    scr_scr = __int_OpenScreen(Intui, &ns);
    if (!scr_scr) { scr_close(); return SCR_ERR_SCREEN; }
    __int_ShowTitle(Intui, scr_scr, 0);               /* title bar layer behind the backdrop window */

    for (i = 0; i < (int)sizeof nw; i++) ((UBYTE *)&nw)[i] = 0;
    nw.LeftEdge = 0; nw.TopEdge = 0; nw.Width = SCR_W; nw.Height = SCR_H; nw.DetailPen = 0; nw.BlockPen = 1;
    nw.IDCMPFlags = IDCMP_RAWKEY | IDCMP_VANILLAKEY;
    nw.Flags = WFLG_BACKDROP | WFLG_BORDERLESS | WFLG_ACTIVATE | WFLG_RMBTRAP | WFLG_SIMPLE_REFRESH | WFLG_NOCAREREFRESH;
    nw.Screen = scr_scr; nw.Type = CUSTOMSCREEN;
    scr_win = __int_OpenWindow(Intui, &nw);
    if (!scr_win) { scr_close(); return SCR_ERR_WINDOW; }
    scr_rp = scr_win->RPort;

    scr_font = __gfx_OpenFont(Gfx, &scr_topaz8);       /* ROM topaz 8; the screen font already is, this pins it */
    if (scr_font) __gfx_SetFont(Gfx, scr_rp, scr_font);
    __gfx_SetDrMd(Gfx, scr_rp, JAM1);
    scr_set_palette(scr_default_palette, 16);
    scr_console_open();
    scr_key_source = 0;
    return 0;
}

void scr_close(void)
{
    struct IntuiMessage *msg;
    if (scr_win) {
        /* strip pending IDCMP messages before the port disappears (the 1.3 CloseWindow rule) */
        Forbid();
        while ((msg = (struct IntuiMessage *)GetMsg(scr_win->UserPort)) != 0) ReplyMsg((struct Message *)msg);
        __int_ModifyIDCMP(Intui, scr_win, 0);
        Permit();
        __int_CloseWindow(Intui, scr_win); scr_win = 0; scr_rp = 0;
    }
    if (scr_font) { __gfx_CloseFont(Gfx, scr_font); scr_font = 0; }
    if (scr_scr) { __int_CloseScreen(Intui, scr_scr); scr_scr = 0; }
    scr_console_close();
    if (scr_gfx) { CloseLibrary(scr_gfx); scr_gfx = 0; }
    if (scr_intui) { CloseLibrary(scr_intui); scr_intui = 0; }
}

void scr_set_palette(const UWORD *rgb4, int count)
{
    if (!scr_scr || count <= 0) return;
    if (count > 16) count = 16;
    __gfx_LoadRGB4(Gfx, &scr_scr->ViewPort, rgb4, count);
}

struct Screen   *scr_screen(void)   { return scr_scr; }
struct Window   *scr_window(void)   { return scr_win; }
struct RastPort *scr_rastport(void) { return scr_rp; }
int scr_font_height(void) { return scr_rp ? scr_rp->TxHeight : 8; }
int scr_font_width(void)  { return scr_rp ? scr_rp->TxWidth : 8; }
int scr_console_ok(void)  { return scr_console != 0; }
int scr_last_key_source(void) { return scr_key_source; }
UWORD scr_last_qualifier(void) { return scr_qual; }

int scr_planes(UBYTE **planes, int max, UWORD *bytes_per_row)
{
    int p, depth;
    if (!scr_scr) return 0;
    depth = scr_scr->BitMap.Depth;
    if (depth > max) depth = max;
    for (p = 0; p < depth; p++) planes[p] = scr_scr->BitMap.Planes[p];
    *bytes_per_row = scr_scr->BitMap.BytesPerRow;
    return depth;
}

void scr_wait_blit(void) { if (scr_gfx) __gfx_WaitBlit(Gfx); }

int scr_font_glyphs(UBYTE *lo, UBYTE *hi, const UBYTE **chardata, UWORD *modulo, const ULONG **charloc)
{
    struct TextFont *f = scr_font ? scr_font : (scr_rp ? scr_rp->Font : 0);
    if (!f || f->tf_YSize != 8 || !f->tf_CharData || !f->tf_CharLoc) return 0;
    *lo = f->tf_LoChar; *hi = f->tf_HiChar; *chardata = (const UBYTE *)f->tf_CharData;
    *modulo = f->tf_Modulo; *charloc = (const ULONG *)f->tf_CharLoc;
    return 1;
}

/* ---- drawing ---------------------------------------------------------------------------------------- */

void scr_clear(int pen)
{
    if (scr_rp) __gfx_SetRast(Gfx, scr_rp, (ULONG)pen);
}

void scr_fill(int x, int y, int w, int h, int pen)
{
    int x1 = x + w - 1, y1 = y + h - 1;
    if (!scr_rp || w <= 0 || h <= 0) return;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x1 >= SCR_W) x1 = SCR_W - 1;
    if (y1 >= SCR_H) y1 = SCR_H - 1;
    if (x > x1 || y > y1) return;
    __gfx_SetAPen(Gfx, scr_rp, (ULONG)pen);
    __gfx_RectFill(Gfx, scr_rp, x, y, x1, y1);
}

void scr_hline(int x, int y, int w, int pen) { scr_fill(x, y, w, 1, pen); }

void scr_scroll_up(int x, int y, int w, int h, int dy, int bg)
{
    int x1 = x + w - 1, y1 = y + h - 1;
    if (!scr_rp || w <= 0 || h <= 0 || dy <= 0) return;
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x1 >= SCR_W) x1 = SCR_W - 1;
    if (y1 >= SCR_H) y1 = SCR_H - 1;
    if (x > x1 || y > y1) return;
    if (dy > y1 - y + 1) dy = y1 - y + 1;
    __gfx_SetBPen(Gfx, scr_rp, (ULONG)bg);             /* ScrollRaster fills the vacated rows with the BgPen */
    __gfx_ScrollRaster(Gfx, scr_rp, 0, dy, x, y, x1, y1);
}
void scr_vline(int x, int y, int h, int pen) { scr_fill(x, y, 1, h, pen); }

static int scr_text_mode(int x, int y, int pen, int bg, int mode, const char *s)
{
    int n = scr_slen(s), w;
    if (!scr_rp || n == 0) return 0;
    if (x >= SCR_W || y >= SCR_H || y + (int)scr_rp->TxHeight <= 0) return 0;
    w = __gfx_TextLength(Gfx, scr_rp, s, (ULONG)n);
    if (x + w > SCR_W) {                               /* the layer clips, but Text() with a count past the edge
                                                          still renders the whole string into the clip; shorten */
        ULONG cw = scr_rp->TxWidth ? scr_rp->TxWidth : 8; int fit = (int)((ULONG)(SCR_W - x) / cw);   /* unsigned: no __divs */
        if (fit <= 0) return 0;
        if (fit < n) n = fit;
        w = __gfx_TextLength(Gfx, scr_rp, s, (ULONG)n);
    }
    __gfx_SetAPen(Gfx, scr_rp, (ULONG)pen);
    if (mode == JAM2) __gfx_SetBPen(Gfx, scr_rp, (ULONG)bg);
    __gfx_SetDrMd(Gfx, scr_rp, (ULONG)mode);
    __gfx_Move(Gfx, scr_rp, x, y + scr_rp->TxBaseline);
    __gfx_Text(Gfx, scr_rp, s, (ULONG)n);
    return w;
}

int scr_text(int x, int y, int pen, const char *s) { return scr_text_mode(x, y, pen, 0, JAM1, s); }
int scr_text_bg(int x, int y, int pen, int bg, const char *s) { return scr_text_mode(x, y, pen, bg, JAM2, s); }
int scr_text_width(const char *s) { return scr_rp ? (int)__gfx_TextLength(Gfx, scr_rp, s, (ULONG)scr_slen(s)) : 0; }

static int scr_module(const UBYTE *bits, int stride, int r, int c)
{
    return (bits[r * stride + (c >> 3)] >> (7 - (c & 7))) & 1;
}

int scr_bitmap_1bpp_rects_ex(int x, int y, int w_modules, int h_modules, const UBYTE *bits, int stride, int sx, int sy, int pen_on, int pen_off)
{
    int r, c;
    if (!scr_rp || sx <= 0 || sy <= 0 || w_modules <= 0 || h_modules <= 0 || stride <= 0) return 0;
    if (x >= SCR_W || y >= SCR_H || x + w_modules * sx <= 0 || y + h_modules * sy <= 0) return 0;
    scr_fill(x, y, w_modules * sx, h_modules * sy, pen_off);
    __gfx_SetAPen(Gfx, scr_rp, (ULONG)pen_on);
    for (r = 0; r < h_modules; r++) {
        int py = y + r * sy;
        if (py >= SCR_H) break;
        if (py + sy <= 0) continue;
        c = 0;
        while (c < w_modules) {
            int run;
            if (!scr_module(bits, stride, r, c)) { c++; continue; }
            run = 1;
            while (c + run < w_modules && scr_module(bits, stride, r, c + run)) run++;
            {
                int x0 = x + c * sx, x1 = x0 + run * sx - 1, y0 = py, y1 = py + sy - 1;
                if (x0 < 0) x0 = 0;
                if (y0 < 0) y0 = 0;
                if (x1 >= SCR_W) x1 = SCR_W - 1;
                if (y1 >= SCR_H) y1 = SCR_H - 1;
                if (x0 <= x1 && y0 <= y1) __gfx_RectFill(Gfx, scr_rp, x0, y0, x1, y1);
            }
            c += run;
        }
    }
    return 1;
}

int scr_bitmap_1bpp_rects(int x, int y, int w_modules, int h_modules, const UBYTE *bits, int scale, int pen_on, int pen_off)
{
    return scr_bitmap_1bpp_rects_ex(x, y, w_modules, h_modules, bits, (w_modules + 7) >> 3, scale, scale, pen_on, pen_off);
}

/* 4 modules (a nibble) -> 16 pixels at scale 4; a byte -> 16 pixels at scale 2 (table built on first use) */
static const UWORD scr_spread4[16] = {
    0x0000, 0x000F, 0x00F0, 0x00FF, 0x0F00, 0x0F0F, 0x0FF0, 0x0FFF,
    0xF000, 0xF00F, 0xF0F0, 0xF0FF, 0xFF00, 0xFF0F, 0xFFF0, 0xFFFF
};
static UWORD scr_spread2[256];
static int   scr_spread2_ready;

/* one module row (row_bytes source bytes) -> one pixel row of w_modules*sx bits in dst (row_bytes*sx bytes) */
static void scr_expand_row(UBYTE *dst, const UBYTE *src, int row_bytes, int w_modules, int sx)
{
    int b, k;
    UBYTE last_mask = (w_modules & 7) ? (UBYTE)(0xFF00u >> (w_modules & 7)) : 0xFF;   /* padding bits -> 0 */
    if (sx == 1) { for (b = 0; b < row_bytes; b++) dst[b] = src[b]; dst[row_bytes - 1] &= last_mask; return; }
    if (sx == 8) {                                     /* one byte per module: the 8x4 QR module */
        for (b = 0; b < row_bytes; b++) {
            UBYTE v = src[b]; if (b == row_bytes - 1) v &= last_mask;
            for (k = 0; k < 8; k++) dst[8 * b + k] = (v & (0x80 >> k)) ? 0xFF : 0x00;
        }
        return;
    }
    if (sx == 4) {
        UWORD *d = (UWORD *)dst;
        for (b = 0; b < row_bytes; b++) {
            UBYTE v = src[b]; if (b == row_bytes - 1) v &= last_mask;
            d[2 * b] = scr_spread4[v >> 4]; d[2 * b + 1] = scr_spread4[v & 15];
        }
        return;
    }
    if (sx == 2) {
        UWORD *d = (UWORD *)dst;
        if (!scr_spread2_ready) {
            int v;
            for (v = 0; v < 256; v++) {
                UWORD w = 0; int bit;
                for (bit = 0; bit < 8; bit++) if (v & (0x80 >> bit)) w |= (UWORD)(0xC000u >> (2 * bit));
                scr_spread2[v] = w;
            }
            scr_spread2_ready = 1;
        }
        for (b = 0; b < row_bytes; b++) { UBYTE v = src[b]; if (b == row_bytes - 1) v &= last_mask; d[b] = scr_spread2[v]; }
        return;
    }
    {   /* generic width: running destination bit mask */
        UBYTE dmask = 0x80, smask = 0x80, sbyte = *src;
        int c, n = row_bytes * sx;
        for (b = 0; b < n; b++) dst[b] = 0;
        for (c = 0; c < w_modules; c++) {
            int on = (sbyte & smask) != 0;
            for (k = 0; k < sx; k++) {
                if (on) *dst |= dmask;
                dmask >>= 1;
                if (!dmask) { dmask = 0x80; dst++; }
            }
            smask >>= 1;
            if (!smask) { smask = 0x80; sbyte = *++src; }
        }
    }
}

int scr_bitmap_1bpp_ex(int x, int y, int w_modules, int h_modules, const UBYTE *bits, int stride, int sx, int sy, int pen_on, int pen_off)
{
    int w = w_modules * sx, h = h_modules * sy, bpr, r, k, words, row_bytes = (w_modules + 7) >> 3;
    ULONG size;
    UBYTE *tpl, *row;
    UWORD rowbuf[(SCR_W / 8 + 64) / 2 + 4];                       /* row_bytes*sx <= w/8 + sx bytes */

    if (!scr_rp || sx <= 0 || sx > 64 || sy <= 0 || w_modules <= 0 || h_modules <= 0 || stride < row_bytes) return 0;
    if (x >= SCR_W || y >= SCR_H || x + w <= 0 || y + h <= 0) return 0;
    if (w > SCR_W + 8 * sx) return scr_bitmap_1bpp_rects_ex(x, y, w_modules, h_modules, bits, stride, sx, sy, pen_on, pen_off);
    bpr = ((w + 15) >> 4) << 1;                        /* template rows are word aligned */
    words = bpr >> 1;
    size = (ULONG)bpr * (ULONG)h;
    tpl = (UBYTE *)AllocMem(size, MEMF_CHIP);
    if (!tpl) return scr_bitmap_1bpp_rects_ex(x, y, w_modules, h_modules, bits, stride, sx, sy, pen_on, pen_off);

    /* Expand each module row once into a Fast RAM buffer (the stack), then copy it sy times into the
     * Chip RAM template as words; bit-by-bit CPU writes into Chip RAM would compete with the display DMA. */
    row = tpl;
    for (r = 0; r < h_modules; r++) {
        rowbuf[words - 1] = 0;                        /* the expansion may end before the word-aligned row end */
        scr_expand_row((UBYTE *)rowbuf, bits + r * stride, row_bytes, w_modules, sx);
        for (k = 0; k < sy; k++, row += bpr) {
            UWORD *d = (UWORD *)row; int b;
            for (b = 0; b < words; b++) d[b] = rowbuf[b];
        }
    }
    __gfx_SetAPen(Gfx, scr_rp, (ULONG)pen_on);
    __gfx_SetBPen(Gfx, scr_rp, (ULONG)pen_off);
    __gfx_SetDrMd(Gfx, scr_rp, JAM2);
    /* BltTemplate clips through the layer; keep the blit inside the screen ourselves for the negative side */
    {
        int xs = 0, ys = 0, bw = w, bh = h, dx = x, dy = y;
        if (dx < 0) { xs = -dx; bw += dx; dx = 0; }
        if (dy < 0) { ys = -dy; bh += dy; dy = 0; }
        if (dx + bw > SCR_W) bw = SCR_W - dx;
        if (dy + bh > SCR_H) bh = SCR_H - dy;
        if (bw > 0 && bh > 0) __gfx_BltTemplate(Gfx, tpl + (ULONG)ys * (ULONG)bpr, xs, bpr, scr_rp, dx, dy, bw, bh);
    }
    __gfx_SetDrMd(Gfx, scr_rp, JAM1);
    FreeMem(tpl, size);
    return 1;
}

int scr_bitmap_1bpp(int x, int y, int w_modules, int h_modules, const UBYTE *bits, int scale, int pen_on, int pen_off)
{
    return scr_bitmap_1bpp_ex(x, y, w_modules, h_modules, bits, (w_modules + 7) >> 3, scale, scale, pen_on, pen_off);
}

/* ---- keyboard --------------------------------------------------------------------------------------- */

/* Built-in fallback (US layout, Amiga raw codes 0x00..0x5F; see docs/UI.md). Index = raw code, two tables:
 * unshifted and shifted. 0 = no character (SCR_KEY_RAW | code is returned instead). */
static const char scr_us_plain[0x60] =
    "`1234567890-=\\\0" "0"                      /* 00-0F: 0D backslash, 0E unused, 0F numpad 0 */
    "qwertyuiop[]\0" "123"                       /* 10-1F: 1C unused, 1D-1F numpad 1 2 3 */
    "asdfghjkl;'\0\0" "456"                      /* 20-2F: 2B/2C unused, 2D-2F numpad 4 5 6 */
    "\0zxcvbnm,./\0." "789"                      /* 30-3F: 30 unused, 3C numpad ., 3D-3F numpad 7 8 9 */
    " \b\t\r\r\x1b\x7f\0\0\0-\0\0\0\0\0"         /* 40 space 41 bs 42 tab 43 enter 44 return 45 esc 46 del 4A numpad - */
    "\0\0\0\0\0\0\0\0\0\0()/*+\0";               /* 50-59 F1-F10, 5A-5E numpad ( ) / * +, 5F help */
static const char scr_us_shift[0x60] =
    "~!@#$%^&*()_+|\0" "0"
    "QWERTYUIOP{}\0" "123"
    "ASDFGHJKL:\"\0\0" "456"
    "\0ZXCVBNM<>?\0." "789"
    " \b\t\r\r\x1b\x7f\0\0\0-\0\0\0\0\0"
    "\0\0\0\0\0\0\0\0\0\0()/*+\0";

static LONG scr_translate_table(UWORD code, UWORD qual)
{
    int shift = (qual & (IEQUALIFIER_LSHIFT | IEQUALIFIER_RSHIFT)) != 0;
    int ch;
    if (code >= 0x60) return SCR_KEY_RAW | code;      /* qualifiers themselves: 0x60-0x67 */
    ch = (shift ? scr_us_shift : scr_us_plain)[code];
    if (ch == 0) return SCR_KEY_RAW | code;
    if ((qual & IEQUALIFIER_CAPSLOCK) && ch >= 'a' && ch <= 'z') ch -= 32;
    if ((qual & IEQUALIFIER_CONTROL) && ch >= 0x40) ch &= 0x1f;
    return ch;
}

static LONG scr_translate_event(UWORD code, UWORD qual, ULONG deadkeys)
{
    struct InputEvent ie;
    char buf[8];
    LONG n;
    if (code & IECODE_UP_PREFIX) return SCR_KEY_TIMEOUT;         /* key release */
    if (code >= 0x60 && code <= 0x67) return SCR_KEY_TIMEOUT;    /* shift/alt/ctrl/amiga alone */
    if (scr_console) {
        ie.ie_NextEvent = 0; ie.ie_Class = IECLASS_RAWKEY; ie.ie_SubClass = 0;
        ie.ie_Code = code; ie.ie_Qualifier = qual; ie.ie_addr = deadkeys;
        ie.ie_TimeStamp[0] = 0; ie.ie_TimeStamp[1] = 0;
        n = __con_RawKeyConvert(scr_console, &ie, buf, sizeof buf, 0);  /* keymap 0 = the system default */
        scr_key_source = 'C';
        if (n == 1) return (LONG)(UBYTE)buf[0];
        if (n == 0 && (code == 0x44 || code == 0x43)) return 13;   /* belt and braces for Return/Enter */
        return SCR_KEY_RAW | code;                                  /* CSI sequences (cursor, F-keys) or nothing */
    }
    scr_key_source = 'T';
    return scr_translate_table(code, qual);
}

LONG scr_translate_raw(UWORD code, UWORD qualifier) { return scr_translate_event(code, qualifier, 0); }

LONG scr_wait_key(ULONG timeout_ticks)
{
    struct IntuiMessage *msg;
    ULONG waited = 0, sig;
    if (!scr_win) return SCR_KEY_TIMEOUT;
    sig = 1UL << scr_win->UserPort->mp_SigBit;
    for (;;) {
        while ((msg = (struct IntuiMessage *)GetMsg(scr_win->UserPort)) != 0) {
            ULONG cls = msg->Class, dead = 0;
            UWORD code = msg->Code, qual = msg->Qualifier;
            LONG key = SCR_KEY_TIMEOUT;
            if (cls == IDCMP_RAWKEY && msg->IAddress) dead = *(ULONG *)msg->IAddress;   /* dead key info */
            ReplyMsg((struct Message *)msg);
            if (cls == IDCMP_VANILLAKEY) { scr_key_source = 'V'; key = code; }
            else if (cls == IDCMP_RAWKEY) key = scr_translate_event(code, qual, dead);
            if (key != SCR_KEY_TIMEOUT) { scr_qual = qual; return key; }
        }
        if (timeout_ticks == SCR_FOREVER) { Wait(sig); continue; }
        if (waited >= timeout_ticks) return SCR_KEY_TIMEOUT;
        __gfx_WaitTOF(Gfx);                            /* one frame (20 ms PAL); the task sleeps meanwhile */
        waited++;
        /* a message that arrived during the frame is picked up by the GetMsg loop above */
    }
}
