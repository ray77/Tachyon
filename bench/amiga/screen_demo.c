/*
 * Tachyon - demo and test of the client's screen skeleton (ui/screen.c) on Kickstart 1.3.
 *
 * Opens the 640x256x4 Intuition screen, fills the background, draws a title line, the 16-colour palette
 * bar, a Topaz 8 text block and a fake 49-module QR matrix (checkerboard with the three finder patterns)
 * at scale 4, centred; waits up to 10 s for a key; closes everything. Every step is logged to
 * SYS:result.txt ("ok:" / "FAIL:") with DateStamp timings (1/50 s ticks -> ms) and the Chip/Fast memory
 * before, with and after the screen; SYS:done is created last for tools/run-fsuae.sh. Freestanding.
 * make amiga-screen / make run-screen.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "../../ui/screen.h"

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;

static BPTR con, logfile;
static int fails;

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void out(const char *s)
{
    int n = slen(s);
    if (con) Write(con, (APTR)s, n);
    if (logfile) Write(logfile, (APTR)s, n);
}
static void out_dec(ULONG u) { char b[12]; int i = 11; b[i] = 0; do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u); out(b + i); }
static void out_hex(ULONG u) { static const char hx[] = "0123456789abcdef"; char b[9]; int i; for (i = 7; i >= 0; i--) { b[i] = hx[u & 15]; u >>= 4; } b[8] = 0; out(b); }
static void dec_to(char *d, ULONG u) { char b[12]; int i = 11, j = 0; b[i] = 0; do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u); while (b[i]) d[j++] = b[i++]; d[j] = 0; }

static ULONG ticks_now(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return (ULONG)ds.ds_Days * (24UL * 60UL * 60UL * 50UL) + (ULONG)ds.ds_Minute * (60UL * 50UL) + (ULONG)ds.ds_Tick;
}

static void step(int ok, const char *what)
{
    out(ok ? "ok:   " : "FAIL: "); out(what); out("\n");
    if (!ok) fails++;
}

/* "<name>: N calls in T ms (U ms per call)" - ticks are 20 ms, so each step repeats its calls */
static void timing(const char *name, ULONG calls, ULONG t0, ULONG t1)
{
    ULONG ms = (t1 - t0) * 20, per10 = calls ? (ms * 10) / calls : 0;
    out("time: "); out(name); out(": "); out_dec(calls); out(" calls in "); out_dec(ms); out(" ms (");
    out_dec(per10 / 10); out("."); out_dec(per10 % 10); out(" ms per call)\n");
}

/* fake QR: 49 modules, checkerboard data, the three 7x7 finder patterns with their separators */
#define QR_N 49
#define QR_ROW_BYTES 10                              /* like ui/qr.h QR_STRIDE: rows word aligned */
#define QR_PACKED_BYTES ((QR_N + 7) / 8)             /* the plain scr_bitmap_1bpp form: rows padded to bytes */
static UBYTE qr[QR_N * QR_ROW_BYTES];
static UBYTE qr_packed[QR_N * QR_PACKED_BYTES];
static void qr_set(int r, int c, int v)
{
    UBYTE m = (UBYTE)(0x80u >> (c & 7));
    if (v) qr[r * QR_ROW_BYTES + (c >> 3)] |= m; else qr[r * QR_ROW_BYTES + (c >> 3)] &= (UBYTE)~m;
}
static void qr_finder(int r0, int c0)
{
    int r, c;
    for (r = -1; r <= 7; r++) for (c = -1; c <= 7; c++) {
        int rr = r0 + r, cc = c0 + c, v;
        if (rr < 0 || cc < 0 || rr >= QR_N || cc >= QR_N) continue;
        if (r < 0 || c < 0 || r > 6 || c > 6) v = 0;                      /* separator */
        else if (r == 0 || r == 6 || c == 0 || c == 6) v = 1;             /* outer ring */
        else if (r >= 2 && r <= 4 && c >= 2 && c <= 4) v = 1;             /* centre 3x3 */
        else v = 0;
        qr_set(rr, cc, v);
    }
}
static void qr_build(void)
{
    int r, c;
    for (r = 0; r < QR_N; r++) for (c = 0; c < QR_N; c++) qr_set(r, c, (r + c) & 1);
    qr_finder(0, 0); qr_finder(0, QR_N - 7); qr_finder(QR_N - 7, 0);
    for (c = 8; c < QR_N - 8; c++) qr_set(6, c, (c & 1) == 0);               /* timing patterns */
    for (r = 8; r < QR_N - 8; r++) qr_set(r, 6, (r & 1) == 0);
    for (r = 0; r < QR_N; r++) for (c = 0; c < QR_PACKED_BYTES; c++) qr_packed[r * QR_PACKED_BYTES + c] = qr[r * QR_ROW_BYTES + c];
}

static const char *txt_block[] = {
            "Topaz 8, 80 Spalten x 32 Zeilen, JAM1 auf Pen 1.",
            "Der Client zeichnet mit graphics.library in das",
            "RastPort des Backdrop-Fensters; Intuition, DOS",
            "und TheWire13 laufen darunter weiter.",
            "",
            "Tasten: RAWKEY -> console.device RawKeyConvert",
            "(Systemkeymap), VANILLAKEY direkt von Intuition.",
            "Umlaute: \xe4\xf6\xfc\xc4\xd6\xdc\xdf  ASCII: !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
            "0123456789 abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    0 };

int main(void)
{
    ULONG chip0, fast0, chip1, fast1, chip2, fast2, t0, t1, t_start;
    LONG rc, key;
    int i, j;
    char line[96];
    BPTR done;

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    con = Output();
    logfile = Open((STRPTR)"SYS:result.txt", MODE_NEWFILE);
    t_start = ticks_now();
    out("Tachyon screen demo: Intuition custom screen 640x256x4 on Kickstart 1.3 (ui/screen.c)\n");

    chip0 = AvailMem(MEMF_CHIP); fast0 = AvailMem(MEMF_FAST);
    out("mem:  before open: chip "); out_dec(chip0); out(" fast "); out_dec(fast0); out("\n");

    t0 = ticks_now();
    rc = scr_open();
    t1 = ticks_now();
    out("info: scr_open rc "); out_dec((ULONG)rc); out(" in "); out_dec((t1 - t0) * 20); out(" ms\n");
    step(rc == 0, "scr_open (intuition.library 33, graphics.library 33, OpenScreen, OpenWindow)");
    if (rc) { out("RESULT: FAIL (scr_open)\n"); goto end; }

    out("info: Screen $"); out_hex((ULONG)scr_screen()); out(" Window $"); out_hex((ULONG)scr_window());
    out(" RastPort $"); out_hex((ULONG)scr_rastport()); out("\n");
    step(scr_screen() != 0, "OpenScreen pointer non-null");
    step(scr_window() != 0, "OpenWindow pointer non-null (backdrop, borderless, IDCMP RAWKEY|VANILLAKEY)");
    {
        struct Screen *s = scr_screen();
        out("info: screen "); out_dec((ULONG)s->Width); out("x"); out_dec((ULONG)s->Height); out(" depth ");
        out_dec((ULONG)s->BitMap.Depth); out(" BytesPerRow "); out_dec((ULONG)s->BitMap.BytesPerRow);
        out(" ViewPort.Modes $"); out_hex((ULONG)s->ViewPort.Modes); out(" planes in ");
        out(TypeOfMem(s->BitMap.Planes[0]) & MEMF_CHIP ? "Chip" : "non-Chip"); out("\n");
        step(s->Width == 640 && s->Height == 256 && s->BitMap.Depth == 4 && (s->ViewPort.Modes & HIRES), "screen is 640x256, depth 4, HIRES");
        step((TypeOfMem(s->BitMap.Planes[0]) & MEMF_CHIP) != 0, "bitplanes in Chip RAM");
    }
    out("info: font "); out_dec((ULONG)scr_font_width()); out("x"); out_dec((ULONG)scr_font_height());
    out(" (RastPort TxWidth x TxHeight), baseline "); out_dec((ULONG)scr_rastport()->TxBaseline); out("\n");
    step(scr_font_width() == 8 && scr_font_height() == 8, "Topaz 8 on the window RastPort");

    chip1 = AvailMem(MEMF_CHIP); fast1 = AvailMem(MEMF_FAST);
    out("mem:  screen open: chip "); out_dec(chip1); out(" fast "); out_dec(fast1); out(" -> used chip ");
    out_dec(chip0 - chip1); out(" fast "); out_dec(fast0 - fast1); out("\n");
    step(chip0 - chip1 >= 81920 && chip0 - chip1 <= 98304, "Chip used 80 KiB (bitplanes) .. 96 KiB");

    /* ---- drawing, each step repeated so the 20 ms ticks give a usable figure ---- */
    t0 = ticks_now();
    for (i = 0; i < 20; i++) scr_clear(SCR_PAL_BG);
    t1 = ticks_now();
    timing("scr_clear (SetRast 640x256x4)", 20, t0, t1);
    step(1, "scr_clear(1)");

    t0 = ticks_now();
    for (i = 0; i < 50; i++) {
        scr_fill(0, 0, SCR_W, 12, SCR_PAL_DKGREEN);
        scr_text(8, 2, SCR_PAL_WHITE, "Tachyon - WhatsApp fuer den Amiga 500");
        scr_text(SCR_W - 8 - 8 * 15, 2, SCR_PAL_LTGREEN, "Kickstart 1.3");
    }
    t1 = ticks_now();
    timing("title line (fill + 2 texts)", 50, t0, t1);
    step(1, "title line");

    t0 = ticks_now();
    for (j = 0; j < 20; j++) for (i = 0; i < 16; i++) scr_fill(8 + i * 36, 18, 36, 14, i);
    t1 = ticks_now();
    timing("palette bar scr_fill 36x14", 320, t0, t1);
    scr_hline(8, 17, 16 * 36, SCR_PAL_WHITE); scr_hline(8, 32, 16 * 36, SCR_PAL_WHITE);
    for (i = 0; i <= 16; i++) scr_vline(8 + i * 36, 17, 16, SCR_PAL_WHITE);
    step(1, "16-colour palette bar");

    t0 = ticks_now();
    for (i = 0; i < 400; i++) { scr_hline(8, 36 + (i & 3), 300, SCR_PAL_GREY); scr_vline(8 + (i & 3), 36, 4, SCR_PAL_GREY); }
    t1 = ticks_now();
    timing("scr_hline 300 px + scr_vline 4 px", 800, t0, t1);
    step(1, "scr_hline / scr_vline");

    t0 = ticks_now();
    for (j = 0; j < 5; j++) {
        const char **txt = txt_block;
        for (i = 0; txt[i]; i++) scr_text(8, 44 + i * 8, i == 0 ? SCR_PAL_YELLOW : SCR_PAL_LTGREY, txt[i]);
        scr_text_bg(8, 44 + 11 * 8, SCR_PAL_BLACK, SCR_PAL_LTGREEN, " JAM2: Text mit Hintergrund (Pen 15) ");
    }
    t1 = ticks_now();
    timing("text block 10 lines Topaz 8 (scr_text) + 1 scr_text_bg", 5, t0, t1);
    step(1, "text block Topaz 8");

    /* QR matrix: 49 modules at scale 4 = 196 px, centred in the right half, 4-module quiet zone in white */
    qr_build();
    {
        int qx = 640 - 8 - 196 - 16, qy = 44 + 2;
        t0 = ticks_now();
        for (i = 0; i < 5; i++) {
            scr_fill(qx - 16, qy - 16, 196 + 32, 196 + 32, SCR_PAL_WHITE);
            rc = scr_bitmap_1bpp(qx, qy, QR_N, QR_N, qr_packed, 4, SCR_PAL_BLACK, SCR_PAL_WHITE);
        }
        t1 = ticks_now();
        timing("QR 49 modules scale 4: quiet zone + scr_bitmap_1bpp (BltTemplate)", 5, t0, t1);
        step(rc == 1, "scr_bitmap_1bpp 49x49 scale 4 (Chip template + BltTemplate)");
        t0 = ticks_now();
        for (i = 0; i < 2; i++) rc = scr_bitmap_1bpp_rects(qx, qy, QR_N, QR_N, qr_packed, 4, SCR_PAL_BLACK, SCR_PAL_WHITE);
        t1 = ticks_now();
        timing("same matrix via scr_bitmap_1bpp_rects (RectFill runs)", 2, t0, t1);
        step(rc == 1, "scr_bitmap_1bpp_rects 49x49 scale 4 (fallback)");
        /* the client's real format (docs/UI.md, QR section): stride 10, 8x4 pixels per module = 392x196, drawn
         * over the text area for the timing only, the text block is redrawn afterwards */
        t0 = ticks_now();
        for (i = 0; i < 5; i++) rc = scr_bitmap_1bpp_ex(120, 44, QR_N, QR_N, qr, QR_ROW_BYTES, 8, 4, SCR_PAL_BLACK, SCR_PAL_WHITE);
        t1 = ticks_now();
        timing("QR 49 modules 8x4 px (stride 10) scr_bitmap_1bpp_ex", 5, t0, t1);
        step(rc == 1, "scr_bitmap_1bpp_ex 49x49 modules 8x4 px, stride 10");
        t0 = ticks_now();
        for (i = 0; i < 5; i++) rc = scr_bitmap_1bpp_ex(120, 44, QR_N, QR_N, qr, QR_ROW_BYTES, 6, 3, SCR_PAL_BLACK, SCR_PAL_WHITE);
        t1 = ticks_now();
        timing("QR 49 modules 6x3 px (generic width) scr_bitmap_1bpp_ex", 5, t0, t1);
        step(rc == 1, "scr_bitmap_1bpp_ex 49x49 modules 6x3 px");
        scr_fill(120, 44, 392, 196, SCR_PAL_BG);
        for (i = 0; txt_block[i]; i++) scr_text(8, 44 + i * 8, i == 0 ? SCR_PAL_YELLOW : SCR_PAL_LTGREY, txt_block[i]);
        scr_text_bg(8, 44 + 11 * 8, SCR_PAL_BLACK, SCR_PAL_LTGREEN, " JAM2: Text mit Hintergrund (Pen 15) ");
        /* the blitter part alone: a ready 196x196 template (Chip RAM) through BltTemplate, JAM2, 4 planes */
        {
            UBYTE *tpl = (UBYTE *)AllocMem(25 * 196, MEMF_CHIP);
            if (tpl) {
                struct RastPort *rp = scr_rastport();
                for (i = 0; i < 25 * 196; i++) tpl[i] = (UBYTE)((i & 4) ? 0xF0 : 0x0F);   /* any pattern, unsigned-only arithmetic */
                __gfx_SetAPen(scr_gfx, rp, SCR_PAL_BLACK); __gfx_SetBPen(scr_gfx, rp, SCR_PAL_WHITE); __gfx_SetDrMd(scr_gfx, rp, JAM2);
                t0 = ticks_now();
                for (i = 0; i < 10; i++) __gfx_BltTemplate(scr_gfx, tpl, 0, 25, rp, qx, qy, 196, 196);
                t1 = ticks_now();
                __gfx_SetDrMd(scr_gfx, rp, JAM1);
                timing("BltTemplate 196x196 alone (ready template)", 10, t0, t1);
                FreeMem(tpl, 25 * 196);
            }
            t0 = ticks_now();
            for (i = 0; i < 10; i++) scr_fill(qx - 16, qy - 16, 196 + 32, 196 + 32, SCR_PAL_WHITE);
            t1 = ticks_now();
            timing("scr_fill 228x228 alone (quiet zone)", 10, t0, t1);
        }
        /* final picture: the template version again, plus the scale 2 and scale 1 variants below the text */
        scr_bitmap_1bpp(qx, qy, QR_N, QR_N, qr_packed, 4, SCR_PAL_BLACK, SCR_PAL_WHITE);
        scr_fill(8, 150, 98 + 8, 98 + 8, SCR_PAL_WHITE); scr_bitmap_1bpp_ex(12, 154, QR_N, QR_N, qr, QR_ROW_BYTES, 2, 2, SCR_PAL_BLACK, SCR_PAL_WHITE);
        scr_fill(130, 150, 49 + 8, 49 + 8, SCR_PAL_WHITE); scr_bitmap_1bpp_ex(134, 154, QR_N, QR_N, qr, QR_ROW_BYTES, 1, 1, SCR_PAL_BLACK, SCR_PAL_WHITE);
        scr_text(200, 150, SCR_PAL_LTGREY, "<- Skalierung 2 und 1");
        scr_text(200, 160, SCR_PAL_LTGREY, "rechts: 49 Module x 4 px");
    }

    /* ---- keyboard translation self-test (no key press needed): raw codes through the same path ---- */
    out("info: console.device "); out(scr_console_ok() ? "open (RawKeyConvert, system keymap)" : "NOT open - built-in US table"); out("\n");
    step(scr_console_ok(), "console.device opened as library (unit -1) for RawKeyConvert");
    {
        static const struct { UWORD code, qual; LONG want; const char *name; } kt[] = {
            { 0x20, 0, 'a', "raw $20 -> a" }, { 0x20, IEQUALIFIER_LSHIFT, 'A', "raw $20 + shift -> A" },
            { 0x01, 0, '1', "raw $01 -> 1" }, { 0x40, 0, ' ', "raw $40 -> space" }, { 0x44, 0, 13, "raw $44 -> return" },
            { 0x41, 0, 8, "raw $41 -> backspace" }, { 0x45, 0, 27, "raw $45 -> escape" },
            { 0x4C, 0, SCR_KEY_RAW | 0x4C, "raw $4C (cursor up) -> SCR_KEY_RAW" },
            { 0xA0, 0, SCR_KEY_TIMEOUT, "raw $A0 (key release) -> ignored" } };
        int all = 1;
        for (i = 0; i < (int)(sizeof kt / sizeof kt[0]); i++) {
            LONG got = scr_translate_raw(kt[i].code, kt[i].qual);
            int ok = got == kt[i].want;
            if (!ok) all = 0;
            out("key:  "); out(kt[i].name); out(": got "); out_dec((ULONG)got); out(ok ? "" : " (unexpected)");
            out(" via "); line[0] = (char)scr_last_key_source(); line[1] = 0; out(line[0] ? line : "-"); out("\n");
        }
        step(all, "raw key translation self-test (a, A, 1, space, return, backspace, escape, cursor, release)");
    }

    /* ---- wait up to 10 s for a key ---- */
    scr_fill(0, SCR_H - 12, SCR_W, 12, SCR_PAL_DKGREEN);
    scr_text(8, SCR_H - 10, SCR_PAL_WHITE, "Taste druecken (10 s) ...");
    t0 = ticks_now();
    key = scr_wait_key(500);
    t1 = ticks_now();
    out("key:  scr_wait_key(500) -> "); out_dec((ULONG)key);
    if (key == SCR_KEY_TIMEOUT) out(" (timeout)");
    else if (key & SCR_KEY_RAW) { out(" (raw code $"); out_hex((ULONG)(key & 0xff)); out(")"); }
    else { out(" ('"); line[0] = (char)key; line[1] = 0; out(key >= 32 ? line : "?"); out("')"); }
    out(" after "); out_dec((t1 - t0) * 20); out(" ms, source ");
    line[0] = (char)scr_last_key_source(); line[1] = 0; out(line[0] ? line : "-"); out("\n");
    step(key == SCR_KEY_TIMEOUT ? ((t1 - t0) >= 495 && (t1 - t0) <= 530) : 1, key == SCR_KEY_TIMEOUT ? "scr_wait_key timeout after 10.0 s" : "scr_wait_key returned a key");
    dec_to(line, (ULONG)key);
    scr_text(8 + 8 * 26, SCR_H - 10, SCR_PAL_YELLOW, key == SCR_KEY_TIMEOUT ? "Timeout, Bildschirm wird geschlossen." : line);
    scr_wait_key(50);                                  /* one second to see the result */

    t0 = ticks_now();
    scr_close();
    t1 = ticks_now();
    out("info: scr_close in "); out_dec((t1 - t0) * 20); out(" ms\n");
    chip2 = AvailMem(MEMF_CHIP); fast2 = AvailMem(MEMF_FAST);
    out("mem:  after close: chip "); out_dec(chip2); out(" fast "); out_dec(fast2); out(" (difference to before: chip ");
    out_dec(chip0 >= chip2 ? chip0 - chip2 : 0); out(" fast "); out_dec(fast0 >= fast2 ? fast0 - fast2 : 0); out(")\n");
    step(chip2 + 4096 >= chip0, "Chip RAM back after scr_close (within 4 KiB)");
    step(scr_screen() == 0 && scr_window() == 0, "scr_close cleared screen/window");

    out("info: total "); out_dec((ticks_now() - t_start) * 20); out(" ms\n");
    out(fails ? "RESULT: FAIL " : "RESULT: PASS "); out_dec((ULONG)fails); out(" failed step(s)\n");
end:
    if (logfile) Close(logfile);
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
    return fails ? 5 : 0;
}
