/*
 * Tachyon - the WhatsApp connection probe on the Amiga (Kickstart 1.3, bsdsocket.library via net/bsdsock_io.c).
 *
 * Same protocol core as the host probe (tests/wa_probe_core.c): TCP -> TLS 1.3 -> WebSocket -> Noise XX
 * with the heartbeat armed, against web.whatsapp.com through whatever SANA-II device the running TCP/IP
 * stack (TheWire13) drives. Everything is logged with DateStamp timestamps to the console and
 * SYS:result.txt; SYS:done is created last for the host script. Freestanding: no C library.
 *
 * Inputs on SYS: (written by tools/run-fsuae-net.sh):
 *   seed.bin   64 bytes of entropy for the DRBG (the emulated A500 has no entropy source, docs/RNG.md)
 *   now.txt    "YYYYMMDDHHMMSSZ" for the certificate validity check, used when the Amiga clock is in 1978
 *   waip.txt   dotted address of web.whatsapp.com, fallback when the stack's DNS fails
 *   gap.txt    seconds of X25519 ladders between ServerHello and ClientFinish (default 0: the real
 *              Noise computation on the 68000 already takes 25-40 s)
 *   noisecache.bin  optional, 32 bytes: fingerprint of WhatsApp's verified intermediate Noise certificate from
 *              an earlier run (host or Amiga); written back after a successful run (ENVARC: in the client)
 *   pair.txt   present: pairing / login mode (docs/PROTOCOL.md 11) instead of the plain probe. The credentials record
 *              SYS:tachyon.creds (proto/creds.c) is loaded when present (paired -> login, else the stored identity
 *              pairs); without it a new identity is generated. The QR codes are drawn on the client screen
 *              (ui/screen.c, 8x4 or 6x3 pixels per module) with a countdown; the record is written as soon as the
 *              pairing is complete and again after the run.
 * The three X25519 key pairs (TLS, Noise static, Noise ephemeral) are computed first, while the stack is
 * still starting, so none of it sits in the connected window.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "../net/bsdsock_io.h"
#include "../tests/wa_probe_core.h"
#include "../proto/creds.h"
#include "../ui/screen.h"

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;

static BPTR con, logfile, owncon;    /* owncon: our CON: window when stdout is not a console (run >NIL: in the Startup-Sequence) */
static bsdsock_io net;
static ULONG tick0;
static ULONG wa_addr;
static char aline[300];

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void out(const char *s)
{
    int n = slen(s);
    if (con) Write(con, (APTR)s, n);
    if (logfile) Write(logfile, (APTR)s, n);
}

/* 1/50 s ticks since midnight of day 0, milliseconds since program start */
static ULONG ticks_now(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return (ULONG)ds.ds_Days * (24UL * 60UL * 60UL * 50UL) + (ULONG)ds.ds_Minute * (60UL * 50UL) + (ULONG)ds.ds_Tick;
}
static uint32_t now_ms(void) { return (ticks_now() - tick0) * 20; }

/* progress while the 68000 computes (identity 18 s, TLS 32 s, Noise 41 s, pair-success verify + sign 19 s): the
 * CRYPTO_YIELD hook prints a dot every 2 s on the console (not into the log file) and, with the screen open, in its
 * bottom line - otherwise the user takes the silent AmigaDOS window for a crash. The heartbeat chains to this hook. */
static int screen_open;
static uint32_t prog_last; static int con_dots, scr_dots;
static void progress_tick(void *ctx)
{
    static uint32_t calls; uint32_t now; (void)ctx;
    if (++calls & 15) return;                 /* DateStamp only every 16th yield (the heartbeat already asks once per yield) */
    now = now_ms();
    if (now - prog_last < 2000) return;
    prog_last = now;
    if (con) { Write(con, (APTR)".", 1); con_dots++; }
    if (screen_open) {
        if (scr_dots >= 76) { scr_fill(0, SCR_H - 10, SCR_W, 8, SCR_PAL_BG); scr_dots = 0; }
        scr_text(8 + 8 * scr_dots++, SCR_H - 10, SCR_PAL_LTGREY, ".");
    }
}
static void log_line(void *ctx, const char *s)
{
    (void)ctx;
    if (con_dots) { if (con) Write(con, (APTR)"\n", 1); con_dots = 0; }
    wa_fmt(aline, sizeof aline, "+%7Ts  %s\n", now_ms(), s);
    out(aline);
    prog_last = now_ms();
}
static void logf1(const char *fmt, const char *a, uint32_t b) { char l[200]; wa_fmt(l, sizeof l, fmt, a, b); log_line(0, l); }

static LONG read_file(const char *name, uint8_t *buf, LONG cap)
{
    BPTR f = Open((STRPTR)name, MODE_OLDFILE); LONG n;
    if (!f) return -1;
    n = Read(f, buf, cap);
    Close(f);
    return n;
}

/* DateStamp days (since 1978-01-01) -> "YYYYMMDDHHMMSSZ"; 1 if the year is plausible for a live certificate check */
static int clock_string(char *s)
{
    struct DateStamp ds; ULONG z, era, doe, yoe, doy, mp, y, m, d, hh, mm, ss;
    DateStamp(&ds);
    z = (ULONG)ds.ds_Days + 2922 + 719468;         /* days since 1970-01-01, then shifted to 0000-03-01 (H. Hinnant) */
    era = z / 146097; doe = z - era * 146097;
    yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = yoe + era * 400; doy = doe - (365 * yoe + yoe / 4 - yoe / 100); mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1; m = mp < 10 ? mp + 3 : mp - 9; if (m <= 2) y++;
    hh = (ULONG)ds.ds_Minute / 60; mm = (ULONG)ds.ds_Minute % 60; ss = (ULONG)ds.ds_Tick / 50;
    wa_fmt(s, 16, "%04u%02u%02u%02u%02u%02uZ", y, m, d, hh, mm, ss);
    return y >= 2025;
}

/* ---- pairing: credentials file and the QR screen ------------------------------------------------- */
static wa_creds creds; static int pair_mode;

static void write_creds(void *ctx)
{
    static uint8_t rec[WA_CREDS_SIZE]; BPTR f; (void)ctx;
    if (wa_creds_write(rec, sizeof rec, &creds) != WA_CREDS_SIZE) return;
    f = Open((STRPTR)"SYS:tachyon.creds", MODE_NEWFILE);
    if (f) { Write(f, rec, WA_CREDS_SIZE); Close(f); logf1("creds: SYS:tachyon.creds written (%s)", creds.paired ? "paired" : "identity only", 0); }
    else log_line(0, "creds: cannot write SYS:tachyon.creds");
}

#define QR_TOP 40                     /* first pixel row of the quiet zone */
static void screen_text_line(int row, int pen, const char *s)
{
    scr_fill(0, row, SCR_W, 8, SCR_PAL_BG);
    scr_text(8, row, pen, s);
}
static void show_qr(void *ctx, const char *text, const qr *code, uint32_t valid_ms, uint32_t index, uint32_t count)
{
    int sx, sy, n = code->size, w, h, x, y; char l[96]; uint32_t t0 = now_ms(); (void)ctx; (void)text;
    if (!screen_open) {
        int rc = scr_open();
        if (rc) { logf1("screen: scr_open failed (%u) - the code is only in the log", (const char *)(ULONG)rc, 0); return; }
        screen_open = 1;
        scr_clear(SCR_PAL_BG);
        scr_fill(0, 0, SCR_W, 12, SCR_PAL_DKGREEN);
        scr_text(8, 2, SCR_PAL_WHITE, "Tachyon - WhatsApp fuer den Amiga 500");
        scr_text(SCR_W - 8 - 8 * 13, 2, SCR_PAL_LTGREEN, "Kickstart 1.3");
        scr_text(8, 16, SCR_PAL_LTGREY, "WhatsApp am Telefon: Einstellungen > Verknuepfte Geraete > Geraet hinzufuegen, dann diesen Code scannen.");
    }
    /* PAL hires pixels are ~0.52:1: 8x4 px per module up to 53 modules (V9), 6x3 above (docs/UI.md) */
    if (n <= 53) { sx = 8; sy = 4; } else { sx = 6; sy = 3; }
    w = (n + 8) * sx; h = (n + 8) * sy;
    x = (int)((uint32_t)(SCR_W - w) >> 1); x &= ~7; y = QR_TOP;   /* unsigned: no __divs on the 68000 */
    scr_fill(x, y, w, h, SCR_PAL_WHITE);                                           /* quiet zone, 4 modules */
    scr_bitmap_1bpp_ex(x + 4 * sx, y + 4 * sy, n, n, code->modules, QR_STRIDE, sx, sy, SCR_PAL_BLACK, SCR_PAL_WHITE);
    wa_fmt(l, sizeof l, "Code %u von %u  -  Version %u, %u x %u Module, %ux%u Pixel je Modul", index, count, (uint32_t)code->version, (uint32_t)n, (uint32_t)n, (uint32_t)sx, (uint32_t)sy);
    screen_text_line(SCR_H - 20, SCR_PAL_LTGREY, l);
    wa_fmt(l, sizeof l, "gueltig noch %u s", valid_ms / 1000);
    screen_text_line(SCR_H - 10, SCR_PAL_YELLOW, l); scr_dots = 0;
    wa_fmt(l, sizeof l, "screen: code drawn in %u ms: %u x %u modules at %ux%u px, %u x %u px with quiet zone", now_ms() - t0, (uint32_t)n, (uint32_t)n, (uint32_t)sx, (uint32_t)sy, (uint32_t)w, (uint32_t)h);
    log_line(0, l);
}
static void qr_tick(void *ctx, uint32_t remaining_ms)
{
    static uint32_t last = 0xffffffffUL; uint32_t s = (remaining_ms + 500) / 1000; char l[48]; (void)ctx;
    if (!screen_open || s == last) return;
    last = s;
    wa_fmt(l, sizeof l, "gueltig noch %u s   ", s);
    screen_text_line(SCR_H - 10, s <= 5 ? SCR_PAL_RED : SCR_PAL_YELLOW, l);
}
static void qr_hide(void *ctx, const char *status)
{
    (void)ctx;
    if (!screen_open) return;
    scr_fill(0, QR_TOP, SCR_W, SCR_H - QR_TOP - 24, SCR_PAL_BG);
    screen_text_line(SCR_H - 20, SCR_PAL_LTGREEN, status);
    screen_text_line(SCR_H - 10, SCR_PAL_BG, ""); scr_dots = 0;
}

static int io_send(void *ctx, const uint8_t *p, uint32_t n) { (void)ctx; return bsdsock_send(&net, p, n); }
static int32_t io_recv(void *ctx, uint8_t *p, uint32_t cap, uint32_t timeout_ms) { (void)ctx; return (int32_t)bsdsock_recv(&net, p, cap, timeout_ms); }
static int io_reconnect(void *ctx) { (void)ctx; return bsdsock_connect(&net, wa_addr, 443); }

static void finish(void)
{
    BPTR done;
    if (screen_open) { scr_close(); screen_open = 0; }
    bsdsock_close(&net);
    if (logfile) Close(logfile);
    if (owncon) { Close(owncon); owncon = 0; con = 0; }
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
}

int main(void)
{
    static wa_probe_io io; static uint8_t seed[64], small[64], ncache[32]; static char nowstr[16], waip[20];
    uint32_t t_conn, t_dns, t_prep, gap_ms = 0, tries;
    LONG n;
    char addr[16];

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    con = Output();
    if (!con || !IsInteractive(con)) { owncon = Open((STRPTR)"CON:0/11/640/245/Tachyon WhatsApp-Probe", MODE_NEWFILE); if (owncon) con = owncon; }
    logfile = Open((STRPTR)"SYS:result.txt", MODE_NEWFILE);
    tick0 = ticks_now();
    out("Tachyon WhatsApp probe on the A500: bsdsocket.library -> TLS 1.3 -> WebSocket -> Noise XX\n");
    { static const char hint[] = "Bitte warten. Der 68000 rechnet: Identitaet und Schluessel ca. 25 s, dann TLS ca. 32 s und Noise ca. 42 s\n"
                                 "je Verbindung; ein Punkt alle 2 s heisst: es geht weiter. Beim Pairing erscheint der QR-Code auf einem eigenen Schirm.\n";
      if (con) Write(con, (APTR)hint, slen(hint)); }

    /* inputs */
    if (read_file("SYS:seed.bin", seed, 64) != 64) { out("RESULT: SYS:seed.bin missing (64 bytes of entropy needed)\n"); finish(); return 10; }
    if (clock_string(nowstr)) logf1("clock: Amiga time %s", nowstr, 0);
    else {
        n = read_file("SYS:now.txt", small, 15);
        if (n == 15) { int i; for (i = 0; i < 15; i++) nowstr[i] = (char)small[i]; nowstr[15] = 0; logf1("clock: Amiga clock not set, using host time %s from SYS:now.txt", nowstr, 0); }
        else { nowstr[0] = 0; log_line(0, "clock: no time source, certificate validity period not checked"); }
    }
    n = read_file("SYS:waip.txt", small, 19); if (n > 0) { int i; for (i = 0; i < n && small[i] > ' '; i++) waip[i] = (char)small[i]; waip[i] = 0; } else waip[0] = 0;
    n = read_file("SYS:gap.txt", small, 8); if (n > 0) { int i; for (i = 0; i < n && small[i] >= '0' && small[i] <= '9'; i++) gap_ms = gap_ms * 10 + (uint32_t)(small[i] - '0'); gap_ms *= 1000; }

    io.ctx = 0; io.send = io_send; io.recv = io_recv; io.reconnect = io_reconnect; io.now_ms = now_ms; io.log = log_line;
    io.host = "web.whatsapp.com"; io.now = nowstr[0] ? nowstr : 0; io.seed = seed; io.seed_len = 64;
    io.gap_ms = gap_ms; io.tunnel = 0; io.use_cache = 0; io.debug = 0; io.hold_ms = 0;
    io.noise_cache_in = read_file("SYS:noisecache.bin", ncache, 32) == 32 ? ncache : 0;
    log_line(0, io.noise_cache_in ? "noise: certificate cache loaded from SYS:noisecache.bin" : "noise: certificate cache empty (no SYS:noisecache.bin)");
    pair_mode = read_file("SYS:pair.txt", small, 4) >= 0;
    io.mode = pair_mode ? WA_MODE_PAIR : WA_MODE_PROBE;
    if (pair_mode) {
        static uint8_t rec[WA_CREDS_SIZE + 1];
        io.creds = &creds; io.creds_loaded = 0; io.qr_mask = 2;        /* fixed mask: ~2 s less per code on the 68000 */
        io.show_qr = show_qr; io.qr_tick = qr_tick; io.qr_hide = qr_hide; io.save_creds = write_creds;
        n = read_file("SYS:tachyon.creds", rec, sizeof rec);
        if (n > 0) {
            if (!wa_creds_read(&creds, rec, (uint32_t)n)) { out("RESULT: SYS:tachyon.creds is not a valid record - refusing to continue (delete it to pair anew)\n"); finish(); return 10; }
            io.creds_loaded = 1;
            log_line(0, creds.paired ? "creds: SYS:tachyon.creds loaded: paired, will log in (identity check skipped on the 68000: 20 s)" : "creds: SYS:tachyon.creds loaded: identity only, will pair");
        } else log_line(0, "creds: no SYS:tachyon.creds: a new identity will be generated, QR pairing follows");
    }

    /* offline part first: the three X25519 key pairs (~10 s on the 68000) while the stack starts in parallel */
    t_prep = now_ms();
    crypto_yield_hook = progress_tick; prog_last = now_ms();     /* dots while computing; the heartbeat chains to it */
    if (!wa_probe_prepare(&io)) { out(io.result); out("\n"); finish(); return 10; }
    t_prep = now_ms() - t_prep;

    /* the stack: TheWire13 is started by the Startup-Sequence just after us and needs a few seconds */
    for (tries = 0; tries < 120; tries++) {
        if (bsdsock_open(&net)) { if (bsdsock_stack_ready(&net)) break; bsdsock_close(&net); }
        Delay(25);
    }
    if (!net.base) { log_line(0, "net: bsdsocket.library did not open within 60 s - is the TCP/IP stack running?"); out("RESULT: no bsdsocket.library\n"); finish(); return 10; }
    logf1("net: bsdsocket.library v%u open, stack answers (socket() ok) after %u tries", (const char *)(ULONG)net.base->lib_Version, tries + 1);
    t_dns = now_ms();
    if (!bsdsock_resolve(&net, "web.whatsapp.com", waip[0] ? waip : 0, &wa_addr)) {
        logf1("net: %s failed, errno %u, and no SYS:waip.txt fallback", net.fail ? net.fail : "resolve", (uint32_t)net.err);
        out("RESULT: name resolution failed\n"); finish(); return 10;
    }
    t_dns = now_ms() - t_dns;
    bsdsock_ntoa(wa_addr, addr);
    logf1("dns: web.whatsapp.com -> %s in %u ms", addr, t_dns);
    t_conn = now_ms();
    if (!bsdsock_connect(&net, wa_addr, 443)) {
        logf1("tcp: %s failed, errno %u", net.fail ? net.fail : "connect", (uint32_t)net.err);
        out("RESULT: TCP connect failed\n"); finish(); return 10;
    }
    t_conn = now_ms() - t_conn;
    logf1("tcp: connected to %s:443 in %u ms", addr, t_conn);

    {
        int ok = wa_probe_run(&io);
        if (!ok && net.fail) logf1("net: last failed call %s, errno %u", net.fail, (uint32_t)net.err);
        if (ok && io.noise_cache_valid) {
            BPTR cf = Open((STRPTR)"SYS:noisecache.bin", MODE_NEWFILE);
            if (cf) { Write(cf, io.noise_cache_fp, 32); Close(cf); log_line(0, "noise: certificate cache fingerprint written to SYS:noisecache.bin"); }
        }
        wa_fmt(aline, sizeof aline, "TIMING: keys %u ms (tls %u + noise %u, before connect), dns %u ms, tcp connect %u ms, tls %u ms, ws %u ms, server hello %u ms, client finish %u ms, accepted %u ms (ms since connect, %u pongs%s)\n",
               t_prep, io.t_tls_key, io.t_noise_keys, t_dns, t_conn, io.t_tls, io.t_ws, io.t_hello, io.t_finish, io.t_accepted, io.pongs, io.noise_cert_cached ? ", Noise cert cache hit" : "");
        out(aline);
        if (pair_mode) {
            wa_fmt(aline, sizeof aline, "PAIRING: codes shown %u, first code at %u ms, pair-success at %u ms, verify %u ms, sign %u ms, pair-device-sign at %u ms, stream:error 515 at %u ms, login connect at %u ms, login success at %u ms\n",
                   io.qr_shown, io.t_qr_shown, io.t_pair_success, io.d_verify, io.d_sign, io.t_sign_sent, io.t_515, io.t_login_connect, io.t_login_accepted);
            out(aline);
            if (io.creds_loaded) write_creds(0);
        }
        out(io.result); out("\n");
        finish();
        return ok ? 0 : 5;
    }
}
