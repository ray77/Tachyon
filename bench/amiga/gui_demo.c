/*
 * Tachyon - demo and timing of the chat interface (ui/gui.c) on Kickstart 1.3: make amiga-gui / make run-gui.
 *
 * Opens the screen, loads a scripted conversation (5 chats, 40+ German messages with umlauts), paints it and
 * measures: the initial paint (own renderer and graphics.library Text()), the repaint for an incoming message on
 * the three scroll paths (ScrollRaster, CPU copy, row repaint), key echo, a status tick, a chat switch, then runs
 * the interactive loop for 60 s with a fake clock and a fake incoming message every 7 s (type, send, scroll, F1;
 * Esc Esc or Amiga-Q ends early) and logs the key latency seen there. Everything goes to SYS:result.txt with
 * DateStamp ticks (20 ms; repeated operations are averaged), SYS:done is created last for tools/run-fsuae.sh.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "../../ui/screen.h"
#include "../../ui/gui.h"

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;

static BPTR con, logfile;
static int fails;
static UBYTE arena[48 * 1024];                      /* BSS: Fast RAM */

static int dslen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void out(const char *s)
{
    int n = dslen(s);
    if (con) Write(con, (APTR)s, n);
    if (logfile) Write(logfile, (APTR)s, n);
}
static void out_dec(ULONG u) { char b[12]; int i = 11; b[i] = 0; do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u); out(b + i); }
static void out_frac(ULONG tenths) { out_dec(tenths / 10); out("."); out_dec(tenths % 10); }

static ULONG ticks_now(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return (ULONG)ds.ds_Days * (24UL * 60UL * 60UL * 50UL) + (ULONG)ds.ds_Minute * (60UL * 50UL) + (ULONG)ds.ds_Tick;
}

static void step(int ok, const char *what) { out(ok ? "ok:   " : "FAIL: "); out(what); out("\n"); if (!ok) fails++; }

/* "time: <name>: N x in T ms (U ms each)" */
static void timing(const char *name, ULONG calls, ULONG t0, ULONG t1)
{
    ULONG ms = (t1 - t0) * 20, per10 = calls ? (ms * 10) / calls : 0;
    out("time: "); out(name); out(": "); out_dec(calls); out(" x in "); out_dec(ms); out(" ms ("); out_frac(per10); out(" ms each)\n");
}

#define BASE 1795780800UL                            /* 2026-11-27 12:00 UTC */

struct line { UBYTE chat, from_me; UWORD dt; const char *text; };
static const char *chat_jid[] = { "4917612345678@s.whatsapp.net", "4915112345678@s.whatsapp.net", "120363012345678901@g.us", "4916012345678@s.whatsapp.net", "4917012345678@s.whatsapp.net" };
static const char *chat_name[] = { "Anna M\xC3\xBCller", "J\xC3\xB6rg", "Amiga-Stammtisch", "Papa", "Werkstatt Fr\xC3\xB6" "bel" };
static const struct line script[] = {
    { 0, 0, 0,    "Hallo Domy! Hast du den Amiga schon ans Netz bekommen? \xF0\x9F\x98\x80" },
    { 0, 1, 40,   "Fast. TLS 1.3 l\xC3\xA4uft, der Noise-Handshake auch. Heute Abend kommt die Oberfl\xC3\xA4" "che dran." },
    { 0, 0, 90,   "Sch\xC3\xB6n! Und das hier liest du jetzt echt auf einem 68000 mit 7 MHz?" },
    { 0, 1, 95,   "Ja. 640x256, 16 Farben, Topaz 8. Der Textrenderer schreibt direkt in die Bitplanes." },
    { 0, 0, 100,  "Wie lange dauert der Login?" },
    { 0, 1, 103,  "47 Sekunden vom Programmstart. Drei X25519-Leitern \xC3\xA0 7,7 s, der Rest ist RSA und Netz." },
    { 1, 0, 120,  "Kommst du Samstag zum Stammtisch? Bring den A500 mit, die wollen alle WhatsApp auf dem 1084 sehen \xF0\x9F\x98\x8E" },
    { 1, 1, 125,  "Klar. Ich bringe auch das A2065-Kabel mit, falls das WLAN dort wieder spinnt." },
    { 1, 0, 130,  "Super. Thomas fragt, ob die Gruppen schon gehen." },
    { 1, 1, 132,  "Noch nicht - erst Einzelchats. Sender Keys kommen danach." },
    { 2, 0, 140,  "Thomas: Ich bringe die Kickstart-ROMs mit" },
    { 2, 0, 141,  "Sabine: und ich den Kuchen \xF0\x9F\x8E\x82" },
    { 2, 0, 142,  "Thomas: Kuchen > ROMs" },
    { 2, 0, 150,  "Sabine: Hat jemand noch ein Netzteil f\xC3\xBCr den 1084? Meins brummt." },
    { 2, 0, 151,  "Thomas: Ich hab eins. Kondensatoren getauscht, l\xC3\xA4uft wie neu." },
    { 3, 1, 160,  "Ich melde mich morgen, Papa." },
    { 3, 0, 161,  "Gut. Gr\xC3\xBC\xC3\x9F" "e an alle!" },
    { 4, 0, 170,  "Guten Tag, Ihr Bestellung (Fr\xC3\xA4smaschinenteile) ist eingetroffen. Abholung Mo-Fr 8-17 Uhr." },
    { 4, 1, 172,  "Danke, ich komme Dienstag vorbei." },
    { 0, 0, 180,  "Und Umlaute? \xC3\xA4\xC3\xB6\xC3\xBC\xC3\x84\xC3\x96\xC3\x9C\xC3\x9F - gehen die?" },
    { 0, 1, 181,  "Alles ISO-8859-1 auf dem Schirm, UTF-8 auf der Leitung. Emoji werden zu :) und so." },
    { 0, 0, 182,  "\xF0\x9F\x91\x8D \xF0\x9F\x8E\x89 \xE2\x9D\xA4\xEF\xB8\x8F" },
    { 0, 1, 183,  "Siehst du? +1, *party* und <3." },
    { 0, 0, 190,  "Donaudampfschifffahrtsgesellschaftskapit\xC3\xA4nsm\xC3\xBCtzenhalterungsschraubenschl\xC3\xBCsselsatz" },
    { 0, 1, 191,  "Harte Umbr\xC3\xBC" "che gehen auch, siehst du ja." },
    { 0, 0, 200,  "Mehrzeilig:\nzweite Zeile\ndritte Zeile" },
    { 0, 1, 201,  "Kurz." },
    { 0, 0, 210,  "Was meinst du, wie lange braucht der Signal-Ratchet pro Nachricht?" },
    { 0, 1, 211,  "Eine X25519-Leiter beim Sitzungsaufbau, danach nur noch HMAC und AES - unter einer Sekunde." },
    { 1, 0, 220,  "Moin! Der Stack ist TheWire13, der Treiber ein SANA-II-Wrapper um die A2065." },
    { 1, 1, 221,  "Und der Speicher? 1 MiB Fast reicht f\xC3\xBCr den Login, der Client will 2 MiB." },
    { 1, 0, 222,  "Das ist schneller als mein DSL-Router morgens \xF0\x9F\x98\x82" },
    { 0, 0, 230,  "Und dann?" }, { 0, 1, 231, "Ja." }, { 0, 0, 232, "Und dann?" }, { 0, 1, 233, "Ja." },
    { 0, 0, 234,  "Und dann?" }, { 0, 1, 235, "Ja." }, { 0, 0, 236, "Und dann?" }, { 0, 1, 237, "Ja." },
    { 0, 0, 240,  "Ok, ich schreibe dir gleich noch mal. Lass den Amiga an!" },
    { 0, 1, 241,  "Er l\xC3\xA4uft. Nachrichten kommen alle 7 Sekunden rein, sagt die Demo." },
};
#define NSCRIPT (sizeof script / sizeof script[0])

static const char *incoming[] = {
    "Bist du noch da?", "Die Demo l\xC3\xA4uft schon eine Weile.", "Tippe doch mal was - Return schickt es ab.",
    "F1 zeigt die Tasten.", "Shift+Auf bl\xC3\xA4ttert im Verlauf.", "Tab wechselt zur Chatliste.",
    "Und Esc Esc beendet die Demo.", "Noch eine Nachricht mit \xC3\x84\xC3\x96\xC3\x9C.", "Letzte Runde \xF0\x9F\x91\x8B"
};

int main(void)
{
    ULONG t0, t1, t_start, now = BASE + 300, chip0, fast0, chip1, fast1;
    LONG rc;
    int i, cur;
    struct gui_stats st;
    BPTR done;
    ULONG pending_id = 0, pending_at = 0;

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    con = Output();
    logfile = Open((STRPTR)"SYS:result.txt", MODE_NEWFILE);
    t_start = ticks_now();
    out("Tachyon GUI demo: chat interface (ui/gui.c) on the 640x256x4 screen, Kickstart 1.3\n");
    chip0 = AvailMem(MEMF_CHIP); fast0 = AvailMem(MEMF_FAST);

    rc = scr_open();
    step(rc == 0, "scr_open");
    if (rc) { out("RESULT: FAIL (scr_open)\n"); goto end; }
    rc = gui_init(arena, sizeof arena);
    step(rc == 0, "gui_init (48 KiB arena)");
    out("info: text mode after init: "); out(gui_text_mode() == GUI_TEXT_FAST ? "fast (own renderer, ROM Topaz glyphs)" : "OS Text()"); out("\n");
    step(gui_text_mode() == GUI_TEXT_FAST, "fast text renderer available (font glyphs + planes)");
    gui_set_tz(3600);
    gui_set_time(now);
    gui_set_connection(GUI_CONN_ONLINE, "Demo ohne Netz - web.whatsapp.com simuliert");

    for (i = 0; i < 5; i++) gui_add_chat(chat_jid[i], chat_name[i]);
    t0 = ticks_now();
    for (i = 0; i < (int)NSCRIPT; i++) {
        ULONG ts = BASE - 86400UL + (ULONG)script[i].dt * 60UL;
        if (script[i].dt >= 230) ts = BASE + (ULONG)(script[i].dt - 230) * 60UL;   /* the last ones today */
        gui_add_message(script[i].chat, script[i].from_me, ts, script[i].text, -1, script[i].from_me ? GUI_ST_READ : GUI_ST_READ);
    }
    t1 = ticks_now();
    timing("gui_add_message (model only)", NSCRIPT, t0, t1);
    gui_stats(&st);
    out("info: arena: "); out_dec(st.msgs); out(" messages in "); out_dec(st.slots); out(" slots, text "); out_dec(st.text_used); out("/"); out_dec(st.text_cap); out(" bytes\n");

    /* ---- initial paint, fast renderer ---- */
    t0 = ticks_now();
    gui_redraw_all();
    t1 = ticks_now();
    timing("initial paint gui_redraw_all (fast renderer)", 1, t0, t1);
    step((t1 - t0) * 20 < 1500, "initial paint under 1.5 s");
    t0 = ticks_now();
    for (i = 0; i < 3; i++) gui_redraw_all();
    t1 = ticks_now();
    timing("gui_redraw_all repeated (fast renderer)", 3, t0, t1);

    /* ---- the same through graphics.library Text() ---- */
    gui_set_text_mode(GUI_TEXT_OS);
    t0 = ticks_now();
    gui_redraw_all();
    t1 = ticks_now();
    timing("gui_redraw_all via Text()/RectFill (OS path)", 1, t0, t1);
    gui_set_text_mode(GUI_TEXT_FAST);
    gui_redraw_all();

    /* ---- incoming message on the three scroll paths (current chat: the first = Anna) ---- */
    cur = gui_current_chat();
    {
        static const int modes[3] = { GUI_SCROLL_BLIT, GUI_SCROLL_CPU, GUI_SCROLL_REDRAW };
        static const char *names[3] = { "incoming message, ScrollRaster + new rows", "incoming message, CPU plane copy + new rows", "incoming message, repaint changed rows" };
        int m, k;
        for (m = 0; m < 3; m++) {
            gui_set_scroll_mode(modes[m]);
            t0 = ticks_now();
            for (k = 0; k < 6; k++) { gui_add_message(cur, k & 1, now + k, k & 1 ? "Ja, und?" : "Noch eine Nachricht f\xC3\xBCr die Zeitmessung.", -1, GUI_ST_READ); gui_redraw_dirty(); }
            t1 = ticks_now();
            timing(names[m], 6, t0, t1);
            if (m == 0) step((t1 - t0) * 20 / 6 < 150, "incoming message repaint under 150 ms (ScrollRaster path)");
        }
        gui_set_scroll_mode(GUI_SCROLL_BLIT);
        /* a two-line message (wrap) */
        t0 = ticks_now();
        for (k = 0; k < 4; k++) { gui_add_message(cur, 0, now + 10 + k, "Eine l\xC3\xA4ngere Nachricht, die sicher auf zwei Zeilen umbrochen wird, damit der Scroll zwei Zeilen weit geht.", -1, GUI_ST_READ); gui_redraw_dirty(); }
        t1 = ticks_now();
        timing("incoming two-line message, ScrollRaster", 4, t0, t1);
    }

    /* ---- key echo: typing into the input line ---- */
    t0 = ticks_now();
    for (i = 0; i < 40; i++) { gui_pump('a' + (LONG)((ULONG)i % 26UL)); gui_redraw_dirty(); }
    t1 = ticks_now();
    timing("key echo (gui_pump + gui_redraw_dirty)", 40, t0, t1);
    step((t1 - t0) * 20 / 40 < 50, "key echo under 50 ms");
    gui_pump(27);                                   /* Esc clears */
    gui_redraw_dirty();

    /* ---- status tick on the newest own message, chat switch ---- */
    {
        ULONG id = gui_add_message(cur, 1, now + 20, "Eigene Nachricht f\xC3\xBCr den Status-Haken.", -1, GUI_ST_PENDING);
        gui_redraw_dirty();
        t0 = ticks_now();
        for (i = 0; i < 6; i++) { gui_set_status(cur, id, (i & 1) ? GUI_ST_READ : GUI_ST_DELIVERED); gui_redraw_dirty(); }
        t1 = ticks_now();
        timing("status tick update (footer row + list entry)", 6, t0, t1);
    }
    t0 = ticks_now();
    for (i = 0; i < 4; i++) { gui_select_chat((int)((ULONG)(cur + 1 + i) % 5UL)); gui_redraw_dirty(); }
    t1 = ticks_now();
    timing("chat switch (header + list + conversation)", 4, t0, t1);
    gui_select_chat(cur); gui_redraw_dirty();
    t0 = ticks_now();
    for (i = 0; i < 4; i++) { gui_pump(SCR_KEY_RAW | 0x50); gui_redraw_dirty(); gui_pump(' '); gui_redraw_dirty(); }
    t1 = ticks_now();
    timing("help overlay open + close", 4, t0, t1);
    gui_pump(27); gui_redraw_dirty();

    chip1 = AvailMem(MEMF_CHIP); fast1 = AvailMem(MEMF_FAST);
    out("mem:  chip used "); out_dec(chip0 - chip1); out(" fast used "); out_dec(fast0 - fast1); out(" (screen + GUI statics incl. 48 KiB arena in BSS)\n");

    /* ---- interactive loop: 60 s, a fake incoming message every 7 s, fake clock ---- */
    {
        ULONG t_loop = ticks_now(), last_msg = t_loop, last_clock = t_loop, keys = 0, key_ticks = 0, key_max = 0, msgs_in = 0, act_sends = 0;
        int n_in = 0, quit = 0;
        gui_set_connection(GUI_CONN_ONLINE, "Demo: 60 s interaktiv, Nachricht alle 7 s");
        gui_redraw_dirty();
        while (!quit) {
            ULONG t = ticks_now(), k0, k1;
            LONG key;
            int act;
            if (t - t_loop >= 60 * 50) break;
            key = scr_wait_key(5);                                     /* 100 ms poll keeps the echo under 50 ms + 100 */
            k0 = ticks_now();
            act = gui_pump(key);
            if (act == GUI_ACT_SEND) {
                char utf8[2 * GUI_INPUT_MAX + 4];
                int n = gui_take_outgoing(utf8, sizeof utf8);
                pending_id = gui_add_message(gui_action_chat(), 1, now, utf8, n, GUI_ST_PENDING);
                pending_at = k0; act_sends++;
            } else if (act == GUI_ACT_QUIT) quit = 1;
            if (pending_id && k0 - pending_at >= 100) { gui_set_status(0, pending_id, GUI_ST_SENT); }
            if (pending_id && k0 - pending_at >= 200) { gui_set_status(0, pending_id, GUI_ST_DELIVERED); }
            if (pending_id && k0 - pending_at >= 350) { gui_set_status(0, pending_id, GUI_ST_READ); pending_id = 0; }
            if (k0 - last_clock >= 50) { last_clock += 50; now += 60; gui_set_time(now); }    /* the fake clock runs 60x */
            if (k0 - last_msg >= 7 * 50) {
                int chat = ((ULONG)n_in % 3UL == 2) ? (int)((ULONG)(gui_current_chat() + 1) % 5UL) : gui_current_chat();
                last_msg = k0;
                gui_add_message(chat, 0, now, incoming[(ULONG)n_in % (sizeof incoming / sizeof incoming[0])], -1, GUI_ST_READ);
                n_in++; msgs_in++;
            }
            gui_redraw_dirty();
            k1 = ticks_now();
            if (key != SCR_KEY_TIMEOUT) { keys++; key_ticks += k1 - k0; if (k1 - k0 > key_max) key_max = k1 - k0; }
        }
        out("info: interactive loop: "); out_dec(keys); out(" keys, "); out_dec(msgs_in); out(" fake incoming, "); out_dec(act_sends); out(" sent");
        out(quit ? ", ended by the user" : ", 60 s elapsed"); out("\n");
        if (keys) { out("time: key latency in the loop: avg "); out_frac((key_ticks * 200) / keys); out(" ms, max "); out_dec(key_max * 20); out(" ms\n"); }
    }

    gui_stats(&st);
    out("info: arena at the end: "); out_dec(st.msgs); out(" messages, text "); out_dec(st.text_used); out("/"); out_dec(st.text_cap);
    out(" bytes, dropped "); out_dec(st.dropped); out(", rows drawn "); out_dec(st.rows_drawn); out(", scrolls "); out_dec(st.scrolls); out("\n");

    scr_close();
    out("info: total "); out_dec((ticks_now() - t_start) * 20); out(" ms\n");
    out(fails ? "RESULT: FAIL " : "RESULT: PASS "); out_dec((ULONG)fails); out(" failed step(s)\n");
end:
    if (logfile) Close(logfile);
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
    return fails ? 5 : 0;
}
