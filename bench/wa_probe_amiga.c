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
 *   chat.txt   present (with pair.txt): the interim chat (docs/SIGNAL.md). Line 1: the peer's number (JID user, digits; the
 *              phone is device 0), line 2: a text to send once after <active/> (may be empty), line 3: seconds to stay
 *              online (default 180). Typed lines in the console window go to the peer; incoming texts are printed.
 *              Sessions live in SYS:tachyon.sessions (written as .tmp, then renamed).
 *   pair.txt   present: pairing / login mode (docs/PROTOCOL.md 11) instead of the plain probe; the chat interface (ui/gui.c,
 *              docs/UI.md "Client-Oberfläche") takes the screen for the whole run: chat list, conversation, status line with
 *              the connection state, typed lines go to the selected chat, incoming texts and acks appear as they arrive.
 *              The credentials record
 *              SYS:tachyon.creds (proto/creds.c) is loaded when present (paired -> login, else the stored identity
 *              pairs); without it a new identity is generated. The QR codes are drawn on the client screen
 *              (ui/screen.c, 8x4 or 6x3 pixels per module) with a countdown; the record is written as soon as the
 *              pairing is complete and again after the run.
 * The three X25519 key pairs (TLS, Noise static, Noise ephemeral) are computed first, while the stack is
 * still starting, so none of it sits in the connected window.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "../net/bsdsock_io.h"
#include "../tests/wa_probe_core.h"
#include "../proto/creds.h"
#include "../proto/prekeys.h"
#include "../proto/nextkeys.h"
#include "../proto/signal.h"
#include "../ui/screen.h"
#include "../ui/gui.h"

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;

static BPTR con, logfile, owncon;    /* owncon: our CON: window when stdout is not a console (run >NIL: in the Startup-Sequence) */
static bsdsock_io net;
static ULONG tick0;
static ULONG wa_addr;
static char aline[300];

static int str_len(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void out(const char *s)
{
    int n = str_len(s);
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
static int gui_on, qr_visible;               /* the chat interface owns the screen (pair/login mode); a QR code covers it */
static void gui_tick(void);
static uint32_t gui_last_tick;
static uint32_t prog_last; static int con_dots, scr_dots;
static void progress_tick(void *ctx)
{
    static uint32_t calls; uint32_t now; (void)ctx;
    /* without the GUI: DateStamp only every 16th yield (X25519 yields often). With it: every yield - AES-GCM yields only
     * every 64 blocks (~0.25 s on the 68000), and with the 16-fold divisor the keys were echoed every 3-4 s while a
     * TLS record or the 166 KB frame was decrypted (live attempt 7b: "typing is very slow") */
    if ((++calls & 15) && !gui_on) return;
    now = now_ms();
    if (gui_on && now - gui_last_tick >= 200) gui_tick();   /* keys and the clock while the 68000 computes (X3DH: a minute) */
    if (now - prog_last < 2000) return;
    prog_last = now;
    if (con) { Write(con, (APTR)".", 1); con_dots++; }
    if (screen_open && !gui_on) {
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
static wa_creds creds; static int pair_mode; static wa_prekeys prekeys; static wa_nextkeys nextkeys;
static sig_store *sessions; static uint8_t *sessions_rec;      /* Chip RAM (chip_alloc), the record buffer serves reading and writing */
static char chat_peer[32], chat_text[200];

/* the big buffers (receive buffers of the core, session store and record) live in Chip RAM: Fast RAM is the scarce
 * one on a 2 MiB machine (the stack, the code and the static data of the probe fill it), Chip has ~300 KB to spare and
 * the CPU reads it at full speed outside the display DMA slots */
static APTR chip_blocks[12]; static ULONG chip_sizes[12]; static int chip_n;
static void *chip_alloc(void *ctx, uint32_t n)
{
    APTR p; (void)ctx;
    if (chip_n >= 12) return 0;
    p = AllocMem(n, MEMF_CHIP | MEMF_CLEAR);
    if (!p) return 0;
    chip_blocks[chip_n] = p; chip_sizes[chip_n] = n; chip_n++;
    return p;
}
static void chip_free_all(void) { while (chip_n) { chip_n--; FreeMem(chip_blocks[chip_n], chip_sizes[chip_n]); } }

/* the session store: SYS:tachyon.sessions.tmp first, then the old record is deleted and the new one renamed into place
 * (AmigaDOS Rename does not overwrite), so a crash never leaves a torn record under the real name */
static void write_sessions(void *ctx)
{
    uint32_t n; BPTR f; (void)ctx;
    if (!sessions || !(n = sig_store_write(sessions_rec, SIG_STORE_MAX_SIZE, sessions))) return;
    f = Open((STRPTR)"SYS:tachyon.sessions.tmp", MODE_NEWFILE);
    if (!f) { log_line(0, "sessions: cannot write SYS:tachyon.sessions.tmp"); return; }
    if (Write(f, sessions_rec, n) != (LONG)n) { Close(f); log_line(0, "sessions: short write"); return; }
    Close(f);
    DeleteFile((STRPTR)"SYS:tachyon.sessions");
    if (!Rename((STRPTR)"SYS:tachyon.sessions.tmp", (STRPTR)"SYS:tachyon.sessions")) log_line(0, "sessions: rename failed");
    else logf1("sessions: SYS:tachyon.sessions written (%s%u sessions)", "", sessions->n);
}
/* a typed line from the console window, without blocking (CON: hands over whole lines) */
static int chat_input(void *ctx, char *line, uint32_t cap)
{
    LONG n; uint32_t i; (void)ctx;
    if (!con || !WaitForChar(con, 1)) return 0;
    n = Read(con, line, cap - 1);
    if (n <= 0) return 0;
    for (i = 0; i < (uint32_t)n && line[i] != '\n' && line[i] != '\r'; i++) ;
    line[i] = 0;
    return 1;
}
static void chat_recv(void *ctx, const char *from, const char *text)
{
    char l[260]; (void)ctx;
    wa_fmt(l, sizeof l, "\n*** %s: %s\n\n", from, text);
    if (con_dots) { if (con) Write(con, (APTR)"\n", 1); con_dots = 0; }
    if (con) Write(con, (APTR)l, str_len(l));
}


/* ---- the chat interface (ui/gui.c): the core's event callbacks feed the model, the ticks paint and read keys ---------- */
#define GUI_ARENA_SIZE (32UL * 1024UL)       /* 512 descriptors + 24 KiB text; 48 KiB left no Chip RAM for the staging buffer (live attempt 7) */
static UBYTE *gui_arena; static int gui_arena_chip;                 /* Fast RAM when the stack left enough, else Chip */
static ULONG fast_before_gui, fast_after_gui;
static char self_jid[GUI_JID_MAX];                                   /* "<own number>@s.whatsapp.net": the self chat */
static const char *host_now = "";                                     /* SYS:now.txt when the Amiga clock is unset (main sets it) */
static uint32_t unix_base, unix_base_ms;                             /* the server's clock (t attributes) anchored to now_ms */
static int gui_in, gui_quit;                                         /* reentrancy guard; Esc Esc / Amiga-Q seen */
static uint32_t gui_ticks, gui_tick_sum, gui_tick_max, gui_sec_last, gui_slow_ticks;
static UBYTE chat_named[GUI_MAX_CHATS];                              /* 1 = the chat shows a pushname, not the number */
/* lines composed in the GUI wait here for the core's chat_input_to (one per linger-loop iteration, at most 1 s later) */
struct out_line { char user[32]; int lid; ULONG gui_id; int len; char text[504]; };
static struct out_line outq[4]; static int outq_head, outq_n; static ULONG sending_gui_id;
static uint32_t outq_pushed, outq_woken;                                 /* lines queued / early returns from io_recv (one per line) */
/* our message ids on the wire -> GUI message ids, for the server's <ack> and the peer's <receipt> */
struct sent_ref { char msg_id[24]; ULONG gui_id; }; static struct sent_ref sent[8]; static int sent_next;

static int str_eq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
static void scpy(char *d, const char *s, uint32_t cap) { uint32_t i = 0; while (s[i] && i + 1 < cap) { d[i] = s[i]; i++; } d[i] = 0; }

/* seconds since 1970: the server's clock once a stanza carried t=, before that the Amiga clock (DateStamp) when it is
 * set, else the host time from SYS:now.txt ("YYYYMMDDHHMMSSZ", anchored at program start by gui_start) */
static uint32_t now_unix(void)
{
    struct DateStamp ds;
    if (unix_base) return unix_base + (now_ms() - unix_base_ms) / 1000;
    DateStamp(&ds);
    if (ds.ds_Days < 17000) return 0;                                /* before 2024-07: the clock was never set (1978) */
    return ((uint32_t)ds.ds_Days + 2922) * 86400UL + (uint32_t)ds.ds_Minute * 60UL + (uint32_t)ds.ds_Tick / 50;
}
static uint32_t dig(const char *s, int n) { uint32_t v = 0; while (n--) v = v * 10 + (uint32_t)(*s++ - '0'); return v; }
static uint32_t clockstr_to_unix(const char *s)                      /* days from civil (H. Hinnant), 32-bit unsigned */
{
    uint32_t y = dig(s, 4), m = dig(s + 4, 2), d = dig(s + 6, 2), era, yoe, doy, doe;
    if (y < 2000 || m < 1 || m > 12 || d < 1) return 0;
    if (m <= 2) y--;
    era = y / 400; yoe = y - era * 400; doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1; doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return (era * 146097 + doe - 719468) * 86400UL + dig(s + 8, 2) * 3600UL + dig(s + 10, 2) * 60UL + dig(s + 12, 2);
}
static int is_self(const char *user, int lid) { return str_eq(user, creds.jid_user) || (lid && creds.lid_user[0] && str_eq(user, creds.lid_user)); }
/* the chat for a sender/recipient: the self chat for our own number or LID, else "<user>@s.whatsapp.net" / "<lid>@lid";
 * a pushname replaces the number as the name once seen */
static int chat_for(const char *user, int lid, const char *pushname)
{
    char jid[GUI_JID_MAX]; int c;
    if (is_self(user, lid)) { c = gui_find_chat(self_jid); return c >= 0 ? c : gui_add_chat(self_jid, "Du"); }
    wa_fmt(jid, sizeof jid, "%s@%s", user, lid ? "lid" : "s.whatsapp.net");
    c = gui_find_chat(jid);
    if (c < 0) { c = gui_add_chat(jid, pushname && *pushname ? pushname : user); if (c >= 0) chat_named[c] = pushname && *pushname; }
    else if (pushname && *pushname && !chat_named[c]) { gui_set_chat_name(c, pushname); chat_named[c] = 1; }
    return c;
}
static void remember_sent(const char *msg_id, ULONG gui_id) { scpy(sent[sent_next & 7].msg_id, msg_id, sizeof sent[0].msg_id); sent[sent_next & 7].gui_id = gui_id; sent_next++; }
static ULONG lookup_sent(const char *msg_id) { int i; for (i = 0; i < 8; i++) if (sent[i].msg_id[0] && str_eq(sent[i].msg_id, msg_id)) return sent[i].gui_id; return 0; }

/* GUI_ACT_SEND: the composed line becomes a pending bubble and waits in the queue for the core */
static void queue_outgoing(void)
{
    char utf8[2 * GUI_INPUT_MAX + 4]; int n = gui_take_outgoing(utf8, sizeof utf8), chat = gui_action_chat(), i; const char *jid = gui_chat_jid(chat); ULONG id; struct out_line *o;
    if (n <= 0 || !jid[0]) return;
    while (n > (int)sizeof outq[0].text - 1 || (n > 0 && ((UBYTE)utf8[n] & 0xC0) == 0x80)) n--;   /* cut at a code point (GUI_TEXT_MAX) */
    utf8[n] = 0;
    id = gui_add_message(chat, 1, now_unix(), utf8, n, GUI_ST_PENDING);
    if (outq_n >= 4) { gui_set_status(chat, id, GUI_ST_FAILED); log_line(0, "chat: outgoing queue full, line dropped"); return; }
    o = &outq[(outq_head + outq_n) & 3]; outq_n++; outq_pushed++;
    for (i = 0; jid[i] && jid[i] != '@' && i + 1 < (int)sizeof o->user; i++) o->user[i] = jid[i];
    o->user[i] = 0; o->lid = jid[i] == '@' && jid[i + 1] == 'l'; o->gui_id = id; o->len = n;
    for (i = 0; i <= n; i++) o->text[i] = utf8[i];
}
/* the core asks once per linger-loop iteration: GUI lines first (with their destination), then a console line (to chat_user) */
static int chat_input_to(void *ctx, char *user, uint32_t ucap, uint32_t *device, int *lid, char *line, uint32_t cap)
{
    *device = 0; *lid = 0; user[0] = 0;
    if (outq_n) {
        struct out_line *o = &outq[outq_head & 3]; uint32_t i;
        outq_head++; outq_n--;
        scpy(user, o->user, ucap); *lid = o->lid; sending_gui_id = o->gui_id;
        for (i = 0; i < (uint32_t)o->len && i + 1 < cap; i++) line[i] = o->text[i];
        line[i] = 0;
        return 1;
    }
    if (gui_quit) { gui_quit = 0; scpy(line, "/quit", cap); return 1; }
    return chat_input(ctx, line, cap);
}
/* one GUI step: a key (poll), the clock, what changed on the screen; never blocks, ~25 ms for a key echo, 140 ms for a
 * new message, up to 0.5 s for a chat switch (docs/UI.md). Called from io_recv's slices and from the yield hook. */
static void gui_tick(void)
{
    uint32_t t0, d, u; LONG key; int act, n;
    if (!gui_on || gui_in || qr_visible) return;
    gui_in = 1; t0 = now_ms();
    /* every key that waits in the window's queue, up to 32 per tick: during a long computation ticks are 200 ms apart
     * (live run 6: one key per tick made typing crawl), the echo is drawn once afterwards */
    for (n = 0; n < 32; n++) {
        key = scr_wait_key(0);
        if (key == SCR_KEY_TIMEOUT && n) break;
        act = gui_pump(key);
        if (act == GUI_ACT_SEND) queue_outgoing();
        else if (act == GUI_ACT_QUIT) gui_quit = 1;
        if (key == SCR_KEY_TIMEOUT) break;
    }
    u = now_unix();
    if (u != gui_sec_last) { gui_sec_last = u; gui_set_time(u); }
    gui_redraw_dirty();
    d = now_ms() - t0; gui_ticks++; gui_tick_sum += d; if (d > gui_tick_max) gui_tick_max = d; if (d > 100) gui_slow_ticks++;
    gui_last_tick = now_ms(); gui_in = 0;
}

/* ---- the core's event callbacks ---- */
static void on_state(void *ctx, int state, const char *detail)
{
    char l[64]; (void)ctx;
    if (!gui_on) return;
    switch (state) {
    case WA_CONN_TLS:    gui_set_connection(GUI_CONN_CONNECTING, "TLS 1.3 zu web.whatsapp.com ..."); break;
    case WA_CONN_WS:     gui_set_connection(GUI_CONN_HANDSHAKE, "WebSocket offen, Noise XX ..."); break;
    case WA_CONN_NOISE:  gui_set_connection(GUI_CONN_HANDSHAKE, creds.paired ? "Noise XX steht, Anmeldung ..." : "Noise XX steht, Pairing ..."); break;
    case WA_CONN_LOGIN:  wa_fmt(l, sizeof l, "angemeldet als :%u, passiv", creds.jid_device); gui_set_connection(GUI_CONN_ONLINE, l); break;
    case WA_CONN_ONLINE: gui_set_connection(GUI_CONN_ONLINE, "web.whatsapp.com, Noise XX, online"); break;
    case WA_CONN_CLOSED: gui_set_connection(GUI_CONN_OFFLINE, "Verbindung beendet"); break;
    default:             wa_fmt(l, sizeof l, "Fehler: %s", detail && detail[0] == 'R' && detail[7] == ' ' ? detail + 8 : detail ? detail : "?"); gui_set_connection(GUI_CONN_ERROR, l); break;
    }
    gui_redraw_dirty();
}
static void on_time(void *ctx, uint32_t unix_seconds)
{
    (void)ctx;
    if (!unix_seconds || unix_seconds < now_unix()) return;             /* an older t= (offline stanza) is not the server's clock */
    if (!unix_base) { char l[96]; wa_fmt(l, sizeof l, "clock: server time %u, the GUI clock follows it (Amiga clock %s)", unix_seconds, now_unix() ? "was set" : "unset"); log_line(0, l); }
    unix_base = unix_seconds; unix_base_ms = now_ms();
    if (gui_on) gui_set_time(unix_seconds);
}
static void on_text(void *ctx, const char *user, uint32_t device, int lid, const char *pushname, uint32_t ts, const char *utf8, uint32_t len)
{
    int chat; (void)ctx; (void)device;
    if (!gui_on) return;
    chat = chat_for(user, lid, pushname);
    if (chat < 0) { log_line(0, "gui: chat list full (32), text not shown"); return; }
    if (!gui_add_message(chat, 0, ts ? ts : now_unix(), utf8, (int)len, GUI_ST_READ)) log_line(0, "gui: message store full, text not shown");
}
static void on_sent(void *ctx, const char *user, uint32_t device, int lid, const char *text, const char *msg_id, int ok)
{
    ULONG gid = sending_gui_id; (void)ctx; (void)device;
    sending_gui_id = 0;
    if (!gui_on) return;
    if (!gid) {                                                          /* the scripted CHAT_SEND text or a console line */
        int chat = chat_for(user, lid, 0);
        if (chat < 0) return;
        gid = gui_add_message(chat, 1, now_unix(), text, -1, ok ? GUI_ST_PENDING : GUI_ST_FAILED);
    } else if (!ok) gui_set_status(-1, gid, GUI_ST_FAILED);
    if (ok && gid && msg_id && msg_id[0]) remember_sent(msg_id, gid);
}
static void on_ack(void *ctx, const char *msg_id, int status)
{
    ULONG gid; (void)ctx;
    if (!gui_on || !(gid = lookup_sent(msg_id))) return;
    gui_set_status(-1, gid, status == WA_MSG_SENT ? GUI_ST_SENT : status == WA_MSG_DELIVERED ? GUI_ST_DELIVERED : status == WA_MSG_READ ? GUI_ST_READ : GUI_ST_FAILED);
}

/* screen + GUI before the key computation, so the user sees the state from the first second; 0 = ok */
static int gui_start(void)
{
    uint32_t t0 = now_ms(), i; int rc; char l[160];
    if ((rc = scr_open()) != 0) { wa_fmt(l, sizeof l, "screen: scr_open failed (%u) - running without the GUI", (uint32_t)rc); log_line(0, l); return -1; }
    screen_open = 1;
    fast_before_gui = AvailMem(MEMF_FAST);
    /* the arena goes to Chip RAM: on the 2 MiB machine the probe (600 KB) and TheWire13 leave ~115 KB of Fast RAM (live
     * attempt 4), and the GUI code and statics already take ~90 KB of that; Chip has ~100 KB spare after the 80 KiB of
     * bitplanes, and the arena is only read for the model (gui_add_message 3 ms). Fast RAM only when plenty is left. */
    if (AvailMem(MEMF_FAST | MEMF_LARGEST) >= 1024UL * 1024UL) gui_arena = (UBYTE *)AllocMem(GUI_ARENA_SIZE, MEMF_FAST | MEMF_CLEAR);
    if (!gui_arena) { gui_arena = (UBYTE *)AllocMem(GUI_ARENA_SIZE, MEMF_CHIP | MEMF_CLEAR); gui_arena_chip = 1; }
    if (!gui_arena) { gui_arena = (UBYTE *)AllocMem(GUI_ARENA_SIZE, MEMF_PUBLIC | MEMF_CLEAR); gui_arena_chip = 0; }
    if (!gui_arena || gui_init(gui_arena, GUI_ARENA_SIZE) != 0) { log_line(0, "gui: no memory for the 32 KiB arena - running without the GUI"); scr_close(); screen_open = 0; return -1; }
    gui_on = 1;
    gui_set_tz(3600);                                                    /* CET; summer time would need +7200 */
    if (!now_unix() && host_now[0] && (unix_base = clockstr_to_unix(host_now)) != 0) unix_base_ms = now_ms();   /* the Amiga clock is unset: host time */
    gui_set_time(now_unix());
    wa_fmt(self_jid, sizeof self_jid, "%s@s.whatsapp.net", creds.jid_user[0] ? creds.jid_user : "0");
    if (creds.jid_user[0]) gui_add_chat(self_jid, "Du");
    if (chat_peer[0]) chat_for(chat_peer, 0, 0);
    if (sessions) for (i = 0; i < sessions->n; i++) chat_for(sessions->e[i].user, sessions->e[i].lid, 0);
    gui_set_connection(GUI_CONN_CONNECTING, "Schl\xC3\xBCssel werden berechnet ...");   /* UTF-8: gui_set_connection converts to Latin-1 (live run 9 showed "Schl?ssel") */
    gui_redraw_all();
    fast_after_gui = AvailMem(MEMF_FAST);
    wa_fmt(l, sizeof l, "gui: screen + chat interface up in %u ms: %u chats, arena 32 KiB in %s RAM, text %s, Fast RAM %u -> %u bytes free", now_ms() - t0, (uint32_t)gui_chat_count(),
           gui_arena_chip ? "Chip" : "Fast", gui_text_mode() == GUI_TEXT_FAST ? "own renderer" : "OS Text()", fast_before_gui, fast_after_gui);
    log_line(0, l);
    return 0;
}
/* the end of the run stays on the screen for a while (a key ends the wait) */
static void gui_end(int ok, const char *result)
{
    uint32_t t0; char l[64];
    if (!gui_on) return;
    wa_fmt(l, sizeof l, "%s - Taste schlie\xC3\x9Ft", ok ? "Ende" : "Abbruch");
    gui_set_connection(ok ? GUI_CONN_OFFLINE : GUI_CONN_ERROR, l);
    gui_redraw_dirty();
    (void)result;
    t0 = now_ms();
    while (now_ms() - t0 < 20000) { if (scr_wait_key(25) != SCR_KEY_TIMEOUT) break; gui_tick(); }
    gui_on = 0;
}

static void consume_nextkeys(void *ctx) { (void)ctx; DeleteFile((STRPTR)"SYS:tachyon.next"); log_line(0, "keys: SYS:tachyon.next consumed (deleted)"); }
static void write_nextkeys(void *ctx)
{
    static uint8_t rec[WA_NEXTKEYS_SIZE]; uint32_t n; BPTR f; (void)ctx;
    if (!(n = wa_nextkeys_write(rec, sizeof rec, &nextkeys))) return;
    f = Open((STRPTR)"SYS:tachyon.next", MODE_NEWFILE);
    if (f) { Write(f, rec, n); Close(f); log_line(0, nextkeys.have_es ? "keys: SYS:tachyon.next written (key pairs + es for the next start)" : "keys: SYS:tachyon.next written (key pairs for the next start)"); }
    else log_line(0, "keys: cannot write SYS:tachyon.next");
}

static void write_prekeys(void *ctx)
{
    static uint8_t rec[WA_PREKEYS_MAX_SIZE]; uint32_t n; BPTR f; (void)ctx;
    if (!(n = wa_prekeys_write(rec, sizeof rec, &prekeys))) return;
    f = Open((STRPTR)"SYS:tachyon.prekeys", MODE_NEWFILE);
    if (f) { Write(f, rec, n); Close(f); logf1("prekeys: SYS:tachyon.prekeys written (%s%u keys)", "", prekeys.n); }
    else log_line(0, "prekeys: cannot write SYS:tachyon.prekeys");
}
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
    if (gui_on) { qr_visible = 1; scr_fill(0, 12, SCR_W, SCR_H - 12, SCR_PAL_BG); scr_text(8, 16, SCR_PAL_LTGREY, "WhatsApp am Telefon: Einstellungen > Verknuepfte Geraete > Geraet hinzufuegen, dann diesen Code scannen."); }
    else if (!screen_open) {
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
    if (gui_on) { qr_visible = 0; gui_set_connection(GUI_CONN_HANDSHAKE, status); gui_redraw_all(); return; }
    scr_fill(0, QR_TOP, SCR_W, SCR_H - QR_TOP - 24, SCR_PAL_BG);
    screen_text_line(SCR_H - 20, SCR_PAL_LTGREEN, status);
    screen_text_line(SCR_H - 10, SCR_PAL_BG, ""); scr_dots = 0;
}

static int io_send(void *ctx, const uint8_t *p, uint32_t n) { (void)ctx; return bsdsock_send(&net, p, n); }
/* the socket read while the GUI is up: the window's IDCMP signal is in the wait's wake mask, so a keypress ends the
 * WaitSelect at once and is echoed before the wait resumes; the wait is also cut into 200-ms slices (stacks without
 * sigmask support), and a tick runs every 200 ms even while data streams in (live runs 6-7b: during the 60-s receive of
 * the offline batch every recv returned data, so no tick ran and typed keys piled up until the stream paused).
 * Polls with timeout 0 pass straight through. */
static int32_t io_recv(void *ctx, uint8_t *p, uint32_t cap, uint32_t timeout_ms)
{
    uint32_t t0, left; (void)ctx;
    if (!gui_on || timeout_ms < 100) return (int32_t)bsdsock_recv(&net, p, cap, timeout_ms);
    net.wake_mask = scr_wake_mask();
    t0 = now_ms(); left = timeout_ms;
    for (;;) {
        uint32_t slice = left < 200 ? left : 200, used; int32_t r = (int32_t)bsdsock_recv(&net, p, cap, slice);
        if (r < 0) return r;
        if (r > 0) { if (now_ms() - gui_last_tick >= 200) gui_tick(); return r; }
        gui_tick();                                              /* a key (woken) or the slice's end */
        if (outq_pushed != outq_woken) { outq_woken = outq_pushed; return 0; }   /* a line was typed: back to the core once, so the chat loop sends it
                                                                                  * before its next wait (outside the chat loop the core just waits again) */
        used = now_ms() - t0;
        if (used >= timeout_ms) return 0;
        left = timeout_ms - used;
    }
}
static int io_reconnect(void *ctx) { (void)ctx; return bsdsock_connect(&net, wa_addr, 443); }

static void finish(void)
{
    BPTR done;
    if (screen_open) { scr_close(); screen_open = 0; }
    if (gui_arena) { FreeMem(gui_arena, GUI_ARENA_SIZE); gui_arena = 0; }
    bsdsock_close(&net);
    if (logfile) Close(logfile);
    chip_free_all();
    if (owncon) { Close(owncon); owncon = 0; con = 0; }
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
}

int main(void)
{
    static wa_probe_io io; static uint8_t seed[64], small[64], ncache[96], tcache[X509_CACHE_FILE_MAX]; static char nowstr[16], waip[20];
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
    { static const char hint[] = "Bitte warten. Der 68000 rechnet: Identitaet, Schluessel und Prekeys bis zu 60 s, dann TLS ca. 32 s und Noise ca. 42 s\n"
                                 "je Verbindung; ein Punkt alle 2 s heisst: es geht weiter. Beim Pairing erscheint der QR-Code auf einem eigenen Schirm.\n";
      if (con) Write(con, (APTR)hint, str_len(hint)); }

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

    io.ctx = 0; io.send = io_send; io.recv = io_recv; io.reconnect = io_reconnect; io.now_ms = now_ms; io.log = log_line; io.alloc = chip_alloc;
    io.host = "web.whatsapp.com"; io.now = nowstr[0] ? nowstr : 0; io.seed = seed; io.seed_len = 64;
    io.gap_ms = gap_ms; io.tunnel = 0; io.use_cache = 0; io.debug = 0; io.hold_ms = 0;
    n = read_file("SYS:noisecache.bin", ncache, 96);
    io.noise_cache_in = n >= 32 ? ncache : 0; io.noise_leaf_cache_in = n >= 64 ? ncache + 32 : 0; io.noise_static_in = n == 96 ? ncache + 64 : 0;
    log_line(0, io.noise_static_in ? "noise: certificate cache loaded from SYS:noisecache.bin (intermediate + leaf + server static)" : io.noise_leaf_cache_in ? "noise: certificate cache loaded from SYS:noisecache.bin (intermediate + leaf)" : io.noise_cache_in ? "noise: certificate cache loaded from SYS:noisecache.bin (intermediate)" : "noise: certificate cache empty (no SYS:noisecache.bin)");
    n = read_file("SYS:tlscache.bin", tcache, sizeof tcache);
    if (n > 0) { io.tls_cache_in = tcache; io.tls_cache_in_len = (uint32_t)n; }
    log_line(0, n > 0 ? "tls: certificate cache loaded from SYS:tlscache.bin" : "tls: certificate cache empty (no SYS:tlscache.bin)");
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
        /* one-time prekeys: a batch of 10 (33 s before the connection), uploaded after <success> when the server runs low */
        {   static uint8_t prec[WA_PREKEYS_MAX_SIZE + 1];
            io.prekeys = &prekeys; io.prekeys_loaded = 0; io.prekeys_wanted = 10; io.save_prekeys = write_prekeys; io.linger_ms = 10000;
            /* key material for the next start (SYS:tachyon.next): consumed before use, recomputed while online */
            io.nextkeys = &nextkeys; io.nextkeys_loaded = 0; io.precompute_next = 1; io.consume_nextkeys = consume_nextkeys; io.save_nextkeys = write_nextkeys;
            {   static uint8_t nrec[WA_NEXTKEYS_SIZE + 1]; LONG nn = read_file("SYS:tachyon.next", nrec, sizeof nrec);
                if (nn > 0 && wa_nextkeys_read(&nextkeys, nrec, (uint32_t)nn)) { io.nextkeys_loaded = 1; log_line(0, nextkeys.have_es ? "keys: SYS:tachyon.next loaded (key pairs + es for this connection)" : "keys: SYS:tachyon.next loaded (key pairs for this connection)"); }
                else if (nn > 0) { log_line(0, "keys: SYS:tachyon.next is not a valid record, ignored and deleted"); DeleteFile((STRPTR)"SYS:tachyon.next"); }
            }
            n = read_file("SYS:tachyon.prekeys", prec, sizeof prec);
            if (n > 0) {
                if (!wa_prekeys_read(&prekeys, prec, (uint32_t)n)) { out("RESULT: SYS:tachyon.prekeys is not a valid record - refusing to continue (delete it for a new batch)\n"); finish(); return 10; }
                io.prekeys_loaded = 1;
                logf1("prekeys: SYS:tachyon.prekeys loaded: %s%u keys", "", prekeys.n);
            }
        }
        /* Signal sessions and the interim chat (docs/SIGNAL.md) */
        {   static uint8_t ctext[300];
            sessions = (sig_store *)chip_alloc(0, sizeof(sig_store)); sessions_rec = (uint8_t *)chip_alloc(0, SIG_STORE_MAX_SIZE + 1);
            if (!sessions || !sessions_rec) { out("RESULT: no Chip RAM for the session store\n"); finish(); return 10; }
            io.sessions = sessions; io.sessions_loaded = 0; io.save_sessions = write_sessions; io.chat_recv = chat_recv;
            n = read_file("SYS:tachyon.sessions", sessions_rec, SIG_STORE_MAX_SIZE + 1);
            if (n <= 0) n = read_file("SYS:tachyon.sessions.tmp", sessions_rec, SIG_STORE_MAX_SIZE + 1);      /* a crash between the write and the rename */
            if (n > 0) {
                if (!sig_store_read(sessions, sessions_rec, (uint32_t)n)) { out("RESULT: SYS:tachyon.sessions is not a valid record - refusing to continue (delete it to start without sessions)\n"); finish(); return 10; }
                io.sessions_loaded = 1;
                logf1("sessions: SYS:tachyon.sessions loaded: %s%u sessions", "", sessions->n);
            }
            n = read_file("SYS:chat.txt", ctext, sizeof ctext - 1);
            if (n > 0) {
                uint32_t i = 0, k = 0, secs = 0;
                while (i < (uint32_t)n && ctext[i] != '\n' && k < sizeof chat_peer - 1) chat_peer[k++] = (char)ctext[i++];
                chat_peer[k] = 0; if (i < (uint32_t)n) i++;
                k = 0;
                while (i < (uint32_t)n && ctext[i] != '\n' && k < sizeof chat_text - 1) chat_text[k++] = (char)ctext[i++];
                chat_text[k] = 0; if (i < (uint32_t)n) i++;
                while (i < (uint32_t)n && ctext[i] >= '0' && ctext[i] <= '9') secs = secs * 10 + (uint32_t)(ctext[i++] - '0');
                if (chat_peer[0]) {
                    io.chat_user = chat_peer; io.chat_device = 0; io.chat_lid = 0; io.chat_send = chat_text[0] ? chat_text : 0; io.chat_input = chat_input;
                    io.linger_ms = (secs ? secs : 180) * 1000;
                    logf1("chat: peer %s (the phone), online for %u s after <active/>; type a line + Return in this window to send it", chat_peer, io.linger_ms / 1000);
                    if (chat_text[0]) logf1("chat: one text queued for after <active/>: \"%s\"", chat_text, 0);
                }
            }
        }
    }

    /* the chat interface (pair/login mode): screen and GUI before the key computation; the core reports into it */
    host_now = nowstr;
    if (pair_mode && gui_start() == 0) {
        io.on_state = on_state; io.on_time = on_time; io.on_text = on_text; io.on_sent = on_sent; io.on_ack = on_ack; io.chat_input_to = chat_input_to;
    }

    /* offline part first: the three X25519 key pairs (~10 s on the 68000) while the stack starts in parallel */
    t_prep = now_ms();
    crypto_yield_hook = progress_tick; prog_last = now_ms();     /* dots while computing; the heartbeat chains to it */
    if (!wa_probe_prepare(&io)) { out(io.result); out("\n"); gui_end(0, io.result); finish(); return 10; }
    t_prep = now_ms() - t_prep;
    { char l[120]; wa_fmt(l, sizeof l, "mem: after the buffers (%u Chip blocks, staging %u KB): Chip %u KB free, Fast %u KB free (before the stack starts)", (uint32_t)chip_n, chip_n ? (uint32_t)chip_sizes[chip_n - 1] / 1024 : 0, (uint32_t)AvailMem(MEMF_CHIP) / 1024, (uint32_t)AvailMem(MEMF_FAST) / 1024); log_line(0, l); }
    if (gui_on) { gui_set_connection(GUI_CONN_CONNECTING, "Warte auf den TCP/IP-Stack ..."); gui_tick(); }

    /* the stack: TheWire13 is started by the Startup-Sequence just after us and needs a few seconds */
    for (tries = 0; tries < 120; tries++) {
        if (bsdsock_open(&net)) { if (bsdsock_stack_ready(&net)) break; bsdsock_close(&net); }
        Delay(25); gui_tick();
    }
    if (!net.base) { log_line(0, "net: bsdsocket.library did not open within 60 s - is the TCP/IP stack running?"); out("RESULT: no bsdsocket.library\n"); gui_end(0, "no stack"); finish(); return 10; }
    logf1("net: bsdsocket.library v%u open, stack answers (socket() ok) after %u tries", (const char *)(ULONG)net.base->lib_Version, tries + 1);
    t_dns = now_ms();
    if (gui_on) { gui_set_connection(GUI_CONN_CONNECTING, "DNS: web.whatsapp.com ..."); gui_tick(); }
    if (!bsdsock_resolve(&net, "web.whatsapp.com", waip[0] ? waip : 0, &wa_addr)) {
        logf1("net: %s failed, errno %u, and no SYS:waip.txt fallback", net.fail ? net.fail : "resolve", (uint32_t)net.err);
        out("RESULT: name resolution failed\n"); gui_end(0, "dns"); finish(); return 10;
    }
    t_dns = now_ms() - t_dns;
    bsdsock_ntoa(wa_addr, addr);
    logf1("dns: web.whatsapp.com -> %s in %u ms", addr, t_dns);
    t_conn = now_ms();
    if (gui_on) { char l[48]; wa_fmt(l, sizeof l, "TCP zu %s:443 ...", addr); gui_set_connection(GUI_CONN_CONNECTING, l); gui_tick(); }
    if (!bsdsock_connect(&net, wa_addr, 443)) {
        logf1("tcp: %s failed, errno %u", net.fail ? net.fail : "connect", (uint32_t)net.err);
        out("RESULT: TCP connect failed\n"); gui_end(0, "tcp"); finish(); return 10;
    }
    t_conn = now_ms() - t_conn;
    logf1("tcp: connected to %s:443 in %u ms", addr, t_conn);

    {
        int ok = wa_probe_run(&io);
        if (net.fail) logf1("net: last failed socket call %s, errno %u", net.fail, (uint32_t)net.err);   /* also when the core closed the stream itself (a failed send inside the offline batch, live run 6) */
        if (ok && io.noise_cache_valid) {
            BPTR cf = Open((STRPTR)"SYS:noisecache.bin", MODE_NEWFILE);
            if (cf) { Write(cf, io.noise_cache_fp, 32); if (io.noise_leaf_valid) { Write(cf, io.noise_leaf_fp, 32); if (io.noise_static_valid) Write(cf, io.noise_static_out, 32); } Close(cf); log_line(0, io.noise_static_valid ? "noise: certificate cache (intermediate + leaf + server static) written to SYS:noisecache.bin" : io.noise_leaf_valid ? "noise: certificate cache (intermediate + leaf) written to SYS:noisecache.bin" : "noise: certificate cache fingerprint written to SYS:noisecache.bin"); }
            if (io.tls_cache_out_len) { BPTR tf = Open((STRPTR)"SYS:tlscache.bin", MODE_NEWFILE); if (tf) { Write(tf, io.tls_cache_out, io.tls_cache_out_len); Close(tf); log_line(0, "tls: certificate cache written to SYS:tlscache.bin"); } }
        }
        wa_fmt(aline, sizeof aline, "TIMING: keys %u ms (tls %u + noise %u, before connect), dns %u ms, tcp connect %u ms, tls %u ms, ws %u ms, server hello %u ms, client finish %u ms, accepted %u ms (ms since connect, %u pongs%s)\n",
               t_prep, io.t_tls_key, io.t_noise_keys, t_dns, t_conn, io.t_tls, io.t_ws, io.t_hello, io.t_finish, io.t_accepted, io.pongs, io.noise_cert_cached ? ", Noise cert cache hit" : "");
        out(aline);
        if (pair_mode) {
            wa_fmt(aline, sizeof aline, "PAIRING: codes shown %u, first code at %u ms, pair-success at %u ms, verify %u ms, sign %u ms, pair-device-sign at %u ms, stream:error 515 at %u ms, login connect at %u ms, login success at %u ms\n",
                   io.qr_shown, io.t_qr_shown, io.t_pair_success, io.d_verify, io.d_sign, io.t_sign_sent, io.t_515, io.t_login_connect, io.t_login_accepted);
            out(aline);
            wa_fmt(aline, sizeof aline, "LOGIN: server prekeys %u, uploaded %u, active %d at %u ms, stanzas %u, acks %u, messages %u, prekey generation %u ms\n",
                   io.server_prekeys, io.prekeys_uploaded, io.active_set, io.t_active, io.frames_after_login, io.acks_sent, io.messages_seen, io.d_prekeys);
            out(aline);
            wa_fmt(aline, sizeof aline, "MESSAGES: sent %u (server ack at %u ms, peer receipt at %u ms), received %u (last at %u ms), undecryptable %u, receipts %u, sessions started %u (last X3DH %u ms), encrypt %u ms, decrypt %u ms\n",
                   io.msgs_sent, io.t_msg_ack, io.t_msg_receipt, io.msgs_received, io.t_msg_received, io.msgs_failed, io.receipts_sent, io.sessions_started, io.d_session, io.d_encrypt, io.d_decrypt);
            out(aline);
            if (io.prekeys_loaded) write_prekeys(0);
            if (io.creds_loaded) write_creds(0);
        }
        if (gui_on) {
            struct gui_stats st; gui_stats(&st);
            wa_fmt(aline, sizeof aline, "GUI: %u ticks, %u ms average, %u ms max, %u over 100 ms; %u chats, %u messages (%u dropped), %u rows drawn, %u scrolls; arena in %s RAM, Fast RAM %u free after init\n",
                   gui_ticks, gui_ticks ? gui_tick_sum / gui_ticks : 0, gui_tick_max, gui_slow_ticks, (uint32_t)st.chats, (uint32_t)st.msgs, st.dropped, st.rows_drawn, st.scrolls, gui_arena_chip ? "Chip" : "Fast", fast_after_gui);
            out(aline);
        }
        out(io.result); out("\n");
        gui_end(ok, io.result);
        finish();
        return ok ? 0 : 5;
    }
}
