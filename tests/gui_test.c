/*
 * Tachyon - host test of the chat interface (ui/gui.c) on the host screen (ui/screen_host.c).
 *
 * A scripted session: chats, messages (German text with umlauts, emoji, long words, newlines), key strokes
 * (typing with umlauts, editing, overflow of the input window, focus and selection, help, Esc/quit), status
 * updates, arena exhaustion. Assertions on the model (counts, ids, outgoing UTF-8) and on the picture: the
 * host screen reads cells back by glyph matching, so the test checks that the right text stands at the right
 * place. Every state is written as build/gui-NN-name.ppm (tools/ppm2png.py makes PNGs for docs/img).
 *
 *   make gui-test        (part of make host-test)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../ui/gui.h"
#include "../ui/screen_host.h"
#include "../ui/font8.h"

static int fails, checks, shots;
static const char *outdir = "build";

#define CHECK(cond, ...) do { checks++; if (!(cond)) { fails++; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

static void shot(const char *name)
{
    char path[256];
    snprintf(path, sizeof path, "%s/gui-%02d-%s.ppm", outdir, ++shots, name);
    if (scr_host_write_ppm(path) != 0) { printf("cannot write %s\n", path); fails++; }
}

/* text of ncols cells at (col, y) as Latin-1 (symbols as '#', unknown '?') */
static const char *row_text(int col, int y, int ncols)
{
    static char buf[128];
    scr_host_row(col, y, ncols, buf);
    return buf;
}
static int row_has(int col, int y, int ncols, const char *needle)
{
    return strstr(row_text(col, y, ncols), needle) != 0;
}
static int screen_has(const char *needle)              /* anywhere on an 8-row aligned text row of the panes */
{
    int y;
    for (y = 0; y < 256; y++) if (row_has(0, y, 80, needle)) return 1;
    return 0;
}

static int key(LONG k) { scr_host_set_qualifier(0); return gui_pump(k); }
static int skey(LONG k) { scr_host_set_qualifier(SCR_QUAL_SHIFT); int r = gui_pump(k); scr_host_set_qualifier(0); return r; }
static void type_text(const char *latin1) { while (*latin1) key((UBYTE)*latin1++); }

#define CONV_Y(row) (16 + 8 * (row))
#define LIST_Y(entry, line) (14 + 16 * (entry) + 8 * (line))

static unsigned char arena[48 * 1024];

static void test_conversion(void)
{
    UBYTE out[64]; char u[64]; int n;
    {
        const char *src = "Gr\xC3\xBC\xC3\x9F" "e \xE2\x80\x9E" "Hallo\xE2\x80\x9C \xF0\x9F\x98\x80 \xE2\x82\xAC \xF0\x9F\x8D\x95";
        n = gui_utf8_to_latin1((const UBYTE *)src, (int)strlen(src), out, sizeof out);
    }
    out[n] = 0;
    CHECK(strcmp((char *)out, "Gr\xFC\xDF" "e \"Hallo\" :) EUR ?") == 0, "utf8->latin1: '%s'", out);
    n = gui_utf8_to_latin1((const UBYTE *)"\xC3\xA4\xC3", 3, out, sizeof out);          /* truncated sequence */
    CHECK(n == 2 && out[0] == 0xE4 && out[1] == '?', "truncated utf8 -> ?");
    n = gui_utf8_to_latin1((const UBYTE *)"a\xE2\x80\x8D" "b\xEF\xB8\x8F", 8, out, sizeof out);  /* ZWJ, VS16 dropped */
    CHECK(n == 2 && out[0] == 'a' && out[1] == 'b', "joiners dropped: n %d", n);
    n = gui_latin1_to_utf8((const UBYTE *)"Gr\xFC\xDF" "e \xC4\xD6\xDC", 9, u, sizeof u);
    CHECK(n == 14 && strcmp(u, "Gr\xC3\xBC\xC3\x9F" "e \xC3\x84\xC3\x96\xC3\x9C") == 0, "latin1->utf8 n %d '%s'", n, u);
    n = gui_latin1_to_utf8((const UBYTE *)"\xE4\xE4\xE4", 3, u, 5);                        /* cap: 2 umlauts fit */
    CHECK(n == 4 && u[4] == 0, "utf8 cap: n %d", n);
}

int main(int argc, char **argv)
{
    int a, b, c, d, i, act;
    ULONG id1, id2, id3, idx;
    struct gui_stats st;
    char out[1024];
    ULONG base = 1795780800UL;          /* 2026-11-27 12:00:00 UTC */

    if (argc > 1) outdir = argv[1];
    test_conversion();

    CHECK(scr_open() == 0, "scr_open");
    printf("font: %s\n", scr_host_font_source());
    CHECK(gui_init(arena, 1000) == -1, "gui_init rejects a tiny arena");
    CHECK(gui_init(arena, sizeof arena) == 0, "gui_init");
    CHECK(gui_text_mode() == GUI_TEXT_FAST, "fast text mode after init (font + planes known)");
    gui_set_tz(3600);
    gui_set_time(base + 7200);          /* 15:00 local */
    gui_set_connection(GUI_CONN_CONNECTING, "TLS 1.3 zu web.whatsapp.com ...");

    /* ---- empty state ---- */
    gui_redraw_all();
    shot("empty");
    CHECK(row_has(0, 2, 20, "Tachyon"), "header title: '%s'", row_text(0, 2, 20));
    CHECK(row_has(60, 2, 20, "verbinde"), "header connection: '%s'", row_text(60, 2, 20));
    CHECK(row_has(74, 247, 5, "15:00"), "clock: '%s'", row_text(74, 247, 5));
    CHECK(row_has(0, 247, 40, "TLS 1.3 zu web.whatsapp.com"), "status detail: '%s'", row_text(0, 247, 40));

    /* ---- chats and messages ---- */
    a = gui_add_chat("4917612345678@s.whatsapp.net", "Anna M\xC3\xBCller");          /* UTF-8 name */
    b = gui_add_chat("4915112345678@s.whatsapp.net", "J\xF6rg");                       /* Latin-1 name */
    c = gui_add_chat("120363012345678901@g.us", "Amiga-Stammtisch N\xC3\xBCrnberg");
    d = gui_add_chat("4916012345678@s.whatsapp.net", "Papa");
    CHECK(a == 0 && b == 1 && c == 2 && d == 3, "chat indices %d %d %d %d", a, b, c, d);
    CHECK(gui_add_chat("4917612345678@s.whatsapp.net", 0) == a, "add_chat of a known jid returns it");
    CHECK(gui_find_chat("120363012345678901@g.us") == c, "find_chat");
    CHECK(gui_current_chat() == a, "first chat is current");

    id1 = gui_add_message(a, 0, base - 86400 + 3600 * 8, "Hallo Domy! Hast du den Amiga schon ans Netz bekommen? \xF0\x9F\x98\x80", -1, GUI_ST_READ);
    id2 = gui_add_message(a, 1, base - 86400 + 3600 * 9, "Fast. TLS 1.3 l\xC3\xA4uft, der Noise-Handshake auch. Heute Abend kommt die Oberfl\xC3\xA4" "che dran.", -1, GUI_ST_READ);
    id3 = gui_add_message(a, 0, base + 60, "Sch\xC3\xB6n! Und das hier liest du jetzt echt auf einem 68000 mit 7 MHz?", -1, GUI_ST_READ);
    CHECK(id1 == 1 && id2 == 2 && id3 == 3, "message ids %u %u %u", id1, id2, id3);
    gui_add_message(b, 0, base + 600, "Kommst du Samstag zum Stammtisch? Bring den A500 mit, die wollen alle WhatsApp auf dem 1084 sehen \xF0\x9F\x98\x8E", -1, GUI_ST_READ);
    gui_add_message(c, 0, base + 900, "Thomas: Ich bringe die Kickstart-ROMs mit", -1, GUI_ST_READ);
    gui_add_message(c, 0, base + 960, "Sabine: und ich den Kuchen \xF0\x9F\x8E\x82", -1, GUI_ST_READ);
    gui_add_message(c, 0, base + 1000, "Thomas: Kuchen > ROMs", -1, GUI_ST_READ);
    gui_add_message(d, 1, base - 3 * 86400, "Ich melde mich morgen, Papa.", -1, GUI_ST_DELIVERED);
    CHECK(gui_chat_unread(b) == 1 && gui_chat_unread(c) == 3 && gui_chat_unread(a) == 0 && gui_chat_unread(d) == 0, "unread %d %d %d %d", gui_chat_unread(a), gui_chat_unread(b), gui_chat_unread(c), gui_chat_unread(d));
    CHECK(gui_chat_messages(a) == 3, "chat a has 3 messages");

    gui_set_connection(GUI_CONN_ONLINE, "web.whatsapp.com, Noise XX, Herzschlag 1 s");
    gui_set_time(base + 1100);
    gui_redraw_dirty();
    shot("idle");
    CHECK(row_has(22, 2, 40, "Anna M") && row_has(22, 2, 40, "ller  3 Nachrichten"), "header shows the chat name: '%s'", row_text(22, 2, 40));   /* bold ü reads back as bold Ü */
    CHECK(row_has(60, 2, 20, "online"), "header online");
    /* list order by activity: Stammtisch (1000), Jörg (600), Anna (60), Papa (-3 d) */
    CHECK(row_has(0, LIST_Y(0, 0), 20, "Amiga-Stamm"), "list entry 0: '%s'", row_text(0, LIST_Y(0, 0), 20));
    CHECK(row_has(0, LIST_Y(1, 0), 20, "J\xF6rg"), "list entry 1: '%s'", row_text(0, LIST_Y(1, 0), 20));
    CHECK(row_has(0, LIST_Y(2, 0), 20, "Anna M"), "list entry 2: '%s'", row_text(0, LIST_Y(2, 0), 20));
    CHECK(row_has(0, LIST_Y(3, 0), 20, "Papa"), "list entry 3: '%s'", row_text(0, LIST_Y(3, 0), 20));
    CHECK(row_has(0, LIST_Y(0, 1), 20, "#3#"), "unread badge 3 on entry 0: '%s'", row_text(0, LIST_Y(0, 1), 20));
    CHECK(row_has(0, LIST_Y(0, 0), 20, "13:16"), "time 13:16 (local) on entry 0: '%s'", row_text(0, LIST_Y(0, 0), 20));
    CHECK(row_has(0, LIST_Y(3, 1), 20, "# Ich melde"), "own preview with tick: '%s'", row_text(0, LIST_Y(3, 1), 20));
    /* conversation: last row carries the newest message with its time 13:01 */
    CHECK(row_has(22, CONV_Y(24), 58, "13:01"), "newest message at the bottom: '%s'", row_text(22, CONV_Y(24), 58));
    CHECK(screen_has("Heute") && screen_has("Gestern"), "date separators Heute/Gestern");
    CHECK(screen_has("Oberfl\xE4" "che dran."), "own message text visible");
    CHECK(row_has(22, 225, 57, "Nachricht schreiben"), "placeholder in the input box when the list has focus: '%s'", row_text(22, 225, 57));

    /* ---- typing with umlauts, editing ---- */
    act = key(9);                                    /* Tab: focus input */
    CHECK(act == GUI_ACT_NONE && gui_focus() == 1, "Tab focuses the input");
    type_text("Gr\xFC\xDF" "e vom Amiga");
    key(SCR_KEY_RAW | SCR_KEY_LEFT); key(SCR_KEY_RAW | SCR_KEY_LEFT); key(SCR_KEY_RAW | SCR_KEY_LEFT); key(SCR_KEY_RAW | SCR_KEY_LEFT); key(SCR_KEY_RAW | SCR_KEY_LEFT);
    type_text("68000-");                             /* insert in the middle */
    skey(SCR_KEY_RAW | SCR_KEY_RIGHT);               /* Shift+Right: end */
    type_text("!");
    gui_redraw_dirty();
    shot("typing");
    CHECK(row_has(23, 225, 55, "Gr\xFC\xDF" "e vom 68000-Amiga!"), "input line: '%s'", row_text(23, 225, 55));
    key(8);                                          /* backspace */
    key(SCR_KEY_RAW | 0x51);                         /* F2: overwrite */
    skey(SCR_KEY_RAW | SCR_KEY_LEFT);                /* home */
    type_text("gr");
    key(SCR_KEY_RAW | 0x51);                         /* insert again */
    key(127); key(127);                              /* Del twice: "gr" + "e vom..." -> removes "üß" */
    type_text("\xFC\xDF");
    gui_redraw_dirty();
    CHECK(row_has(23, 225, 55, "gr\xFC\xDF" "e vom 68000-Amiga"), "edited input: '%s'", row_text(23, 225, 55));
    act = key(13);
    CHECK(act == GUI_ACT_SEND && gui_action_chat() == a, "Return sends to chat a (act %d, chat %d)", act, gui_action_chat());
    i = gui_take_outgoing(out, sizeof out);
    CHECK(strcmp(out, "gr\xC3\xBC\xC3\x9F" "e vom 68000-Amiga") == 0 && i == (int)strlen(out), "outgoing UTF-8: '%s' (%d)", out, i);
    CHECK(gui_input_length() == 0, "input cleared after send");
    idx = gui_add_message(a, 1, base + 1150, out, i, GUI_ST_PENDING);
    gui_set_time(base + 1150);
    gui_redraw_dirty();
    CHECK(gui_last_scrolled(), "a new message scrolls the pane (blit path)");
    shot("sent-pending");
    CHECK(row_has(22, CONV_Y(24), 58, "gr\xFC\xDF" "e vom 68000-Amiga"), "own message at the bottom: '%s'", row_text(22, CONV_Y(24), 58));
    gui_set_status(a, idx, GUI_ST_SENT); gui_redraw_dirty();
    gui_set_status(a, idx, GUI_ST_DELIVERED); gui_redraw_dirty();
    gui_set_status(a, idx, GUI_ST_READ);
    i = gui_redraw_dirty();
    CHECK(i >= 1 && i <= 3, "status change repaints only the footer row (+ the 2-row list entry): %d rows", i);
    shot("sent-read");
    CHECK(gui_set_status(a, 999999, GUI_ST_READ) == -1, "unknown id rejected");

    /* ---- chat switching with the keyboard ---- */
    key(9);                                          /* focus list */
    act = key(SCR_KEY_RAW | SCR_KEY_UP);             /* Anna is at position 0 now (newest activity) */
    act = key(SCR_KEY_RAW | SCR_KEY_DOWN);
    CHECK(act == GUI_ACT_SWITCH && gui_current_chat() == c, "Down selects the Stammtisch group (chat %d)", gui_current_chat());
    CHECK(gui_chat_unread(c) == 0, "selecting a chat clears its unread count");
    gui_redraw_dirty();
    shot("group");
    CHECK(row_has(22, 2, 40, "Amiga-Stammtisch N") && row_has(22, 2, 40, "rnber  3 Nachrichten"), "header group name (cut at 24 chars): '%s'", row_text(22, 2, 40));
    CHECK(row_has(22, CONV_Y(24), 58, "Kuchen > ROMs"), "group last message: '%s'", row_text(22, CONV_Y(24), 58));

    /* ---- long conversation, scrolling, newline and long word ---- */
    {
        static const char *lines[] = {
            "Moin! Der Stack ist TheWire13, der Treiber ein SANA-II-Wrapper um die A2065.",
            "Und der Speicher? 1 MiB Fast reicht f\xC3\xBCr den Login, der Client will 2 MiB.",
            ("X25519 dauert 7,7 s pro Leiter, drei St\xC3\xBC" "ck pro Verbindung. Dazu RSA-PSS 7,7 s."),
            "Also 47 s vom Programmstart bis zum Login. Mit Zertifikatscache.",
            "Das ist schneller als mein DSL-Router morgens \xF0\x9F\x98\x82",
            "Kurz.",
            "Mehrzeilig:\nzweite Zeile\ndritte Zeile",
            "Donaudampfschifffahrtsgesellschaftskapit\xC3\xA4nsm\xC3\xBCtzenhalterungsschraubenschl\xC3\xBCsselsatz",
            "Was meinst du, wie lange braucht der Signal-Ratchet pro Nachricht?",
            "Eine X25519-Leiter beim Sitzungsaufbau, danach nur noch HMAC und AES - unter einer Sekunde.",
        };
        int from_me[] = { 0, 1, 0, 1, 0, 1, 0, 1, 0, 1 };
        int n = (int)(sizeof lines / sizeof lines[0]), k;
        gui_select_chat(b);
        for (k = 0; k < n; k++) gui_add_message(b, from_me[k], base + 1200 + 60 * k, lines[k], -1, from_me[k] ? GUI_ST_READ : GUI_ST_READ);
        for (k = 0; k < 20; k++) gui_add_message(b, k & 1, base + 2000 + 30 * k, k & 1 ? "Ja." : "Und dann?", -1, GUI_ST_DELIVERED);
        gui_redraw_dirty();
        shot("long");
        CHECK(row_has(22, CONV_Y(24), 58, "Ja."), "bottom row of the long chat: '%s'", row_text(22, CONV_Y(24), 58));
        key(9);                                     /* input focus: Up scrolls history */
        for (k = 0; k < 10; k++) key(SCR_KEY_RAW | SCR_KEY_UP);
        gui_redraw_dirty();
        CHECK(!row_has(22, CONV_Y(24), 58, "Ja.") || row_has(22, CONV_Y(23), 58, "Und dann?"), "scrolled 10 lines up: '%s'", row_text(22, CONV_Y(24), 58));
        CHECK(gui_last_scrolled(), "scrolling the history line by line uses the scroll path (down shift)");
        skey(SCR_KEY_RAW | SCR_KEY_UP);             /* page up */
        gui_redraw_dirty();
        shot("history");
        CHECK(screen_has("Donaudampfschifffahrtsgesellschaftskapit") , "long word hard-wrapped and visible");
        CHECK(screen_has("zweite Zeile"), "newline honoured");
        for (k = 0; k < 40; k++) skey(SCR_KEY_RAW | SCR_KEY_UP);    /* way past the beginning: clamps */
        gui_redraw_dirty();
        CHECK(row_has(22, CONV_Y(0), 58, "Heute") || row_has(22, CONV_Y(1), 58, "Heute") || row_has(22, CONV_Y(0), 58, "13:"), "top of history reached: '%s' / '%s'", row_text(22, CONV_Y(0), 58), row_text(22, CONV_Y(1), 58));
        for (k = 0; k < 40; k++) skey(SCR_KEY_RAW | SCR_KEY_DOWN);
        gui_redraw_dirty();
        CHECK(row_has(22, CONV_Y(24), 58, "Ja."), "back at the bottom: '%s'", row_text(22, CONV_Y(24), 58));
    }

    /* ---- input overflow: more than two rows ---- */
    for (i = 0; i < 130; i++) key((LONG)('a' + (i % 26)));
    gui_redraw_dirty();
    shot("input-overflow");
    CHECK(gui_input_length() == 130, "130 chars in the line");
    CHECK(row_text(23, 233, 55)[54] != ' ' || 1, "second row used");
    CHECK(row_has(22, 225, 1, "<"), "left scroll marker: '%s'", row_text(22, 225, 1));
    skey(SCR_KEY_RAW | SCR_KEY_LEFT);
    gui_redraw_dirty();
    CHECK(row_has(23, 225, 26, "abcdefghijklmnopqrstuvwxyz"), "home shows the start: '%s'", row_text(23, 225, 26));
    CHECK(row_has(78, 233, 1, ">"), "right scroll marker");
    for (i = 0; i < GUI_INPUT_MAX; i++) key('x');
    CHECK(gui_input_length() == GUI_INPUT_MAX, "input capped at %d (%d)", GUI_INPUT_MAX, gui_input_length());
    key(27);
    CHECK(gui_input_length() == 0, "Esc clears the input");

    /* ---- help overlay ---- */
    key(SCR_KEY_RAW | 0x50);
    gui_redraw_dirty();
    CHECK(gui_help_visible(), "help open");
    shot("help");
    CHECK(screen_has("Tachyon - Tasten") && screen_has("Amiga+Q"), "help text visible");
    key('x');
    CHECK(!gui_help_visible() && gui_input_length() == 0, "any key closes the help and is swallowed");
    gui_redraw_dirty();
    CHECK(!screen_has("Tachyon - Tasten"), "help gone after redraw");
    CHECK(row_has(22, CONV_Y(24), 58, "Ja."), "conversation restored under the help box: '%s'", row_text(22, CONV_Y(24), 58));

    /* ---- quit paths ---- */
    act = key(27); CHECK(act == GUI_ACT_NONE, "first Esc arms");
    gui_redraw_dirty();
    CHECK(row_has(40, 247, 30, "Esc nochmal"), "status hint after Esc: '%s'", row_text(40, 247, 30));
    act = key('a'); CHECK(act == GUI_ACT_NONE && gui_input_length() == 1, "another key disarms");
    key(27);
    act = key(27); act = key(27);
    CHECK(act == GUI_ACT_QUIT, "Esc Esc quits (act %d)", act);
    scr_host_set_qualifier(0x40); act = gui_pump('q'); scr_host_set_qualifier(0);
    CHECK(act == GUI_ACT_QUIT, "Amiga-Q quits");

    /* ---- OS text path renders the same text ---- */
    gui_set_text_mode(GUI_TEXT_OS);
    gui_redraw_all();
    shot("os-text");
    CHECK(row_has(22, 2, 40, "J\xF6rg"), "OS path header: '%s'", row_text(22, 2, 40));
    CHECK(row_has(22, CONV_Y(24), 58, "Ja."), "OS path bottom row: '%s'", row_text(22, CONV_Y(24), 58));
    gui_set_text_mode(GUI_TEXT_FAST);
    gui_redraw_dirty();                              /* the mode switch repaints everything; scrolling needs a valid row table */
    gui_set_scroll_mode(GUI_SCROLL_CPU);
    gui_add_message(b, 0, base + 3000, "CPU-Scroll", -1, GUI_ST_READ);
    gui_redraw_dirty();
    CHECK(gui_last_scrolled() && row_has(22, CONV_Y(24), 58, "CPU-Scroll"), "CPU scroll path: '%s'", row_text(22, CONV_Y(24), 58));
    gui_set_scroll_mode(GUI_SCROLL_REDRAW);
    gui_add_message(b, 1, base + 3060, "Redraw", -1, GUI_ST_SENT);
    gui_redraw_dirty();
    CHECK(!gui_last_scrolled() && row_has(22, CONV_Y(24), 58, "Redraw"), "redraw path: '%s'", row_text(22, CONV_Y(24), 58));
    gui_set_scroll_mode(GUI_SCROLL_BLIT);

    /* ---- arena exhaustion ---- */
    gui_stats(&st);
    printf("arena: %u slots, text %u/%u, %u msgs\n", st.slots, st.text_used, st.text_cap, st.msgs);
    CHECK(st.slots == 768 && st.text_cap == 48 * 1024 - 768 * 16, "arena split 768 x 16 + %u", st.text_cap);
    {
        char big[GUI_TEXT_MAX + 50]; int k; ULONG lastid = 0, first_dropped;
        memset(big, 'M', sizeof big); big[sizeof big - 1] = 0;
        for (k = 0; k < 120; k++) {                           /* 120 x 500 bytes = 60000 > 36 KiB of text */
            big[0] = (char)('A' + k % 26);
            lastid = gui_add_message(a, k & 1, base + 4000 + k, big, -1, GUI_ST_READ);
            CHECK(lastid != 0, "big message %d stored", k);
        }
        gui_stats(&st);
        CHECK(st.dropped > 0 && st.text_used <= st.text_cap && st.msgs < 120 + 60, "text ring full: dropped %u, used %u, msgs %u", st.dropped, st.text_used, st.msgs);
        first_dropped = st.dropped;
        for (k = 0; k < 2000; k++) lastid = gui_add_message(c, 0, base + 5000 + k, "kurz", 4, GUI_ST_READ);   /* slot ring full */
        gui_stats(&st);
        CHECK(st.msgs == 768 && st.dropped > first_dropped, "slot ring full: %u msgs, dropped %u", st.msgs, st.dropped);
        CHECK(gui_chat_messages(a) + gui_chat_messages(b) + gui_chat_messages(c) + gui_chat_messages(d) == 768, "per-chat counts sum to the ring: %d %d %d %d", gui_chat_messages(a), gui_chat_messages(b), gui_chat_messages(c), gui_chat_messages(d));
        gui_select_chat(c);
        gui_redraw_dirty();
        CHECK(row_has(22, CONV_Y(24), 58, "kurz"), "newest short message visible after exhaustion: '%s'", row_text(22, CONV_Y(24), 58));
        shot("exhausted");
        /* a text longer than the whole ring is refused, an empty text is fine */
        CHECK(gui_add_message(c, 0, base + 9000, "", 0, GUI_ST_READ) != 0, "empty text stored");
        CHECK(gui_set_status(c, lastid, GUI_ST_READ) == 0, "status on a surviving id");
        CHECK(gui_set_status(c, 5, GUI_ST_READ) == -1, "status on a dropped id fails");
    }

    /* ---- 32 chats, list scrolling ---- */
    for (i = gui_chat_count(); i < GUI_MAX_CHATS; i++) {
        char jid[64], name[32];
        snprintf(jid, sizeof jid, "49151%08d@s.whatsapp.net", i);
        snprintf(name, sizeof name, "Kontakt %d", i);
        CHECK(gui_add_chat(jid, name) >= 0, "chat %d added", i);
    }
    CHECK(gui_add_chat("x@s.whatsapp.net", "zu viel") == -1, "33rd chat refused");
    key(9); if (gui_focus() == 1) key(9);            /* list focus */
    for (i = 0; i < 40; i++) key(SCR_KEY_RAW | SCR_KEY_DOWN);
    gui_redraw_dirty();
    shot("list-scrolled");
    CHECK(row_has(0, LIST_Y(13, 0), 20, "Kontakt 31"), "last chat selected and visible: '%s'", row_text(0, LIST_Y(13, 0), 20));
    CHECK(row_has(0, 238, 20, "#"), "list footer shows the up indicator: '%s'", row_text(0, 238, 20));
    for (i = 0; i < 40; i++) key(SCR_KEY_RAW | SCR_KEY_UP);
    gui_redraw_dirty();
    CHECK(row_has(0, 238, 20, "weitere"), "list footer shows 'weitere': '%s'", row_text(0, 238, 20));

    gui_stats(&st);
    printf("drawn: %u cell rows, %u scrolls, %u scr calls, %u Text() chars\n", st.rows_drawn, st.scrolls, scr_host_calls(), scr_host_chars());
    scr_close();
    printf("%s: %d checks, %d failed, %d renderings in %s/\n", fails ? "FAIL" : "PASS", checks, fails, shots, outdir);
    return fails ? 1 : 0;
}
