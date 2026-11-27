/*
 * Tachyon - chat interface (ui/gui.h): model and view.
 *
 * Screen layout (80 columns x 256 rows, cell = 8x8 Topaz; see docs/UI.md "Client-Oberfläche"):
 *   y 0..11    header: "Tachyon", the open chat, connection state
 *   y 14..237  left: chat list, 14 entries of 2 rows (name + time, preview + unread badge), 20 columns
 *   y 238..245 left: scroll indicators of the list
 *   y 16..215  right (columns 22..78): conversation, 25 rows of bubbles (incoming left, own right, footer with
 *              time and status tick), date separators
 *   y 223..243 right: input box, two rows of 55 columns (a window on the line, scrolls horizontally)
 *   y 246..255 status line: connection detail, key hints, clock
 *
 * Drawing: every region is composed into a row of cells (char, fg, bg) and painted in runs of equal pens, either
 * by ui/ftext.c straight into the planes (GUI_TEXT_FAST) or by scr_text_bg/scr_fill (GUI_TEXT_OS). Only dirty
 * regions are painted: the conversation keeps the row table it painted last and repaints rows whose content
 * changed; when the new table is the old one shifted up (a new message) the pane is scrolled (ScrollRaster or CPU)
 * and only the new rows are painted.
 *
 * Message store: the arena is split into descriptors (16 bytes each, a quarter of the arena) and a text ring.
 * Both are FIFO: when either is full the oldest message of the store is dropped. Texts are kept as UTF-8 as
 * received and converted to Latin-1 for display (umlauts direct, typographic quotes/dashes to ASCII, a few emoji
 * to ASCII faces, everything else '?'); the input line is Latin-1 (scr_wait_key) and is encoded to UTF-8 when sent.
 */
#include "gui.h"
#include "screen.h"
#include "font8.h"
#include "ftext.h"

/* ---- geometry ----------------------------------------------------------------------------------------- */
#define COLS        80
#define HDR_H       12
#define HDR_TEXT_Y  2
#define LIST_COLS   20
#define LIST_Y0     14
#define LIST_ENTRY_H 16
#define LIST_VISIBLE 14
#define LIST_FOOT_Y 238
#define GAP_COL     20              /* columns 20, 21: gap between the panes */
#define CONV_COL    22
#define CONV_COLS   57              /* columns 22..78, column 79 is the right margin */
#define CONV_Y0     16
#define CONV_ROWS   25
#define CONV_H      (CONV_ROWS * 8)
#define BUBBLE_MAX  46              /* bubble width in cells incl. the padding cells */
#define WRAP_W      (BUBBLE_MAX - 2)
#define INPUT_Y0    223
#define INPUT_H     21
#define INPUT_ROW1  225
#define INPUT_ROW2  233
#define INPUT_COL   23
#define INPUT_COLS  55
#define INPUT_WIN   (2 * INPUT_COLS)
#define STATUS_Y    246
#define STATUS_TEXT_Y 247

/* ---- pens (gui_palette below) ------------------------------------------------------------------------- */
#define P_BLACK  0
#define P_BG     1                  /* conversation background */
#define P_WHITE  2
#define P_GREEN  3                  /* accent: title, unread badge, online */
#define P_OWN    4                  /* own bubble */
#define P_PANEL  5                  /* header, incoming bubble, date pill */
#define P_LTGREY 6                  /* secondary text */
#define P_GREY   7                  /* time stamps, hints */
#define P_LIST   8                  /* chat list background */
#define P_RED    9
#define P_YELLOW 10
#define P_BLUE   11                 /* read ticks */
#define P_SEL    12                 /* selected chat, help box */
#define P_ORANGE 13
#define P_SEP    14                 /* frame of the help box */
#define P_INPUT  15                 /* input box */

static const UWORD gui_palette[16] = {
    0x000, 0x011, 0xEEE, 0x2D6, 0x054, 0x223, 0xACB, 0x89A,
    0x112, 0xE55, 0xED5, 0x5BE, 0x234, 0xF93, 0x456, 0x123
};

/* ---- model ---------------------------------------------------------------------------------------------- */
struct gui_msg {                    /* 16 bytes */
    ULONG id;
    ULONG ts;
    UWORD toff, tlen;
    UBYTE chat, flags;              /* flags: bit 0 from_me, bits 1..3 status */
    UBYTE hh, mm;
};
#define MF_FROM_ME 0x01
#define MF_STATUS(f) (((f) >> 1) & 7)
#define MF_MAKE(from_me, st) ((UBYTE)(((from_me) ? 1 : 0) | ((st) << 1)))

struct gui_chat {
    char  jid[GUI_JID_MAX];
    UBYTE name[GUI_NAME_MAX + 1];
    UBYTE name_len;
    UBYTE used, dirty;
    UWORD unread, count;
    ULONG last_ts;                  /* order key */
    UBYTE last_hh, last_mm;
    UBYTE prev[16];                 /* preview: first characters of the last message, Latin-1 */
    UBYTE prev_len, prev_from_me, prev_status;
    ULONG prev_id;
};

static struct gui_msg *slots;
static UWORD  nslots, mhead, mcount;
static UBYTE *tring;
static ULONG  tcap, thead, ttail;
static ULONG  next_id = 1, dropped;

static struct gui_chat chats[GUI_MAX_CHATS];
static UBYTE  order[GUI_MAX_CHATS];
static int    nchats, cur_chat = -1;

static int    conn_state = GUI_CONN_OFFLINE;
static UBYTE  conn_detail[40];
static int    conn_detail_len;
static int    clk_hh = -1, clk_mm;
static LONG   tz_east;
static ULONG  today_day;            /* days since 1970 of "today" in local time, 0 = unknown */

/* ---- view state ------------------------------------------------------------------------------------------ */
static int    text_mode = GUI_TEXT_FAST, scroll_mode = GUI_SCROLL_BLIT, last_scrolled;
static int    focus;                /* 0 list, 1 input */
static int    help_open, help_dirty, esc_armed, insert_mode = 1;
static int    hdr_dirty, list_dirty_all, conv_dirty, input_dirty, status_dirty;
static int    list_top, conv_scroll;
static ULONG  rows_drawn, scroll_count;

static UBYTE  input[GUI_INPUT_MAX + 1];
static int    input_len, cursor, input_win;
static UBYTE  outgoing[GUI_INPUT_MAX + 1];
static int    outgoing_len, action_chat = -1;

struct row {
    ULONG id;                       /* message id, 0 none */
    ULONG day;                      /* date separator: the day */
    UWORD start, len;               /* text line within the converted text */
    UBYTE kind;                     /* 0 empty, 1 text, 2 date separator, 3 footer only, 0xFF invalid */
    UBYTE ln;
    UBYTE b0, bw;                   /* bubble: first column (pane relative) and width in cells */
    UBYTE flags;                    /* ROW_* */
    UBYTE st;                       /* message status (footer) */
};
#define ROW_FROM_ME 0x01
#define ROW_FOOTER  0x02
#define ROW_FIRST   0x04
static struct row rows_old[CONV_ROWS], rows_new[CONV_ROWS];

static UBYTE  conv_buf[GUI_TEXT_MAX + 4];
static int    conv_len;
static ULONG  conv_id;              /* message whose Latin-1 text is in conv_buf */

/* one composed cell row */
static UBYTE  cell_ch[COLS], cell_fg[COLS], cell_bg[COLS], cell_st[COLS];

/* ---- small helpers ----------------------------------------------------------------------------------------- */
static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void bzero_(void *p, ULONG n) { UBYTE *b = (UBYTE *)p; while (n--) *b++ = 0; }
static void bcopy_(void *d, const void *s, ULONG n) { UBYTE *dd = (UBYTE *)d; const UBYTE *ss = (const UBYTE *)s; while (n--) *dd++ = *ss++; }
static int streq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

static struct gui_msg *slot_at(UWORD i)          /* i-th oldest message */
{
    ULONG k = (ULONG)mhead + i;
    if (k >= nslots) k -= nslots;
    return &slots[k];
}

static void put_dec(UBYTE *d, ULONG v, int width)  /* right-aligned, zero padded when width > 0 */
{
    UBYTE b[12]; int i = 0, j;
    do { b[i++] = (UBYTE)('0' + v % 10); v /= 10; } while (v);
    for (j = i; j < width; j++) d[width - 1 - j] = '0';
    for (j = 0; j < i; j++) d[(width > i ? width : i) - 1 - j] = b[j];
}
static int dec_len(ULONG v) { int n = 1; while (v >= 10) { v /= 10; n++; } return n; }

static void local_hm(ULONG ts, UBYTE *hh, UBYTE *mm)
{
    ULONG t = ts + (ULONG)tz_east, s = t % 86400UL;
    *hh = (UBYTE)(s / 3600UL); *mm = (UBYTE)((s % 3600UL) / 60UL);
}
static ULONG local_day(ULONG ts) { return (ts + (ULONG)tz_east) / 86400UL; }

/* civil date from days since 1970-01-01 (unsigned variant of the days-from-civil inverse) */
static void civil(ULONG days, ULONG *y, ULONG *m, ULONG *d)
{
    ULONG z = days + 719468UL, era = z / 146097UL, doe = z - era * 146097UL;
    ULONG yoe = (doe - doe / 1460UL + doe / 36524UL - doe / 146096UL) / 365UL;
    ULONG doy = doe - (365UL * yoe + yoe / 4UL - yoe / 100UL);
    ULONG mp = (5UL * doy + 2UL) / 153UL;
    *d = doy - (153UL * mp + 2UL) / 5UL + 1UL;
    *m = mp < 10UL ? mp + 3UL : mp - 9UL;
    *y = yoe + era * 400UL + (*m <= 2UL ? 1UL : 0UL);
}

/* ---- UTF-8 <-> Latin-1 -------------------------------------------------------------------------------------- */
static const struct { ULONG cp; const char *tag; } emoji_tags[] = {
    { 0x1F600, ":)" }, { 0x1F603, ":)" }, { 0x1F604, ":)" }, { 0x1F601, ":)" }, { 0x1F606, "xD" }, { 0x1F642, ":)" },
    { 0x1F60A, ":)" }, { 0x1F602, "xD" }, { 0x1F923, "xD" }, { 0x1F609, ";)" }, { 0x1F60D, ":)" }, { 0x1F618, ":*" },
    { 0x1F61B, ":P" }, { 0x1F61C, ";P" }, { 0x1F61D, ":P" }, { 0x1F622, ":(" }, { 0x1F62D, ":'(" }, { 0x1F610, ":|" },
    { 0x1F62E, ":O" }, { 0x1F914, ":?" }, { 0x1F615, ":/" }, { 0x1F621, ">:(" }, { 0x1F644, ":/" }, { 0x1F605, "^^'" },
    { 0x1F44D, "+1" }, { 0x1F44E, "-1" }, { 0x1F44B, "o/" }, { 0x1F64F, "_/\\_" }, { 0x1F389, "*party*" },
    { 0x2764,  "<3" }, { 0x1F49A, "<3" }, { 0x1F499, "<3" }, { 0x1F49C, "<3" }, { 0x1F495, "<3" }, { 0x1F525, "*fire*" },
    { 0x1F60E, "B)" }, { 0x1F607, "O:)" }, { 0x1F608, ">:)" }, { 0x1F634, "-_-" }, { 0x1F62A, "-_-" }, { 0x1F917, "(hug)" },
    { 0x2705,  "[x]" }, { 0x274C, "[X]" }, { 0x2B50, "*" }, { 0x1F4AA, "(strong)" }, { 0x1F44C, "OK" }, { 0x1F91D, "(shake)" },
    { 0x1F37B, "(beer)" }, { 0x2615,  "(coffee)" }, { 0x1F382, "(cake)" }, { 0x1F680, "(rocket)" }, { 0x1F3B5, "(music)" },
    { 0, 0 }
};

static int cp_emit(ULONG cp, UBYTE *out, int cap, int n)
{
    const char *tag = 0;
    int i;
    if (cp < 0x80 || (cp >= 0xA0 && cp < 0x100)) { if (n < cap) out[n++] = (UBYTE)cp; return n; }
    if (cp < 0xA0) { if (n < cap) out[n++] = '?'; return n; }
    switch (cp) {
    case 0x2018: case 0x2019: case 0x201A: case 0x2032: tag = "'"; break;
    case 0x201C: case 0x201D: case 0x201E: case 0x2033: tag = "\""; break;
    case 0x2010: case 0x2011: case 0x2012: case 0x2013: case 0x2014: case 0x2212: tag = "-"; break;
    case 0x2026: tag = "..."; break;
    case 0x20AC: tag = "EUR"; break;
    case 0x2022: tag = "\xB7"; break;
    case 0x2122: tag = "TM"; break;
    case 0x2192: tag = "->"; break;
    case 0x2190: tag = "<-"; break;
    case 0x200B: case 0x200C: case 0x200D: case 0x2060: case 0xFE0E: case 0xFE0F: case 0xFEFF: return n;   /* joiners, selectors */
    default: break;
    }
    if (!tag && cp >= 0x1F3FB && cp <= 0x1F3FF) return n;        /* skin tone modifiers */
    if (!tag && cp >= 0x1F1E6 && cp <= 0x1F1FF) { if (n < cap) out[n++] = (UBYTE)('A' + (cp - 0x1F1E6)); return n; }  /* flag letters */
    if (!tag) for (i = 0; emoji_tags[i].tag; i++) if (emoji_tags[i].cp == cp) { tag = emoji_tags[i].tag; break; }
    if (!tag) tag = "?";
    while (*tag && n < cap) out[n++] = (UBYTE)*tag++;
    return n;
}

int gui_utf8_to_latin1(const UBYTE *s, int len, UBYTE *out, int cap)
{
    int i = 0, n = 0;
    while (i < len) {
        UBYTE c = s[i];
        ULONG cp; int need;
        if (c < 0x80) { cp = c; need = 0; }
        else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; need = 1; }
        else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; need = 2; }
        else if ((c & 0xF8) == 0xF0) { cp = c & 0x07; need = 3; }
        else { i++; if (n < cap) out[n++] = '?'; continue; }
        if (need && i + need >= len) { i++; if (n < cap) out[n++] = '?'; continue; }
        i++;
        while (need-- > 0) {
            if ((s[i] & 0xC0) != 0x80) { cp = '?'; break; }
            cp = (cp << 6) | (s[i] & 0x3F); i++;
        }
        n = cp_emit(cp, out, cap, n);
    }
    return n;
}

int gui_latin1_to_utf8(const UBYTE *s, int n, char *out, int cap)
{
    int i, o = 0;
    for (i = 0; i < n; i++) {
        UBYTE c = s[i];
        if (c < 0x80) { if (o + 1 >= cap) break; out[o++] = (char)c; }
        else { if (o + 2 >= cap) break; out[o++] = (char)(0xC0 | (c >> 6)); out[o++] = (char)(0x80 | (c & 0x3F)); }
    }
    if (cap > 0) out[o < cap ? o : cap - 1] = 0;
    return o;
}

/* ---- drawing primitives: a composed cell row ------------------------------------------------------------------- */
static UBYTE sym_ascii(UBYTE c)
{
    switch (c) {
    case F8_TICK: return 'v'; case F8_DTICK: return 'V'; case F8_CLOCK: return '~'; case F8_CAP_L: case F8_CAP_R: return ' ';
    case F8_DOT: return '*'; case F8_ARROW_DN: return 'v'; case F8_ARROW_UP: return '^'; case F8_ARROW_RT: return '>';
    case F8_HLINE: return '-'; case F8_BANG: return '!'; case F8_BLOCK: return ' '; case F8_ULINE: return '_';
    case F8_TAIL_L: case F8_TAIL_R: return ' ';
    default: return c < 32 ? '?' : c;
    }
}

static void d_fill(int col, int y, int ncols, int h, int pen)
{
    if (text_mode == GUI_TEXT_FAST) ftext_fill(col, y, ncols, h, pen);
    else scr_fill(col * 8, y, ncols * 8, h, pen);
}

/* paints cells[c0..c0+n) of the composed row at pixel row y as runs of equal fg/bg/style */
static void flush_cells(int c0, int n, int y)
{
    int i = 0;
    rows_drawn++;
    while (i < n) {
        int j = i + 1, fg = cell_fg[c0 + i], bg = cell_bg[c0 + i], st = cell_st[c0 + i];
        while (j < n && cell_fg[c0 + j] == fg && cell_bg[c0 + j] == bg && cell_st[c0 + j] == st) j++;
        if (text_mode == GUI_TEXT_FAST) {
            ftext_text(c0 + i, y, fg, bg, cell_ch + c0 + i, j - i, st);
        } else {
            char tmp[COLS + 1]; int k, blank = 1;
            for (k = i; k < j; k++) { tmp[k - i] = (char)sym_ascii(cell_ch[c0 + k]); if (tmp[k - i] != ' ') blank = 0; }
            tmp[j - i] = 0;
            if (blank) scr_fill((c0 + i) * 8, y, (j - i) * 8, 8, bg);
            else { scr_text_bg((c0 + i) * 8, y, fg, bg, tmp); if (st & FTEXT_BOLD) scr_text((c0 + i) * 8 + 1, y, fg, tmp); }
        }
        i = j;
    }
}

static void cells_clear(int c0, int n, int bg)
{
    int i;
    for (i = 0; i < n; i++) { cell_ch[c0 + i] = ' '; cell_fg[c0 + i] = (UBYTE)bg; cell_bg[c0 + i] = (UBYTE)bg; cell_st[c0 + i] = 0; }
}
static int cells_put(int c, const UBYTE *s, int n, int fg, int bg, int st, int limit)   /* returns next column */
{
    int i;
    for (i = 0; i < n && c + i < limit; i++) { cell_ch[c + i] = s[i]; cell_fg[c + i] = (UBYTE)fg; cell_bg[c + i] = (UBYTE)bg; cell_st[c + i] = (UBYTE)st; }
    return c + (i < n ? i : n);
}
static int cells_puts(int c, const char *s, int fg, int bg, int st, int limit) { return cells_put(c, (const UBYTE *)s, slen(s), fg, bg, st, limit); }
static void cells_put1(int c, UBYTE ch, int fg, int bg) { cell_ch[c] = ch; cell_fg[c] = (UBYTE)fg; cell_bg[c] = (UBYTE)bg; cell_st[c] = 0; }

/* ---- message store ---------------------------------------------------------------------------------------- */
static LONG text_fit(ULONG len)                 /* offset for len bytes or -1 */
{
    if (mcount == 0) { thead = ttail = 0; return len <= tcap ? 0 : -1; }
    if (ttail > thead) {
        if (tcap - ttail >= len) return (LONG)ttail;
        if (thead >= len) return 0;
        return -1;
    }
    if (ttail < thead) return thead - ttail >= len ? (LONG)ttail : -1;
    return len == 0 ? (LONG)ttail : -1;         /* ttail == thead with messages: the ring is full */
}

static void drop_oldest(void)
{
    struct gui_msg *m = slot_at(0);
    if (m->chat < GUI_MAX_CHATS && chats[m->chat].count) chats[m->chat].count--;
    if (++mhead >= nslots) mhead = 0;
    mcount--; dropped++;
    if (mcount == 0) thead = ttail = 0; else thead = slot_at(0)->toff;
    conv_dirty = 1;
}

static struct gui_msg *find_msg(ULONG id, UWORD *index)
{
    UWORD i = mcount;
    while (i-- > 0) { struct gui_msg *m = slot_at(i); if (m->id == id) { if (index) *index = i; return m; } }
    return 0;
}

/* ---- chats ------------------------------------------------------------------------------------------------- */
static void sort_chats(void)                     /* insertion sort by last_ts descending, stable */
{
    int i, j;
    for (i = 1; i < nchats; i++) {
        UBYTE k = order[i];
        for (j = i; j > 0 && chats[order[j - 1]].last_ts < chats[k].last_ts; j--) order[j] = order[j - 1];
        order[j] = k;
    }
}
static int order_pos(int chat) { int i; for (i = 0; i < nchats; i++) if (order[i] == chat) return i; return -1; }

static void list_follow_selection(void)
{
    int pos = cur_chat >= 0 ? order_pos(cur_chat) : 0, old = list_top;
    if (pos < 0) pos = 0;
    if (pos < list_top) list_top = pos;
    if (pos >= list_top + LIST_VISIBLE) list_top = pos - LIST_VISIBLE + 1;
    if (list_top != old) list_dirty_all = 1;
}

static void set_name(struct gui_chat *c, const char *name)
{
    int n = slen(name), i, ascii_only = 1;
    for (i = 0; i < n; i++) if ((UBYTE)name[i] >= 0x80) ascii_only = 0;
    if (ascii_only) { if (n > GUI_NAME_MAX) n = GUI_NAME_MAX; bcopy_(c->name, name, (ULONG)n); c->name_len = (UBYTE)n; }
    else {
        /* UTF-8 or Latin-1? valid UTF-8 continuation structure decides */
        int utf8 = 1;
        for (i = 0; i < n; i++) {
            UBYTE b = (UBYTE)name[i];
            if (b < 0x80) continue;
            if ((b & 0xE0) == 0xC0 && i + 1 < n && ((UBYTE)name[i + 1] & 0xC0) == 0x80) { i += 1; continue; }
            if ((b & 0xF0) == 0xE0 && i + 2 < n && ((UBYTE)name[i + 1] & 0xC0) == 0x80 && ((UBYTE)name[i + 2] & 0xC0) == 0x80) { i += 2; continue; }
            if ((b & 0xF8) == 0xF0 && i + 3 < n && ((UBYTE)name[i + 1] & 0xC0) == 0x80) { i += 3; continue; }
            utf8 = 0; break;
        }
        if (utf8) c->name_len = (UBYTE)gui_utf8_to_latin1((const UBYTE *)name, n, c->name, GUI_NAME_MAX);
        else { if (n > GUI_NAME_MAX) n = GUI_NAME_MAX; bcopy_(c->name, name, (ULONG)n); c->name_len = (UBYTE)n; }
    }
    c->name[c->name_len] = 0;
}

int gui_add_chat(const char *jid, const char *name)
{
    struct gui_chat *c;
    int i = gui_find_chat(jid), n;
    if (i >= 0) { if (name && *name) gui_set_chat_name(i, name); return i; }
    if (nchats >= GUI_MAX_CHATS) return -1;
    i = nchats++;
    c = &chats[i];
    bzero_(c, sizeof *c);
    n = slen(jid); if (n > GUI_JID_MAX - 1) n = GUI_JID_MAX - 1;
    bcopy_(c->jid, jid, (ULONG)n); c->jid[n] = 0;
    set_name(c, name && *name ? name : jid);
    c->used = 1; c->dirty = 1;
    order[i] = (UBYTE)i;
    sort_chats();
    list_dirty_all = 1;
    if (cur_chat < 0) { cur_chat = i; hdr_dirty = 1; conv_dirty = 1; }
    return i;
}

int gui_find_chat(const char *jid) { int i; for (i = 0; i < nchats; i++) if (streq(chats[i].jid, jid)) return i; return -1; }
int gui_set_chat_name(int chat, const char *name)
{
    if (chat < 0 || chat >= nchats) return -1;
    set_name(&chats[chat], name); chats[chat].dirty = 1;
    if (chat == cur_chat) hdr_dirty = 1;
    return 0;
}
const char *gui_chat_jid(int chat) { return chat >= 0 && chat < nchats ? chats[chat].jid : ""; }
int gui_chat_count(void) { return nchats; }
int gui_current_chat(void) { return cur_chat; }
int gui_chat_unread(int chat) { return chat >= 0 && chat < nchats ? chats[chat].unread : 0; }
int gui_chat_messages(int chat) { return chat >= 0 && chat < nchats ? chats[chat].count : 0; }

int gui_select_chat(int chat)
{
    if (chat < 0 || chat >= nchats) return -1;
    if (cur_chat >= 0) chats[cur_chat].dirty = 1;
    cur_chat = chat;
    chats[chat].unread = 0; chats[chat].dirty = 1;
    conv_scroll = 0; conv_dirty = 1; hdr_dirty = 1;
    list_follow_selection();
    return 0;
}

/* ---- messages ------------------------------------------------------------------------------------------------ */
static void set_preview(struct gui_chat *c, struct gui_msg *m, const UBYTE *utf8, int len)
{
    UBYTE tmp[64]; int n, i;
    n = gui_utf8_to_latin1(utf8, len > 48 ? 48 : len, tmp, sizeof tmp);
    for (i = 0; i < n && i < 15; i++) { if (tmp[i] == '\n' || tmp[i] == '\r') break; c->prev[i] = tmp[i] < 32 ? ' ' : tmp[i]; }
    c->prev_len = (UBYTE)i; c->prev_from_me = (UBYTE)(m->flags & MF_FROM_ME); c->prev_status = (UBYTE)MF_STATUS(m->flags);
    c->prev_id = m->id; c->last_hh = m->hh; c->last_mm = m->mm;
}

ULONG gui_add_message(int chat, int from_me, ULONG ts, const char *utf8, int len, int status)
{
    struct gui_msg *m; struct gui_chat *c;
    LONG off;
    if (chat < 0 || chat >= nchats || !slots) return 0;
    if (len < 0) len = slen(utf8);
    if (len > GUI_TEXT_MAX) { len = GUI_TEXT_MAX; while (len > 0 && ((UBYTE)utf8[len] & 0xC0) == 0x80) len--; }
    if ((ULONG)len > tcap) return 0;
    if (status < 0 || status > GUI_ST_FAILED) status = from_me ? GUI_ST_PENDING : GUI_ST_READ;
    while (mcount >= nslots || (off = text_fit((ULONG)len)) < 0) { if (mcount == 0) return 0; drop_oldest(); }
    m = slot_at(mcount); mcount++;
    m->id = next_id++; if (next_id == 0) next_id = 1;
    m->ts = ts; m->toff = (UWORD)off; m->tlen = (UWORD)len; m->chat = (UBYTE)chat; m->flags = MF_MAKE(from_me, status);
    local_hm(ts, &m->hh, &m->mm);
    if (len) bcopy_(tring + off, utf8, (ULONG)len);
    ttail = (ULONG)off + (ULONG)len;
    c = &chats[chat];
    c->count++;
    if (ts > c->last_ts || c->last_ts == 0) { c->last_ts = ts ? ts : 1; sort_chats(); list_dirty_all = 1; }
    set_preview(c, m, (const UBYTE *)utf8, len);
    if (!from_me && chat != cur_chat) c->unread++;
    c->dirty = 1;
    if (chat == cur_chat) conv_dirty = 1;
    list_follow_selection();
    return m->id;
}

int gui_set_status(int chat, ULONG msg_id, int status)
{
    if (chat < -1) return -1;
    struct gui_msg *m = find_msg(msg_id, 0);      /* chat is only a hint: the id is unique */
    if (!m || status < 0 || status > GUI_ST_FAILED) return -1;
    m->flags = MF_MAKE(m->flags & MF_FROM_ME, status);
    if (m->chat == cur_chat) conv_dirty = 1;
    if (m->chat < nchats && chats[m->chat].prev_id == msg_id) { chats[m->chat].prev_status = (UBYTE)status; chats[m->chat].dirty = 1; }
    return 0;
}

void gui_set_connection(int state, const char *detail)
{
    int n;
    if (state < 0 || state > GUI_CONN_ERROR) state = GUI_CONN_ERROR;
    conn_state = state;
    conn_detail_len = 0;
    if (detail) {
        n = slen(detail);
        conn_detail_len = gui_utf8_to_latin1((const UBYTE *)detail, n, conn_detail, sizeof conn_detail);
    }
    hdr_dirty = 1; status_dirty = 1;
}

void gui_set_clock(int hh, int mm) { if (hh != clk_hh || mm != clk_mm) status_dirty = 1; clk_hh = hh; clk_mm = mm; }
void gui_set_time(ULONG now)
{
    UBYTE hh, mm; ULONG day = local_day(now);
    local_hm(now, &hh, &mm);
    gui_set_clock(hh, mm);
    if (day != today_day) { today_day = day; conv_dirty = 1; }
}
void gui_set_tz(LONG east) { tz_east = east; }

void gui_stats(struct gui_stats *s)
{
    s->chats = (UWORD)nchats; s->msgs = mcount; s->slots = nslots;
    s->text_cap = tcap;
    s->text_used = mcount == 0 ? 0 : (ttail >= thead ? ttail - thead : tcap - thead + ttail);
    if (mcount && ttail == thead) s->text_used = tcap;
    s->dropped = dropped; s->rows_drawn = rows_drawn; s->scrolls = scroll_count;
}

/* ---- conversation layout ------------------------------------------------------------------------------------- */
static void convert_msg(struct gui_msg *m)
{
    if (conv_id == m->id) return;
    conv_len = gui_utf8_to_latin1(tring + m->toff, m->tlen, conv_buf, GUI_TEXT_MAX);
    conv_id = m->id;
}

#define MAX_MSG_LINES 40
static int wrap_text(const UBYTE *t, int n, int width, UWORD *start, UWORD *len, int maxl)
{
    int pos = 0, nl = 0;
    if (n == 0) { start[0] = 0; len[0] = 0; return 1; }
    while (pos < n && nl < maxl) {
        int end = pos, last_space = -1, i;
        for (i = pos; i < n && i - pos < width; i++) {
            if (t[i] == '\n') break;
            if (t[i] == ' ') last_space = i;
        }
        end = i;
        if (i < n && t[i] == '\n') { start[nl] = (UWORD)pos; len[nl] = (UWORD)(end - pos); nl++; pos = i + 1; if (pos == n) { if (nl < maxl) { start[nl] = (UWORD)pos; len[nl] = 0; nl++; } } continue; }
        if (i >= n) { start[nl] = (UWORD)pos; len[nl] = (UWORD)(end - pos); nl++; break; }
        if (t[i] == ' ') { start[nl] = (UWORD)pos; len[nl] = (UWORD)(i - pos); nl++; pos = i + 1; continue; }
        if (last_space > pos) { start[nl] = (UWORD)pos; len[nl] = (UWORD)(last_space - pos); nl++; pos = last_space + 1; continue; }
        start[nl] = (UWORD)pos; len[nl] = (UWORD)(end - pos); nl++; pos = end;        /* hard break */
    }
    return nl;
}

static int footer_width(int from_me) { return from_me ? 7 : 5; }   /* "HH:MM" + " " + tick */

/* lines of one message into out[] (top to bottom), returns the count; with_sep adds the date separator on top */
static int msg_lines(struct gui_msg *m, int with_sep, struct row *out, int cap)
{
    UWORD st[MAX_MSG_LINES], ln[MAX_MSG_LINES];
    int nl, i, n = 0, from_me = (m->flags & MF_FROM_ME) != 0, fw = footer_width(from_me), cw = 0, inline_footer;
    convert_msg(m);
    nl = wrap_text(conv_buf, conv_len, WRAP_W, st, ln, MAX_MSG_LINES);
    for (i = 0; i < nl; i++) if (ln[i] > cw) cw = ln[i];
    inline_footer = ln[nl - 1] + 1 + fw <= WRAP_W;
    if (inline_footer) { if (ln[nl - 1] + 1 + fw > cw) cw = ln[nl - 1] + 1 + fw; }
    else if (fw > cw) cw = fw;
    if (with_sep && n < cap) {
        bzero_(&out[n], sizeof out[n]);
        out[n].kind = 2; out[n].day = local_day(m->ts); out[n].id = m->id; n++;
    }
    for (i = 0; i < nl && n < cap; i++) {
        struct row *r = &out[n++];
        r->id = m->id; r->kind = 1; r->ln = (UBYTE)i; r->start = st[i]; r->len = ln[i];
        r->bw = (UBYTE)(cw + 2); r->b0 = (UBYTE)(from_me ? CONV_COLS - 1 - r->bw : 1);
        r->flags = (UBYTE)((from_me ? ROW_FROM_ME : 0) | (i == 0 ? ROW_FIRST : 0) | (i == nl - 1 && inline_footer ? ROW_FOOTER : 0));
        r->st = (UBYTE)MF_STATUS(m->flags); r->day = 0;
    }
    if (!inline_footer && n < cap) {
        struct row *r = &out[n++];
        r->id = m->id; r->kind = 3; r->ln = (UBYTE)nl; r->start = 0; r->len = 0;
        r->bw = (UBYTE)(cw + 2); r->b0 = (UBYTE)(from_me ? CONV_COLS - 1 - r->bw : 1);
        r->flags = (UBYTE)((from_me ? ROW_FROM_ME : 0) | ROW_FOOTER); r->st = (UBYTE)MF_STATUS(m->flags); r->day = 0;
    }
    return n;
}

static int next_older(UWORD i, int chat)        /* index of the next older message of chat below i, or -1 */
{
    while (i-- > 0) if (slot_at(i)->chat == chat) return i;
    return -1;
}

/* fills rows_new; returns the number of lines that could not be skipped (scrolled past the beginning) */
static int layout_conv(void)
{
    struct row tmp[MAX_MSG_LINES + 2];
    int fill = CONV_ROWS - 1, skip = conv_scroll, cur, prev;
    int i;
    for (i = 0; i < CONV_ROWS; i++) { bzero_(&rows_new[i], sizeof rows_new[i]); rows_new[i].kind = 0; }
    if (cur_chat < 0 || mcount == 0) return 0;
    cur = next_older(mcount, cur_chat);
    while (cur >= 0 && fill >= 0) {
        struct gui_msg *m = slot_at((UWORD)cur);
        int n, j, with_sep;
        prev = next_older((UWORD)cur, cur_chat);
        with_sep = prev < 0 || local_day(slot_at((UWORD)prev)->ts) != local_day(m->ts);
        n = msg_lines(m, with_sep, tmp, MAX_MSG_LINES + 2);
        for (j = n - 1; j >= 0 && fill >= 0; j--) {
            if (skip > 0) { skip--; continue; }
            rows_new[fill--] = tmp[j];
        }
        cur = prev;
    }
    if (fill >= 0 && conv_scroll > 0) return fill + 1 + skip;    /* room at the top while scrolled: scroll back */
    return skip;
}

static int rows_equal(const struct row *a, const struct row *b)
{
    return a->id == b->id && a->kind == b->kind && a->ln == b->ln && a->start == b->start && a->len == b->len
        && a->b0 == b->b0 && a->bw == b->bw && a->flags == b->flags && a->st == b->st && a->day == b->day;
}

static int day_label(ULONG day, UBYTE *out)
{
    ULONG y, m, d;
    if (today_day && day == today_day) { bcopy_(out, "Heute", 5); return 5; }
    if (today_day && day + 1 == today_day) { bcopy_(out, "Gestern", 7); return 7; }
    civil(day, &y, &m, &d);
    put_dec(out, d, 2); out[2] = '.'; put_dec(out + 3, m, 2); out[5] = '.'; put_dec(out + 6, y, 4);
    return 10;
}

static void compose_footer(int c, struct row *r, struct gui_msg *m, int bp)
{
    UBYTE t[5];
    put_dec(t, m->hh, 2); t[2] = ':'; put_dec(t + 3, m->mm, 2);
    cells_put(c, t, 5, P_LTGREY, bp, 0, COLS);
    if (r->flags & ROW_FROM_ME) {
        UBYTE g; int pen = P_LTGREY;
        switch (r->st) {
        case GUI_ST_PENDING: g = F8_CLOCK; pen = P_GREY; break;
        case GUI_ST_SENT: g = F8_TICK; break;
        case GUI_ST_DELIVERED: g = F8_DTICK; break;
        case GUI_ST_READ: g = F8_DTICK; pen = P_BLUE; break;
        default: g = F8_BANG; pen = P_RED; break;
        }
        cells_put1(c + 5, ' ', bp, bp); cells_put1(c + 6, g, pen, bp);
    }
}

static void draw_conv_row(int i)
{
    struct row *r = &rows_new[i];
    int y = CONV_Y0 + 8 * i, c, bp, from_me, inner_end;
    struct gui_msg *m;
    cells_clear(CONV_COL, CONV_COLS + 1, P_BG);           /* incl. column 79 */
    if (r->kind == 2) {
        UBYTE lab[12]; int n = day_label(r->day, lab), left = CONV_COL + ((CONV_COLS - n - 2) >> 1);
        cells_put1(left, ' ', P_GREY, P_PANEL); cells_put(left + 1, lab, n, P_GREY, P_PANEL, 0, COLS); cells_put1(left + 1 + n, ' ', P_GREY, P_PANEL);
        flush_cells(CONV_COL, CONV_COLS + 1, y);
        return;
    }
    if (r->kind == 0 || r->kind == 0xFF) { flush_cells(CONV_COL, CONV_COLS + 1, y); return; }
    m = find_msg(r->id, 0);
    if (!m) { flush_cells(CONV_COL, CONV_COLS + 1, y); return; }
    from_me = (r->flags & ROW_FROM_ME) != 0;
    bp = from_me ? P_OWN : P_PANEL;
    c = CONV_COL + r->b0;
    inner_end = c + r->bw - 1;                               /* the right padding cell */
    { int k; for (k = c; k <= inner_end; k++) cells_put1(k, ' ', P_WHITE, bp); }
    if (r->flags & ROW_FIRST) {                              /* bubble tail on the first line */
        if (from_me) cells_put1(inner_end + 1, F8_TAIL_R, bp, P_BG); else cells_put1(c - 1, F8_TAIL_L, bp, P_BG);
    }
    if (r->kind == 1) { convert_msg(m); cells_put(c + 1, conv_buf + r->start, r->len, P_WHITE, bp, 0, inner_end); }
    if (r->flags & ROW_FOOTER) compose_footer(inner_end - footer_width(from_me), r, m, bp);
    flush_cells(CONV_COL, CONV_COLS + 1, y);
}

static void conv_invalidate(int from, int to)    /* rows [from, to] must be repainted next time */
{
    int i;
    for (i = from; i <= to && i < CONV_ROWS; i++) if (i >= 0) rows_old[i].kind = 0xFF;
    conv_dirty = 1;
}

static void redraw_conv(void)
{
    int i, k, over, pass;
    for (pass = 0; pass < 3; pass++) {
        over = layout_conv();
        if (over <= 0 || conv_scroll == 0) break;
        conv_scroll -= over; if (conv_scroll < 0) conv_scroll = 0;
    }
    last_scrolled = 0;
    /* shifted by k rows? (the top CONV_ROWS-k new rows equal the old rows k..) */
    if (scroll_mode != GUI_SCROLL_REDRAW) {
        for (k = 1; k <= CONV_ROWS / 2; k++) {
            int match = 1;
            for (i = 0; i < CONV_ROWS - k; i++) if (rows_old[i + k].kind == 0xFF || !rows_equal(&rows_new[i], &rows_old[i + k])) { match = 0; break; }
            if (!match) continue;
            if (scroll_mode == GUI_SCROLL_CPU && text_mode == GUI_TEXT_FAST) ftext_scroll_up(CONV_COL, CONV_Y0, CONV_COLS + 1, CONV_H, 8 * k, P_BG);
            else { scr_scroll_up(CONV_COL * 8, CONV_Y0, (CONV_COLS + 1) * 8, CONV_H, 8 * k, P_BG); if (text_mode == GUI_TEXT_FAST) scr_wait_blit(); }
            scroll_count++; last_scrolled = 1;
            for (i = CONV_ROWS - k; i < CONV_ROWS; i++) draw_conv_row(i);
            for (i = 0; i < CONV_ROWS; i++) rows_old[i] = rows_new[i];
            conv_dirty = 0;
            return;
        }
    }
    for (i = 0; i < CONV_ROWS; i++) {
        if (rows_old[i].kind != 0xFF && rows_equal(&rows_new[i], &rows_old[i])) continue;
        draw_conv_row(i);
        rows_old[i] = rows_new[i];
    }
    conv_dirty = 0;
}

/* ---- header, list, input, status, help ----------------------------------------------------------------------- */
static const char *conn_word(int st, int *pen)
{
    switch (st) {
    case GUI_CONN_ONLINE: *pen = P_GREEN; return "online";
    case GUI_CONN_CONNECTING: *pen = P_YELLOW; return "verbinde";
    case GUI_CONN_HANDSHAKE: *pen = P_YELLOW; return "Handshake";
    case GUI_CONN_ERROR: *pen = P_RED; return "Fehler";
    default: *pen = P_RED; return "offline";
    }
}

static void draw_header(void)
{
    int c, pen; const char *w = conn_word(conn_state, &pen); int wl = slen(w);
    cells_clear(0, COLS, P_PANEL);
    cells_puts(1, "Tachyon", P_GREEN, P_PANEL, FTEXT_BOLD, COLS);
    if (cur_chat >= 0) {
        struct gui_chat *ch = &chats[cur_chat];
        UBYTE t[16]; int n;
        c = cells_put(CONV_COL, ch->name, ch->name_len, P_WHITE, P_PANEL, FTEXT_BOLD, COLS);
        n = dec_len(ch->count); put_dec(t, ch->count, 0);
        c = cells_put(c + 2, t, n, P_GREY, P_PANEL, 0, COLS);
        cells_puts(c + 1, ch->count == 1 ? "Nachricht" : "Nachrichten", P_GREY, P_PANEL, 0, COLS - 12 - wl);
    }
    c = COLS - 2 - wl;
    cells_put1(c - 2, F8_DOT, pen, P_PANEL);
    cells_puts(c, w, P_LTGREY, P_PANEL, 0, COLS);
    d_fill(0, 0, COLS, HDR_H, P_PANEL);
    flush_cells(0, COLS, HDR_TEXT_Y);
    hdr_dirty = 0;
}

static void draw_list_entry(int pos)
{
    int y = LIST_Y0 + pos * LIST_ENTRY_H, idx = list_top + pos, bg, chat;
    struct gui_chat *ch;
    if (idx >= nchats) { d_fill(0, y, LIST_COLS, LIST_ENTRY_H, P_LIST); return; }
    chat = order[idx]; ch = &chats[chat];
    bg = chat == cur_chat ? P_SEL : P_LIST;
    /* row 1: name, time */
    cells_clear(0, LIST_COLS, bg);
    cells_put(1, ch->name, ch->name_len > 12 ? 12 : ch->name_len, P_WHITE, bg, 0, 14);
    if (ch->count || ch->last_ts) {
        UBYTE t[5]; put_dec(t, ch->last_hh, 2); t[2] = ':'; put_dec(t + 3, ch->last_mm, 2);
        cells_put(14, t, 5, ch->unread ? P_GREEN : P_GREY, bg, 0, COLS);
    }
    flush_cells(0, LIST_COLS, y);
    /* row 2: preview, badge */
    cells_clear(0, LIST_COLS, bg);
    if (ch->count) {
        int c = 1, limit = 19, maxp;
        if (ch->unread) {
            int n = ch->unread > 99 ? 3 : dec_len(ch->unread); UBYTE t[4];
            if (ch->unread > 99) { t[0] = '9'; t[1] = '9'; t[2] = '+'; } else put_dec(t, ch->unread, 0);
            limit = 19 - (n + 2);
            cells_put1(limit, F8_CAP_L, P_GREEN, bg); cells_put(limit + 1, t, n, P_BLACK, P_GREEN, 0, COLS); cells_put1(limit + 1 + n, F8_CAP_R, P_GREEN, bg);
            limit--;
        }
        if (ch->prev_from_me) {
            UBYTE g = ch->prev_status == GUI_ST_PENDING ? F8_CLOCK : ch->prev_status == GUI_ST_SENT ? F8_TICK : ch->prev_status == GUI_ST_FAILED ? F8_BANG : F8_DTICK;
            cells_put1(c, g, ch->prev_status == GUI_ST_READ ? P_BLUE : ch->prev_status == GUI_ST_FAILED ? P_RED : P_GREY, bg); c += 2;
        }
        maxp = limit - c; if (maxp < 0) maxp = 0;
        cells_put(c, ch->prev, ch->prev_len > maxp ? maxp : ch->prev_len, ch->unread ? P_LTGREY : P_GREY, bg, 0, limit);
    } else cells_puts(1, ch->jid, P_GREY, bg, 0, 19);
    flush_cells(0, LIST_COLS, y + 8);
    ch->dirty = 0;
}

static void draw_list_footer(void)
{
    int below = nchats - list_top - LIST_VISIBLE, c = 1;
    cells_clear(0, LIST_COLS, P_LIST);
    if (list_top > 0) { UBYTE t[4]; cells_put1(c, F8_ARROW_UP, P_GREY, P_LIST); put_dec(t, (ULONG)list_top, 0); c = cells_put(c + 2, t, dec_len((ULONG)list_top), P_GREY, P_LIST, 0, COLS) + 2; }
    if (below > 0) { UBYTE t[4]; cells_put1(c, F8_ARROW_DN, P_GREY, P_LIST); put_dec(t, (ULONG)below, 0); c = cells_put(c + 2, t, dec_len((ULONG)below), P_GREY, P_LIST, 0, COLS); cells_puts(c + 1, "weitere", P_GREY, P_LIST, 0, LIST_COLS); }
    flush_cells(0, LIST_COLS, LIST_FOOT_Y);
}

static void draw_list(void)
{
    int pos;
    for (pos = 0; pos < LIST_VISIBLE; pos++) {
        int idx = list_top + pos;
        if (list_dirty_all || (idx < nchats && chats[order[idx]].dirty)) draw_list_entry(pos);
    }
    if (list_dirty_all) draw_list_footer();
    list_dirty_all = 0;
}

static void input_follow_cursor(void)
{
    if (cursor < input_win) input_win = cursor;
    if (cursor >= input_win + INPUT_WIN) input_win = cursor - INPUT_WIN + 1;
    if (input_win > 0 && input_len - input_win < INPUT_WIN - 1) { input_win = input_len - INPUT_WIN + 1; if (input_win < 0) input_win = 0; }
}

static void draw_input(void)
{
    int row, k;
    input_follow_cursor();
    for (row = 0; row < 2; row++) {
        int y = row ? INPUT_ROW2 : INPUT_ROW1;
        cells_clear(CONV_COL, CONV_COLS, P_INPUT);
        if (input_len == 0 && row == 0 && focus != 1) cells_puts(INPUT_COL, "Nachricht schreiben ...", P_GREY, P_INPUT, 0, COLS);
        for (k = 0; k < INPUT_COLS; k++) {
            int idx = input_win + row * INPUT_COLS + k, c = INPUT_COL + k;
            if (idx < input_len) cells_put1(c, input[idx], P_WHITE, P_INPUT);
            if (idx == cursor && focus == 1) {
                if (insert_mode) { cell_fg[c] = P_INPUT; cell_bg[c] = P_WHITE; if (idx >= input_len) cell_ch[c] = ' '; }
                else { cell_fg[c] = P_BLACK; cell_bg[c] = P_YELLOW; if (idx >= input_len) cell_ch[c] = ' '; }
            }
        }
        if (row == 0 && input_win > 0) cells_put1(CONV_COL, '<', P_GREY, P_INPUT);
        if (row == 1 && input_win + INPUT_WIN < input_len) cells_put1(CONV_COL + CONV_COLS - 1, '>', P_GREY, P_INPUT);
        if (row == 1 && !insert_mode) cells_put1(CONV_COL + CONV_COLS - 1, 'U', P_YELLOW, P_INPUT);
        flush_cells(CONV_COL, CONV_COLS, y);
    }
    input_dirty = 0;
}

static void draw_status(void)
{
    cells_clear(0, COLS, P_PANEL);
    if (conn_detail_len) cells_put(1, conn_detail, conn_detail_len > 36 ? 36 : conn_detail_len, P_LTGREY, P_PANEL, 0, 38);
    if (esc_armed) cells_puts(40, "Esc nochmal: Beenden", P_YELLOW, P_PANEL, 0, 73);
    else if (focus == 1) cells_puts(40, "F1 Hilfe  Tab Chatliste  Return", P_GREY, P_PANEL, 0, 73);
    else cells_puts(40, "F1 Hilfe  Tab Eingabe  Auf/Ab", P_GREY, P_PANEL, 0, 73);
    if (clk_hh >= 0) { UBYTE t[5]; put_dec(t, (ULONG)clk_hh, 2); t[2] = ':'; put_dec(t + 3, (ULONG)clk_mm, 2); cells_put(74, t, 5, P_WHITE, P_PANEL, 0, COLS); }
    d_fill(0, STATUS_Y, COLS, SCR_H - STATUS_Y, P_PANEL);
    flush_cells(0, COLS, STATUS_TEXT_Y);
    status_dirty = 0;
}

#define HELP_COL 23
#define HELP_COLS 55
#define HELP_Y 32
#define HELP_KEYW 15                /* width of the key column (green) */
static const char *help_lines[] = {
    "Tab            Fokus Chatliste <-> Eingabe",
    "Auf / Ab       Chat w\xE4hlen (Liste), Verlauf (Eingabe)",
    "Shift+Auf/Ab   Verlauf seitenweise bl\xE4ttern",
    "Return         Chat \xF6" "ffnen / Nachricht senden",
    "Links / Rechts Cursor, mit Shift: Anfang / Ende",
    "Backspace, Del Zeichen l\xF6schen",
    "F2             Einf\xFCgen / \xDC" "berschreiben",
    "Esc            Eingabe l\xF6schen, zweimal: Beenden",
    "Amiga+Q        Beenden",
    "F1 / Help      diese Hilfe (jede Taste schlie\xDFt sie)",
    0
};

static void draw_help(void)
{
    int i, n = 0, y;
    while (help_lines[n]) n++;
    d_fill(HELP_COL, HELP_Y, HELP_COLS, 8 * (n + 3) + 4, P_SEP);                 /* frame */
    d_fill(HELP_COL + 1, HELP_Y + 2, HELP_COLS - 2, 8 * (n + 3), P_SEL);
    cells_clear(HELP_COL + 1, HELP_COLS - 2, P_GREEN);
    cells_puts(HELP_COL + 2, "Tachyon - Tasten", P_BLACK, P_GREEN, FTEXT_BOLD, COLS);
    flush_cells(HELP_COL + 1, HELP_COLS - 2, HELP_Y + 2);
    for (i = 0; i < n; i++) {
        y = HELP_Y + 2 + 8 * (i + 2);
        cells_clear(HELP_COL + 1, HELP_COLS - 2, P_SEL);
        cells_puts(HELP_COL + 2, help_lines[i], P_WHITE, P_SEL, 0, HELP_COL + HELP_COLS - 1);
        { int k; for (k = HELP_COL + 2; k < HELP_COL + 2 + HELP_KEYW; k++) cell_fg[k] = P_GREEN; }   /* the key column */
        flush_cells(HELP_COL + 1, HELP_COLS - 2, y);
    }
    help_dirty = 0;
}

static void help_close(void)
{
    int n = 0, y0, y1;
    while (help_lines[n]) n++;
    help_open = 0;
    y0 = HELP_Y; y1 = HELP_Y + 8 * (n + 3) + 4;
    conv_invalidate((int)((ULONG)(y0 - CONV_Y0) >> 3), (int)((ULONG)(y1 - CONV_Y0 + 7) >> 3));   /* the box lies inside the conversation pane (unsigned: no __divs) */
}

/* ---- redraw ---------------------------------------------------------------------------------------------------- */
static void draw_static(void)
{
    d_fill(0, HDR_H, LIST_COLS, SCR_H - HDR_H - (SCR_H - STATUS_Y), P_LIST);          /* list pane */
    d_fill(GAP_COL, HDR_H, 2, STATUS_Y - HDR_H, P_BG);                                 /* gap */
    d_fill(CONV_COL, HDR_H, CONV_COLS + 1, STATUS_Y - HDR_H, P_BG);                    /* conversation + margin */
    d_fill(CONV_COL, INPUT_Y0, CONV_COLS, INPUT_H, P_INPUT);                           /* input box */
}

int gui_redraw_dirty(void)
{
    ULONG before = rows_drawn;
    if (text_mode == GUI_TEXT_FAST) scr_wait_blit();
    if (hdr_dirty) draw_header();
    if (list_dirty_all) draw_list();
    else { int i; for (i = 0; i < nchats; i++) if (chats[i].dirty) { draw_list(); break; } }
    if (conv_dirty && !help_open) redraw_conv();
    if (help_open && help_dirty) draw_help();
    if (input_dirty) draw_input();
    if (status_dirty) draw_status();
    return (int)(rows_drawn - before);
}

void gui_redraw_all(void)
{
    int i;
    if (text_mode == GUI_TEXT_FAST) scr_wait_blit();
    scr_set_palette(gui_palette, 16);
    draw_static();
    for (i = 0; i < CONV_ROWS; i++) rows_old[i].kind = 0xFF;
    for (i = 0; i < nchats; i++) chats[i].dirty = 1;
    hdr_dirty = list_dirty_all = conv_dirty = input_dirty = status_dirty = 1;
    if (help_open) help_dirty = 1;
    gui_redraw_dirty();
    if (help_open) draw_help();
}

void gui_set_text_mode(int mode)
{
    if (mode == GUI_TEXT_FAST && !ftext_ready()) mode = GUI_TEXT_OS;
    text_mode = mode;
}
int  gui_text_mode(void) { return text_mode; }
void gui_set_scroll_mode(int mode) { scroll_mode = mode; }
int  gui_last_scrolled(void) { return last_scrolled; }

/* ---- keys ---------------------------------------------------------------------------------------------------------- */
static void input_insert(UBYTE ch)
{
    int i;
    if (insert_mode || cursor >= input_len) {
        if (input_len >= GUI_INPUT_MAX) return;
        for (i = input_len; i > cursor; i--) input[i] = input[i - 1];
        input[cursor] = ch; input_len++;
    } else input[cursor] = ch;
    cursor++;
    input_dirty = 1;
}

static void input_delete(int at)
{
    int i;
    if (at < 0 || at >= input_len) return;
    for (i = at; i < input_len - 1; i++) input[i] = input[i + 1];
    input_len--;
    input_dirty = 1;
}

static void select_pos(int pos)
{
    if (pos < 0) pos = 0;
    if (pos >= nchats) pos = nchats - 1;
    if (pos < 0 || order[pos] == cur_chat) return;
    gui_select_chat(order[pos]);
}

static void scroll_conv(int lines)
{
    int s = conv_scroll + lines;
    if (s < 0) s = 0;
    if (s != conv_scroll) { conv_scroll = s; conv_dirty = 1; }
}

int gui_pump(LONG key)
{
    UWORD qual = scr_last_qualifier();
    int shift = (qual & SCR_QUAL_SHIFT) != 0, amiga = (qual & SCR_QUAL_AMIGA) != 0;
    action_chat = -1;
    if (key == SCR_KEY_TIMEOUT) return GUI_ACT_NONE;
    if (help_open) { help_close(); return GUI_ACT_NONE; }
    if (key != 27 && esc_armed) { esc_armed = 0; status_dirty = 1; }
    if (key & SCR_KEY_RAW) {
        int code = key & 0xFF;
        switch (code) {
        case 0x50: case SCR_KEY_HELP: help_open = 1; help_dirty = 1; return GUI_ACT_NONE;          /* F1, Help */
        case 0x51: insert_mode = !insert_mode; input_dirty = 1; return GUI_ACT_NONE;                 /* F2 */
        case SCR_KEY_UP:
            if (shift) scroll_conv(CONV_ROWS - 1);
            else if (focus == 0) { int p = order_pos(cur_chat); select_pos(p - 1); if (gui_current_chat() != -1) { action_chat = cur_chat; return GUI_ACT_SWITCH; } }
            else scroll_conv(1);
            return GUI_ACT_NONE;
        case SCR_KEY_DOWN:
            if (shift) scroll_conv(-(CONV_ROWS - 1));
            else if (focus == 0) { int p = order_pos(cur_chat); select_pos(p + 1); action_chat = cur_chat; return GUI_ACT_SWITCH; }
            else scroll_conv(-1);
            return GUI_ACT_NONE;
        case SCR_KEY_LEFT:
            if (focus != 1) { focus = 1; input_dirty = 1; status_dirty = 1; }
            if (shift) cursor = 0; else if (cursor > 0) cursor--;
            input_dirty = 1; return GUI_ACT_NONE;
        case SCR_KEY_RIGHT:
            if (focus != 1) { focus = 1; input_dirty = 1; status_dirty = 1; }
            if (shift) cursor = input_len; else if (cursor < input_len) cursor++;
            input_dirty = 1; return GUI_ACT_NONE;
        default: return GUI_ACT_NONE;
        }
    }
    if (amiga && (key == 'q' || key == 'Q')) return GUI_ACT_QUIT;
    switch (key) {
    case 9:                                                                        /* Tab */
        focus = !focus; input_dirty = 1; status_dirty = 1; return GUI_ACT_NONE;
    case 13:                                                                       /* Return */
        if (focus == 0) { focus = 1; input_dirty = 1; status_dirty = 1; return GUI_ACT_NONE; }
        if (input_len == 0 || cur_chat < 0) return GUI_ACT_NONE;
        bcopy_(outgoing, input, (ULONG)input_len); outgoing_len = input_len; outgoing[outgoing_len] = 0;
        input_len = cursor = input_win = 0; input_dirty = 1;
        action_chat = cur_chat;
        return GUI_ACT_SEND;
    case 27:                                                                       /* Esc */
        if (input_len) { input_len = cursor = input_win = 0; input_dirty = 1; esc_armed = 0; return GUI_ACT_NONE; }
        if (esc_armed) { esc_armed = 0; return GUI_ACT_QUIT; }
        esc_armed = 1; status_dirty = 1; return GUI_ACT_NONE;
    case 8:  if (cursor > 0) { cursor--; input_delete(cursor); } return GUI_ACT_NONE;   /* Backspace */
    case 127: input_delete(cursor); return GUI_ACT_NONE;                           /* Del */
    case 1:  cursor = 0; input_dirty = 1; return GUI_ACT_NONE;                     /* Ctrl-A */
    case 5:  cursor = input_len; input_dirty = 1; return GUI_ACT_NONE;             /* Ctrl-E */
    case 11: input_len = cursor; input_dirty = 1; return GUI_ACT_NONE;             /* Ctrl-K: kill to end */
    default: break;
    }
    if (key >= 32 && key < 256 && !(key >= 0x80 && key < 0xA0)) {
        if (focus != 1) { focus = 1; status_dirty = 1; }
        input_insert((UBYTE)key);
    }
    return GUI_ACT_NONE;
}

int gui_action_chat(void) { return action_chat; }
int gui_take_outgoing(char *utf8, int cap)
{
    int n = gui_latin1_to_utf8(outgoing, outgoing_len, utf8, cap);
    outgoing_len = 0;
    return n;
}
int gui_input_length(void) { return input_len; }
int gui_focus(void) { return focus; }
int gui_help_visible(void) { return help_open; }

/* ---- init ------------------------------------------------------------------------------------------------------------ */
int gui_init(void *arena, ULONG size)
{
    UBYTE *planes[8]; UWORD bpr; int depth, i;
    UBYTE lo, hi; const UBYTE *cd; UWORD mod; const ULONG *cl;
    if (!arena || size < GUI_ARENA_MIN) return -1;
    nslots = (UWORD)((size / 4) / sizeof(struct gui_msg));
    slots = (struct gui_msg *)arena;
    tring = (UBYTE *)arena + (ULONG)nslots * sizeof(struct gui_msg);
    tcap = size - (ULONG)nslots * sizeof(struct gui_msg);
    mhead = mcount = 0; thead = ttail = 0; next_id = 1; dropped = 0;
    nchats = 0; cur_chat = -1; list_top = 0; conv_scroll = 0;
    focus = 0; help_open = 0; esc_armed = 0; insert_mode = 1;        /* the list first: Up/Down picks a chat, typing jumps to the input */
    input_len = cursor = input_win = 0; outgoing_len = 0;
    conv_id = 0; conv_len = 0; rows_drawn = 0; scroll_count = 0;
    conn_state = GUI_CONN_OFFLINE; conn_detail_len = 0; clk_hh = -1; today_day = 0;
    for (i = 0; i < CONV_ROWS; i++) rows_old[i].kind = 0xFF;
    for (i = 0; i < GUI_MAX_CHATS; i++) chats[i].used = 0;
    if (scr_font_glyphs(&lo, &hi, &cd, &mod, &cl)) font8_load(lo, hi, cd, mod, cl); else font8_load_symbols();
    depth = scr_planes(planes, 8, &bpr);
    if (depth > 0) ftext_init(planes, depth, bpr);
    text_mode = ftext_ready() ? GUI_TEXT_FAST : GUI_TEXT_OS;
    scroll_mode = GUI_SCROLL_BLIT;
    hdr_dirty = list_dirty_all = conv_dirty = input_dirty = status_dirty = 1;
    return 0;
}
