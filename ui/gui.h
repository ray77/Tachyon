/*
 * Tachyon - the client's chat interface (ui/gui.c): model (chats, message store in a fixed arena) and view on the
 * 640x256x16 screen of ui/screen.c. Self-contained: the network/Signal code feeds it with gui_add_message /
 * gui_set_status / gui_set_connection, calls gui_pump(scr_wait_key(0)) + gui_redraw_dirty() from its 1-second
 * heartbeat hook (no call blocks, none takes more than ~100 ms except gui_redraw_all) and sends what
 * gui_take_outgoing hands over when gui_pump returns GUI_ACT_SEND. Layout, keys and timings: docs/UI.md
 * "Client-Oberfläche". Freestanding C, no libc, 32-bit unsigned arithmetic only. Not reentrant (one GUI).
 */
#ifndef TACHYON_GUI_H
#define TACHYON_GUI_H

#include <exec/types.h>

#define GUI_MAX_CHATS   32
#define GUI_NAME_MAX    24          /* display name, Latin-1, without NUL */
#define GUI_JID_MAX     48          /* "<number>@s.whatsapp.net" or "<id>@g.us", with NUL */
#define GUI_TEXT_MAX    500         /* bytes of UTF-8 stored per message (longer texts are cut at a code point) */
#define GUI_INPUT_MAX   400         /* characters in the input line (Latin-1); UTF-8 outgoing up to twice that */
#define GUI_ARENA_MIN   8192        /* smallest arena gui_init accepts; the client uses 48 KiB */

/* message status (own messages; incoming messages carry GUI_ST_READ) */
#define GUI_ST_PENDING   0
#define GUI_ST_SENT      1
#define GUI_ST_DELIVERED 2
#define GUI_ST_READ      3
#define GUI_ST_FAILED    4

/* connection state for the header and the status line */
#define GUI_CONN_OFFLINE    0
#define GUI_CONN_CONNECTING 1
#define GUI_CONN_HANDSHAKE  2
#define GUI_CONN_ONLINE     3
#define GUI_CONN_ERROR      4

/* gui_pump results */
#define GUI_ACT_NONE   0
#define GUI_ACT_SEND   1            /* text composed for gui_action_chat(): fetch it with gui_take_outgoing */
#define GUI_ACT_QUIT   2            /* Amiga-Q or Esc twice */
#define GUI_ACT_SWITCH 3            /* the user selected another chat (gui_action_chat()) */

/* text/scroll paths (gui_set_text_mode / gui_set_scroll_mode), measured in the demo */
#define GUI_TEXT_FAST   1           /* own renderer into the planes (ui/ftext.c) */
#define GUI_TEXT_OS     0           /* graphics.library Text()/RectFill through ui/screen.c */
#define GUI_SCROLL_REDRAW 0         /* new message: repaint the conversation rows that changed */
#define GUI_SCROLL_BLIT   1         /* ScrollRaster the pane, paint only the new rows */
#define GUI_SCROLL_CPU    2         /* CPU copy of the planes (fast text mode only), paint the new rows */

struct gui_stats {
    UWORD chats;
    UWORD msgs;                     /* messages in the arena */
    UWORD slots;                    /* message descriptors the arena holds */
    ULONG text_used, text_cap;      /* text ring bytes */
    ULONG dropped;                  /* messages dropped because the arena was full */
    ULONG rows_drawn;               /* cell rows painted by gui_redraw_* so far */
    ULONG scrolls;                  /* conversation scrolls (blit or CPU) so far */
};

/* ---- model ---------------------------------------------------------------------------------------- */
int   gui_init(void *arena, ULONG size);                   /* after scr_open(); 0 ok, -1 arena too small */
int   gui_add_chat(const char *jid, const char *name);     /* name UTF-8 or Latin-1; returns the chat index, -1 if full */
int   gui_find_chat(const char *jid);                      /* index or -1 */
int   gui_set_chat_name(int chat, const char *name);
const char *gui_chat_jid(int chat);
int   gui_chat_count(void);
int   gui_current_chat(void);                              /* the chat shown in the conversation pane, -1 if none */
int   gui_select_chat(int chat);
/* text UTF-8 (len bytes, or -1 for NUL terminated); returns the message id (> 0) or 0 when nothing could be stored */
ULONG gui_add_message(int chat, int from_me, ULONG ts, const char *utf8, int len, int status);
int   gui_set_status(int chat, ULONG msg_id, int status);  /* 0 ok, -1 unknown id */
int   gui_chat_unread(int chat);
int   gui_chat_messages(int chat);
void  gui_set_connection(int state, const char *detail);  /* detail: short text for the status line (Latin-1/UTF-8) */
void  gui_set_clock(int hh, int mm);                       /* the clock in the status line */
void  gui_set_time(ULONG unix_now);                        /* clock and "today" (date separators) from a timestamp */
void  gui_set_tz(LONG seconds_east_of_utc);                /* for HH:MM of messages added afterwards; default 0 */
void  gui_stats(struct gui_stats *s);

/* ---- input ---------------------------------------------------------------------------------------- */
int   gui_pump(LONG key);                                   /* one scr_wait_key result (SCR_KEY_TIMEOUT is fine) */
int   gui_action_chat(void);                                /* chat of the last GUI_ACT_SEND / GUI_ACT_SWITCH */
int   gui_take_outgoing(char *utf8, int cap);               /* composed text as UTF-8, NUL terminated; length or 0 */
int   gui_input_length(void);                               /* characters in the input line */
int   gui_focus(void);                                      /* 0 chat list, 1 input line */
int   gui_help_visible(void);

/* ---- view ----------------------------------------------------------------------------------------- */
int   gui_redraw_dirty(void);                               /* paints what changed; returns the cell rows painted */
void  gui_redraw_all(void);                                 /* the initial paint (and after anything else drew) */
void  gui_set_text_mode(int mode);                          /* GUI_TEXT_FAST (default when the planes are known) / GUI_TEXT_OS */
int   gui_text_mode(void);
void  gui_set_scroll_mode(int mode);                        /* GUI_SCROLL_* (default GUI_SCROLL_BLIT) */
int   gui_last_scrolled(void);                              /* 1 when the last gui_redraw_dirty scrolled the pane */

/* ---- text helpers (also used by the test) ---------------------------------------------------------- */
int   gui_utf8_to_latin1(const UBYTE *s, int n, UBYTE *out, int cap);   /* returns the Latin-1 length */
int   gui_latin1_to_utf8(const UBYTE *s, int n, char *out, int cap);    /* returns the UTF-8 length (NUL appended) */

#endif
