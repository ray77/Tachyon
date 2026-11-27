/*
 * Tachyon - WABinary, WhatsApp's binary node format (everything after the Noise handshake is spoken in it).
 * Reference: whatsmeow binary/ and Baileys src/WABinary/ (commits and token tables: docs/PROTOCOL.md section 10).
 *
 * Freestanding C (no libc), 32-bit only. No allocation: the decoder builds the tree in an arena the caller
 * supplies, bounds-checks every read, limits the nesting depth to WAB_MAX_DEPTH and returns an error code.
 * Strings are (pointer, length) slices WITHOUT a terminating NUL: they point into the token table, into the
 * input frame (raw strings and byte content, zero copy) or into the arena (unpacked nibble/hex strings).
 * The input buffer and the arena must therefore stay untouched as long as the tree is used.
 *
 * Every string, JID and list remembers the wire form it was decoded from, and the encoder reproduces it: an
 * accepted node encodes back to the same bytes (the server does not always pick the shortest form). Nodes
 * built by the caller leave the form fields 0 (WAB_F_AUTO, WAB_JID_AUTO, WAB_L_AUTO) and get the preferred
 * encoding: token, else nibble or hex packing, else raw bytes. A form that cannot express the value (after
 * the caller changed it) is ignored in the same way.
 */
#ifndef TACHYON_WABINARY_H
#define TACHYON_WABINARY_H

#include <stdint.h>

#ifndef WAB_MAX_DEPTH
#define WAB_MAX_DEPTH 16            /* nodes on the path from the root; real stanzas stay below 8 */
#endif

#define WAB_FLAG_COMPRESSED 2       /* first byte of a decrypted frame: the rest is zlib compressed */

enum {
    WAB_OK = 0,
    WAB_ERR_TRUNCATED,      /* a length or count reaches past the end of the input */
    WAB_ERR_FORMAT,         /* a byte that is not allowed at this position */
    WAB_ERR_PACKED,         /* invalid nibble/hex packed string */
    WAB_ERR_DEPTH,          /* nesting deeper than WAB_MAX_DEPTH */
    WAB_ERR_ARENA,          /* arena too small */
    WAB_ERR_TRAILING,       /* bytes left after the node */
    WAB_ERR_COMPRESSED,     /* compressed: unsupported */
    WAB_ERR_VALUE,          /* encoder: the node cannot be expressed in the format */
    WAB_ERR_BUFFER          /* encoder: output buffer too small */
};

/* wire form of a string (also of byte content) */
enum { WAB_F_AUTO = 0, WAB_F_TOKEN, WAB_F_RAW8, WAB_F_RAW20, WAB_F_RAW32, WAB_F_NIBBLE, WAB_F_HEX,
       WAB_F_EMPTY /* the single byte 0 (LIST_EMPTY): empty attribute value or JID user */ };
/* wire form of a JID */
enum { WAB_JID_AUTO = 0, WAB_JID_PAIR, WAB_JID_AD, WAB_JID_FB, WAB_JID_INTEROP };
/* wire form of a list header */
enum { WAB_L_AUTO = 0, WAB_L_EMPTY, WAB_L_8, WAB_L_16 };
/* kind of a value and of a node's content */
enum { WAB_NONE = 0, WAB_STR, WAB_JID, WAB_BYTES, WAB_LIST };
/* AD_JID domain byte ("agent" in whatsmeow) */
enum { WAB_DOMAIN_WHATSAPP = 0, WAB_DOMAIN_LID = 1, WAB_DOMAIN_HOSTED = 128, WAB_DOMAIN_HOSTED_LID = 129 };

typedef struct wab_str {
    const uint8_t *p;
    uint32_t len;
    uint8_t form;           /* WAB_F_* */
} wab_str;

typedef struct wab_jid {
    wab_str user, server;   /* AD JIDs carry no server on the wire: the decoder fills it in from the domain */
    uint16_t device;        /* AD (0..255), FB, interop */
    uint16_t integrator;    /* interop */
    uint8_t agent;          /* AD: domain byte as received */
    uint8_t type;           /* WAB_JID_* */
} wab_jid;

typedef struct wab_value {
    uint8_t kind;           /* WAB_STR, WAB_BYTES (content only) or WAB_JID */
    wab_str str;            /* WAB_STR and WAB_BYTES */
    wab_jid jid;            /* WAB_JID */
} wab_value;

typedef struct wab_attr {
    wab_str key;
    wab_value val;          /* WAB_STR or WAB_JID */
} wab_attr;

/* Content: val.kind is WAB_NONE (no content), WAB_STR, WAB_BYTES, WAB_JID or WAB_LIST (children). Raw
 * content on the wire decodes as WAB_BYTES (also when it holds text); tokens and packed strings as WAB_STR. */
typedef struct wab_node {
    wab_str tag;
    const wab_attr *attrs;
    uint32_t n_attrs;
    wab_value val;
    const struct wab_node *children;
    uint32_t n_children;
    uint8_t list_form;      /* WAB_L_* of the node's own list header */
    uint8_t children_form;  /* WAB_L_* of the child list header */
} wab_node;

typedef struct wab_arena {
    uint8_t *base;
    uint32_t size, used;
} wab_arena;

/* Use mem[0..size) as arena; a second call (or used = 0) releases everything decoded before. */
void wab_arena_init(wab_arena *a, void *mem, uint32_t size);

/* Decode a decrypted frame: flags byte followed by exactly one node. */
int wab_decode_frame(const uint8_t *frame, uint32_t len, wab_arena *a, const wab_node **out);
/* Decode exactly one node (no flags byte). */
int wab_decode_node(const uint8_t *data, uint32_t len, wab_arena *a, const wab_node **out);

/* Encode into out[0..cap); *len receives the encoded length - also with WAB_ERR_BUFFER, where it is the size
 * needed (out may be 0 if cap is 0). The frame variant writes the flags byte 0 (uncompressed) first. */
int wab_encode_frame(const wab_node *n, uint8_t *out, uint32_t cap, uint32_t *len);
int wab_encode_node(const wab_node *n, uint8_t *out, uint32_t cap, uint32_t *len);

const char *wab_errstr(int err);

/* ---- helpers for building and reading nodes ---------------------------------------------------- */
wab_str   wab_s(const char *s);                             /* slice of a C string, form AUTO */
int       wab_str_eq(const wab_str *s, const char *cs);
wab_value wab_text(const char *s);                          /* WAB_STR value */
wab_value wab_bytes(const uint8_t *p, uint32_t len);        /* WAB_BYTES content */
wab_value wab_jid_value(const char *user, const char *server, uint32_t device);   /* user may be "" */
void      wab_node_init(wab_node *n, const char *tag);      /* no attributes, no content */
const wab_value *wab_get_attr(const wab_node *n, const char *key);                 /* 0 = not present */
const wab_node  *wab_get_child(const wab_node *n, const char *tag);                /* first match or 0 */

#endif
