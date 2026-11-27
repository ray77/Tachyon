/*
 * Tachyon - WABinary codec, see wabinary.h.
 *
 * A node is a list of 1 + 2 * attributes (+ 1 with content) elements: tag, key/value pairs, content.
 * Strings are one of: a single-byte token, a dictionary byte (236..239) + index, a packed nibble or hex
 * string, raw bytes with an 8/20/32-bit length, or 0 (empty); values and content may also be JIDs, content
 * may be a list of nodes.
 */
#include "wabinary.h"
#include "wabinary_tokens.h"

enum {
    T_LIST_EMPTY = 0,
    T_DICT_0 = 236, T_DICT_3 = 239,
    T_INTEROP_JID = 245, T_FB_JID = 246, T_AD_JID = 247,
    T_LIST_8 = 248, T_LIST_16 = 249,
    T_JID_PAIR = 250,
    T_HEX_8 = 251,
    T_BINARY_8 = 252, T_BINARY_20 = 253, T_BINARY_32 = 254,
    T_NIBBLE_8 = 255
};

#define PACKED_AUTO_MAX 127         /* upstream packs strings up to this length ... */
#define PACKED_WIRE_MAX 254         /* ... the 7-bit byte count could express this much */

static const uint8_t wab_empty[1] = { 0 };

/* ---- helpers ----------------------------------------------------------------------------------- */
static uint32_t wab_strlen(const char *s) { uint32_t n = 0; while (s[n]) n++; return n; }

static int wab_equal(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    while (n--) if (*a++ != *b++) return 0;
    return 1;
}

static void wab_set_token(wab_str *s, uint32_t token)
{
    s->p = wab_tok_data + wab_tok_off[token];
    s->len = (uint32_t)(wab_tok_off[token + 1] - wab_tok_off[token]);
    s->form = WAB_F_TOKEN;
}

/* token number of s, or 0 */
static uint32_t wab_find_token(const uint8_t *p, uint32_t len)
{
    uint32_t lo = 0, hi = WAB_N_TOKENS - 1;
    if (!len || len > WAB_MAX_TOKEN_LEN) return 0;
    while (lo < hi) {
        uint32_t mid = (lo + hi) >> 1, tok = wab_tok_sorted[mid], i;
        const uint8_t *t = wab_tok_data + wab_tok_off[tok];
        uint32_t tl = (uint32_t)(wab_tok_off[tok + 1] - wab_tok_off[tok]);
        uint32_t m = tl < len ? tl : len;
        for (i = 0; i < m && t[i] == p[i]; i++) ;
        if (i == m && tl == len) return tok;
        if (i == m ? tl < len : t[i] < p[i]) lo = mid + 1; else hi = mid;
    }
    return 0;
}

/* server of an AD JID domain; every unknown domain means s.whatsapp.net (both upstreams) */
static const char *wab_domain_server(uint32_t agent)
{
    if (agent == WAB_DOMAIN_LID) return "lid";
    if (agent == WAB_DOMAIN_HOSTED) return "hosted";
    if (agent == WAB_DOMAIN_HOSTED_LID) return "hosted.lid";
    return "s.whatsapp.net";
}

wab_str wab_s(const char *s)
{
    wab_str r;
    r.p = (const uint8_t *)s; r.len = wab_strlen(s); r.form = WAB_F_AUTO;
    return r;
}

int wab_str_eq(const wab_str *s, const char *cs)
{
    uint32_t n = wab_strlen(cs);
    return s->len == n && wab_equal(s->p, (const uint8_t *)cs, n);
}

static void wab_clear_value(wab_value *v)
{
    v->kind = WAB_NONE;
    v->str.p = wab_empty; v->str.len = 0; v->str.form = WAB_F_AUTO;
    v->jid.user = v->str; v->jid.server = v->str;
    v->jid.device = 0; v->jid.integrator = 0; v->jid.agent = 0; v->jid.type = WAB_JID_AUTO;
}

wab_value wab_text(const char *s)
{
    wab_value v;
    wab_clear_value(&v);
    v.kind = WAB_STR; v.str = wab_s(s);
    return v;
}

wab_value wab_bytes(const uint8_t *p, uint32_t len)
{
    wab_value v;
    wab_clear_value(&v);
    v.kind = WAB_BYTES; v.str.p = p; v.str.len = len;
    return v;
}

wab_value wab_jid_value(const char *user, const char *server, uint32_t device)
{
    wab_value v;
    wab_clear_value(&v);
    v.kind = WAB_JID;
    v.jid.user = wab_s(user); v.jid.server = wab_s(server); v.jid.device = (uint16_t)device;
    return v;
}

void wab_node_init(wab_node *n, const char *tag)
{
    n->tag = wab_s(tag);
    n->attrs = 0; n->n_attrs = 0;
    wab_clear_value(&n->val);
    n->children = 0; n->n_children = 0;
    n->list_form = WAB_L_AUTO; n->children_form = WAB_L_AUTO;
}

const wab_value *wab_get_attr(const wab_node *n, const char *key)
{
    uint32_t i;
    for (i = 0; i < n->n_attrs; i++) if (wab_str_eq(&n->attrs[i].key, key)) return &n->attrs[i].val;
    return 0;
}

const wab_node *wab_get_child(const wab_node *n, const char *tag)
{
    uint32_t i;
    if (n->val.kind != WAB_LIST) return 0;
    for (i = 0; i < n->n_children; i++) if (wab_str_eq(&n->children[i].tag, tag)) return &n->children[i];
    return 0;
}

const char *wab_errstr(int err)
{
    switch (err) {
    case WAB_OK:             return "ok";
    case WAB_ERR_TRUNCATED:  return "truncated";
    case WAB_ERR_FORMAT:     return "invalid format";
    case WAB_ERR_PACKED:     return "invalid packed string";
    case WAB_ERR_DEPTH:      return "nesting too deep";
    case WAB_ERR_ARENA:      return "arena too small";
    case WAB_ERR_TRAILING:   return "trailing bytes";
    case WAB_ERR_COMPRESSED: return "compressed: unsupported";
    case WAB_ERR_VALUE:      return "node cannot be encoded";
    case WAB_ERR_BUFFER:     return "output buffer too small";
    default:                 return "unknown error";
    }
}

/* ---- arena ------------------------------------------------------------------------------------- */
#define WAB_ALIGN ((uint32_t)sizeof(void *))

void wab_arena_init(wab_arena *a, void *mem, uint32_t size)
{
    uint32_t skip = (WAB_ALIGN - ((uint32_t)(uintptr_t)mem & (WAB_ALIGN - 1))) & (WAB_ALIGN - 1);
    if (skip > size) skip = size;
    a->base = (uint8_t *)mem + skip;
    a->size = size - skip;
    a->used = 0;
}

/* n bytes, pointer aligned; 0 = full. Allocations are rounded up, so used stays aligned. */
static void *wab_alloc(wab_arena *a, uint32_t n)
{
    void *r;
    uint32_t room = a->size - a->used;
    if (n > room) return 0;
    r = a->base + a->used;
    n = (n + WAB_ALIGN - 1) & ~(WAB_ALIGN - 1);
    a->used += n > room ? room : n;
    return r;
}

/* ---- decoder ----------------------------------------------------------------------------------- */
typedef struct {
    const uint8_t *p;
    uint32_t len, pos;
    wab_arena *a;
} wab_dec;

static int rd_byte(wab_dec *d, uint32_t *v)
{
    if (d->pos >= d->len) return WAB_ERR_TRUNCATED;
    *v = d->p[d->pos++];
    return WAB_OK;
}

/* big endian, 1..4 bytes */
static int rd_int(wab_dec *d, uint32_t n, uint32_t *v)
{
    uint32_t r = 0;
    if (n > d->len - d->pos) return WAB_ERR_TRUNCATED;
    while (n--) r = (r << 8) | d->p[d->pos++];
    *v = r;
    return WAB_OK;
}

static int rd_packed(wab_dec *d, int hex, wab_str *s)
{
    uint32_t head, count, odd, chars, i;
    uint8_t *out;
    int e = rd_byte(d, &head);
    if (e) return e;
    count = head & 127; odd = head >> 7;
    if (odd && !count) return WAB_ERR_PACKED;
    if (count > d->len - d->pos) return WAB_ERR_TRUNCATED;
    chars = count + count - odd;
    s->p = wab_empty; s->len = chars; s->form = (uint8_t)(hex ? WAB_F_HEX : WAB_F_NIBBLE);
    if (!chars) return WAB_OK;
    out = (uint8_t *)wab_alloc(d->a, chars);
    if (!out) return WAB_ERR_ARENA;
    s->p = out;
    for (i = 0; i < chars; i++) {
        uint32_t b = d->p[d->pos + (i >> 1)], v = (i & 1) ? b & 15 : b >> 4;
        if (v < 10) out[i] = (uint8_t)('0' + v);
        else if (hex) out[i] = (uint8_t)('A' + v - 10);
        else if (v == 10) out[i] = '-';
        else if (v == 11) out[i] = '.';
        else return WAB_ERR_PACKED;
    }
    /* the unused half of the last byte is 15 in both encoders */
    if (odd && (d->p[d->pos + count - 1] & 15) != 15) return WAB_ERR_PACKED;
    d->pos += count;
    return WAB_OK;
}

static int rd_raw(wab_dec *d, uint32_t tag, wab_str *s)
{
    uint32_t n;
    int e = rd_int(d, tag == T_BINARY_8 ? 1u : tag == T_BINARY_20 ? 3u : 4u, &n);
    if (e) return e;
    if (tag == T_BINARY_20 && n >= (1UL << 20)) return WAB_ERR_FORMAT;
    if (n > d->len - d->pos) return WAB_ERR_TRUNCATED;
    s->p = d->p + d->pos; s->len = n;
    s->form = (uint8_t)(tag == T_BINARY_8 ? WAB_F_RAW8 : tag == T_BINARY_20 ? WAB_F_RAW20 : WAB_F_RAW32);
    d->pos += n;
    return WAB_OK;
}

/* a plain string whose first byte is tag (no JID, no list) */
static int rd_string(wab_dec *d, uint32_t tag, wab_str *s)
{
    if (tag == T_LIST_EMPTY) { s->p = wab_empty; s->len = 0; s->form = WAB_F_EMPTY; return WAB_OK; }
    if (tag < WAB_N_SINGLE) { wab_set_token(s, tag); return WAB_OK; }
    if (tag >= T_DICT_0 && tag <= T_DICT_3) {
        uint32_t i;
        int e = rd_byte(d, &i);
        if (e) return e;
        wab_set_token(s, WAB_N_SINGLE + ((tag - T_DICT_0) << 8) + i);
        return WAB_OK;
    }
    if (tag == T_NIBBLE_8 || tag == T_HEX_8) return rd_packed(d, tag == T_HEX_8, s);
    if (tag >= T_BINARY_8 && tag <= T_BINARY_32) return rd_raw(d, tag, s);
    return WAB_ERR_FORMAT;
}

static int rd_next_string(wab_dec *d, wab_str *s)
{
    uint32_t tag;
    int e = rd_byte(d, &tag);
    return e ? e : rd_string(d, tag, s);
}

static int rd_jid(wab_dec *d, uint32_t tag, wab_jid *j)
{
    uint32_t v;
    int e;
    if (tag == T_JID_PAIR) {
        j->type = WAB_JID_PAIR;
        if ((e = rd_next_string(d, &j->user)) != 0) return e;
        if ((e = rd_next_string(d, &j->server)) != 0) return e;
    } else if (tag == T_AD_JID) {
        j->type = WAB_JID_AD;
        if ((e = rd_byte(d, &v)) != 0) return e;
        j->agent = (uint8_t)v;
        if ((e = rd_byte(d, &v)) != 0) return e;
        j->device = (uint16_t)v;
        if ((e = rd_next_string(d, &j->user)) != 0) return e;
        j->server = wab_s(wab_domain_server(j->agent));
    } else {                                                    /* FB_JID, INTEROP_JID */
        j->type = (uint8_t)(tag == T_FB_JID ? WAB_JID_FB : WAB_JID_INTEROP);
        if ((e = rd_next_string(d, &j->user)) != 0) return e;
        if ((e = rd_int(d, 2, &v)) != 0) return e;
        j->device = (uint16_t)v;
        if (tag == T_INTEROP_JID) {
            if ((e = rd_int(d, 2, &v)) != 0) return e;
            j->integrator = (uint16_t)v;
        }
        if ((e = rd_next_string(d, &j->server)) != 0) return e;
    }
    return j->server.len ? WAB_OK : WAB_ERR_FORMAT;
}

static int is_jid_tag(uint32_t tag) { return (tag >= T_INTEROP_JID && tag <= T_AD_JID) || tag == T_JID_PAIR; }

/* string or JID */
static int rd_value(wab_dec *d, uint32_t tag, wab_value *v)
{
    if (is_jid_tag(tag)) { v->kind = WAB_JID; return rd_jid(d, tag, &v->jid); }
    v->kind = WAB_STR;
    return rd_string(d, tag, &v->str);
}

static int rd_list_size(wab_dec *d, uint32_t tag, uint32_t *size, uint8_t *form)
{
    if (tag == T_LIST_EMPTY) { *size = 0; *form = WAB_L_EMPTY; return WAB_OK; }
    if (tag == T_LIST_8) { *form = WAB_L_8; return rd_int(d, 1, size); }
    if (tag == T_LIST_16) { *form = WAB_L_16; return rd_int(d, 2, size); }
    return WAB_ERR_FORMAT;
}

static int rd_node(wab_dec *d, wab_node *n, uint32_t depth)
{
    uint32_t tag, size, na, i;
    wab_attr *attrs;
    wab_node *kids;
    int e;
    if (depth >= WAB_MAX_DEPTH) return WAB_ERR_DEPTH;
    wab_node_init(n, "");
    if ((e = rd_byte(d, &tag)) != 0) return e;
    if ((e = rd_list_size(d, tag, &size, &n->list_form)) != 0) return e;
    if (!size) return WAB_ERR_FORMAT;
    if ((e = rd_next_string(d, &n->tag)) != 0) return e;
    if (!n->tag.len) return WAB_ERR_FORMAT;
    na = (size - 1) >> 1;
    if (na) {
        /* every attribute takes at least 2 bytes: reject absurd counts before reserving memory */
        if (na > (d->len - d->pos) >> 1) return WAB_ERR_TRUNCATED;
        attrs = (wab_attr *)wab_alloc(d->a, na * (uint32_t)sizeof *attrs);
        if (!attrs) return WAB_ERR_ARENA;
        for (i = 0; i < na; i++) {
            wab_attr *at = &attrs[i];
            wab_clear_value(&at->val);
            if ((e = rd_next_string(d, &at->key)) != 0) return e;
            if (!at->key.len) return WAB_ERR_FORMAT;
            if ((e = rd_byte(d, &tag)) != 0) return e;
            if ((e = rd_value(d, tag, &at->val)) != 0) return e;
        }
        n->attrs = attrs;
        n->n_attrs = na;
    }
    if (size & 1) return WAB_OK;                                /* odd size: no content */
    if ((e = rd_byte(d, &tag)) != 0) return e;
    if (tag == T_LIST_EMPTY || tag == T_LIST_8 || tag == T_LIST_16) {
        n->val.kind = WAB_LIST;
        if ((e = rd_list_size(d, tag, &size, &n->children_form)) != 0) return e;
        if (!size) return WAB_OK;
        /* a node takes at least 3 bytes (list header, tag); size <= 65535, so no overflow (and no division,
         * which would pull in a library routine on the 68000) */
        if (size * 3u > d->len - d->pos) return WAB_ERR_TRUNCATED;
        kids = (wab_node *)wab_alloc(d->a, size * (uint32_t)sizeof *kids);
        if (!kids) return WAB_ERR_ARENA;
        for (i = 0; i < size; i++) if ((e = rd_node(d, &kids[i], depth + 1)) != 0) return e;
        n->children = kids;
        n->n_children = size;
        return WAB_OK;
    }
    if (tag >= T_BINARY_8 && tag <= T_BINARY_32) { n->val.kind = WAB_BYTES; return rd_raw(d, tag, &n->val.str); }
    return rd_value(d, tag, &n->val);
}

int wab_decode_node(const uint8_t *data, uint32_t len, wab_arena *a, const wab_node **out)
{
    wab_dec d;
    wab_node *n;
    int e;
    *out = 0;
    d.p = data; d.len = len; d.pos = 0; d.a = a;
    n = (wab_node *)wab_alloc(a, (uint32_t)sizeof *n);
    if (!n) return WAB_ERR_ARENA;
    e = rd_node(&d, n, 0);
    if (e) return e;
    if (d.pos != d.len) return WAB_ERR_TRAILING;
    *out = n;
    return WAB_OK;
}

int wab_decode_frame(const uint8_t *frame, uint32_t len, wab_arena *a, const wab_node **out)
{
    *out = 0;
    if (!len) return WAB_ERR_TRUNCATED;
    if (frame[0] & WAB_FLAG_COMPRESSED) return WAB_ERR_COMPRESSED;
    return wab_decode_node(frame + 1, len - 1, a, out);
}

/* ---- encoder ----------------------------------------------------------------------------------- */
typedef struct {
    uint8_t *p;
    uint32_t cap, len;              /* len keeps counting past cap: it is the size needed */
} wab_enc;

#define WAB_OUT_MAX 0x7fffffffUL

static void wr_byte(wab_enc *w, uint32_t b)
{
    if (w->len < w->cap) w->p[w->len] = (uint8_t)b;
    w->len++;
}

static void wr_int(wab_enc *w, uint32_t v, uint32_t n)
{
    while (n--) wr_byte(w, v >> (n << 3));
}

static int wr_data(wab_enc *w, const uint8_t *p, uint32_t n)
{
    if (w->len > WAB_OUT_MAX || n > WAB_OUT_MAX - w->len) return WAB_ERR_VALUE;
    if (w->len <= w->cap && n <= w->cap - w->len) {
        uint8_t *o = w->p + w->len;
        uint32_t i;
        for (i = 0; i < n; i++) o[i] = p[i];
    }
    w->len += n;
    return WAB_OK;
}

static int nibble_value(uint32_t c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c == '-') return 10;
    if (c == '.') return 11;
    return -1;
}

static int hex_value(uint32_t c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
    return -1;
}

static int packable(const wab_str *s, int hex, uint32_t max)
{
    uint32_t i;
    if (s->len > max) return 0;
    for (i = 0; i < s->len; i++) if ((hex ? hex_value(s->p[i]) : nibble_value(s->p[i])) < 0) return 0;
    return 1;
}

static void wr_packed(wab_enc *w, const wab_str *s, int hex)
{
    uint32_t i;
    wr_byte(w, hex ? T_HEX_8 : T_NIBBLE_8);
    wr_byte(w, ((s->len + 1) >> 1) | ((s->len & 1) << 7));
    for (i = 0; i < s->len; i += 2) {
        uint32_t hi = (uint32_t)(hex ? hex_value(s->p[i]) : nibble_value(s->p[i])), lo = 15;
        if (i + 1 < s->len) lo = (uint32_t)(hex ? hex_value(s->p[i + 1]) : nibble_value(s->p[i + 1]));
        wr_byte(w, (hi << 4) | lo);
    }
}

/* raw bytes in the requested width, or the shortest one if form is not a raw form that fits */
static int wr_raw(wab_enc *w, const wab_str *s, uint32_t form)
{
    if (!((form == WAB_F_RAW8 && s->len < 256) || (form == WAB_F_RAW20 && s->len < (1UL << 20)) || form == WAB_F_RAW32))
        form = s->len < 256 ? WAB_F_RAW8 : s->len < (1UL << 20) ? WAB_F_RAW20 : WAB_F_RAW32;
    if (form == WAB_F_RAW8) { wr_byte(w, T_BINARY_8); wr_byte(w, s->len); }
    else if (form == WAB_F_RAW20) { wr_byte(w, T_BINARY_20); wr_int(w, s->len, 3); }
    else { wr_byte(w, T_BINARY_32); wr_int(w, s->len, 4); }
    return wr_data(w, s->p, s->len);
}

static void wr_token(wab_enc *w, uint32_t tok)
{
    if (tok < WAB_N_SINGLE) wr_byte(w, tok);
    else {
        tok -= WAB_N_SINGLE;
        wr_byte(w, T_DICT_0 + (tok >> 8));
        wr_byte(w, tok & 255);
    }
}

static int wr_string(wab_enc *w, const wab_str *s)
{
    uint32_t tok;
    switch (s->form) {                                          /* reproduce the recorded form if it fits */
    case WAB_F_RAW8: case WAB_F_RAW20: case WAB_F_RAW32: return wr_raw(w, s, s->form);
    case WAB_F_NIBBLE: if (packable(s, 0, PACKED_WIRE_MAX)) { wr_packed(w, s, 0); return WAB_OK; } break;
    case WAB_F_HEX:    if (packable(s, 1, PACKED_WIRE_MAX)) { wr_packed(w, s, 1); return WAB_OK; } break;
    case WAB_F_EMPTY:  if (!s->len) { wr_byte(w, T_LIST_EMPTY); return WAB_OK; } break;
    default: break;
    }
    if (!s->len) return wr_raw(w, s, WAB_F_RAW8);
    tok = wab_find_token(s->p, s->len);
    if (tok) { wr_token(w, tok); return WAB_OK; }
    if (packable(s, 0, PACKED_AUTO_MAX)) { wr_packed(w, s, 0); return WAB_OK; }
    if (packable(s, 1, PACKED_AUTO_MAX)) { wr_packed(w, s, 1); return WAB_OK; }
    return wr_raw(w, s, WAB_F_AUTO);
}

static uint32_t domain_of_server(const wab_str *server, int *ok)
{
    *ok = 1;
    if (wab_str_eq(server, "s.whatsapp.net")) return WAB_DOMAIN_WHATSAPP;
    if (wab_str_eq(server, "lid")) return WAB_DOMAIN_LID;
    if (wab_str_eq(server, "hosted")) return WAB_DOMAIN_HOSTED;
    if (wab_str_eq(server, "hosted.lid")) return WAB_DOMAIN_HOSTED_LID;
    *ok = 0;
    return 0;
}

/* a JID part: like any string, but an empty one defaults to the single byte 0 (both upstreams) */
static int wr_jid_user(wab_enc *w, const wab_str *s)
{
    if (!s->len && s->form == WAB_F_AUTO) { wr_byte(w, T_LIST_EMPTY); return WAB_OK; }
    return wr_string(w, s);
}

static int wr_jid(wab_enc *w, const wab_jid *j)
{
    uint32_t type = j->type, domain, agent;
    int known, e;
    domain = domain_of_server(&j->server, &known);
    agent = domain;
    /* AD: keep a received domain byte as long as it still matches the server */
    if (type == WAB_JID_AD && wab_str_eq(&j->server, wab_domain_server(j->agent))) { agent = j->agent; known = 1; }
    /* a recorded type that would lose information is ignored */
    if ((type == WAB_JID_AD && (!known || j->device > 255)) || (type == WAB_JID_PAIR && (j->device || j->integrator)) ||
        type > WAB_JID_INTEROP)
        type = WAB_JID_AUTO;
    if (type == WAB_JID_AUTO) {                                 /* whatsmeow encoder.go writeJID */
        if (known && (j->device || domain >= WAB_DOMAIN_HOSTED)) type = WAB_JID_AD;
        else if (wab_str_eq(&j->server, "msgr")) type = WAB_JID_FB;
        else if (wab_str_eq(&j->server, "interop")) type = WAB_JID_INTEROP;
        else if (j->device || j->integrator) return WAB_ERR_VALUE;
        else type = WAB_JID_PAIR;
        agent = domain;
    }
    if (!j->server.len) return WAB_ERR_VALUE;
    if (type == WAB_JID_AD) {
        if (j->device > 255) return WAB_ERR_VALUE;
        wr_byte(w, T_AD_JID); wr_byte(w, agent); wr_byte(w, j->device);
        return wr_string(w, &j->user);
    }
    if (type == WAB_JID_PAIR) {
        wr_byte(w, T_JID_PAIR);
        if ((e = wr_jid_user(w, &j->user)) != 0) return e;
        return wr_string(w, &j->server);
    }
    wr_byte(w, type == WAB_JID_FB ? T_FB_JID : T_INTEROP_JID);
    if ((e = wr_string(w, &j->user)) != 0) return e;
    wr_int(w, j->device, 2);
    if (type == WAB_JID_INTEROP) wr_int(w, j->integrator, 2);
    return wr_string(w, &j->server);
}

static void wr_list_start(wab_enc *w, uint32_t size, uint32_t form)
{
    if (form == WAB_L_EMPTY && !size) wr_byte(w, T_LIST_EMPTY);
    else if (form == WAB_L_8 && size < 256) { wr_byte(w, T_LIST_8); wr_byte(w, size); }
    else if (form == WAB_L_16) { wr_byte(w, T_LIST_16); wr_int(w, size, 2); }
    else if (!size) wr_byte(w, T_LIST_EMPTY);
    else if (size < 256) { wr_byte(w, T_LIST_8); wr_byte(w, size); }
    else { wr_byte(w, T_LIST_16); wr_int(w, size, 2); }
}

static int wr_node(wab_enc *w, const wab_node *n, uint32_t depth)
{
    uint32_t i, kind = n->val.kind;
    int e;
    if (depth >= WAB_MAX_DEPTH) return WAB_ERR_DEPTH;
    if (!n->tag.len || n->n_attrs > 32767 || kind > WAB_LIST) return WAB_ERR_VALUE;
    i = 1 + n->n_attrs + n->n_attrs + (kind != WAB_NONE);
    if (i > 65535) return WAB_ERR_VALUE;
    wr_list_start(w, i, n->list_form);
    if ((e = wr_string(w, &n->tag)) != 0) return e;
    for (i = 0; i < n->n_attrs; i++) {
        const wab_attr *at = &n->attrs[i];
        if (!at->key.len) return WAB_ERR_VALUE;
        if ((e = wr_string(w, &at->key)) != 0) return e;
        if (at->val.kind == WAB_STR) e = wr_string(w, &at->val.str);
        else if (at->val.kind == WAB_JID) e = wr_jid(w, &at->val.jid);
        else e = WAB_ERR_VALUE;
        if (e) return e;
    }
    switch (kind) {
    case WAB_STR:   return wr_string(w, &n->val.str);           /* an empty one is written as raw: see wr_string */
    case WAB_BYTES: return wr_raw(w, &n->val.str, n->val.str.form);
    case WAB_JID:   return wr_jid(w, &n->val.jid);
    case WAB_LIST:
        if (n->n_children > 65535) return WAB_ERR_VALUE;
        wr_list_start(w, n->n_children, n->children_form);
        for (i = 0; i < n->n_children; i++) if ((e = wr_node(w, &n->children[i], depth + 1)) != 0) return e;
        return WAB_OK;
    default:        return WAB_OK;
    }
}

static int wab_encode(const wab_node *n, uint8_t *out, uint32_t cap, uint32_t *len, int frame)
{
    wab_enc w;
    int e;
    w.p = out; w.cap = cap; w.len = 0;
    if (frame) wr_byte(&w, 0);
    e = wr_node(&w, n, 0);
    *len = w.len;
    if (e) return e;
    return w.len > cap ? WAB_ERR_BUFFER : WAB_OK;
}

int wab_encode_frame(const wab_node *n, uint8_t *out, uint32_t cap, uint32_t *len) { return wab_encode(n, out, cap, len, 1); }
int wab_encode_node(const wab_node *n, uint8_t *out, uint32_t cap, uint32_t *len) { return wab_encode(n, out, cap, len, 0); }
