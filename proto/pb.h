/*
 * Tachyon - minimal protobuf wire helpers (reader and writer), freestanding, 32-bit arithmetic only.
 *
 * Reader: pb_next() walks one message field by field (varint, length delimited, fixed32/64 skipped) with
 * every length checked against the end of the buffer; varints wider than 32 bits keep their low 32 bits
 * (the fields Tachyon reads - serials, key indices, lengths - all fit). Writer: pb_w_* append to a bounded
 * buffer and return 0 once anything did not fit (the flag is sticky: check once after the last write).
 * Nested messages are written bottom-up into their own buffer and embedded with pb_w_bytes.
 * static inline: included by the host tests, the probe core and the Amiga unity builds alike.
 */
#ifndef TACHYON_PB_H
#define TACHYON_PB_H

#include <stdint.h>

#define PB_VARINT 0
#define PB_FIXED64 1
#define PB_BYTES 2
#define PB_FIXED32 5

/* ---- reader ---------------------------------------------------------------------------------- */
static inline int pb_read_varint(const uint8_t **pp, const uint8_t *end, uint32_t *v)
{
    const uint8_t *p = *pp; uint32_t r = 0; int sh = 0;
    do { if (p >= end) return 0; if (sh < 32) r |= (uint32_t)(*p & 0x7f) << sh; sh += 7; if (sh > 70) return 0; } while (*p++ & 0x80);
    *pp = p; *v = r; return 1;
}

/* next field: *field, *wire; varint value in *val; length-delimited data in *data and *len. 0 at the end or on error. */
static inline int pb_next(const uint8_t **pp, const uint8_t *end, uint32_t *field, uint32_t *wire, uint32_t *val, const uint8_t **data, uint32_t *len)
{
    const uint8_t *p = *pp; uint32_t tag, v;
    if (p >= end) return 0;
    if (!pb_read_varint(&p, end, &tag)) return 0;
    *field = tag >> 3; *wire = tag & 7; *data = 0; *len = 0; *val = 0;
    if (*wire == PB_VARINT) { if (!pb_read_varint(&p, end, &v)) return 0; *val = v; }
    else if (*wire == PB_BYTES) { if (!pb_read_varint(&p, end, &v)) return 0; if (v > (uint32_t)(end - p)) return 0; *data = p; *len = v; p += v; }
    else if (*wire == PB_FIXED64) { if (end - p < 8) return 0; p += 8; }
    else if (*wire == PB_FIXED32) { if (end - p < 4) return 0; p += 4; }
    else return 0;
    *pp = p; return 1;
}

/* ---- writer ---------------------------------------------------------------------------------- */
typedef struct { uint8_t *p; uint32_t cap, len; int ok; } pb_writer;

static inline void pb_w_init(pb_writer *w, uint8_t *buf, uint32_t cap) { w->p = buf; w->cap = cap; w->len = 0; w->ok = 1; }
static inline void pb_w_byte(pb_writer *w, uint8_t b) { if (w->len < w->cap) w->p[w->len++] = b; else w->ok = 0; }
static inline void pb_w_raw(pb_writer *w, const uint8_t *d, uint32_t n) { uint32_t i; for (i = 0; i < n; i++) pb_w_byte(w, d[i]); }
static inline void pb_w_varint(pb_writer *w, uint32_t v) { while (v >= 0x80) { pb_w_byte(w, (uint8_t)(v | 0x80)); v >>= 7; } pb_w_byte(w, (uint8_t)v); }
/* 64-bit varint from two 32-bit halves (a JID user number is above 2^32) */
static inline void pb_w_varint64(pb_writer *w, uint32_t hi, uint32_t lo)
{
    while (hi || lo >= 0x80) {
        pb_w_byte(w, (uint8_t)(lo | 0x80));
        lo = (lo >> 7) | (hi << 25); hi >>= 7;
    }
    pb_w_byte(w, (uint8_t)lo);
}
static inline void pb_w_tag(pb_writer *w, uint32_t field, uint32_t wire) { pb_w_varint(w, (field << 3) | wire); }
static inline void pb_w_uint(pb_writer *w, uint32_t field, uint32_t v) { pb_w_tag(w, field, PB_VARINT); pb_w_varint(w, v); }
static inline void pb_w_bool(pb_writer *w, uint32_t field, int v) { pb_w_uint(w, field, v ? 1u : 0u); }
static inline void pb_w_bytes(pb_writer *w, uint32_t field, const uint8_t *d, uint32_t n) { pb_w_tag(w, field, PB_BYTES); pb_w_varint(w, n); pb_w_raw(w, d, n); }
static inline void pb_w_str(pb_writer *w, uint32_t field, const char *s) { uint32_t n = 0; while (s[n]) n++; pb_w_bytes(w, field, (const uint8_t *)s, n); }

#endif
