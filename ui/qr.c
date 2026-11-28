/* QR code encoder, see qr.h. Written for the 68000: all quantities that would need a multiply or a
 * divide are tabled or counted, the only 32-bit operations are add, subtract, shift and logic. */
#include "qr.h"

/* per version 1..15: total codewords, ECC codewords per block (L, M), number of blocks (L, M) */
static const uint16_t total_cw[15] = { 26, 44, 70, 100, 134, 172, 196, 242, 292, 346, 404, 466, 532, 581, 655 };
static const uint8_t ecc_len[2][15] = {
    {  7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22 },
    { 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24 },
};
static const uint8_t num_blocks[2][15] = {
    { 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4,  6 },
    { 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10 },
};
/* alignment pattern centres, 0 terminated */
static const uint8_t align_pos[15][5] = {
    { 0 },                { 6, 18, 0 },         { 6, 22, 0 },         { 6, 26, 0 },         { 6, 30, 0 },
    { 6, 34, 0 },         { 6, 22, 38, 0 },     { 6, 24, 42, 0 },     { 6, 26, 46, 0 },     { 6, 28, 50, 0 },
    { 6, 30, 54, 0 },     { 6, 32, 58, 0 },     { 6, 34, 62, 0 },     { 6, 26, 46, 66, 0 }, { 6, 26, 48, 70, 0 },
};
/* 7x7 finder plus one separator column, 5x5 alignment pattern; MSB = leftmost module */
static const uint8_t finder_rows[7] = { 0xfe, 0x82, 0xba, 0xba, 0xba, 0x82, 0xfe };
static const uint8_t align_rows[5] = { 0x1f, 0x11, 0x15, 0x11, 0x1f };
/* the eight masks repeat every 6 modules in x and every 12 in y; bit 5 = x 0 */
static const uint8_t mask_pat[8][12] = {
    { 0x2a, 0x15, 0x2a, 0x15, 0x2a, 0x15, 0x2a, 0x15, 0x2a, 0x15, 0x2a, 0x15 },
    { 0x3f, 0x00, 0x3f, 0x00, 0x3f, 0x00, 0x3f, 0x00, 0x3f, 0x00, 0x3f, 0x00 },
    { 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24, 0x24 },
    { 0x24, 0x09, 0x12, 0x24, 0x09, 0x12, 0x24, 0x09, 0x12, 0x24, 0x09, 0x12 },
    { 0x38, 0x38, 0x07, 0x07, 0x38, 0x38, 0x07, 0x07, 0x38, 0x38, 0x07, 0x07 },
    { 0x3f, 0x20, 0x24, 0x2a, 0x24, 0x20, 0x3f, 0x20, 0x24, 0x2a, 0x24, 0x20 },
    { 0x3f, 0x38, 0x36, 0x2a, 0x2d, 0x23, 0x3f, 0x38, 0x36, 0x2a, 0x2d, 0x23 },
    { 0x2a, 0x07, 0x23, 0x15, 0x38, 0x1c, 0x2a, 0x07, 0x23, 0x15, 0x38, 0x1c },
};
/* GF(256) with the primitive polynomial 0x11d; gf_exp is doubled so log sums need no modulo */
static const uint8_t gf_exp[510] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26,
    0x4c, 0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9, 0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0,
    0x9d, 0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35, 0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23,
    0x46, 0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0, 0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1,
    0x5f, 0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc, 0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0,
    0xfd, 0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f, 0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2,
    0xd9, 0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce,
    0x81, 0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93, 0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc,
    0x85, 0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9, 0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54,
    0xa8, 0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa, 0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73,
    0xe6, 0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e, 0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff,
    0xe3, 0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4, 0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41,
    0x82, 0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e, 0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6,
    0x51, 0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef, 0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09,
    0x12, 0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5, 0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16,
    0x2c, 0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83, 0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e, 0x01,
    0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1d, 0x3a, 0x74, 0xe8, 0xcd, 0x87, 0x13, 0x26, 0x4c,
    0x98, 0x2d, 0x5a, 0xb4, 0x75, 0xea, 0xc9, 0x8f, 0x03, 0x06, 0x0c, 0x18, 0x30, 0x60, 0xc0, 0x9d,
    0x27, 0x4e, 0x9c, 0x25, 0x4a, 0x94, 0x35, 0x6a, 0xd4, 0xb5, 0x77, 0xee, 0xc1, 0x9f, 0x23, 0x46,
    0x8c, 0x05, 0x0a, 0x14, 0x28, 0x50, 0xa0, 0x5d, 0xba, 0x69, 0xd2, 0xb9, 0x6f, 0xde, 0xa1, 0x5f,
    0xbe, 0x61, 0xc2, 0x99, 0x2f, 0x5e, 0xbc, 0x65, 0xca, 0x89, 0x0f, 0x1e, 0x3c, 0x78, 0xf0, 0xfd,
    0xe7, 0xd3, 0xbb, 0x6b, 0xd6, 0xb1, 0x7f, 0xfe, 0xe1, 0xdf, 0xa3, 0x5b, 0xb6, 0x71, 0xe2, 0xd9,
    0xaf, 0x43, 0x86, 0x11, 0x22, 0x44, 0x88, 0x0d, 0x1a, 0x34, 0x68, 0xd0, 0xbd, 0x67, 0xce, 0x81,
    0x1f, 0x3e, 0x7c, 0xf8, 0xed, 0xc7, 0x93, 0x3b, 0x76, 0xec, 0xc5, 0x97, 0x33, 0x66, 0xcc, 0x85,
    0x17, 0x2e, 0x5c, 0xb8, 0x6d, 0xda, 0xa9, 0x4f, 0x9e, 0x21, 0x42, 0x84, 0x15, 0x2a, 0x54, 0xa8,
    0x4d, 0x9a, 0x29, 0x52, 0xa4, 0x55, 0xaa, 0x49, 0x92, 0x39, 0x72, 0xe4, 0xd5, 0xb7, 0x73, 0xe6,
    0xd1, 0xbf, 0x63, 0xc6, 0x91, 0x3f, 0x7e, 0xfc, 0xe5, 0xd7, 0xb3, 0x7b, 0xf6, 0xf1, 0xff, 0xe3,
    0xdb, 0xab, 0x4b, 0x96, 0x31, 0x62, 0xc4, 0x95, 0x37, 0x6e, 0xdc, 0xa5, 0x57, 0xae, 0x41, 0x82,
    0x19, 0x32, 0x64, 0xc8, 0x8d, 0x07, 0x0e, 0x1c, 0x38, 0x70, 0xe0, 0xdd, 0xa7, 0x53, 0xa6, 0x51,
    0xa2, 0x59, 0xb2, 0x79, 0xf2, 0xf9, 0xef, 0xc3, 0x9b, 0x2b, 0x56, 0xac, 0x45, 0x8a, 0x09, 0x12,
    0x24, 0x48, 0x90, 0x3d, 0x7a, 0xf4, 0xf5, 0xf7, 0xf3, 0xfb, 0xeb, 0xcb, 0x8b, 0x0b, 0x16, 0x2c,
    0x58, 0xb0, 0x7d, 0xfa, 0xe9, 0xcf, 0x83, 0x1b, 0x36, 0x6c, 0xd8, 0xad, 0x47, 0x8e,
};
static const uint8_t gf_log[256] = {
    0x00, 0x00, 0x01, 0x19, 0x02, 0x32, 0x1a, 0xc6, 0x03, 0xdf, 0x33, 0xee, 0x1b, 0x68, 0xc7, 0x4b,
    0x04, 0x64, 0xe0, 0x0e, 0x34, 0x8d, 0xef, 0x81, 0x1c, 0xc1, 0x69, 0xf8, 0xc8, 0x08, 0x4c, 0x71,
    0x05, 0x8a, 0x65, 0x2f, 0xe1, 0x24, 0x0f, 0x21, 0x35, 0x93, 0x8e, 0xda, 0xf0, 0x12, 0x82, 0x45,
    0x1d, 0xb5, 0xc2, 0x7d, 0x6a, 0x27, 0xf9, 0xb9, 0xc9, 0x9a, 0x09, 0x78, 0x4d, 0xe4, 0x72, 0xa6,
    0x06, 0xbf, 0x8b, 0x62, 0x66, 0xdd, 0x30, 0xfd, 0xe2, 0x98, 0x25, 0xb3, 0x10, 0x91, 0x22, 0x88,
    0x36, 0xd0, 0x94, 0xce, 0x8f, 0x96, 0xdb, 0xbd, 0xf1, 0xd2, 0x13, 0x5c, 0x83, 0x38, 0x46, 0x40,
    0x1e, 0x42, 0xb6, 0xa3, 0xc3, 0x48, 0x7e, 0x6e, 0x6b, 0x3a, 0x28, 0x54, 0xfa, 0x85, 0xba, 0x3d,
    0xca, 0x5e, 0x9b, 0x9f, 0x0a, 0x15, 0x79, 0x2b, 0x4e, 0xd4, 0xe5, 0xac, 0x73, 0xf3, 0xa7, 0x57,
    0x07, 0x70, 0xc0, 0xf7, 0x8c, 0x80, 0x63, 0x0d, 0x67, 0x4a, 0xde, 0xed, 0x31, 0xc5, 0xfe, 0x18,
    0xe3, 0xa5, 0x99, 0x77, 0x26, 0xb8, 0xb4, 0x7c, 0x11, 0x44, 0x92, 0xd9, 0x23, 0x20, 0x89, 0x2e,
    0x37, 0x3f, 0xd1, 0x5b, 0x95, 0xbc, 0xcf, 0xcd, 0x90, 0x87, 0x97, 0xb2, 0xdc, 0xfc, 0xbe, 0x61,
    0xf2, 0x56, 0xd3, 0xab, 0x14, 0x2a, 0x5d, 0x9e, 0x84, 0x3c, 0x39, 0x53, 0x47, 0x6d, 0x41, 0xa2,
    0x1f, 0x2d, 0x43, 0xd8, 0xb7, 0x7b, 0xa4, 0x76, 0xc4, 0x17, 0x49, 0xec, 0x7f, 0x0c, 0x6f, 0xf6,
    0x6c, 0xa1, 0x3b, 0x52, 0x29, 0x9d, 0x55, 0xaa, 0xfb, 0x60, 0x86, 0xb1, 0xbb, 0xcc, 0x3e, 0x5a,
    0xcb, 0x59, 0x5f, 0xb0, 0x9c, 0xa9, 0xa0, 0x51, 0x0b, 0xf5, 0x16, 0xeb, 0x7a, 0x75, 0x2c, 0xd7,
    0x4f, 0xae, 0xd5, 0xe9, 0xe6, 0xe7, 0xad, 0xe8, 0x74, 0xd6, 0xf4, 0xea, 0xa8, 0x50, 0x58, 0xaf,
};

static uint32_t row_off(uint32_t y) { return (y << 3) + (y << 1); }

static void put(uint8_t *bm, uint32_t x, uint32_t y, uint32_t v)
{
    uint8_t *p = bm + row_off(y) + (x >> 3);
    uint8_t b = (uint8_t)(0x80u >> (x & 7u));
    if (v) *p |= b; else *p &= (uint8_t)~b;
}

static uint32_t get(const uint8_t *bm, uint32_t x, uint32_t y)
{
    return bm[row_off(y) + (x >> 3)] & (0x80u >> (x & 7u));
}

static void set_func(qr *q, qr_work *w, uint32_t x, uint32_t y, uint32_t dark)
{
    put(q->modules, x, y, dark);
    put(w->func, x, y, 1u);
}

/* ---- Reed-Solomon ------------------------------------------------------- */
/* generator polynomial (x - a^0)...(x - a^(e-1)) without the leading 1, highest power first, as logs;
 * all its coefficients are non-zero for the degrees QR uses */
static void rs_generator(uint8_t *g, uint32_t e)
{
    uint32_t i, k;
    for (k = 0; k < e; k++) g[k] = 0;
    g[e - 1] = 1;
    for (i = 0; i < e; i++) {                 /* multiply by (x + a^i) */
        for (k = 0; k < e; k++) {
            uint32_t v = g[k] ? gf_exp[(uint32_t)gf_log[g[k]] + i] : 0u;
            if (k + 1 < e) v ^= g[k + 1];
            g[k] = (uint8_t)v;
        }
    }
    for (k = 0; k < e; k++) g[k] = gf_log[g[k]];
}

/* ---- codewords ---------------------------------------------------------- */
/* the byte stream before the 4-bit shift: mode nibble, character count, data, zeros */
static uint32_t pre_byte(const uint8_t *data, uint32_t len, uint32_t cnt, uint32_t i)
{
    if (i == 0) return 0x04u;
    if (i <= cnt) return (cnt == 2u && i == 1u) ? (len >> 8) : (len & 0xffu);
    i -= cnt + 1u;
    return i < len ? data[i] : 0u;
}

/* data codewords, split into blocks, ECC appended, both written in interleaved order */
static void make_codewords(qr_work *w, const uint8_t *data, uint32_t len, uint32_t ver, uint32_t ecc)
{
    uint32_t e = ecc_len[ecc][ver - 1], blocks = num_blocks[ecc][ver - 1];
    uint32_t total = total_cw[ver - 1], ndata = total, cnt = ver >= 10u ? 2u : 1u;
    uint32_t short_len = 0, longs, shorts, used = len + cnt + 1u;
    uint32_t i, j, k, di = 0, pad = 0xecu;

    for (j = 0; j < blocks; j++) ndata -= e;
    for (longs = ndata; longs >= blocks; longs -= blocks) short_len++;
    shorts = blocks - longs;
    rs_generator(w->gen, e);

    for (j = 0; j < blocks; j++) {
        uint32_t n = short_len + (j >= shorts ? 1u : 0u), pos = j;
        for (k = 0; k < e; k++) w->rem[k] = 0;
        for (i = 0; i < n; i++, di++) {
            uint32_t d, f;
            if (di < used) {
                d = ((pre_byte(data, len, cnt, di) << 4) | (pre_byte(data, len, cnt, di + 1u) >> 4)) & 0xffu;
            } else {
                d = pad;
                pad ^= 0xecu ^ 0x11u;
            }
            if (i == short_len) pos -= shorts;       /* the extra byte of the long blocks follows without gaps */
            w->cw[pos] = (uint8_t)d;
            pos += blocks;
            f = d ^ w->rem[0];
            for (k = 0; k + 1u < e; k++) w->rem[k] = w->rem[k + 1u];
            w->rem[e - 1u] = 0;
            if (f) {
                const uint8_t *x = gf_exp + gf_log[f];
                for (k = 0; k < e; k++) w->rem[k] ^= x[w->gen[k]];
            }
        }
        for (k = 0, pos = ndata + j; k < e; k++, pos += blocks) w->cw[pos] = w->rem[k];
    }
}

/* ---- function patterns -------------------------------------------------- */
/* 15 format bits: ECC level and mask, BCH(15,5), fixed XOR pattern; written twice */
static void draw_format(qr *q, qr_work *w, uint32_t mask)
{
    uint32_t n = q->size, i;
    uint32_t d = ((q->ecc == QR_ECC_L ? 1u : 0u) << 3) | mask, r = d;
    for (i = 0; i < 10; i++) r = (r << 1) ^ ((r & 0x200u) ? 0x537u : 0u);
    r = ((d << 10) | (r & 0x3ffu)) ^ 0x5412u;
    for (i = 0; i < 15; i++, r >>= 1) {
        uint32_t b = r & 1u;
        if (i < 6)       set_func(q, w, 8, i, b);
        else if (i < 8)  set_func(q, w, 8, i + 1u, b);
        else if (i == 8) set_func(q, w, 7, 8, b);
        else             set_func(q, w, 14u - i, 8, b);
        if (i < 8)       set_func(q, w, n - 1u - i, 8, b);
        else             set_func(q, w, 8, n - 15u + i, b);
    }
    set_func(q, w, 8, n - 8u, 1);             /* the dark module */
}

/* 18 version bits, BCH(18,6), versions 7 and up */
static void draw_version(qr *q, qr_work *w)
{
    uint32_t n = q->size, v = q->version, r = v, bits, i, a, b;
    if (v < 7u) return;
    for (i = 0; i < 12; i++) r = (r << 1) ^ ((r & 0x800u) ? 0x1f25u : 0u);
    bits = (v << 12) | (r & 0xfffu);
    for (b = 0, a = n - 11u, i = 0; i < 18; i++, bits >>= 1) {
        set_func(q, w, a, b, bits & 1u);
        set_func(q, w, b, a, bits & 1u);
        if (++a == n - 8u) { a = n - 11u; b++; }
    }
}

static void draw_function_patterns(qr *q, qr_work *w)
{
    uint32_t n = q->size, i, x, y, ax, ay;
    const uint8_t *pos = align_pos[q->version - 1u];

    for (i = 0; i < n; i++) {                 /* timing patterns */
        set_func(q, w, i, 6, !(i & 1u));
        set_func(q, w, 6, i, !(i & 1u));
    }
    for (y = 0; y < 8; y++) {                 /* three finders with their separators */
        uint32_t row = y < 7u ? finder_rows[y] : 0u;
        uint32_t yb = n - 1u - y;             /* the pattern is symmetric: mirrored rows are fine */
        for (x = 0; x < 8; x++) {
            uint32_t v = row & (0x80u >> x);
            set_func(q, w, x, y, v);
            set_func(q, w, n - 1u - x, y, v);
            set_func(q, w, x, yb, v);
        }
    }
    for (ay = 0; pos[ay]; ay++) {
        for (ax = 0; pos[ax]; ax++) {
            uint32_t cx = pos[ax], cy = pos[ay];
            if ((cx == 6u && cy == 6u) || (cx == 6u && cy == n - 7u) || (cx == n - 7u && cy == 6u)) continue;
            for (y = 0; y < 5; y++)
                for (x = 0; x < 5; x++)
                    set_func(q, w, cx - 2u + x, cy - 2u + y, align_rows[y] & (0x10u >> x));
        }
    }
    draw_format(q, w, 0);                     /* reserves the area; rewritten per mask */
    draw_version(q, w);
}

/* two-module columns from the right, alternately upwards and downwards, skipping the timing column;
 * the function map decides which modules take data, the remainder bits stay 0 */
static void draw_codewords(qr *q, qr_work *w)
{
    uint32_t n = q->size, bit = 0, nbits = (uint32_t)total_cw[q->version - 1u] << 3;
    uint32_t right, vert, j, up = 1;

    for (right = n - 1u; ; right -= 2u, up ^= 1u) {
        if (right == 6u) right = 5u;
        for (vert = 0; vert < n; vert++) {
            uint32_t y = up ? n - 1u - vert : vert;
            for (j = 0; j < 2; j++) {
                uint32_t x = right - j;
                if (get(w->func, x, y) || bit >= nbits) continue;
                if (w->cw[bit >> 3] & (0x80u >> (bit & 7u))) put(q->modules, x, y, 1);
                bit++;
            }
        }
        if (right < 3u) break;
    }
}

/* XOR the mask over all data modules; a second call removes it again */
static void apply_mask(qr *q, const qr_work *w, uint32_t mask)
{
    uint32_t n = q->size, nb = (n + 7u) >> 3, y, ym = 0, i, k;
    uint8_t last = (uint8_t)(0xff00u >> (((n - 1u) & 7u) + 1u));   /* valid bits of the last byte */
    uint8_t *m = q->modules;
    const uint8_t *f = w->func;

    for (y = 0; y < n; y++, m += QR_STRIDE, f += QR_STRIDE) {
        uint32_t p = mask_pat[mask][ym];
        uint8_t pat[3];
        p |= p << 6; p |= p << 12;            /* 24 mask bits: 4 periods in 3 bytes */
        pat[0] = (uint8_t)(p >> 16); pat[1] = (uint8_t)(p >> 8); pat[2] = (uint8_t)p;
        for (i = 0, k = 0; i < nb; i++) {
            uint8_t v = (uint8_t)(pat[k] & ~f[i]);
            if (i == nb - 1u) v &= last;
            m[i] ^= v;
            if (++k == 3u) k = 0;
        }
        if (++ym == 12u) ym = 0;
    }
}

/* ---- mask evaluation ---------------------------------------------------- */
/* one row or column: rule 1 (runs of 5 or more) and rule 3 (1:1:3:1:1 with 4 light modules on a side).
 * p points at the first byte, bm selects the first module's bit; step is used for columns only. */
static uint32_t line_penalty(const uint8_t *p, uint32_t n, uint32_t step, uint32_t bm, uint32_t horiz)
{
    uint32_t score = 0, run = 0, prev = 2, win = 0, i;
    for (i = 0; i < n; i++) {
        uint32_t c = (*p & bm) ? 1u : 0u;
        if (c == prev) {
            run++;
            if (run == 5u) score += 3u;
            else if (run > 5u) score++;
        } else {
            prev = c;
            run = 1;
        }
        win = ((win << 1) | c) & 0x7ffu;
        if (i >= 10u && (win == 0x5d0u || win == 0x05du)) score += 40u;
        if (horiz) {
            bm >>= 1;
            if (!bm) { bm = 0x80u; p++; }
        } else {
            p += step;
        }
    }
    return score;
}

/* total penalty of the current matrix; gives up early once it reaches limit */
static uint32_t penalty(const qr *q, uint32_t limit)
{
    uint32_t n = q->size, score = 0, dark = 0, total = 0, x, y, k, bm;
    const uint8_t *row = q->modules;

    for (y = 0; y < n; y++, row += QR_STRIDE) {
        const uint8_t *p = row;
        uint32_t left = 0, upleft = 0;
        score += line_penalty(row, n, 0, 0x80u, 1);
        total += n;
        for (x = 0, bm = 0x80u; x < n; x++) {  /* dark count and rule 2 (2x2 blocks) */
            uint32_t c = (*p & bm) ? 1u : 0u;
            dark += c;
            if (y) {
                uint32_t up = (*(p - QR_STRIDE) & bm) ? 1u : 0u;
                if (x && c == left && c == up && c == upleft) score += 3u;
                upleft = up;
            }
            left = c;
            bm >>= 1;
            if (!bm) { bm = 0x80u; p++; }
        }
        if (score >= limit) return score;
    }
    for (x = 0, bm = 0x80u, row = q->modules; x < n; x++) {
        score += line_penalty(row, n, QR_STRIDE, bm, 0);
        bm >>= 1;
        if (!bm) { bm = 0x80u; row++; }
        if (score >= limit) return score;
    }
    /* rule 4: 10 points per full 5 % the dark share is away from 50 %: |20 dark - 10 total| / total */
    {
        uint32_t d20 = (dark << 4) + (dark << 2), t10 = (total << 3) + (total << 1);
        uint32_t dev = d20 > t10 ? d20 - t10 : t10 - d20;
        for (k = total; k <= dev; k += total) score += 10u;
    }
    return score;
}

/* ---- API ---------------------------------------------------------------- */
int qr_encode_ex(qr *q, qr_work *w, const uint8_t *data, uint32_t len, uint32_t ecc,
                 uint32_t min_version, uint32_t mask)
{
    uint32_t ver, i;

    if (len > QR_MAX_INPUT || ecc > QR_ECC_M || mask > QR_MASK_AUTO) return -1;
    if (min_version < 1u || min_version > QR_MAX_VERSION) return -1;
    for (ver = min_version; ver <= QR_MAX_VERSION; ver++) {
        uint32_t cap = total_cw[ver - 1u], j;
        for (j = 0; j < num_blocks[ecc][ver - 1u]; j++) cap -= ecc_len[ecc][ver - 1u];
        if (len + (ver >= 10u ? 3u : 2u) <= cap) break;
    }
    if (ver > QR_MAX_VERSION) return -1;

    q->version = (uint8_t)ver;
    q->size = (uint8_t)(17u + (ver << 2));
    q->ecc = (uint8_t)ecc;
    for (i = 0; i < QR_BITMAP_BYTES; i++) q->modules[i] = w->func[i] = 0;

    make_codewords(w, data, len, ver, ecc);
    draw_function_patterns(q, w);
    draw_codewords(q, w);

    if (mask == QR_MASK_AUTO) {
        uint32_t best = 0xffffffffu, m;
        for (m = 0; m < 8; m++) {
            uint32_t s;
            apply_mask(q, w, m);
            draw_format(q, w, m);
            s = penalty(q, best);
            if (s < best) { best = s; mask = m; }
            apply_mask(q, w, m);
        }
    }
    apply_mask(q, w, mask);
    draw_format(q, w, mask);
    q->mask = (uint8_t)mask;
    return 0;
}

int qr_encode(qr *q, qr_work *w, const uint8_t *data, uint32_t len, uint32_t ecc)
{
    return qr_encode_ex(q, w, data, len, ecc, 1, QR_MASK_AUTO);
}

/* ---- PBM ---------------------------------------------------------------- */
static uint32_t pbm_put_dec(char *out, uint32_t v)     /* v < 10000 */
{
    static const uint16_t pow10[4] = { 1000, 100, 10, 1 };
    uint32_t i, len = 0;
    for (i = 0; i < 4; i++) {
        uint32_t digit = 0;
        while (v >= pow10[i]) { v -= pow10[i]; digit++; }
        if (digit || len || i == 3u) out[len++] = (char)('0' + digit);
    }
    return len;
}

uint32_t qr_render_pbm(const qr *q, char *out, uint32_t cap, uint32_t scale)
{
    uint32_t units = (uint32_t)q->size + 2u * QR_QUIET, width = 0, rowbytes, need, pos = 0;
    uint32_t i, mx, my, sx, sy;
    char head[16];
    uint32_t hlen = 0;

    if (scale < 1u || scale > 64u) return 0;
    for (i = 0; i < scale; i++) width += units;
    rowbytes = (width + 7u) >> 3;

    head[hlen++] = 'P'; head[hlen++] = '4'; head[hlen++] = '\n';
    hlen += pbm_put_dec(head + hlen, width); head[hlen++] = ' ';
    hlen += pbm_put_dec(head + hlen, width); head[hlen++] = '\n';
    for (need = hlen, i = 0; i < width; i++) need += rowbytes;
    if (need > cap) return 0;
    for (i = 0; i < hlen; i++) out[pos++] = head[i];

    for (my = 0; my < units; my++) {
        for (sy = 0; sy < scale; sy++) {
            uint32_t acc = 0, nbits = 0;
            for (mx = 0; mx < units; mx++) {
                uint32_t qx = mx - QR_QUIET, qy = my - QR_QUIET;     /* wraps in the quiet zone */
                uint32_t dark = (qx < q->size && qy < q->size) ? qr_module(q, qx, qy) : 0u;
                for (sx = 0; sx < scale; sx++) {
                    acc = (acc << 1) | dark;
                    if (++nbits == 8u) { out[pos++] = (char)acc; acc = 0; nbits = 0; }
                }
            }
            if (nbits) out[pos++] = (char)(acc << (8u - nbits));
        }
    }
    return pos;
}
