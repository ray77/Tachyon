#include "inflate.h"

#define MAXBITS   15
#define MAXLCODES 286
#define MAXDCODES 30
#define MAXCODES  (MAXLCODES + MAXDCODES)
#define FIXLCODES 288

typedef struct {
    const uint8_t *in; uint32_t in_len, in_pos;
    uint32_t bitbuf, bitcnt;
    uint8_t *out; uint32_t cap, len;
    int err;
} inf_state;

typedef struct { uint16_t count[MAXBITS + 1]; uint16_t symbol[FIXLCODES]; } huffman;

static huffman lencode, distcode;           /* dynamic-block tables (not re-entrant) */
static huffman fixlen, fixdist;             /* the fixed code, built on first use */
static uint16_t lengths[MAXCODES];

/* `need` (<= 13) bits, least significant first */
static uint32_t inf_bits(inf_state *s, uint32_t need)
{
    uint32_t val = s->bitbuf;
    while (s->bitcnt < need) {
        if (s->in_pos == s->in_len) { s->err = WA_INFLATE_ERR_TRUNCATED; return 0; }
        val |= (uint32_t)s->in[s->in_pos++] << s->bitcnt;
        s->bitcnt += 8;
    }
    s->bitbuf = val >> need;
    s->bitcnt -= need;
    return val & ((1u << need) - 1);
}

/* canonical decoding: walk the code lengths, counting how many codes are shorter (puff.c inf_decode()) */
static int32_t inf_decode(inf_state *s, const huffman *h)
{
    int32_t code = 0, first = 0, index = 0, count; uint32_t len;
    for (len = 1; len <= MAXBITS; len++) {
        code |= (int32_t)inf_bits(s, 1);
        if (s->err) return -1;
        count = h->count[len];
        if (code - count < first) return h->symbol[index + (code - first)];
        index += count; first += count; first <<= 1; code <<= 1;
    }
    return -1;                                  /* ran out of codes */
}

/* count[] and symbol[] from the code lengths; returns 0 for a complete code, > 0 for an incomplete one (bits left
 * over), < 0 when over-subscribed */
static int32_t inf_construct(huffman *h, const uint16_t *length, uint32_t n)
{
    uint16_t offs[MAXBITS + 1]; uint32_t symbol, len; int32_t left;
    for (len = 0; len <= MAXBITS; len++) h->count[len] = 0;
    for (symbol = 0; symbol < n; symbol++) h->count[length[symbol]]++;
    if (h->count[0] == n) return 0;             /* no codes at all: inf_decode() will fail on use */
    left = 1;
    for (len = 1; len <= MAXBITS; len++) { left <<= 1; left -= h->count[len]; if (left < 0) return left; }
    offs[1] = 0;
    for (len = 1; len < MAXBITS; len++) offs[len + 1] = (uint16_t)(offs[len] + h->count[len]);
    for (symbol = 0; symbol < n; symbol++) if (length[symbol]) h->symbol[offs[length[symbol]]++] = (uint16_t)symbol;
    return left;
}

static const uint16_t lbase[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
static const uint16_t lext[29]  = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
static const uint16_t dbase[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
static const uint16_t dext[30]  = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

/* literal/length and distance codes of one block until end-of-block */
static int inf_codes(inf_state *s, const huffman *lc, const huffman *dc)
{
    for (;;) {
        int32_t sym = inf_decode(s, lc);
        if (sym < 0) return s->err ? s->err : WA_INFLATE_ERR_DATA;
        if (sym < 256) {
            if (s->len == s->cap) return WA_INFLATE_ERR_OUTPUT;
            s->out[s->len++] = (uint8_t)sym;
        } else if (sym == 256) {
            return WA_INFLATE_OK;
        } else {
            uint32_t len, dist;
            sym -= 257;
            if (sym >= 29) return WA_INFLATE_ERR_DATA;
            len = lbase[sym] + inf_bits(s, lext[sym]);
            if (s->err) return s->err;
            sym = inf_decode(s, dc);
            if (sym < 0) return s->err ? s->err : WA_INFLATE_ERR_DATA;
            if (sym >= 30) return WA_INFLATE_ERR_DATA;
            dist = dbase[sym] + inf_bits(s, dext[sym]);
            if (s->err) return s->err;
            if (dist > s->len) return WA_INFLATE_ERR_DATA;              /* too far back */
            if (len > s->cap - s->len) return WA_INFLATE_ERR_OUTPUT;
            while (len--) { s->out[s->len] = s->out[s->len - dist]; s->len++; }
        }
    }
}

static int inf_stored(inf_state *s)
{
    uint32_t len, nlen;
    s->bitbuf = 0; s->bitcnt = 0;                                       /* to the byte boundary */
    if (s->in_len - s->in_pos < 4) return WA_INFLATE_ERR_TRUNCATED;
    len  = s->in[s->in_pos] | ((uint32_t)s->in[s->in_pos + 1] << 8);
    nlen = s->in[s->in_pos + 2] | ((uint32_t)s->in[s->in_pos + 3] << 8);
    s->in_pos += 4;
    if ((len ^ 0xffffu) != nlen) return WA_INFLATE_ERR_DATA;
    if (s->in_len - s->in_pos < len) return WA_INFLATE_ERR_TRUNCATED;
    if (len > s->cap - s->len) return WA_INFLATE_ERR_OUTPUT;
    while (len--) s->out[s->len++] = s->in[s->in_pos++];
    return WA_INFLATE_OK;
}

static int inf_fixed(inf_state *s)
{
    static int built;
    if (!built) {
        uint32_t symbol;
        for (symbol = 0; symbol < 144; symbol++) lengths[symbol] = 8;
        for (; symbol < 256; symbol++) lengths[symbol] = 9;
        for (; symbol < 280; symbol++) lengths[symbol] = 7;
        for (; symbol < FIXLCODES; symbol++) lengths[symbol] = 8;
        inf_construct(&fixlen, lengths, FIXLCODES);
        for (symbol = 0; symbol < MAXDCODES; symbol++) lengths[symbol] = 5;
        inf_construct(&fixdist, lengths, MAXDCODES);                        /* incomplete (30 of 32): fine, puff does the same */
        built = 1;
    }
    return inf_codes(s, &fixlen, &fixdist);
}

static int inf_dynamic(inf_state *s)
{
    static const uint16_t order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    uint32_t nlen, ndist, ncode, index; int32_t err;

    nlen  = inf_bits(s, 5) + 257;
    ndist = inf_bits(s, 5) + 1;
    ncode = inf_bits(s, 4) + 4;
    if (s->err) return s->err;
    if (nlen > MAXLCODES || ndist > MAXDCODES) return WA_INFLATE_ERR_DATA;

    for (index = 0; index < ncode; index++) { lengths[order[index]] = (uint16_t)inf_bits(s, 3); if (s->err) return s->err; }
    for (; index < 19; index++) lengths[order[index]] = 0;
    err = inf_construct(&lencode, lengths, 19);
    if (err != 0) return WA_INFLATE_ERR_DATA;                           /* the code length code must be complete */

    index = 0;
    while (index < nlen + ndist) {
        int32_t symbol = inf_decode(s, &lencode); uint32_t len = 0, rep;
        if (symbol < 0) return s->err ? s->err : WA_INFLATE_ERR_DATA;
        if (symbol < 16) { lengths[index++] = (uint16_t)symbol; continue; }
        if (symbol == 16) { if (index == 0) return WA_INFLATE_ERR_DATA; len = lengths[index - 1]; rep = 3 + inf_bits(s, 2); }
        else if (symbol == 17) rep = 3 + inf_bits(s, 3);
        else rep = 11 + inf_bits(s, 7);
        if (s->err) return s->err;
        if (index + rep > nlen + ndist) return WA_INFLATE_ERR_DATA;
        while (rep--) lengths[index++] = (uint16_t)len;
    }
    if (lengths[256] == 0) return WA_INFLATE_ERR_DATA;                  /* no end-of-block code */

    err = inf_construct(&lencode, lengths, nlen);
    if (err && (err < 0 || nlen != (uint32_t)lencode.count[0] + lencode.count[1])) return WA_INFLATE_ERR_DATA;
    err = inf_construct(&distcode, lengths + nlen, ndist);
    if (err && (err < 0 || ndist != (uint32_t)distcode.count[0] + distcode.count[1])) return WA_INFLATE_ERR_DATA;
    return inf_codes(s, &lencode, &distcode);
}

uint32_t wa_adler32(const uint8_t *p, uint32_t n)
{
    uint32_t a = 1, b = 0;
    while (n) {
        uint32_t k = n < 5552 ? n : 5552;                               /* NMAX: b stays below 2^32 */
        n -= k;
        while (k--) { a += *p++; b += a; }
        a %= 65521u; b %= 65521u;
    }
    return (b << 16) | a;
}

int wa_inflate(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t cap, uint32_t *out_len)
{
    inf_state s; uint32_t cmf, flg, last, type, adler; int err;
    *out_len = 0;
    if (in_len < 2 + 4) return WA_INFLATE_ERR_TRUNCATED;
    cmf = in[0]; flg = in[1];
    if ((cmf & 0x0f) != 8 || (cmf >> 4) > 7 || ((cmf << 8) | flg) % 31u != 0 || (flg & 0x20)) return WA_INFLATE_ERR_HEADER;
    s.in = in; s.in_len = in_len - 4; s.in_pos = 2;                     /* the last 4 bytes are the Adler-32 */
    s.bitbuf = 0; s.bitcnt = 0; s.out = out; s.cap = cap; s.len = 0; s.err = 0;
    do {
        last = inf_bits(&s, 1); type = inf_bits(&s, 2);
        if (s.err) return s.err;
        if (type == 0) err = inf_stored(&s);
        else if (type == 1) { err = inf_fixed(&s); }
        else if (type == 2) { err = inf_dynamic(&s); }
        else err = WA_INFLATE_ERR_DATA;
        if (err) { *out_len = s.len; return err; }
    } while (!last);
    *out_len = s.len;
    adler = ((uint32_t)in[in_len - 4] << 24) | ((uint32_t)in[in_len - 3] << 16) | ((uint32_t)in[in_len - 2] << 8) | in[in_len - 1];
    if (adler != wa_adler32(out, s.len)) return WA_INFLATE_ERR_CHECKSUM;
    return WA_INFLATE_OK;
}

const char *wa_inflate_errstr(int e)
{
    switch (e) {
    case WA_INFLATE_OK: return "ok";
    case WA_INFLATE_ERR_HEADER: return "not a zlib stream";
    case WA_INFLATE_ERR_DATA: return "invalid deflate data";
    case WA_INFLATE_ERR_TRUNCATED: return "truncated";
    case WA_INFLATE_ERR_OUTPUT: return "output buffer too small";
    case WA_INFLATE_ERR_CHECKSUM: return "Adler-32 mismatch";
    default: return "?";
    }
}
