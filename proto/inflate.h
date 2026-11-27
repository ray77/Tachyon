/*
 * Tachyon - zlib inflate (RFC 1950 wrapper, RFC 1951 deflate) for WhatsApp's compressed frames: a decrypted frame
 * whose flags byte has bit 1 set (WAB_FLAG_COMPRESSED) carries a zlib stream instead of the bare binary node
 * (whatsmeow message.go: zlib.NewReader). Freestanding, 32-bit arithmetic only, no tables beyond the fixed deflate
 * ones, canonical Huffman decoding bit by bit (Mark Adler's puff.c algorithm): small, correct, and fast enough for the
 * few-KiB stanzas the server sends. Stored, fixed and dynamic blocks; the Adler-32 trailer is checked. Not re-entrant
 * (static work tables).
 */
#ifndef TACHYON_INFLATE_H
#define TACHYON_INFLATE_H
#include <stdint.h>

enum {
    WA_INFLATE_OK = 0,
    WA_INFLATE_ERR_HEADER,      /* not a zlib stream (method, window, FCHECK, preset dictionary) */
    WA_INFLATE_ERR_DATA,        /* invalid deflate data (bad block type, code, distance ...) */
    WA_INFLATE_ERR_TRUNCATED,   /* the input ends inside the stream */
    WA_INFLATE_ERR_OUTPUT,      /* the output does not fit into cap bytes */
    WA_INFLATE_ERR_CHECKSUM     /* Adler-32 mismatch */
};

/* in[0..in_len) is a complete zlib stream; the decompressed bytes go to out[0..cap), *out_len receives their count.
 * Returns WA_INFLATE_OK or an error above (then *out_len is what was produced so far). */
int wa_inflate(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t cap, uint32_t *out_len);
const char *wa_inflate_errstr(int e);

/* Adler-32 of p[0..n) (RFC 1950), also used by tests and the stored-block writer in the simulator. */
uint32_t wa_adler32(const uint8_t *p, uint32_t n);

#endif
