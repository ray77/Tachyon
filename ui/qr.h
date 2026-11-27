/* QR code encoder (ISO/IEC 18004, model 2): byte mode, ECC level L or M, versions 1..15.
 * Freestanding, no allocation, no libc, no variable multiply or divide. See docs/UI.md. */
#ifndef WHATSA500_QR_H
#define WHATSA500_QR_H
#include <stdint.h>

#define QR_ECC_L          0u
#define QR_ECC_M          1u
#define QR_MASK_AUTO      8u
#define QR_MAX_INPUT      300u
#define QR_MAX_VERSION    15u
#define QR_MAX_SIZE       77u   /* modules per side: 17 + 4 * version */
#define QR_STRIDE         10u   /* bytes per bitmap row, even so rows stay word aligned */
#define QR_BITMAP_BYTES   (QR_MAX_SIZE * QR_STRIDE)
#define QR_MAX_CODEWORDS  655u
#define QR_MAX_ECC        30u
#define QR_QUIET          4u    /* quiet zone in modules; not part of the bitmap */

/* The result. Row y starts at modules[y * QR_STRIDE]; bit 7 of the first byte is x = 0
 * (bitplane order); 1 = dark. Bits right of the last module are 0. */
typedef struct {
    uint8_t size;      /* modules per side, 21..77 */
    uint8_t version;   /* 1..15 */
    uint8_t ecc;       /* QR_ECC_L or QR_ECC_M */
    uint8_t mask;      /* 0..7 */
    uint8_t modules[QR_BITMAP_BYTES];
} qr;

/* Scratch memory for one encode call (about 1.5 KiB); contents are meaningless afterwards. */
typedef struct {
    uint8_t func[QR_BITMAP_BYTES];     /* 1 = function pattern or reserved, not data */
    uint8_t cw[QR_MAX_CODEWORDS];      /* interleaved data and ECC codewords */
    uint8_t gen[QR_MAX_ECC];           /* generator polynomial, coefficients as logarithms */
    uint8_t rem[QR_MAX_ECC];           /* Reed-Solomon remainder of one block */
} qr_work;

static inline uint32_t qr_module(const qr *q, uint32_t x, uint32_t y)
{
    return (q->modules[(y << 3) + (y << 1) + (x >> 3)] >> (7u - (x & 7u))) & 1u;
}

/* Smallest version that fits, best mask. Returns 0, or -1 if len > QR_MAX_INPUT or ecc is unknown. */
int qr_encode(qr *q, qr_work *w, const uint8_t *data, uint32_t len, uint32_t ecc);

/* Same, with a lower bound for the version (1..15) and optionally a fixed mask (0..7, or QR_MASK_AUTO). */
int qr_encode_ex(qr *q, qr_work *w, const uint8_t *data, uint32_t len, uint32_t ecc,
                 uint32_t min_version, uint32_t mask);

/* Binary PBM (P4) with the 4-module quiet zone, scale pixels per module (1..64).
 * Returns the number of bytes written, or 0 if cap is too small or scale is out of range. */
uint32_t qr_render_pbm(const qr *q, char *out, uint32_t cap, uint32_t scale);

#endif
