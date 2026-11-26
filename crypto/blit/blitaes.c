#include "blitaes.h"

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

/* arena words are big-endian (Blitter view); written bytewise so the host model sees the same bits */
void ba_setup(const aes_key *k, uint8_t *arena)
{
    static const uint16_t mhi[4] = { 0xff00, 0xf0f0, 0xcccc, 0xaaaa };
    int rnd, b, r, c, i;
    for (rnd = 0; rnd <= k->rounds; rnd++)
        for (b = 0; b < 8; b++)
            for (r = 0; r < 4; r++)
                for (c = 0; c < 4; c++)
                    put16(arena + BA_KEYS + (rnd * 128 + (b * 4 + r) * 4 + c) * 2, (k->rk[16 * rnd + 4 * c + r] >> b) & 1 ? 0xffff : 0);
    for (i = 0; i < 128; i++) arena[BA_KEYPAT + i] = k->rk[i & 15];
    for (i = 0; i < 4; i++) for (c = 0; c < 512; c++) put16(arena + BA_MASKS + (i * 512 + c) * 2, mhi[i]);
}

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); }
static void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static uint16_t minterm(uint8_t lf, uint16_t a, uint16_t b, uint16_t c)
{
    uint16_t d = 0;
    int m;
    for (m = 0; m < 8; m++) {
        if (!(lf & (1 << m))) continue;
        d |= ((m & 4) ? a : (uint16_t)~a) & ((m & 2) ? b : (uint16_t)~b) & ((m & 1) ? c : (uint16_t)~c);
    }
    return d;
}

/* Blitter model: lines x words, per-channel modulo after each line, A barrel shifter with the
 * previous word carried across (cleared at blit start), descending mode processes from the
 * given (last) addresses downwards and shifts left. Byte-addressed, big-endian words. */
void ba_exec_soft(uint8_t *arena, const ba_blit *p, int n, int round)
{
    int i, line, x;
    for (i = 0; i < n; i++) {
        const ba_blit *e = &p[i];
        uint32_t h = (e->size >> 6) ? (e->size >> 6) : 1024, w = (e->size & 63) ? (e->size & 63) : 64;
        int32_t a = (int32_t)e->a, b = (int32_t)e->b, c = (int32_t)e->c + ((e->flags & 1) ? round * 256 : 0), d = (int32_t)e->d;
        int32_t amod = (int16_t)e->amod, bmod = (int16_t)e->bmod, cmod = (int16_t)e->cmod, dmod = (int16_t)e->dmod;
        int desc = (e->con1 & 2) != 0, step = desc ? -2 : 2, ash = (e->con0 >> 12) & 15;
        uint16_t prev = 0;
        if (desc) { amod = -amod; bmod = -bmod; cmod = -cmod; dmod = -dmod; }
        for (line = 0; line < (int)h; line++) {
            for (x = 0; x < (int)w; x++) {
                uint16_t av = 0, bv = 0, cv = 0, as;
                if (e->con0 & 0x800) { av = rd16(arena + a); a += step; }
                if (e->con0 & 0x400) { bv = rd16(arena + b); b += step; }
                if (e->con0 & 0x200) { cv = rd16(arena + c); c += step; }
                if (ash == 0) as = av;
                else if (!desc) as = (uint16_t)((av >> ash) | (prev << (16 - ash)));
                else as = (uint16_t)((av << ash) | (prev >> (16 - ash)));
                prev = av;
                wr16(arena + d, minterm((uint8_t)e->con0, as, bv, cv));
                d += step;
            }
            a += amod; b += bmod; c += cmod; d += dmod;
        }
    }
}

void ba_encrypt_soft(const aes_key *k, uint8_t *arena, const uint8_t *in, uint8_t *out)
{
    int rnd, i;
    ba_setup(k, arena);
    for (i = 0; i < BA_BLOCKS * 16; i++) arena[BA_STATE + i] = in[i];
    ba_exec_soft(arena, ba_prog + BA_SEC_WHITE, BA_NWHITE, 0);
    ba_exec_soft(arena, ba_prog + BA_SEC_TIN, BA_NTIN, 0);
    for (rnd = 1; rnd < k->rounds; rnd++) {
        ba_exec_soft(arena, ba_prog + BA_SEC_SBOX, BA_NSBOX, rnd);
        ba_exec_soft(arena, ba_prog + BA_SEC_MIX, BA_NMIX, rnd);
    }
    ba_exec_soft(arena, ba_prog + BA_SEC_SBOX, BA_NSBOX, rnd);
    ba_exec_soft(arena, ba_prog + BA_SEC_FINAL, BA_NFINAL, rnd);
    ba_exec_soft(arena, ba_prog + BA_SEC_TOUT, BA_NTOUT, 0);
    for (i = 0; i < BA_BLOCKS * 16; i++) out[i] = arena[BA_STATE + i];
}
