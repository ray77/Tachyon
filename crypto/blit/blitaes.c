#include "blitaes.h"

void ba_keys(const aes_key *k, uint16_t *keys)
{
    int rnd, b, r, c;
    for (rnd = 0; rnd <= k->rounds; rnd++)
        for (b = 0; b < 8; b++)
            for (r = 0; r < 4; r++)
                for (c = 0; c < 4; c++)
                    keys[rnd * 128 + (b * 4 + r) * 4 + c] = (k->rk[16 * rnd + 4 * c + r] >> b) & 1 ? 0xffff : 0;
}

/* lane (b,r,c), word w, bit j (MSB first) <-> block 16w + j, byte 4c + r, bit b */
void ba_pack(const aes_key *k, const uint8_t *in, uint16_t *state)
{
    int b, r, c, w, j;
    for (b = 0; b < 8; b++)
        for (r = 0; r < 4; r++)
            for (c = 0; c < 4; c++) {
                uint16_t *lane = state + ((b * 4 + r) * 4 + c) * BA_L;
                uint8_t kb = k->rk[4 * c + r];
                for (w = 0; w < BA_L; w++) {
                    uint16_t v = 0;
                    for (j = 0; j < 16; j++) v = (uint16_t)((v << 1) | (((in[(16 * w + j) * 16 + 4 * c + r] ^ kb) >> b) & 1));
                    lane[w] = v;
                }
            }
}

void ba_unpack(const uint16_t *state, uint8_t *out)
{
    int b, r, c, w, j;
    for (w = 0; w < BA_L; w++) for (j = 0; j < 16; j++) for (c = 0; c < 16; c++) out[(16 * w + j) * 16 + c] = 0;
    for (b = 0; b < 8; b++)
        for (r = 0; r < 4; r++)
            for (c = 0; c < 4; c++) {
                const uint16_t *lane = state + ((b * 4 + r) * 4 + c) * BA_L;
                for (w = 0; w < BA_L; w++)
                    for (j = 0; j < 16; j++)
                        out[(16 * w + j) * 16 + 4 * c + r] |= (uint8_t)(((lane[w] >> (15 - j)) & 1) << b);
            }
}

/* software Blitter: D = LF(A,B,C) over h lines of w words; only the C channel uses a modulo here */
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

void ba_exec_soft(uint8_t *arena, const ba_blit *p, int n, int round)
{
    int i, line, x;
    for (i = 0; i < n; i++) {
        const ba_blit *e = &p[i];
        uint32_t h = (e->size >> 6) ? (e->size >> 6) : 1024, w = (e->size & 63) ? (e->size & 63) : 64;
        uint32_t a = e->a, b = e->b, c = e->c + ((e->flags & 1) ? (uint32_t)round * 256 : 0), d = e->d;
        int32_t cmod = (int16_t)e->cmod;
        for (line = 0; line < (int)h; line++) {
            for (x = 0; x < (int)w; x++) {
                uint16_t av = (e->con0 & 0x800) ? *(uint16_t *)(arena + a) : 0;
                uint16_t bv = (e->con0 & 0x400) ? *(uint16_t *)(arena + b) : 0;
                uint16_t cv = (e->con0 & 0x200) ? *(uint16_t *)(arena + c) : 0;
                *(uint16_t *)(arena + d) = minterm((uint8_t)e->con0, av, bv, cv);
                a += 2; b += 2; c += 2; d += 2;
            }
            c = (uint32_t)((int32_t)c + cmod);
        }
    }
}

void ba_encrypt_soft(const aes_key *k, uint8_t *arena, const uint8_t *in, uint8_t *out)
{
    int rnd;
    ba_keys(k, (uint16_t *)(arena + BA_KEYS));
    ba_pack(k, in, (uint16_t *)(arena + BA_STATE));
    for (rnd = 1; rnd < k->rounds; rnd++) {
        ba_exec_soft(arena, ba_prog, BA_NSBOX, rnd);
        ba_exec_soft(arena, ba_prog + BA_NSBOX, BA_NMIX, rnd);
    }
    ba_exec_soft(arena, ba_prog, BA_NSBOX, rnd);
    ba_exec_soft(arena, ba_prog + BA_NSBOX + BA_NMIX, BA_NFINAL, rnd);
    ba_unpack((const uint16_t *)(arena + BA_STATE), out);
}
