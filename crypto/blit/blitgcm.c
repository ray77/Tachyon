/* AES-GCM with the CTR keystream on the Blitter. See blitgcm.h for the construction. */
#include "blitgcm.h"

#ifdef BLITGCM_HW
#include <exec/types.h>
#include <hardware/custom.h>
#include <hardware/dmabits.h>
#include <hardware/intbits.h>
#include <graphics/gfxbase.h>
#include <proto/graphics.h>
extern struct GfxBase *GfxBase;
#define CUSTOM ((volatile struct Custom *)0xdff000)
void ba_exec_asm(__reg("a0") uint8_t *arena, __reg("a1") const ba_blit *p, __reg("d0") int n, __reg("d1") unsigned long keyoff);
#endif

#define NOW(c) ((c)->now ? (c)->now() : 0)
#define COPW (BLITGCM_COP_BLOCK / 2)

static void bg_put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static void put32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

static void bg_ghash(const aes_gcm_key *g, uint8_t y[16], const uint8_t x[16])
{
#ifdef FE16_ASM
    ghash_mul_tab(y, x, &g->m[0][0]);
#else
    ghash_mul_tab_c(y, x, g);
#endif
}

/* ---- counter lanes ------------------------------------------------------------------------
 * Lane (bit b of byte y) of the state: row t = (y&1)*8 + (7-b) (1 KiB each), word (y>>1) + 8*w
 * for w = 0..63; bit 15-k of that word belongs to block 64k + w. The counter occupies bytes 12..15:
 * bit n of the counter is byte 15 - (n>>3), bit n&7 -> rows 15-n (n < 16, column 14) and 31-n
 * (n >= 16, column 12). Bits 0..5 follow w directly, bits 6..31 depend only on (ctr + w) >> 6,
 * which takes two values over a batch: tab[0] for u0 = ctr >> 6 and tab[1] for u0 + 1.         */
static uint16_t keymask(const aes_key *k, int n) { return ((k->rk[15 - (n >> 3)] >> (n & 7)) & 1) ? 0xffff : 0; }

void blitgcm_ctr_params(bg_ctr_params *p, const aes_key *k, const uint8_t j0[12], uint32_t ctr)
{
    uint32_t u0 = ctr >> 6;
    int y, r, t, n, kk;
    for (y = 0; y < 12; y++) {
        uint8_t v = (uint8_t)(j0[y] ^ k->rk[y]);
        for (r = 0; r < 8; r++) p->cst[y][r] = (v >> (7 - r)) & 1 ? 0xffff : 0;
    }
    for (t = 0; t < 2; t++) {
        uint32_t u = u0 + (uint32_t)t;
        for (n = 6; n < 32; n++) {
            uint16_t wv = 0;
            for (kk = 0; kk < 16; kk++) wv |= (uint16_t)((((u + (uint32_t)kk) >> (n - 6)) & 1) << (15 - kk));
            p->tab[t][n - 6] = (uint16_t)(wv ^ keymask(k, n));
        }
    }
    for (n = 0; n < 6; n++) p->klo[n] = keymask(k, n);
    p->ctr = ctr;
}

void blitgcm_ctr_fill_c(uint8_t *arena, const bg_ctr_params *p)
{
    uint8_t *st = arena + BA_STATE;
    int y, r, w, n;
    for (y = 0; y < 12; y++) {
        uint8_t *base = st + (y & 1) * 8192 + (y >> 1) * 2;
        for (r = 0; r < 8; r++) {
            uint8_t *q = base + r * 1024, hi = (uint8_t)(p->cst[y][r] >> 8), lo = (uint8_t)p->cst[y][r];
            for (w = 0; w < 64; w++, q += 16) { q[0] = hi; q[1] = lo; }
        }
    }
    for (w = 0; w < 64; w++) {
        uint32_t c = p->ctr + (uint32_t)w;
        const uint16_t *tb = p->tab[(c >> 6) != (p->ctr >> 6)];
        uint8_t *base = st + 16 * w;
        for (n = 0; n < 6; n++) bg_put16(base + 14 + (15 - n) * 1024, (uint16_t)(((c >> n) & 1 ? 0xffff : 0) ^ p->klo[n]));
        for (n = 6; n < 16; n++) bg_put16(base + 14 + (15 - n) * 1024, tb[n - 6]);
        for (n = 16; n < 32; n++) bg_put16(base + 12 + (31 - n) * 1024, tb[n - 6]);
    }
}

/* ---- chain backends ------------------------------------------------------------------------ */
#ifdef BLITGCM_HW

/* one Copper block: WAIT for Blitter idle (BFD = 0), 21 MOVEs, COP1LC -> next (VBL-safe restart) */
static void cop_block(uint16_t *w, const uint8_t *arena, const ba_blit *e, int round, const uint16_t *next)
{
    uint32_t a = (uint32_t)(arena + e->a), b = (uint32_t)(arena + e->b), d = (uint32_t)(arena + e->d),
             c = (uint32_t)(arena + e->c + ((e->flags & 1) ? (uint32_t)round * 256 : 0)), nx = (uint32_t)next;
    int j = 0;
    w[j++] = 0x0001; w[j++] = 0x0000;
    w[j++] = 0x0040; w[j++] = e->con0;
    w[j++] = 0x0042; w[j++] = e->con1;
    w[j++] = 0x0044; w[j++] = 0xffff;
    w[j++] = 0x0046; w[j++] = 0xffff;
    w[j++] = 0x0048; w[j++] = (uint16_t)(c >> 16); w[j++] = 0x004a; w[j++] = (uint16_t)c;     /* words 11, 13: key pointer */
    w[j++] = 0x004c; w[j++] = (uint16_t)(b >> 16); w[j++] = 0x004e; w[j++] = (uint16_t)b;
    w[j++] = 0x0050; w[j++] = (uint16_t)(a >> 16); w[j++] = 0x0052; w[j++] = (uint16_t)a;
    w[j++] = 0x0054; w[j++] = (uint16_t)(d >> 16); w[j++] = 0x0056; w[j++] = (uint16_t)d;
    w[j++] = 0x0060; w[j++] = e->cmod;
    w[j++] = 0x0062; w[j++] = e->bmod;
    w[j++] = 0x0064; w[j++] = e->amod;
    w[j++] = 0x0066; w[j++] = e->dmod;
    w[j++] = 0x0058; w[j++] = e->size;
    w[j++] = 0x01fe; w[j++] = 0; w[j++] = 0x01fe; w[j++] = 0;
    w[j++] = 0x0080; w[j++] = (uint16_t)(nx >> 16);
    w[j++] = 0x0082; w[j++] = (uint16_t)nx;
}

/* terminators: both wait for the last blit first */
static void cop_term_flag(uint16_t *w)
{
    w[0] = 0x0001; w[1] = 0x0000;
    w[2] = 0x009c; w[3] = 0x8400;           /* INTREQ: set AUD3 = section done */
    w[4] = 0xffff; w[5] = 0xfffe;           /* wait forever */
}
static void cop_term_jump(uint16_t *w, const uint16_t *target)
{
    uint32_t t = (uint32_t)target;
    w[0] = 0x0001; w[1] = 0x0000;
    w[2] = 0x0080; w[3] = (uint16_t)(t >> 16);
    w[4] = 0x0082; w[5] = (uint16_t)t;
    w[6] = 0x0088; w[7] = 0x0000;           /* COPJMP1: continue at target */
    w[8] = 0xffff; w[9] = 0xfffe;
}

static void bg_cop_build(uint16_t *list, const uint8_t *arena, const ba_blit *p, int n, int round)
{
    int i;
    for (i = 0; i < n; i++) cop_block(list + i * COPW, arena, p + i, round, list + (i + 1) * COPW);
}

static void bg_patch_mix(blitgcm_ctx *c, int round)
{
    int i;
    for (i = 0; i < BLITGCM_MIXKEYS; i++) {
        uint32_t a = c->mixkey_base[i] + (uint32_t)round * 256;
        c->mixkey_word[i][0] = (uint16_t)(a >> 16);
        c->mixkey_word[i][2] = (uint16_t)a;
    }
}

static void bg_hw_init(blitgcm_ctx *c)
{
    int i, n = 0;
    c->cop_idle = (uint16_t *)c->cop;
    c->cop_idle[0] = 0xffff; c->cop_idle[1] = 0xfffe;
    c->cop_sbox = (uint16_t *)(c->cop + 8);
    c->cop_mix = c->cop_sbox + (BA_NSBOX + 1) * COPW;
    c->cop_fin = c->cop_mix + (BA_NMIX + 1) * COPW;
    c->cop_tout = c->cop_fin + (BA_NFINAL + 1) * COPW;
    bg_cop_build(c->cop_sbox, c->arena, ba_prog + BA_SEC_SBOX, BA_NSBOX, 0);
    cop_term_jump(c->cop_sbox + BA_NSBOX * COPW, c->cop_mix);
    bg_cop_build(c->cop_mix, c->arena, ba_prog + BA_SEC_MIX, BA_NMIX, 1);
    cop_term_flag(c->cop_mix + BA_NMIX * COPW);
    bg_cop_build(c->cop_fin, c->arena, ba_prog + BA_SEC_FINAL, BA_NFINAL, c->g->k.rounds);
    cop_term_jump(c->cop_fin + BA_NFINAL * COPW, c->cop_tout);
    bg_cop_build(c->cop_tout, c->arena, ba_prog + BA_SEC_TOUT, BA_NTOUT, 0);
    cop_term_flag(c->cop_tout + BA_NTOUT * COPW);
    for (i = 0; i < BA_NMIX && n < BLITGCM_MIXKEYS; i++) {
        if (!(ba_prog[BA_SEC_MIX + i].flags & 1)) continue;
        c->mixkey_base[n] = (uint32_t)(c->arena + ba_prog[BA_SEC_MIX + i].c);
        c->mixkey_word[n] = c->cop_mix + i * COPW + 11;
        n++;
    }
}

static void bg_cop_park(blitgcm_ctx *c) { CUSTOM->cop1lc = (ULONG)c->cop_idle; CUSTOM->copjmp1 = 0; }
static void bg_cop_go(const uint16_t *list) { CUSTOM->intreq = INTF_AUD3; CUSTOM->cop1lc = (ULONG)list; CUSTOM->copjmp1 = 0; }

/* Blitter owned, display and sprite DMA off, the gfx VBL server parked on the idle list, Copper may touch
 * Blitter registers. Everything restored in bg_hw_end. No console output in between (docs/TOOLCHAIN.md). */
static void bg_hw_begin(blitgcm_ctx *c)
{
    OwnBlitter();
    WaitBlit();
    c->old_lof = (uint16_t *)GfxBase->LOFlist; c->old_shf = (uint16_t *)GfxBase->SHFlist;
    GfxBase->LOFlist = (UWORD *)c->cop_idle; GfxBase->SHFlist = (UWORD *)c->cop_idle;
    c->olddma = CUSTOM->dmaconr;
    CUSTOM->dmacon = DMAF_RASTER | DMAF_SPRITE;
    CUSTOM->copcon = 2;
    c->hw_active = 1;
}
static void bg_hw_end(blitgcm_ctx *c)
{
    bg_cop_park(c);
    WaitBlit();
    CUSTOM->copcon = 0;
    CUSTOM->dmacon = DMAF_SETCLR | (c->olddma & (DMAF_RASTER | DMAF_SPRITE));
    GfxBase->LOFlist = (UWORD *)c->old_lof; GfxBase->SHFlist = (UWORD *)c->old_shf;
    WaitTOF(); WaitTOF();
    DisownBlitter();
    c->hw_active = 0;
}

static uint32_t bg_vpos(void) { return (((uint32_t)CUSTOM->vposr & 1) << 8) | (CUSTOM->vhposr >> 8); }

static void bg_lanes(blitgcm_ctx *c, const bg_ctr_params *p) { bg_ctr_fill_asm(c->arena, p); }

static void bg_chain_start(blitgcm_ctx *c)
{
    c->rnd = 1;
    bg_patch_mix(c, 1);
    cop_term_jump(c->cop_sbox + BA_NSBOX * COPW, c->cop_mix);
    c->frame = 0; c->lastv = bg_vpos();
    bg_cop_go(c->cop_sbox);
}

/* 1 when the batch chain is complete (or has been abandoned: c->rnd < 0), 0 while a section runs.
 * Sections: SBOX+MIX for rounds 1..rounds-1, then SBOX+FINAL+TOUT. Timeout per section: 150 frames
 * (a section takes ~12), counted from the beam position so no DOS or interrupt is involved. */
static int bg_chain_poll(blitgcm_ctx *c)
{
    int rounds = c->g->k.rounds;
    if (c->rnd < 0) return 1;
    if (!(CUSTOM->intreqr & INTF_AUD3)) {
        if ((++c->polls & 3) == 0) {                            /* beam position every 4th poll (units are < 5 ms) */
            uint32_t v = bg_vpos();
            if (v + 100 < c->lastv) c->frame++;
            c->lastv = v;
            if (c->frame > 150) { c->timeouts++; c->rnd = -1; bg_cop_park(c); WaitBlit(); return 1; }
        }
        return 0;
    }
    c->frame = 0;
    c->rnd++;
    if (c->rnd < rounds) { bg_patch_mix(c, c->rnd); bg_cop_go(c->cop_sbox); return 0; }
    if (c->rnd == rounds) { cop_term_jump(c->cop_sbox + BA_NSBOX * COPW, c->cop_fin); bg_cop_go(c->cop_sbox); return 0; }
    WaitBlit();
    return 1;
}
static int bg_chain_failed(const blitgcm_ctx *c) { return c->rnd < 0; }
static void bg_idle(blitgcm_ctx *c) { c->idle_polls++; }

static int bg_in_chip(const blitgcm_ctx *c, const void *p, uint32_t n)
{
    uint32_t a = (uint32_t)p;
    return a >= c->chip_lo && a + n <= c->chip_hi;
}

/* out = keystream (arena STATE, natural block order after TOUT) XOR in, nb blocks */
static void bg_xor(blitgcm_ctx *c, uint8_t *out, const uint8_t *in, uint32_t nb)
{
    if (bg_in_chip(c, out, nb * 16) && bg_in_chip(c, in, nb * 16)) {
        ba_blit x;
        x.con0 = 0x0d3c; x.con1 = 0;                        /* A ^ B -> D, 8 words per block, nb lines */
        x.a = (uint32_t)(c->arena + BA_STATE); x.b = (uint32_t)in; x.c = 0; x.d = (uint32_t)out;
        x.amod = x.bmod = x.cmod = x.dmod = 0;
        x.size = (uint16_t)(((nb & 1023) << 6) | 8); x.flags = 0;
        ba_exec_asm((uint8_t *)0, &x, 1, 0);
        c->blit_xor++;
    } else {
        bg_xor_asm(out, c->arena + BA_STATE, in, nb * 4);
    }
}

#else /* host: software Blitter, simulated chain latency */

static void bg_hw_init(blitgcm_ctx *c) { (void)c; }
static void bg_hw_begin(blitgcm_ctx *c) { c->hw_active = 1; }
static void bg_hw_end(blitgcm_ctx *c) { c->hw_active = 0; }
static void bg_lanes(blitgcm_ctx *c, const bg_ctr_params *p) { blitgcm_ctr_fill_c(c->arena, p); }

static void bg_chain_start(blitgcm_ctx *c)
{
    int rounds = c->g->k.rounds, rnd;
    for (rnd = 1; rnd < rounds; rnd++) {
        ba_exec_soft(c->arena, ba_prog + BA_SEC_SBOX, BA_NSBOX, rnd);
        ba_exec_soft(c->arena, ba_prog + BA_SEC_MIX, BA_NMIX, rnd);
    }
    ba_exec_soft(c->arena, ba_prog + BA_SEC_SBOX, BA_NSBOX, rnd);
    ba_exec_soft(c->arena, ba_prog + BA_SEC_FINAL, BA_NFINAL, rnd);
    ba_exec_soft(c->arena, ba_prog + BA_SEC_TOUT, BA_NTOUT, 0);
    c->rnd = c->soft_polls;
}
static int bg_chain_poll(blitgcm_ctx *c) { if (c->rnd > 0) { c->rnd--; return 0; } return 1; }
static int bg_chain_failed(const blitgcm_ctx *c) { (void)c; return 0; }
static void bg_idle(blitgcm_ctx *c) { c->idle_polls++; }

static void bg_xor(blitgcm_ctx *c, uint8_t *out, const uint8_t *in, uint32_t nb)
{
    const uint8_t *ks = c->arena + BA_STATE;
    uint32_t i;
    for (i = 0; i < nb * 16; i++) out[i] = (uint8_t)(in[i] ^ ks[i]);
}

#endif

/* ---- GCM ----------------------------------------------------------------------------------- */
typedef struct {
    blitgcm_ctx *c;
    const uint8_t *in, *aad, *ctp;      /* ctp: where the ciphertext is (in for decrypt, out for encrypt) */
    uint8_t *out;
    uint32_t len, nfull, aadlen, aadpos;
    uint32_t G, glimit, next_cpu, cpu_limit;
    uint8_t y[16], j0[16];
    int dec;
} bg_job;

static void bg_ghash_padded(bg_job *j, const uint8_t *p, uint32_t n)
{
    uint8_t last[16] = { 0 };
    uint32_t i;
    for (i = 0; i < n; i++) last[i] = p[i];
    bg_ghash(j->c->g, j->y, last);
}

static int bg_aad_step(bg_job *j)
{
    uint32_t left = j->aadlen - j->aadpos;
    if (left == 0) return 0;
    if (left >= 16) bg_ghash(j->c->g, j->y, j->aad + j->aadpos); else bg_ghash_padded(j, j->aad + j->aadpos, left);
    j->aadpos += left >= 16 ? 16 : left;
    return 1;
}

/* GHASH of the ciphertext blocks [G, limit), AAD first */
static void bg_ghash_to(bg_job *j, uint32_t limit)
{
    while (bg_aad_step(j)) ;
    while (j->G < limit) { bg_ghash(j->c->g, j->y, j->ctp + 16 * j->G); j->G++; }
}

/* CTR blocks [i, i + n) (counter i + 2) on the CPU: out = in ^ E(ctr). No GHASH. */
static void bg_ctr_run(bg_job *j, uint32_t i, uint32_t n)
{
#ifdef BLITGCM_HW
    bg_ctr_blocks(j->c->g->k.rk, j->j0, j->in + 16 * i, j->out + 16 * i, i + 2, n, j->c->g->k.rounds);
#else
    uint8_t blk[16], ks[16];
    int b;
    for (b = 0; b < 12; b++) blk[b] = j->j0[b];
    for (; n; n--, i++) {
        put32(blk + 12, i + 2);
        aes_encrypt_block(&j->c->g->k, blk, ks);
        for (b = 0; b < 16; b++) j->out[16 * i + b] = (uint8_t)(j->in[16 * i + b] ^ ks[b]);
    }
#endif
}

/* one unit of CPU work while the chain runs; 0 when there is nothing to do */
static int bg_work(bg_job *j)
{
    blitgcm_ctx *c = j->c;
    if (bg_aad_step(j)) return 1;
    if (j->G < j->glimit) {                                 /* two blocks per poll: halves the poll overhead, latency stays ~1.2 ms */
        bg_ghash(c->g, j->y, j->ctp + 16 * j->G); j->G++; c->ghash_overlap++;
        if (j->G < j->glimit) { bg_ghash(c->g, j->y, j->ctp + 16 * j->G); j->G++; c->ghash_overlap++; }
        return 1;
    }
    if (c->cpu_blocks && j->next_cpu < j->cpu_limit) {
        if (j->dec) { bg_ghash(c->g, j->y, j->in + 16 * j->next_cpu); j->G++; }      /* G == next_cpu here */
        bg_ctr_run(j, j->next_cpu, 1);
        j->next_cpu++; c->cpu_own++;
        if (c->batches <= 16) c->cpu_own_batch[c->batches - 1]++;
        return 1;
    }
    return 0;
}

/* worth a chain for R < 1024 remaining blocks? Chain ~2.3 s vs CPU 2.86 ms per block plus the pending
 * GHASH (0.56 ms each) that the CPU can hide under the chain: R > 1000 - pending/4 (FS-UAE numbers). */
static int bg_partial_ok(uint32_t R, uint32_t pending) { return R >= 512 && R + pending / 4 >= 1000; }

static void bg_run(bg_job *j, uint8_t tag[16])
{
    blitgcm_ctx *c = j->c;
    const aes_gcm_key *g = c->g;
    uint32_t P = 0, t, t0 = NOW(c), i, tail;
    uint8_t lens[16] = { 0 }, ej0[16];
    int b;
    c->batches = c->partial = c->cpu_own = c->ghash_overlap = c->timeouts = c->blit_xor = c->idle_polls = 0;
    c->t_lanes = c->t_chain = c->t_xor = c->t_tail = 0;
    for (b = 0; b < 16; b++) c->cpu_own_batch[b] = 0;
    for (;;) {
        uint32_t R = j->nfull - P, nb;
        bg_ctr_params prm;
        if (R >= BA_BLOCKS) nb = BA_BLOCKS;
        else if (bg_partial_ok(R, j->dec ? R : P - j->G)) { uint32_t s = R / 2 < 400 ? R / 2 : 400; nb = R - s; }   /* CPU takes s blocks behind the batch */
        else break;
        if (!c->hw_active) bg_hw_begin(c);
        c->batches++; if (nb < BA_BLOCKS) c->partial++;
        t = NOW(c);
        blitgcm_ctr_params(&prm, &g->k, j->j0, P + 2);
        bg_lanes(c, &prm);
        c->t_lanes += NOW(c) - t;
        t = NOW(c);
        bg_chain_start(c);
        j->glimit = j->dec ? P + nb : P;
        j->next_cpu = P + nb; j->cpu_limit = j->nfull;
        while (!bg_chain_poll(c)) { if (!bg_work(j)) bg_idle(c); }
        c->t_chain += NOW(c) - t;
        t = NOW(c);
        if (j->dec) bg_ghash_to(j, P + nb);                 /* ciphertext must be hashed before it is overwritten (aliasing) */
        if (bg_chain_failed(c)) bg_ctr_run(j, P, nb);
        else bg_xor(c, j->out + 16 * P, j->in + 16 * P, nb);
        c->t_xor += NOW(c) - t;
        P = j->next_cpu;
    }
    if (c->hw_active) bg_hw_end(c);
    /* tail on the CPU: blocks [P, nfull) and the partial block; GHASH in stream order */
    t = NOW(c);
    tail = j->len & 15;
    if (j->dec) {
        bg_ghash_to(j, j->nfull);
        if (tail) bg_ghash_padded(j, j->ctp + 16 * j->nfull, tail);
    }
    if (j->nfull > P) bg_ctr_run(j, P, j->nfull - P);
    if (tail) {
        uint8_t blk[16], ks[16];
        for (b = 0; b < 12; b++) blk[b] = j->j0[b];
        put32(blk + 12, j->nfull + 2);
        aes_encrypt_block(&g->k, blk, ks);
        for (i = 0; i < tail; i++) j->out[16 * j->nfull + i] = (uint8_t)(j->in[16 * j->nfull + i] ^ ks[i]);
    }
    if (!j->dec) {
        bg_ghash_to(j, j->nfull);
        if (tail) bg_ghash_padded(j, j->ctp + 16 * j->nfull, tail);
    }
    put32(lens + 4, j->aadlen * 8);
    put32(lens + 12, j->len * 8);
    bg_ghash(g, j->y, lens);
    aes_encrypt_block(&g->k, j->j0, ej0);
    for (b = 0; b < 16; b++) tag[b] = (uint8_t)(j->y[b] ^ ej0[b]);
    c->t_tail += NOW(c) - t;
    c->t_total = NOW(c) - t0;
}

static void bg_job_init(bg_job *j, blitgcm_ctx *c, const uint8_t iv[12], const uint8_t *aad, uint32_t aadlen,
                        const uint8_t *in, uint32_t len, uint8_t *out, int dec)
{
    int b;
    j->c = c; j->in = in; j->out = out; j->aad = aad; j->aadlen = aadlen; j->aadpos = 0;
    j->len = len; j->nfull = len >> 4; j->dec = dec; j->ctp = dec ? in : out;
    j->G = 0; j->glimit = 0; j->next_cpu = 0; j->cpu_limit = 0;
    for (b = 0; b < 16; b++) j->y[b] = 0;
    for (b = 0; b < 12; b++) j->j0[b] = iv[b];
    j->j0[12] = 0; j->j0[13] = 0; j->j0[14] = 0; j->j0[15] = 1;
}

int blitgcm_init(blitgcm_ctx *c, const aes_gcm_key *g, uint8_t *arena, uint8_t *cop)
{
    int i;
    if (!c || !g || !arena) return 0;
#ifdef BLITGCM_HW
    if (!cop) return 0;
#endif
    for (i = 0; i < (int)sizeof *c; i++) ((uint8_t *)c)[i] = 0;
    c->g = g; c->arena = arena; c->cop = cop;
    c->cpu_blocks = 1;
#ifdef BLITGCM_HW
    c->chip_lo = 0; c->chip_hi = 0x200000;
#endif
    ba_setup(&g->k, arena);
    bg_hw_init(c);
    return 1;
}

void blitgcm_encrypt(blitgcm_ctx *c, const uint8_t iv[12], const uint8_t *aad, uint32_t aadlen,
                     const uint8_t *pt, uint32_t len, uint8_t *ct, uint8_t tag[16])
{
    bg_job j;
    bg_job_init(&j, c, iv, aad, aadlen, pt, len, ct, 0);
    bg_run(&j, tag);
}

int blitgcm_decrypt(blitgcm_ctx *c, const uint8_t iv[12], const uint8_t *aad, uint32_t aadlen,
                    const uint8_t *ct, uint32_t len, const uint8_t tag[16], uint8_t *pt)
{
    bg_job j;
    uint8_t t[16];
    uint32_t i;
    int b, diff = 0;
    bg_job_init(&j, c, iv, aad, aadlen, ct, len, pt, 1);
    bg_run(&j, t);
    for (b = 0; b < 16; b++) diff |= t[b] ^ tag[b];
    if (diff) { for (i = 0; i < len; i++) pt[i] = 0; return 0; }
    return 1;
}
