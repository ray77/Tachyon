/*
 * WhatsBench - custom chip experiments: Blitter vs CPU on the Amiga 500.
 *
 * Hypothesis under test (README): the Blitter can take bulk boolean work off the
 * 68000 (bit-sliced AES rounds, keystream XOR), and does so concurrently when the
 * CPU runs from Fast RAM. This file measures the primitives such a design would
 * rest on; nothing here is cryptography yet.
 *
 * Included from x25519_bench.c (unity build) so it can use out/report/ticks_now.
 * Results are collected while the Blitter is owned and printed afterwards: the
 * console itself needs the Blitter, printing while owning it would deadlock.
 */
#include <hardware/custom.h>
#include <hardware/dmabits.h>
#include <graphics/gfxbase.h>
#include <proto/graphics.h>

struct GfxBase *GfxBase;
#define CUSTOM ((volatile struct Custom *)0xdff000)

#define BLT_WORDS 1024          /* 2 KiB per buffer: 16 rows of 64 words */

static void blit_wait(void)
{
    /* graphics.library WaitBlit() handles the A1000 BBUSY quirk; on an A500 a plain poll works too */
    WaitBlit();
}

/* D = A ^ B ^ C over `words` 16-bit words (minterm 0x96), all pointers in Chip RAM, even */
static void blit_xor3(UWORD *a, UWORD *b, UWORD *c, UWORD *d, UWORD words)
{
    UWORD h = words >> 6, w = words & 63;
    if (w == 0) w = 64; else h += 1;            /* words < 64: one row of w words */
    if (words < 64) { h = 1; w = words; }
    CUSTOM->bltcon0 = 0x0f96;                   /* USEA|USEB|USEC|USED, A^B^C */
    CUSTOM->bltcon1 = 0;
    CUSTOM->bltafwm = 0xffff;
    CUSTOM->bltalwm = 0xffff;
    CUSTOM->bltamod = 0; CUSTOM->bltbmod = 0; CUSTOM->bltcmod = 0; CUSTOM->bltdmod = 0;
    CUSTOM->bltapt = a; CUSTOM->bltbpt = b; CUSTOM->bltcpt = c; CUSTOM->bltdpt = d;
    CUSTOM->bltsize = (UWORD)((h << 6) | (w & 63));
}

/* D = A (copy), minterm 0xF0 */
static void blit_copy(UWORD *a, UWORD *d, UWORD words)
{
    UWORD h = words >> 6, w = words & 63;
    if (w == 0) w = 64; else h += 1;
    if (words < 64) { h = 1; w = words; }
    CUSTOM->bltcon0 = 0x09f0;                   /* USEA|USED, D = A */
    CUSTOM->bltcon1 = 0;
    CUSTOM->bltafwm = 0xffff;
    CUSTOM->bltalwm = 0xffff;
    CUSTOM->bltamod = 0; CUSTOM->bltdmod = 0;
    CUSTOM->bltapt = a; CUSTOM->bltdpt = d;
    CUSTOM->bltsize = (UWORD)((h << 6) | (w & 63));
}

/* A long blit that stays inside one 128-byte row: 1024 rows x 64 words with modulo -128,
 * i.e. 65536 words of A^B^C work (~74 ms at 4 bus cycles/word) without touching other memory. */
static void blit_long_xor3(UWORD *buf)
{
    CUSTOM->bltcon0 = 0x0f96;
    CUSTOM->bltcon1 = 0;
    CUSTOM->bltafwm = 0xffff;
    CUSTOM->bltalwm = 0xffff;
    CUSTOM->bltamod = (UWORD)-128; CUSTOM->bltbmod = (UWORD)-128; CUSTOM->bltcmod = (UWORD)-128; CUSTOM->bltdmod = (UWORD)-128;
    CUSTOM->bltapt = buf; CUSTOM->bltbpt = buf; CUSTOM->bltcpt = buf; CUSTOM->bltdpt = buf;
    CUSTOM->bltsize = 0;                        /* h = 1024 (0), w = 64 (0) */
}

static int blit_busy(void) { return (CUSTOM->dmaconr & DMAF_BLTDONE) != 0; }

static void cpu_xor3(ULONG *a, ULONG *b, ULONG *c, ULONG *d, int longs)
{
    int i;
    for (i = 0; i < longs; i++) d[i] = a[i] ^ b[i] ^ c[i];
}

static void blitter_bench(void)
{
    UWORD *ca, *cb, *cc, *cd;                   /* Chip RAM */
    static ULONG fa[BLT_WORDS / 2], fb[BLT_WORDS / 2], fc[BLT_WORDS / 2], fd[BLT_WORDS / 2];   /* Fast RAM (BSS) */
    static fe16 ma, mb, mh;
    ULONG t_cpu_fast, t_cpu_chip, t_cpu_chip_nodisp, t_mul_idle, t_mul_blit, t_mul_blit_hog, t_mul_blit_nodisp;
    ULONG t_blit[5], t_blit_nodisp, t_copy, t_copy_nodisp, t_long, t_long_nodisp;
    static const UWORD sizes[5] = { 16, 64, 256, 1024, 0 };
    ULONG t0, t1;
    int i, k, ok = 1;
    UWORD dmacon_save;

    GfxBase = (struct GfxBase *)OpenLibrary((STRPTR)"graphics.library", 0);
    if (!GfxBase) { out("graphics.library not available\n"); return; }
    ca = (UWORD *)AllocMem(BLT_WORDS * 2, MEMF_CHIP | MEMF_CLEAR);
    cb = (UWORD *)AllocMem(BLT_WORDS * 2, MEMF_CHIP | MEMF_CLEAR);
    cc = (UWORD *)AllocMem(BLT_WORDS * 2, MEMF_CHIP | MEMF_CLEAR);
    cd = (UWORD *)AllocMem(BLT_WORDS * 2, MEMF_CHIP | MEMF_CLEAR);
    if (!ca || !cb || !cc || !cd) { out("no Chip RAM\n"); goto done; }
    for (i = 0; i < BLT_WORDS; i++) { ca[i] = rnd16(); cb[i] = rnd16(); cc[i] = rnd16(); }
    for (i = 0; i < BLT_WORDS / 2; i++) { fa[i] = ((ULONG)ca[2*i] << 16) | ca[2*i+1]; fb[i] = ((ULONG)cb[2*i] << 16) | cb[2*i+1]; fc[i] = ((ULONG)cc[2*i] << 16) | cc[2*i+1]; }
    for (i = 0; i < 16; i++) { ma[i] = rnd16(); mb[i] = rnd16(); }

    /* CPU reference: 3-source XOR over 1024 words in Fast RAM, then in Chip RAM */
    t0 = ticks_now(); for (k = 0; k < 200; k++) cpu_xor3(fa, fb, fc, fd, BLT_WORDS / 2); t1 = ticks_now(); t_cpu_fast = t1 - t0;
    t0 = ticks_now(); for (k = 0; k < 200; k++) cpu_xor3((ULONG *)ca, (ULONG *)cb, (ULONG *)cc, (ULONG *)cd, BLT_WORDS / 2); t1 = ticks_now(); t_cpu_chip = t1 - t0;
    /* fe16_mul rate with idle Blitter */
    t0 = ticks_now(); for (k = 0; k < 500; k++) fe16_mul(mh, ma, mb); t1 = ticks_now(); t_mul_idle = t1 - t0;

    OwnBlitter();
    blit_wait();
    /* correctness of the Blitter XOR against the CPU result (verified after Disown) */
    blit_xor3(ca, cb, cc, cd, BLT_WORDS); blit_wait();
    for (i = 0; i < BLT_WORDS / 2; i++) if (((ULONG *)cd)[i] != fd[i]) ok = 0;

    for (k = 0; sizes[k]; k++) {
        ULONG reps = 100000UL / sizes[k];       /* ~ 400 ms per size */
        t0 = ticks_now();
        for (i = 0; i < (int)reps; i++) { blit_xor3(ca, cb, cc, cd, sizes[k]); blit_wait(); }
        t1 = ticks_now(); t_blit[k] = t1 - t0;
    }
    t0 = ticks_now(); for (i = 0; i < 200; i++) { blit_copy(ca, cd, BLT_WORDS); blit_wait(); } t1 = ticks_now(); t_copy = t1 - t0;
    t0 = ticks_now(); for (i = 0; i < 20; i++) { blit_long_xor3(cd); blit_wait(); } t1 = ticks_now(); t_long = t1 - t0;

    /* concurrency: CPU does fe16_mul in Fast RAM while the Blitter grinds in Chip RAM */
    t0 = ticks_now();
    blit_long_xor3(cd);
    for (k = 0; k < 500; k++) { fe16_mul(mh, ma, mb); if (!blit_busy()) blit_long_xor3(cd); }
    blit_wait();
    t1 = ticks_now(); t_mul_blit = t1 - t0;
    /* same with BLITHOG ("blitter nasty": Blitter keeps the bus, CPU only gets idle cycles) */
    CUSTOM->dmacon = DMAF_SETCLR | DMAF_BLITHOG;
    t0 = ticks_now();
    blit_long_xor3(cd);
    for (k = 0; k < 500; k++) { fe16_mul(mh, ma, mb); if (!blit_busy()) blit_long_xor3(cd); }
    blit_wait();
    t1 = ticks_now(); t_mul_blit_hog = t1 - t0;
    CUSTOM->dmacon = DMAF_BLITHOG;

    /* display DMA off: the pure Chip bus without bitplane fetches (screen goes dark meanwhile) */
    dmacon_save = CUSTOM->dmaconr;
    CUSTOM->dmacon = DMAF_RASTER;               /* clear BPLEN */
    t0 = ticks_now(); for (i = 0; i < 100; i++) { blit_xor3(ca, cb, cc, cd, BLT_WORDS); blit_wait(); } t1 = ticks_now(); t_blit_nodisp = t1 - t0;
    t0 = ticks_now(); for (i = 0; i < 200; i++) { blit_copy(ca, cd, BLT_WORDS); blit_wait(); } t1 = ticks_now(); t_copy_nodisp = t1 - t0;
    t0 = ticks_now(); for (i = 0; i < 20; i++) { blit_long_xor3(cd); blit_wait(); } t1 = ticks_now(); t_long_nodisp = t1 - t0;
    t0 = ticks_now(); for (k = 0; k < 200; k++) cpu_xor3((ULONG *)ca, (ULONG *)cb, (ULONG *)cc, (ULONG *)cd, BLT_WORDS / 2); t1 = ticks_now(); t_cpu_chip_nodisp = t1 - t0;
    t0 = ticks_now();
    blit_long_xor3(cd);
    for (k = 0; k < 500; k++) { fe16_mul(mh, ma, mb); if (!blit_busy()) blit_long_xor3(cd); }
    blit_wait();
    t1 = ticks_now(); t_mul_blit_nodisp = t1 - t0;
    if (dmacon_save & DMAF_RASTER) CUSTOM->dmacon = DMAF_SETCLR | DMAF_RASTER;
    DisownBlitter();

    out("\n--- custom chips: Blitter vs 68000 (Chip RAM buffers, 1024 words = 2 KiB) ---\n");
    out(ok ? "PASS " : "FAIL "); out("blitter A^B^C == CPU result\n");
    report("cpu xor3 1024 words, Fast RAM (C loop)", t_cpu_fast, 200);
    report("cpu xor3 1024 words, Chip RAM (C loop)", t_cpu_chip, 200);
    report("cpu xor3 1024 words, Chip RAM, display DMA off", t_cpu_chip_nodisp, 200);
    for (k = 0; sizes[k]; k++) {
        out("blit xor3 "); out_dec(sizes[k]); out(" words incl. setup+WaitBlit");
        report("", t_blit[k], 100000UL / sizes[k]);
    }
    report("blit xor3 1024 words, display DMA off", t_blit_nodisp, 100);
    report("blit copy 1024 words", t_copy, 200);
    report("blit copy 1024 words, display DMA off", t_copy_nodisp, 200);
    report("blit xor3 65536 words (one blit)", t_long, 20);
    report("blit xor3 65536 words, display DMA off", t_long_nodisp, 20);
    report("fe16_mul (Fast RAM), Blitter idle", t_mul_idle, 500);
    report("fe16_mul (Fast RAM), Blitter busy", t_mul_blit, 500);
    report("fe16_mul (Fast RAM), Blitter busy + BLITHOG", t_mul_blit_hog, 500);
    report("fe16_mul (Fast RAM), Blitter busy, display off", t_mul_blit_nodisp, 500);
done:
    if (ca) FreeMem(ca, BLT_WORDS * 2);
    if (cb) FreeMem(cb, BLT_WORDS * 2);
    if (cc) FreeMem(cc, BLT_WORDS * 2);
    if (cd) FreeMem(cd, BLT_WORDS * 2);
    CloseLibrary((struct Library *)GfxBase);
}
