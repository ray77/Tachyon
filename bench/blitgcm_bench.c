/*
 * WhatsBench - AES-256-GCM with the CTR keystream on the Blitter (crypto/blit/blitgcm.c) on the
 * real A500: counter lanes asm vs C, library result vs aes_gcm_encrypt/decrypt, throughput with
 * and without CPU-own blocks, and with the buffers in Chip RAM (XOR blit) vs Fast RAM (CPU XOR).
 * No console output while a blitgcm call runs (it owns the Blitter); numbers are printed after.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <graphics/gfxbase.h>
#include <proto/graphics.h>
#include "aes.h"
#include "blitaes.h"
#include "blitgcm.h"

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
struct GfxBase *GfxBase;

static BPTR con, logfile;
static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { int n = slen(s); if (con) Write(con, (APTR)s, n); if (logfile) Write(logfile, (APTR)s, n); }
static void out_dec(ULONG v) { char b[12]; int i = 11; b[i] = 0; do { b[--i] = (char)('0' + v % 10); v /= 10; } while (v); out(b + i); }
static ULONG ticks_now(void) { struct DateStamp ds; DateStamp(&ds); return (ULONG)ds.ds_Minute * 3000UL + (ULONG)ds.ds_Tick; }
static uint16_t rnd_state = 0xbeef;
static uint16_t rnd16(void) { rnd_state ^= rnd_state << 7; rnd_state ^= rnd_state >> 9; rnd_state ^= rnd_state << 8; return rnd_state; }
static void ms(ULONG ticks) { out_dec(ticks * 20); out(" ms"); }
static void rate(ULONG bytes, ULONG ticks) { out_dec(bytes * 50 / (ticks ? ticks : 1)); out(" B/s"); }

#define BIG 65536UL
#define MID 40000UL
static uint8_t pt[BIG], ct[BIG], ref[BIG], dec[BIG], lanes_c[16384];
static aes_gcm_key gk;
static blitgcm_ctx ctx;

static void stats(const char *name, ULONG bytes, ULONG ticks)
{
    out(name); out(": "); ms(ticks); out(" = "); rate(bytes, ticks);
    out("; batches "); out_dec(ctx.batches); out(" (partial "); out_dec(ctx.partial); out("), CPU-own blocks "); out_dec(ctx.cpu_own);
    out(", GHASH under chain "); out_dec(ctx.ghash_overlap); out(", XOR blits "); out_dec(ctx.blit_xor); out(", timeouts "); out_dec(ctx.timeouts);
    out("\n    lanes "); ms(ctx.t_lanes); out(", chain "); ms(ctx.t_chain); out(", xor "); ms(ctx.t_xor); out(", tail "); ms(ctx.t_tail);
    out("; idle polls "); out_dec(ctx.idle_polls); out("; CPU-own per batch:");
    { ULONG b; for (b = 0; b < ctx.batches && b < 16; b++) { out(" "); out_dec(ctx.cpu_own_batch[b]); } }
    out("\n");
}

int main(void)
{
    static uint8_t key[32], iv[12], aad[20], tag[16], rtag[16], tagA[16], tagB[16], tagC[16];
    uint8_t *arena = 0, *cop = 0, *cpt = 0, *cct = 0;
    ULONG t0, t1, t_cpu_mid, t_cpu_big, t_enc, t_dec, tA, tB, tC = 0;
    int i, ok = 1, r, okA, okB = 0, okC = -1;
    BPTR done;

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    con = Output();
    logfile = Open((STRPTR)"SYS:result.txt", MODE_NEWFILE);
    GfxBase = (struct GfxBase *)OpenLibrary((STRPTR)"graphics.library", 0);
    out("WhatsBench blitgcm: AES-256-GCM with the Blitter keystream; arena "); out_dec(BLITGCM_ARENA_BYTES); out(" + Copper lists "); out_dec(BLITGCM_COP_BYTES); out(" bytes Chip RAM\n");
    arena = (uint8_t *)AllocMem(BLITGCM_ARENA_BYTES, MEMF_CHIP | MEMF_CLEAR);
    cop = (uint8_t *)AllocMem(BLITGCM_COP_BYTES, MEMF_CHIP | MEMF_CLEAR);
    if (!arena || !cop || !GfxBase) { out("no Chip RAM / graphics.library\n"); ok = 0; goto done; }
    for (i = 0; i < 32; i++) key[i] = (uint8_t)rnd16();
    for (i = 0; i < 12; i++) iv[i] = (uint8_t)rnd16();
    for (i = 0; i < 20; i++) aad[i] = (uint8_t)rnd16();
    for (i = 0; i < (int)BIG; i++) pt[i] = (uint8_t)rnd16();
    aes_gcm_set_key(&gk, key, 256);
    if (!blitgcm_init(&ctx, &gk, arena, cop)) { out("blitgcm_init failed\n"); ok = 0; goto done; }
    ctx.now = ticks_now;

    /* 1. counter lanes: asm filler == C filler, timing */
    {
        bg_ctr_params p;
        int same;
        blitgcm_ctr_params(&p, &gk.k, iv, 0xfffffff5u);
        for (i = 0; i < 16384; i++) arena[i] = 0xa5;
        t0 = ticks_now(); blitgcm_ctr_fill_c(arena, &p); t1 = ticks_now();
        for (i = 0; i < 16384; i++) lanes_c[i] = arena[i];
        out("counter lanes, C: "); ms(t1 - t0);
        for (i = 0; i < 16384; i++) arena[i] = 0x5a;
        t0 = ticks_now(); for (i = 0; i < 10; i++) bg_ctr_fill_asm(arena, &p); t1 = ticks_now();
        out("; asm: "); out_dec((t1 - t0) * 2); out(" ms (10 runs / 10)\n");
        same = 1;
        for (i = 0; i < 16384; i++) if (arena[i] != lanes_c[i]) { same = 0; break; }
        out(same ? "PASS " : "FAIL "); out("counter lanes asm == C (16 KiB state, counter wraps inside the batch)\n");
        ok &= same;
    }

    {   /* where do CPU data live? (hunk BSS, stack, GHASH tables, code) */
        ULONG here = 0;
        out("memory: pt 0x"); out_dec((ULONG)TypeOfMem(pt)); out(" gk "); out_dec((ULONG)TypeOfMem(&gk)); out(" stack "); out_dec((ULONG)TypeOfMem(&here));
        out(" code "); out_dec((ULONG)TypeOfMem((APTR)main)); out("  (MEMF_CHIP=2, MEMF_FAST=4, +1 public)\n");
    }

    /* 1b. CPU work units idle: AES block (T-tables asm), CTR block via bg_ctr_blocks, GHASH block */
    {
        static uint8_t y[16];
        ULONG ta, tc, tg;
        t0 = ticks_now(); for (i = 0; i < 500; i++) aes_encrypt_block(&gk.k, pt + 16 * i, ct + 16 * i); t1 = ticks_now(); ta = t1 - t0;
        t0 = ticks_now(); for (i = 0; i < 500; i++) bg_ctr_blocks(gk.k.rk, iv, pt + 16 * i, ct + 16 * i, (uint32_t)i + 2, 1, gk.k.rounds); t1 = ticks_now(); tc = t1 - t0;
        t0 = ticks_now(); for (i = 0; i < 2000; i++) ghash_mul_tab(y, pt + 16 * (i & 1023), &gk.m[0][0]); t1 = ticks_now(); tg = t1 - t0;
        out("CPU units idle (us): AES block "); out_dec(ta * 40); out(", CTR block asm "); out_dec(tc * 40); out(", GHASH block "); out_dec(tg * 10); out("\n");
    }

    /* 2. correctness on 40000 bytes + 20 bytes AAD against the CPU implementation */
    t0 = ticks_now(); aes_gcm_encrypt(&gk, iv, aad, 20, pt, MID, ref, rtag); t1 = ticks_now(); t_cpu_mid = t1 - t0;
    t0 = ticks_now(); blitgcm_encrypt(&ctx, iv, aad, 20, pt, MID, ct, tag); t1 = ticks_now(); t_enc = t1 - t0;
    r = 1; for (i = 0; i < (int)MID; i++) if (ct[i] != ref[i]) { r = 0; break; }
    for (i = 0; i < 16; i++) if (tag[i] != rtag[i]) r = 0;
    out(r ? "PASS " : "FAIL "); out("blitgcm_encrypt 40000 B + AAD == aes_gcm_encrypt (ciphertext and tag)\n"); ok &= r;
    stats("  encrypt", MID, t_enc);
    out("  CPU aes_gcm_encrypt: "); ms(t_cpu_mid); out(" = "); rate(MID, t_cpu_mid); out("\n");
    t0 = ticks_now(); r = blitgcm_decrypt(&ctx, iv, aad, 20, ct, MID, tag, dec); t1 = ticks_now(); t_dec = t1 - t0;
    if (r == 1) for (i = 0; i < (int)MID; i++) if (dec[i] != pt[i]) { r = 0; break; }
    out(r == 1 ? "PASS " : "FAIL "); out("blitgcm_decrypt 40000 B: tag accepted, plaintext == original\n"); ok &= r == 1;
    stats("  decrypt", MID, t_dec);
    {   /* tampered tag on a 2-batch message: rejected, output zeroed */
        int zero = 1;
        tag[3] ^= 0x80;
        for (i = 0; i < (int)MID; i++) dec[i] = 0xee;
        r = blitgcm_decrypt(&ctx, iv, aad, 20, ct, MID, tag, dec);
        for (i = 0; i < (int)MID; i++) if (dec[i]) { zero = 0; break; }
        tag[3] ^= 0x80;
        out(r == 0 && zero ? "PASS " : "FAIL "); out("tampered tag rejected, plaintext zeroed\n"); ok &= r == 0 && zero;
    }

    /* 3. throughput on 64 KiB */
    t0 = ticks_now(); aes_gcm_encrypt(&gk, iv, aad, 20, pt, BIG, ref, rtag); t1 = ticks_now(); t_cpu_big = t1 - t0;
    out("\n--- 64 KiB AES-256-GCM, buffers in Fast RAM ---\n");
    out("CPU aes_gcm_encrypt (T-tables + GHASH asm): "); ms(t_cpu_big); out(" = "); rate(BIG, t_cpu_big); out("\n");
    ctx.cpu_blocks = 1;
    t0 = ticks_now(); blitgcm_encrypt(&ctx, iv, aad, 20, pt, BIG, ct, tagA); t1 = ticks_now(); tA = t1 - t0;
    okA = 1; for (i = 0; i < (int)BIG; i++) if (ct[i] != ref[i]) { okA = 0; break; }
    for (i = 0; i < 16; i++) if (tagA[i] != rtag[i]) okA = 0;
    out(okA ? "PASS " : "FAIL "); stats("Blitter chain + GHASH + CPU-own blocks", BIG, tA); ok &= okA;
    ctx.cpu_blocks = 0;
    t0 = ticks_now(); blitgcm_encrypt(&ctx, iv, aad, 20, pt, BIG, ct, tagB); t1 = ticks_now(); tB = t1 - t0;
    okB = 1; for (i = 0; i < (int)BIG; i++) if (ct[i] != ref[i]) { okB = 0; break; }
    for (i = 0; i < 16; i++) if (tagB[i] != rtag[i]) okB = 0;
    out(okB ? "PASS " : "FAIL "); stats("Blitter chain + GHASH only (cpu_blocks = 0)", BIG, tB); ok &= okB;
    ctx.cpu_blocks = 1;
    cpt = (uint8_t *)AllocMem(BIG, MEMF_CHIP); cct = (uint8_t *)AllocMem(BIG, MEMF_CHIP);
    if (cpt && cct) {
        for (i = 0; i < (int)BIG; i++) cpt[i] = pt[i];
        t0 = ticks_now(); blitgcm_encrypt(&ctx, iv, aad, 20, cpt, BIG, cct, tagC); t1 = ticks_now(); tC = t1 - t0;
        okC = 1; for (i = 0; i < (int)BIG; i++) if (cct[i] != ref[i]) { okC = 0; break; }
        for (i = 0; i < 16; i++) if (tagC[i] != rtag[i]) okC = 0;
        out("\n--- 64 KiB, buffers in Chip RAM (ciphertext by XOR blit) ---\n");
        out(okC ? "PASS " : "FAIL "); stats("Blitter chain + GHASH + CPU-own blocks, XOR blit", BIG, tC); ok &= okC;
    } else out("\n(no Chip RAM for 2 x 64 KiB buffers: XOR-blit variant skipped)\n");
    /* 4. steady state: 192 KiB (12 batches) in place, against the CPU, then decrypted in place */
    {
        ULONG big = 196608UL, tref, tbig, tdec2;
        uint8_t *bp = (uint8_t *)AllocMem(big, MEMF_FAST), *bc = (uint8_t *)AllocMem(big, MEMF_FAST);
        if (bp && bc) {
            uint16_t seed = rnd_state;
            int same = 1;
            for (i = 0; i < (int)big; i++) bp[i] = (uint8_t)rnd16();
            t0 = ticks_now(); aes_gcm_encrypt(&gk, iv, aad, 20, bp, big, bc, rtag); t1 = ticks_now(); tref = t1 - t0;
            ctx.cpu_blocks = 1;
            t0 = ticks_now(); blitgcm_encrypt(&ctx, iv, aad, 20, bp, big, bp, tag); t1 = ticks_now(); tbig = t1 - t0;
            for (i = 0; i < (int)big; i++) if (bp[i] != bc[i]) { same = 0; break; }
            for (i = 0; i < 16; i++) if (tag[i] != rtag[i]) same = 0;
            out("\n--- 192 KiB in place (steady state, 12 batches) ---\n");
            out("CPU aes_gcm_encrypt: "); ms(tref); out(" = "); rate(big, tref); out("\n");
            out(same ? "PASS " : "FAIL "); stats("blitgcm_encrypt in place == CPU", big, tbig); ok &= same;
            t0 = ticks_now(); r = blitgcm_decrypt(&ctx, iv, aad, 20, bp, big, tag, bp); t1 = ticks_now(); tdec2 = t1 - t0;
            rnd_state = seed; same = r == 1;
            for (i = 0; i < (int)big; i++) if (bp[i] != (uint8_t)rnd16()) { same = 0; break; }
            out(same ? "PASS " : "FAIL "); stats("blitgcm_decrypt in place == original", big, tdec2); ok &= same;
            out("steady state 192 KiB: CPU "); rate(big, tref); out("; encrypt "); rate(big, tbig); out("; decrypt "); rate(big, tdec2); out("\n");
        } else out("\n(no Fast RAM for 2 x 192 KiB: steady-state run skipped)\n");
        if (bp) FreeMem(bp, big); if (bc) FreeMem(bc, big);
    }

    out("\nsummary 64 KiB: CPU "); rate(BIG, t_cpu_big); out("; Blitter+GHASH "); rate(BIG, tB); out("; Blitter+GHASH+CPU blocks "); rate(BIG, tA);
    if (okC >= 0) { out("; same with XOR blit "); rate(BIG, tC); }
    out("\n");
    out(ok ? "RESULT: all vectors passed\n" : "RESULT: VECTOR MISMATCH\n");
done:
    if (cpt) FreeMem(cpt, BIG); if (cct) FreeMem(cct, BIG);
    if (arena) FreeMem(arena, BLITGCM_ARENA_BYTES); if (cop) FreeMem(cop, BLITGCM_COP_BYTES);
    if (GfxBase) CloseLibrary((struct Library *)GfxBase);
    if (logfile) Close(logfile);
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
    return 0;
}
