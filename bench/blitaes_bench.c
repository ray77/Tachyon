/*
 * WhatsBench - bit-sliced AES-256 on the real Blitter (A500). Separate small binary
 * for fast iteration: builds the key lanes and packs 1024 blocks on the CPU, runs the
 * generated Blitter program (crypto/blit/blitaes_prog.h) with the hardware, compares
 * every block with the byte-oriented reference, and times the phases.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include <hardware/custom.h>
#include <hardware/dmabits.h>
#include <graphics/gfxbase.h>
#include <proto/graphics.h>
#include "aes.h"
#include "blitaes.h"

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
struct GfxBase *GfxBase;
#define CUSTOM ((volatile struct Custom *)0xdff000)

static BPTR con, logfile;
static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }
static void out(const char *s) { int n = slen(s); if (con) Write(con, (APTR)s, n); if (logfile) Write(logfile, (APTR)s, n); }
static void out_dec(ULONG v) { char b[12]; int i = 11; b[i] = 0; do { b[--i] = (char)('0' + v % 10); v /= 10; } while (v); out(b + i); }
static ULONG ticks_now(void) { struct DateStamp ds; DateStamp(&ds); return (ULONG)ds.ds_Minute * 3000UL + (ULONG)ds.ds_Tick; }
static void report(const char *name, ULONG ticks, ULONG n) { out(name); out(": "); out_dec(ticks); out(" ticks / "); out_dec(n); out(" ops = "); out_dec(ticks * 20000UL / n); out(" us/op\n"); }
static uint16_t rnd_state = 0xace1;
static uint16_t rnd16(void) { rnd_state ^= rnd_state << 7; rnd_state ^= rnd_state >> 9; rnd_state ^= rnd_state << 8; return rnd_state; }

void ba_exec_asm(__reg("a0") uint8_t *arena, __reg("a1") const ba_blit *p, __reg("d0") int n, __reg("d1") ULONG keyoff);
static int use_asm;

/* run a program section on the hardware; round selects the key lanes */
static void ba_exec_hw(uint8_t *arena, const ba_blit *p, int n, int round)
{
    int i;
    if (use_asm) { ba_exec_asm(arena, p, n, (ULONG)round * 256); return; }
    ULONG keyoff = (ULONG)round * 256;
    for (i = 0; i < n; i++) {
        const ba_blit *e = &p[i];
        WaitBlit();
        CUSTOM->bltcon0 = e->con0;
        CUSTOM->bltcon1 = e->con1;
        CUSTOM->bltafwm = 0xffff;
        CUSTOM->bltalwm = 0xffff;
        CUSTOM->bltamod = e->amod; CUSTOM->bltbmod = e->bmod; CUSTOM->bltcmod = e->cmod; CUSTOM->bltdmod = e->dmod;
        CUSTOM->bltapt = arena + e->a;
        CUSTOM->bltbpt = arena + e->b;
        CUSTOM->bltcpt = arena + e->c + ((e->flags & 1) ? keyoff : 0);
        CUSTOM->bltdpt = arena + e->d;
        CUSTOM->bltsize = e->size;
    }
    WaitBlit();
}

int main(void)
{
    static aes_key k;
    static uint8_t key[32], in[BA_BLOCKS * 16], outbuf[BA_BLOCKS * 16], want[16];
    uint8_t *arena;
    ULONG t0, t1, t_keys, t_pack, t_sbox, t_mix, t_final, t_unpack, t_total, t_cpu, t_tin, t_tout;
    int i, rnd, bad = 0, ok = 1;
    BPTR done;

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    con = Output();
    logfile = Open((STRPTR)"SYS:result.txt", MODE_NEWFILE);
    GfxBase = (struct GfxBase *)OpenLibrary((STRPTR)"graphics.library", 0);
    out("WhatsBench blitaes: bit-sliced AES-256 on the Blitter, "); out_dec(BA_BLOCKS); out(" blocks per batch, arena "); out_dec(BA_ARENA); out(" bytes\n");
    arena = (uint8_t *)AllocMem(BA_ARENA, MEMF_CHIP | MEMF_CLEAR);
    if (!arena || !GfxBase) { out("no Chip RAM / graphics.library\n"); goto done; }

    for (i = 0; i < 32; i++) key[i] = (uint8_t)rnd16();
    for (i = 0; i < (int)sizeof in; i++) in[i] = (uint8_t)rnd16();
    aes_set_key(&k, key, 256);

  for (use_asm = 0; use_asm < 2; use_asm++) {
    t0 = ticks_now(); ba_setup(&k, arena); t1 = ticks_now(); t_keys = t1 - t0;
    t0 = ticks_now(); for (i = 0; i < (int)sizeof in; i++) arena[BA_STATE + i] = in[i]; t1 = ticks_now(); t_pack = t1 - t0;
    t_sbox = t_mix = t_final = 0;
    OwnBlitter();
    t0 = ticks_now();
    ba_exec_hw(arena, ba_prog + BA_SEC_WHITE, BA_NWHITE, 0);
    ba_exec_hw(arena, ba_prog + BA_SEC_TIN, BA_NTIN, 0);
    t_tin = ticks_now() - t0;
    for (rnd = 1; rnd < k.rounds; rnd++) {
        ULONG a = ticks_now(), b;
        ba_exec_hw(arena, ba_prog + BA_SEC_SBOX, BA_NSBOX, rnd);
        b = ticks_now(); t_sbox += b - a;
        ba_exec_hw(arena, ba_prog + BA_SEC_MIX, BA_NMIX, rnd);
        t_mix += ticks_now() - b;
    }
    { ULONG a = ticks_now(), b; ba_exec_hw(arena, ba_prog + BA_SEC_SBOX, BA_NSBOX, rnd); b = ticks_now(); t_sbox += b - a;
      ba_exec_hw(arena, ba_prog + BA_SEC_FINAL, BA_NFINAL, rnd); t_final = ticks_now() - b; }
    { ULONG a = ticks_now(); ba_exec_hw(arena, ba_prog + BA_SEC_TOUT, BA_NTOUT, 0); t_tout = ticks_now() - a; }
    t1 = ticks_now(); t_total = t1 - t0;
    DisownBlitter();
    t0 = ticks_now(); for (i = 0; i < (int)sizeof outbuf; i++) outbuf[i] = arena[BA_STATE + i]; t1 = ticks_now(); t_unpack = t1 - t0;


    out(use_asm ? "\n--- asm blit executor ---\n" : "\n--- C blit executor (WaitBlit + volatile writes) ---\n");
    report("whitening + transpose in, 65 blits", t_tin, 1);
    report("S-box layers, 14 x 226 blits of 512 words", t_sbox, 14);
    report("MixColumns+key layers, 13 x 432 blits of 64 words", t_mix, 13);
    report("final layer, 128 blits", t_final, 1);
    report("transpose out, 64 blits", t_tout, 1);
    report("all Blitter work for 16 KiB", t_total, 1);
    out("blitter only: "); out_dec(16384UL * 50 / t_total); out(" bytes/s\n");
  }
    t0 = ticks_now();
    for (i = 0; i < BA_BLOCKS; i++) {
        int j;
        aes_encrypt_block(&k, in + 16 * i, want);
        for (j = 0; j < 16; j++) if (want[j] != outbuf[16 * i + j]) { bad++; break; }
    }
    t1 = ticks_now(); t_cpu = t1 - t0;
    ok = bad == 0;
    out(ok ? "PASS " : "FAIL "); out("blitter AES-256 == CPU reference on "); out_dec(BA_BLOCKS); out(" blocks");
    if (bad) { out(" ("); out_dec((ULONG)bad); out(" wrong)"); }
    out("\n");
    report("key lanes + masks (CPU)", t_keys, 1);
    report("copy 16 KiB in (CPU, C)", t_pack, 1);
    report("copy 16 KiB out (CPU, C)", t_unpack, 1);
    out("blitter AES-256 throughput incl. copies (asm executor): "); out_dec(16384UL * 50 / (t_total + t_pack + t_unpack)); out(" bytes/s\n");
    report("CPU aes_encrypt_block (asm T-tables) x 1024", t_cpu, 1024);
    out("cpu throughput: "); out_dec(16384UL * 50 / t_cpu); out(" bytes/s\n");
    out(ok ? "RESULT: all vectors passed\n" : "RESULT: VECTOR MISMATCH\n");
done:
    if (arena) FreeMem(arena, BA_ARENA);
    if (GfxBase) CloseLibrary((struct Library *)GfxBase);
    if (logfile) Close(logfile);
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
    return 0;
}
