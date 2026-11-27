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
#include <hardware/intbits.h>
#include <exec/interrupts.h>
#include <graphics/view.h>
#include "x25519.h"
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
static void out_hex(UWORD v) { char b[5]; int i; for (i = 3; i >= 0; i--) { int n = v & 15; b[i] = (char)(n < 10 ? '0' + n : 'a' + n - 10); v >>= 4; } b[4] = 0; out(b); }
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

/* ---- Copper-driven execution ---------------------------------------------------------
 * One Copper block (88 bytes) per blit:
 *   WAIT 0,0 with BFD=0        -> waits until the Blitter is idle
 *   MOVEs: BLTCON0/1, masks, pointers, modulos, BLTSIZE (starts the blit), 2 NOOPs
 *   MOVE COP1LCH/COP1LCL       -> next block, so that the hardware restart at vertical blank
 *                                 resumes the chain where it is (worst case: one blit re-issued;
 *                                 all chained blits are idempotent, whitening stays CPU-driven)
 * The terminator sets INTREQ AUD3 as the done flag (CPU polls INTREQR; COPER is unusable because
 * the system Copper list sets it every frame) and waits forever.  No CPU cycle is spent per blit.
 * Requirements (see docs/TOOLCHAIN.md): COPCON CDANG, GfxBase->LOFlist/SHFlist parked on an idle
 * list for the duration, no console output while the Blitter is owned.                          */
#define COP_BLOCK_WORDS 44          /* WAIT + 21 MOVEs = 22 instructions of 2 words = 88 bytes */
#define COP_BLOCK_BYTES (COP_BLOCK_WORDS * 2)
#define COP_KEYHI 11                /* word index of the BLTCPTH payload (patched per round) */
#define COP_KEYLO 13

static void cop_build(UWORD *list, uint8_t *arena, const ba_blit *p, int n, int round)
{
    int i;
    for (i = 0; i < n; i++) {
        const ba_blit *e = &p[i];
        UWORD *w = list + i * COP_BLOCK_WORDS;
        ULONG a = (ULONG)(arena + e->a), b = (ULONG)(arena + e->b), c = (ULONG)(arena + e->c + ((e->flags & 1) ? (ULONG)round * 256 : 0)), d = (ULONG)(arena + e->d);
        ULONG next = (ULONG)(w + COP_BLOCK_WORDS);
        int j = 0;
        w[j++] = 0x0001; w[j++] = 0x0000;                   /* WAIT, BFD = 0 */
        w[j++] = 0x0040; w[j++] = e->con0;
        w[j++] = 0x0042; w[j++] = e->con1;
        w[j++] = 0x0044; w[j++] = 0xffff;
        w[j++] = 0x0046; w[j++] = 0xffff;
        w[j++] = 0x0048; w[j++] = (UWORD)(c >> 16); w[j++] = 0x004a; w[j++] = (UWORD)c;
        w[j++] = 0x004c; w[j++] = (UWORD)(b >> 16); w[j++] = 0x004e; w[j++] = (UWORD)b;
        w[j++] = 0x0050; w[j++] = (UWORD)(a >> 16); w[j++] = 0x0052; w[j++] = (UWORD)a;
        w[j++] = 0x0054; w[j++] = (UWORD)(d >> 16); w[j++] = 0x0056; w[j++] = (UWORD)d;
        w[j++] = 0x0060; w[j++] = e->cmod;
        w[j++] = 0x0062; w[j++] = e->bmod;
        w[j++] = 0x0064; w[j++] = e->amod;
        w[j++] = 0x0066; w[j++] = e->dmod;
        w[j++] = 0x0058; w[j++] = e->size;                  /* starts the blit */
        w[j++] = 0x01fe; w[j++] = 0; w[j++] = 0x01fe; w[j++] = 0;   /* NOOPs: BBUSY settles before the next WAIT */
        w[j++] = 0x0080; w[j++] = (UWORD)(next >> 16);
        w[j++] = 0x0082; w[j++] = (UWORD)next;
    }
    { UWORD *w = list + n * COP_BLOCK_WORDS;
      w[0] = 0x0001; w[1] = 0x0000;                         /* wait for the last blit */
      w[2] = 0x009c; w[3] = 0x8400;                         /* INTREQ: set AUD3 = chain done */
      w[4] = 0xffff; w[5] = 0xfffe; }                       /* wait forever */
}

/* patch the key pointer payloads for a new round */
static void cop_patch_keys(UWORD *list, uint8_t *arena, const ba_blit *p, int n, int round)
{
    int i;
    for (i = 0; i < n; i++) {
        if (!(p[i].flags & 1)) continue;
        { ULONG c = (ULONG)(arena + p[i].c + (ULONG)round * 256); UWORD *w = list + i * COP_BLOCK_WORDS; w[COP_KEYHI] = (UWORD)(c >> 16); w[COP_KEYLO] = (UWORD)c; }
    }
}

/* CPU work done while the Copper drives the Blitter */
enum { WORK_FE16 = 0, WORK_AES = 1, WORK_GHASH = 2 };
static int cop_timeouts;
static UWORD *cop_idle;      /* 2-word idle Copper list in Chip RAM (WAIT $FFFF,$FFFE) */
static void cop_park(void) { CUSTOM->cop1lc = (ULONG)cop_idle; CUSTOM->copjmp1 = 0; }
static ULONG cop_work_count;
static const aes_key *cop_work_key; static const aes_gcm_key *cop_work_gkey;
static uint8_t cop_work_buf[16384];
static void cop_run(UWORD *list, int kind)
{
    static fe16 ma, mb, mh;
    static uint8_t y[16];
    ULONG guard = 0, t_start = ticks_now();
    if (cop_timeouts) return;                               /* chain broken: skip the rest */
    CUSTOM->intreq = INTF_AUD3;
    CUSTOM->cop1lc = (ULONG)list;
    CUSTOM->copjmp1 = 0;
    while (!(CUSTOM->intreqr & INTF_AUD3)) {
        switch (kind) {
        case WORK_AES:   { uint8_t *b = cop_work_buf + ((cop_work_count & 1023) << 4); aes_encrypt_block(cop_work_key, b, b); } break;
        case WORK_GHASH: ghash_mul_tab(y, cop_work_buf + ((cop_work_count & 1023) << 4), &cop_work_gkey->m[0][0]); break;
        default:         fe16_mul(mh, ma, mb); break;
        }
        cop_work_count++;
        if ((++guard & 31) == 0 && ticks_now() - t_start > 200) { cop_timeouts++; cop_park(); break; }   /* 4 s: chain broken */
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
    /* ---- Copper-driven runs: Blitter chain issued by the Copper, CPU free for other work ---- */
    {
        UWORD *lst_tin, *lst_sbox, *lst_mix, *lst_fin, *lst_tout;
        ULONG sz_tin = (BA_NTIN + 1) * COP_BLOCK_BYTES, sz_sbox = (BA_NSBOX + 1) * COP_BLOCK_BYTES, sz_mix = (BA_NMIX + 1) * COP_BLOCK_BYTES,
              sz_fin = (BA_NFINAL + 1) * COP_BLOCK_BYTES, sz_tout = (BA_NTOUT + 1) * COP_BLOCK_BYTES;
        cop_idle = (UWORD *)AllocMem(8, MEMF_CHIP);
        lst_tin = (UWORD *)AllocMem(sz_tin, MEMF_CHIP); lst_sbox = (UWORD *)AllocMem(sz_sbox, MEMF_CHIP);
        lst_mix = (UWORD *)AllocMem(sz_mix, MEMF_CHIP); lst_fin = (UWORD *)AllocMem(sz_fin, MEMF_CHIP); lst_tout = (UWORD *)AllocMem(sz_tout, MEMF_CHIP);
        if (lst_tin && lst_sbox && lst_mix && lst_fin && lst_tout && cop_idle) {
            /* runs: 0 = display on / fe16, 1..3 = display off / fe16, 4 = display off / AES blocks, 5 = display off / GHASH */
            enum { NRUNS = 6 };
            static const int run_disp[NRUNS] = { 0, 1, 1, 1, 1, 1 }, run_kind[NRUNS] = { WORK_FE16, WORK_FE16, WORK_FE16, WORK_FE16, WORK_AES, WORK_GHASH };
            ULONG r_ticks[NRUNS], r_work[NRUNS], idle_rate[3], tt0, tt1; int r_bad[NRUNS], run; UWORD r_dma[NRUNS];
            UWORD *old_lof, *old_shf, olddma;
            static aes_gcm_key gk;
            aes_gcm_set_key(&gk, key, 256);
            cop_work_key = &k; cop_work_gkey = &gk;
            /* idle rates: work units per tick with nothing else running */
            cop_work_count = 0; tt0 = ticks_now(); { static fe16 ma, mb, mh; for (i = 0; i < 500; i++) fe16_mul(mh, ma, mb); } tt1 = ticks_now(); idle_rate[0] = 500UL * 1000 / ((tt1 - tt0) ? (tt1 - tt0) : 1);
            tt0 = ticks_now(); for (i = 0; i < 200; i++) aes_encrypt_block(&k, cop_work_buf + 16 * i, cop_work_buf + 16 * i); tt1 = ticks_now(); idle_rate[1] = 200UL * 1000 / ((tt1 - tt0) ? (tt1 - tt0) : 1);
            tt0 = ticks_now(); { static uint8_t y[16]; for (i = 0; i < 500; i++) ghash_mul_tab(y, cop_work_buf + 16 * (i & 1023), &gk.m[0][0]); } tt1 = ticks_now(); idle_rate[2] = 500UL * 1000 / ((tt1 - tt0) ? (tt1 - tt0) : 1);
            ba_setup(&k, arena);
            cop_build(lst_tin, arena, ba_prog + BA_SEC_TIN, BA_NTIN, 0);
            cop_build(lst_sbox, arena, ba_prog + BA_SEC_SBOX, BA_NSBOX, 0);
            cop_build(lst_mix, arena, ba_prog + BA_SEC_MIX, BA_NMIX, 1);
            cop_build(lst_fin, arena, ba_prog + BA_SEC_FINAL, BA_NFINAL, k.rounds);
            cop_build(lst_tout, arena, ba_prog + BA_SEC_TOUT, BA_NTOUT, 0);
            OwnBlitter();
            WaitBlit();
            /* the gfx VBL server writes COP1LC = LOFlist/SHFlist every frame; park them on an idle list.
               The chain rewrites COP1LC after every blit, so its value wins within < 0.5 ms of each VBL. */
            old_lof = GfxBase->LOFlist; old_shf = GfxBase->SHFlist;
            cop_idle[0] = 0xffff; cop_idle[1] = 0xfffe;
            GfxBase->LOFlist = cop_idle; GfxBase->SHFlist = cop_idle;
            for (run = 0; run < NRUNS; run++) {
                for (i = 0; i < (int)sizeof in; i++) arena[BA_STATE + i] = in[i];
                ba_exec_asm(arena, ba_prog + BA_SEC_WHITE, BA_NWHITE, 0);     /* whitening in place: not idempotent -> CPU-driven */
                cop_work_count = 0; cop_timeouts = 0;
                olddma = CUSTOM->dmaconr; r_dma[run] = olddma;
                if (run_disp[run]) CUSTOM->dmacon = DMAF_RASTER | DMAF_SPRITE;  /* bitplane + sprite DMA off */
                CUSTOM->copcon = 2;                                             /* CDANG: Copper may write Blitter registers */
                t0 = ticks_now();
                cop_run(lst_tin, run_kind[run]);
                for (rnd = 1; rnd < k.rounds; rnd++) {
                    cop_run(lst_sbox, run_kind[run]);
                    cop_patch_keys(lst_mix, arena, ba_prog + BA_SEC_MIX, BA_NMIX, rnd);
                    cop_run(lst_mix, run_kind[run]);
                }
                cop_run(lst_sbox, run_kind[run]);
                cop_run(lst_fin, run_kind[run]);
                cop_run(lst_tout, run_kind[run]);
                t1 = ticks_now(); r_ticks[run] = t1 - t0; r_work[run] = cop_work_count;
                cop_park();
                CUSTOM->copcon = 0;
                if (run_disp[run]) CUSTOM->dmacon = DMAF_SETCLR | (olddma & (DMAF_RASTER | DMAF_SPRITE));
                r_bad[run] = 0;
                for (i = 0; i < BA_BLOCKS; i++) {
                    int j;
                    aes_encrypt_block(&k, in + 16 * i, want);
                    for (j = 0; j < 16; j++) if (want[j] != arena[BA_STATE + 16 * i + j]) { r_bad[run]++; break; }
                }
                if (cop_timeouts) r_bad[run] = -1;
            }
            GfxBase->LOFlist = old_lof; GfxBase->SHFlist = old_shf;             /* VBL server restores the system list */
            WaitTOF(); WaitTOF();
            DisownBlitter();
            /* no out() while the Blitter is owned: the console renders text with it (deadlock) */
            out("\n--- Copper-driven chain (no CPU per blit) ---\n");
            for (run = 0; run < NRUNS; run++) {
                ULONG idle_units = r_ticks[run] * idle_rate[run_kind[run]] / 1000;
                out(run_disp[run] ? "display DMA off, " : "display DMA on,  ");
                out(run_kind[run] == WORK_AES ? "CPU: AES blocks  " : run_kind[run] == WORK_GHASH ? "CPU: GHASH       " : "CPU: fe16_mul    ");
                out(r_bad[run] ? "FAIL " : "PASS "); if (r_bad[run] > 0) { out_dec(r_bad[run]); out(" bad blocks "); } if (r_bad[run] < 0) out("TIMEOUT ");
                out_dec(r_ticks[run]); out(" ticks = "); out_dec(16384UL * 50 / (r_ticks[run] ? r_ticks[run] : 1)); out(" B/s blitter; CPU did ");
                out_dec(r_work[run]); out(" of "); out_dec(idle_units); out(" idle units = "); out_dec(r_work[run] * 100 / (idle_units ? idle_units : 1)); out(" % CPU free");
                if (run_kind[run] == WORK_AES) { out("; combined AES-256 "); out_dec((16384UL + 16UL * r_work[run]) * 50 / (r_ticks[run] ? r_ticks[run] : 1)); out(" B/s"); }
                if (run_kind[run] == WORK_GHASH) { out("; GHASH blocks/s "); out_dec(r_work[run] * 50 / (r_ticks[run] ? r_ticks[run] : 1)); }
                out("; DMACONR before 0x"); out_hex(r_dma[run]); out("\n");
                ok &= r_bad[run] == 0;
            }
        } else out("no Chip RAM for Copper lists\n");
        if (cop_idle) FreeMem(cop_idle, 8); if (lst_tout) FreeMem(lst_tout, sz_tout); if (lst_tin) FreeMem(lst_tin, sz_tin);
        if (lst_sbox) FreeMem(lst_sbox, sz_sbox); if (lst_mix) FreeMem(lst_mix, sz_mix); if (lst_fin) FreeMem(lst_fin, sz_fin);
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
