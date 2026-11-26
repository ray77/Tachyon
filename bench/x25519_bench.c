/*
 * WhatsBench - X25519 on the Amiga 500 (Kickstart 1.3, 68000).
 *
 * Verifies the implementation against RFC 7748 vectors on the target, then
 * times field operations and a full X25519 scalar multiplication. Results go
 * to the console and to SYS:result.txt; SYS:done is created last so the host
 * side (tools/run-fsuae.sh) knows the run is complete.
 *
 * Timing uses dos.library DateStamp() (1/50 s ticks on PAL); operations are
 * repeated so the quantisation error stays below 1 %. A CIA based microsecond
 * timer can replace this later.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <dos/dos.h>
#include <dos/dosextens.h>
#include <proto/exec.h>
#include <proto/dos.h>
#include "x25519.h"

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;

static BPTR con, logfile;

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

static void out(const char *s)
{
    int n = slen(s);
    if (con) Write(con, (APTR)s, n);
    if (logfile) Write(logfile, (APTR)s, n);
}

static void out_hex(const uint8_t *b, int n)
{
    static const char hx[] = "0123456789abcdef";
    char buf[3];
    int i;
    buf[2] = 0;
    for (i = 0; i < n; i++) {
        buf[0] = hx[b[i] >> 4];
        buf[1] = hx[b[i] & 15];
        out(buf);
    }
}

static void out_dec(ULONG v)
{
    char buf[12];
    int i = 11;
    buf[i] = 0;
    do { buf[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    out(buf + i);
}

/* elapsed time in 1/50 s ticks */
static ULONG ticks_now(void)
{
    struct DateStamp ds;
    DateStamp(&ds);
    return (ULONG)ds.ds_Days * (24UL * 60UL * 60UL * 50UL)
         + (ULONG)ds.ds_Minute * (60UL * 50UL)
         + (ULONG)ds.ds_Tick;
}

/* print "<name>: <total ticks> ticks for <n> ops = <us> us/op" */
static void report(const char *name, ULONG ticks, ULONG n)
{
    ULONG us = ticks * 20000UL / n;   /* 1 tick = 20000 us; ticks < 2^17 so no overflow */
    out(name); out(": ");
    out_dec(ticks); out(" ticks / "); out_dec(n); out(" ops = ");
    out_dec(us); out(" us/op\n");
}

static void unhex(uint8_t out[32], const char *hex)
{
    int i;
    for (i = 0; i < 32; i++) {
        int hi = hex[2 * i], lo = hex[2 * i + 1];
        hi = hi <= '9' ? hi - '0' : hi - 'a' + 10;
        lo = lo <= '9' ? lo - '0' : lo - 'a' + 10;
        out[i] = (uint8_t)(hi * 16 + lo);
    }
}

/* xorshift32, deterministic test inputs */
static uint32_t rng = 0x2545F491UL;
static uint16_t rnd16(void)
{
    rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
    return (uint16_t)rng;
}

/* asm backends vs portable C: results must be limb-for-limb identical */
static int compare_sqr(void)
{
    fe16 a, c1, c2;
    int t, i, bad = 0;
    for (t = 0; t < 1000; t++) {
        for (i = 0; i < 16; i++) a[i] = (t & 1) ? 0xFFFF : rnd16();
        if ((t & 7) == 4) { for (i = 0; i < 16; i++) a[i] = 0; a[t & 15] = (uint16_t)(1 + t); }
        fe16_sqr_c(c1, a);
        fe16_sqr(c2, a);
        for (i = 0; i < 16; i++) if (c1[i] != c2[i]) { bad++; break; }
        if (bad == 1 && c1[i] != c2[i]) {
            out("  mismatch at test "); out_dec((ULONG)t); out("\n  a    "); out_hex((uint8_t *)a, 32);
            out("\n  c    "); out_hex((uint8_t *)c1, 32); out("\n  asm  "); out_hex((uint8_t *)c2, 32); out("\n");
        }
    }
    out(bad ? "FAIL " : "PASS "); out("fe16_sqr asm == C on 1000 inputs");
    if (bad) { out(" ("); out_dec((ULONG)bad); out(" mismatches)"); }
    out("\n");
    return bad == 0;
}

/* generic asm-vs-C comparison on 1000 inputs (random, 0xFFFF limbs, sparse) */
#define COMPARE_BINARY(NAME, CFN, AFN)                                              \
static int compare_##NAME(void)                                                     \
{                                                                                   \
    fe16 a, b, c1, c2;                                                              \
    int t, i, bad = 0;                                                              \
    for (t = 0; t < 1000; t++) {                                                    \
        for (i = 0; i < 16; i++) {                                                  \
            a[i] = (t & 1) ? 0xFFFF : rnd16();                                      \
            b[i] = (t & 2) ? 0xFFFF : rnd16();                                      \
            if ((t & 7) == 4) { a[i] = 0; b[i] = 0; }                               \
        }                                                                           \
        if ((t & 7) == 4) { a[t & 15] = (uint16_t)(1 + t); b[(t >> 4) & 15] = 0xFFFF; } \
        CFN(c1, a, b);                                                              \
        AFN(c2, a, b);                                                              \
        for (i = 0; i < 16; i++) if (c1[i] != c2[i]) { bad++; break; }              \
        if (bad == 1 && i < 16) {                                                   \
            out("  mismatch at test "); out_dec((ULONG)t);                          \
            out("\n  a    "); out_hex((uint8_t *)a, 32);                            \
            out("\n  b    "); out_hex((uint8_t *)b, 32);                            \
            out("\n  c    "); out_hex((uint8_t *)c1, 32);                           \
            out("\n  asm  "); out_hex((uint8_t *)c2, 32); out("\n");               \
        }                                                                           \
    }                                                                               \
    out(bad ? "FAIL " : "PASS "); out(#AFN " asm == C on 1000 inputs");             \
    if (bad) { out(" ("); out_dec((ULONG)bad); out(" mismatches)"); }               \
    out("\n");                                                                      \
    return bad == 0;                                                                \
}

#define COMPARE_UNARY(NAME, CFN, AFN)                                               \
static int compare_##NAME(void)                                                     \
{                                                                                   \
    fe16 a, c1, c2;                                                                 \
    int t, i, bad = 0;                                                              \
    for (t = 0; t < 1000; t++) {                                                    \
        for (i = 0; i < 16; i++) a[i] = (t & 1) ? 0xFFFF : rnd16();                 \
        if ((t & 7) == 4) { for (i = 0; i < 16; i++) a[i] = 0; a[t & 15] = (uint16_t)(1 + t); } \
        CFN(c1, a);                                                                 \
        AFN(c2, a);                                                                 \
        for (i = 0; i < 16; i++) if (c1[i] != c2[i]) { bad++; break; }              \
        if (bad == 1 && i < 16) {                                                   \
            out("  mismatch at test "); out_dec((ULONG)t);                          \
            out("\n  a    "); out_hex((uint8_t *)a, 32);                            \
            out("\n  c    "); out_hex((uint8_t *)c1, 32);                           \
            out("\n  asm  "); out_hex((uint8_t *)c2, 32); out("\n");               \
        }                                                                           \
    }                                                                               \
    out(bad ? "FAIL " : "PASS "); out(#AFN " asm == C on 1000 inputs");             \
    if (bad) { out(" ("); out_dec((ULONG)bad); out(" mismatches)"); }               \
    out("\n");                                                                      \
    return bad == 0;                                                                \
}

COMPARE_BINARY(add, fe16_add_c, fe16_add)
COMPARE_BINARY(sub, fe16_sub_c, fe16_sub)
COMPARE_UNARY(mul121665, fe16_mul121665_c, fe16_mul121665)

static int compare_mul(void)
{
    fe16 a, b, c1, c2;
    int t, i, bad = 0;
    for (t = 0; t < 1000; t++) {
        for (i = 0; i < 16; i++) {
            /* mix in extreme limbs so carries and the 2^256 folds are exercised */
            a[i] = (t & 1) ? 0xFFFF : rnd16();
            b[i] = (t & 2) ? 0xFFFF : rnd16();
            if ((t & 7) == 4) { a[i] = 0; b[i] = 0; }
        }
        if ((t & 7) == 4) { a[0] = 1; b[0] = 1; }
        fe16_mul_c(c1, a, b);
        fe16_mul(c2, a, b);
        for (i = 0; i < 16; i++) if (c1[i] != c2[i]) { bad++; break; }
        if (bad == 1 && c1[i] != c2[i]) {
            out("  mismatch at test "); out_dec((ULONG)t); out("\n  a    "); out_hex((uint8_t *)a, 32);
            out("\n  b    "); out_hex((uint8_t *)b, 32); out("\n  c    "); out_hex((uint8_t *)c1, 32);
            out("\n  asm  "); out_hex((uint8_t *)c2, 32); out("\n");
        }
    }
    out(bad ? "FAIL " : "PASS "); out("fe16_mul asm == C on 1000 inputs");
    if (bad) { out(" ("); out_dec((ULONG)bad); out(" mismatches)"); }
    out("\n");
    return bad == 0;
}

static int check(const char *name, const char *k_hex, const char *u_hex, const char *want_hex, ULONG *ticks)
{
    uint8_t k[32], u[32], want[32], got[32];
    ULONG t0, t1;
    int i, ok = 1;
    unhex(k, k_hex); unhex(u, u_hex); unhex(want, want_hex);
    t0 = ticks_now();
    x25519_ref(got, k, u);
    t1 = ticks_now();
    *ticks = t1 - t0;
    for (i = 0; i < 32; i++) if (got[i] != want[i]) ok = 0;
    out(ok ? "PASS " : "FAIL "); out(name); out("\n");
    if (!ok) { out("  want "); out_hex(want, 32); out("\n  got  "); out_hex(got, 32); out("\n"); }
    return ok;
}

int main(void)
{
    fe16 a, b, c;
    ULONG t0, t1, n, x25519_ticks;
    int i, ok = 1;
    BPTR done;

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    con = Output();
    logfile = Open((STRPTR)"SYS:result.txt", MODE_NEWFILE);

    out("WhatsBench X25519 (CPU000: field arithmetic in 68000 asm, ladder in C, radix 2^16, vbcc)\n");
    out("ExecBase version "); out_dec(SysBase->LibNode.lib_Version); out("\n");

    /* correctness on target */
    ok &= compare_mul();
    ok &= compare_sqr();
    ok &= compare_add();
    ok &= compare_sub();
    ok &= compare_mul121665();
    ok &= check("RFC 7748 5.2 #1",
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", &x25519_ticks);
    report("x25519", x25519_ticks, 1);
    ok &= check("RFC 7748 6.1 shared secret",
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", &x25519_ticks);
    report("x25519", x25519_ticks, 1);

    /* field operation micro-benchmarks */
    for (i = 0; i < 16; i++) { a[i] = (uint16_t)(0x1234 * (i + 1)); b[i] = (uint16_t)(0x9876 ^ (i * 0x1111)); }

    n = 2000;
    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_mul_c(c, a, b);
    t1 = ticks_now();
    report("fe16_mul_c", t1 - t0, n);

    n = 5000;
    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_mul(c, a, b);
    t1 = ticks_now();
    report("fe16_mul (asm)", t1 - t0, n);
    n = 2000;

    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_sqr(c, a);
    t1 = ticks_now();
    report("fe16_sqr (asm)", t1 - t0, n);

    n = 20000;
    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_add(c, a, b);
    t1 = ticks_now();
    report("fe16_add (asm)", t1 - t0, n);

    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_sub(c, a, b);
    t1 = ticks_now();
    report("fe16_sub (asm)", t1 - t0, n);

    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_mul121665(c, a);
    t1 = ticks_now();
    report("fe16_mul121665 (asm)", t1 - t0, n);

    n = 5000;
    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_add_c(c, a, b);
    t1 = ticks_now();
    report("fe16_add_c", t1 - t0, n);
    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_sub_c(c, a, b);
    t1 = ticks_now();
    report("fe16_sub_c", t1 - t0, n);
    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_mul121665_c(c, a);
    t1 = ticks_now();
    report("fe16_mul121665_c", t1 - t0, n);

    out(ok ? "RESULT: all vectors passed\n" : "RESULT: VECTOR MISMATCH\n");

    if (logfile) Close(logfile);
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
    return ok ? 0 : 10;
}
