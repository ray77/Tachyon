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
#include "sha512.h"
#include "ed25519.h"
#include "sha256.h"
#include "aes.h"
#include "xeddsa_vector.h"


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

/* throughput: "<name>: <bytes> bytes in <ticks> ticks = <bytes/s>" */
static void report_bps(const char *name, ULONG ticks, ULONG bytes)
{
    ULONG bps = ticks ? (bytes / ticks) * 50UL : 0;
    out(name); out(": "); out_dec(bytes); out(" bytes / "); out_dec(ticks); out(" ticks = ");
    out_dec(bps); out(" bytes/s\n");
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

#include "blitter_bench.c"

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

COMPARE_BINARY(mul_comba, fe16_mul_c, fe16_mul_comba)
COMPARE_BINARY(mul_kara, fe16_mul_c, fe16_mul_kara)
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
    ok &= compare_mul_comba();
    ok &= compare_mul_kara();
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
    for (i = 0; i < (int)n; i++) fe16_mul_comba(c, a, b);
    t1 = ticks_now();
    report("fe16_mul_comba (asm)", t1 - t0, n);
    t0 = ticks_now();
    for (i = 0; i < (int)n; i++) fe16_mul_kara(c, a, b);
    t1 = ticks_now();
    report("fe16_mul_kara (asm)", t1 - t0, n);
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

    /* signatures: SHA-512, Ed25519 (RFC 8032 TEST 3), XEdDSA (libsignal vector) */
    {
        static const uint8_t pk3[32] = { 0xfc,0x51,0xcd,0x8e,0x62,0x18,0xa1,0xa3,0x8d,0xa4,0x7e,0xd0,0x02,0x30,0xf0,0x58,
                                         0x08,0x16,0xed,0x13,0xba,0x33,0x03,0xac,0x5d,0xeb,0x91,0x15,0x48,0x90,0x80,0x25 };
        static const uint8_t msg3[2] = { 0xaf, 0x82 };
        uint8_t sig3[64] = { 0x62,0x91,0xd6,0x57,0xde,0xec,0x24,0x02,0x48,0x27,0xe6,0x9c,0x3a,0xbe,0x01,0xa3,
                                          0x0c,0xe5,0x48,0xa2,0x84,0x74,0x3a,0x44,0x5e,0x36,0x80,0xd7,0xdb,0x5a,0xc3,0xac,
                                          0x18,0xff,0x9b,0x53,0x8d,0x16,0xf2,0x90,0xae,0x67,0xf7,0x60,0x98,0x4d,0xc6,0x59,
                                          0x4a,0x7c,0x15,0xe9,0x71,0x6e,0xd2,0x8d,0xc0,0x27,0xbe,0xce,0xea,0x1e,0xc4,0x0a };
        static const uint8_t abc[3] = { 'a', 'b', 'c' };
        static const uint8_t abc_hash0[8] = { 0xdd,0xaf,0x35,0xa1,0x93,0x61,0x7a,0xba };
        uint8_t digest[64];
        int r;
        n = 200;
        t0 = ticks_now();
        for (i = 0; i < (int)n; i++) sha512(digest, abc, 3);
        t1 = ticks_now();
        r = 1; for (i = 0; i < 8; i++) if (digest[i] != abc_hash0[i]) r = 0;
        out(r ? "PASS " : "FAIL "); out("sha512(abc)\n"); ok &= r;
        report("sha512 (1 block, C)", t1 - t0, n);

        t0 = ticks_now();
        r = ed25519_verify(sig3, msg3, 2, pk3);
        t1 = ticks_now();
        out(r ? "PASS " : "FAIL "); out("ed25519_verify RFC 8032 TEST 3\n"); ok &= r;
        report("ed25519_verify", t1 - t0, 1);

        t0 = ticks_now();
        r = xeddsa_verify(xeddsa_sig, xeddsa_msg, XEDDSA_MSG_LEN, xeddsa_pk);
        t1 = ticks_now();
        out(r ? "PASS " : "FAIL "); out("xeddsa_verify libsignal vector\n"); ok &= r;
        report("xeddsa_verify", t1 - t0, 1);

        sig3[0] ^= 1;
        r = ed25519_verify(sig3, msg3, 2, pk3);
        out(!r ? "PASS " : "FAIL "); out("ed25519_verify rejects corrupted signature\n"); ok &= !r;
    }

    /* key generation: constant-time comb vs Montgomery ladder */
    {
        static const uint8_t alice[32] = { 0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,0x66,0x45,
                                           0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,0x1d,0xb9,0x2c,0x2a };
        static const uint8_t alice_pub[32] = { 0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a,
                                               0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a };
        uint8_t pub[32];
        int r = 1;
        t0 = ticks_now();
        x25519_base_comb(pub, alice);
        t1 = ticks_now();
        for (i = 0; i < 32; i++) if (pub[i] != alice_pub[i]) r = 0;
        out(r ? "PASS " : "FAIL "); out("x25519_base_comb RFC 7748 Alice public key\n"); ok &= r;
        report("x25519_base_comb (keygen)", t1 - t0, 1);
    }

    /* symmetric primitives: correctness on target + throughput (C reference) */
    {
        static uint8_t buf[1024], buf2[1024];
        uint8_t key[32], iv[12], tag[16], h[32];
        static const uint8_t abc256[8] = { 0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea };
        static const uint8_t gcm_tc2_tag[16] = { 0xab,0x6e,0x47,0xd4,0x2c,0xec,0x13,0xbd,0xf5,0x3a,0x67,0xb2,0x12,0x57,0xbd,0xdf };
        static aes_gcm_key gk;
        int r, reps = 8;

        sha256(h, (const uint8_t *)"abc", 3);
        r = 1; for (i = 0; i < 8; i++) if (h[i] != abc256[i]) r = 0;
        out(r ? "PASS " : "FAIL "); out("sha256(abc)\n"); ok &= r;
        /* asm block vs C block on 200 pseudo-random blocks and states */
        {
            uint32_t s1[8], s2[8];
            int t, bad = 0;
            for (t = 0; t < 200 && !bad; t++) {
                for (i = 0; i < 64; i++) buf[i] = (uint8_t)rnd16();
                for (i = 0; i < 8; i++) { s1[i] = ((uint32_t)rnd16() << 16) | rnd16(); s2[i] = s1[i]; }
                sha256_block_c(s1, buf);
                sha256_block(s2, buf);
                for (i = 0; i < 8; i++) if (s1[i] != s2[i]) bad = 1;
            }
            out(bad ? "FAIL " : "PASS "); out("sha256_block asm == C on 200 blocks\n"); ok &= !bad;
        }
        for (i = 0; i < 1024; i++) buf[i] = (uint8_t)i;
        reps = 32;
        t0 = ticks_now();
        for (i = 0; i < reps; i++) sha256(h, buf, 1024);
        t1 = ticks_now();
        report_bps("sha256 (asm block)", t1 - t0, 1024UL * reps);
        t0 = ticks_now();
        for (i = 0; i < reps; i++) { uint32_t st[8]; int j; for (j = 0; j < 8; j++) st[j] = j; for (j = 0; j < 16; j++) sha256_block_c(st, buf + 64 * j); }
        t1 = ticks_now();
        report_bps("sha256 (C block)", t1 - t0, 1024UL * reps);
        reps = 8;
        t0 = ticks_now();
        for (i = 0; i < reps; i++) hmac_sha256(h, key, 32, buf, 1024);
        t1 = ticks_now();
        report_bps("hmac-sha256", t1 - t0, 1024UL * reps);

        for (i = 0; i < 32; i++) key[i] = 0;
        for (i = 0; i < 12; i++) iv[i] = 0;
        for (i = 0; i < 16; i++) buf2[i] = 0;
        aes_gcm_set_key(&gk, key, 128);
        aes_gcm_encrypt(&gk, iv, buf2, 0, buf2, 16, buf2, tag);
        r = 1; for (i = 0; i < 16; i++) if (tag[i] != gcm_tc2_tag[i]) r = 0;
        out(r ? "PASS " : "FAIL "); out("aes-128-gcm test case 2\n"); ok &= r;

        /* asm vs C: AES-256 encrypt/decrypt blocks and GHASH on random keys/blocks */
        {
            uint8_t o1[16], o2[16], y1[16], y2[16];
            int t, bade = 0, badd = 0, badg = 0;
            for (t = 0; t < 100; t++) {
                for (i = 0; i < 32; i++) key[i] = (uint8_t)rnd16();
                for (i = 0; i < 16; i++) buf[i] = (uint8_t)rnd16();
                aes_gcm_set_key(&gk, key, 256);
                aes_encrypt_block_c(&gk.k, buf, o1);
                aes_encrypt_block(&gk.k, buf, o2);
                for (i = 0; i < 16; i++) if (o1[i] != o2[i]) bade = 1;
                aes_decrypt_block_c(&gk.k, buf, o1);
                aes_decrypt_block(&gk.k, buf, o2);
                for (i = 0; i < 16; i++) if (o1[i] != o2[i]) badd = 1;
                for (i = 0; i < 16; i++) { y1[i] = (uint8_t)rnd16(); y2[i] = y1[i]; buf2[i] = (uint8_t)rnd16(); }
                ghash_mul_bit(y1, buf2, gk.h);
                ghash_mul_tab(y2, buf2, &gk.m[0][0]);
                for (i = 0; i < 16; i++) if (y1[i] != y2[i]) badg = 1;
            }
            /* localisation aid: x = 0x80 in byte 0 (= 1 in GF) must give H itself */
            for (i = 0; i < 16; i++) { y1[i] = 0; buf2[i] = 0; }
            buf2[0] = 0x80;
            ghash_mul_tab(y1, buf2, &gk.m[0][0]);
            r = 1; for (i = 0; i < 16; i++) if (y1[i] != gk.h[i]) r = 0;
            out(r ? "PASS " : "FAIL "); out("ghash_mul_tab(e0) == H\n"); ok &= r;
            if (!r) { out("  got "); out_hex(y1, 16); out("\n  H   "); out_hex(gk.h, 16); out("\n"); }
            out(bade ? "FAIL " : "PASS "); out("aes_enc_block asm == C on 100 keys/blocks\n"); ok &= !bade;
            out(badd ? "FAIL " : "PASS "); out("aes_dec_block asm == C on 100 keys/blocks\n"); ok &= !badd;
            out(badg ? "FAIL " : "PASS "); out("ghash_mul_tab asm == bitwise on 100 inputs\n"); ok &= !badg;
        }

        for (i = 0; i < 32; i++) key[i] = (uint8_t)i;
        t0 = ticks_now();
        aes_gcm_set_key(&gk, key, 256);
        t1 = ticks_now();
        report("aes_gcm_set_key (AES-256 + GHASH tables)", t1 - t0, 1);
        reps = 500;
        t0 = ticks_now();
        for (i = 0; i < reps; i++) aes_encrypt_block(&gk.k, buf, buf2);
        t1 = ticks_now();
        report("aes-256 block encrypt (asm)", t1 - t0, (ULONG)reps);
        t0 = ticks_now();
        for (i = 0; i < reps; i++) aes_decrypt_block(&gk.k, buf, buf2);
        t1 = ticks_now();
        report("aes-256 block decrypt (asm)", t1 - t0, (ULONG)reps);
        t0 = ticks_now();
        for (i = 0; i < reps; i++) ghash_mul_tab(tag, buf, &gk.m[0][0]);
        t1 = ticks_now();
        report("ghash block (asm)", t1 - t0, (ULONG)reps);
        reps = 8;
        t0 = ticks_now();
        for (i = 0; i < reps; i++) aes_gcm_encrypt(&gk, iv, buf, 0, buf, 1024, buf2, tag);
        t1 = ticks_now();
        report_bps("aes-256-gcm encrypt", t1 - t0, 1024UL * reps);
        t0 = ticks_now();
        for (i = 0; i < reps; i++) aes_cbc_decrypt(&gk.k, (const uint8_t *)key, buf, 1024, buf2);
        t1 = ticks_now();
        report_bps("aes-256-cbc decrypt", t1 - t0, 1024UL * reps);
    }

    blitter_bench();

    out(ok ? "RESULT: all vectors passed\n" : "RESULT: VECTOR MISMATCH\n");

    if (logfile) Close(logfile);
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
    return ok ? 0 : 10;
}
