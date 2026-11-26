/*
 * Host-side tests for SHA-512, the Edwards group operations, Ed25519 (RFC 8032)
 * and libsignal-style XEdDSA verification.
 *
 *   cc -O2 -Icrypto/ref tests/ed25519_test.c crypto/ref/x25519_ref.c crypto/ref/sha512.c crypto/ref/ed25519.c -o build/ed25519_test
 *   build/ed25519_test tests/vectors
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "x25519.h"
#include "sha512.h"
#include "ed25519.h"

static int failures;

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int unhex(uint8_t *out, const char *hex, int maxlen)
{
    int n = 0;
    while (hex[0] && hex[1] && hexval(hex[0]) >= 0 && hexval(hex[1]) >= 0 && n < maxlen) {
        out[n++] = (uint8_t)(hexval(hex[0]) * 16 + hexval(hex[1]));
        hex += 2;
    }
    return n;
}
static void dump(const char *tag, const uint8_t *b, int n)
{
    int i; printf("  %-6s", tag); for (i = 0; i < n; i++) printf("%02x", b[i]); printf("\n");
}
static void result(int ok, const char *name)
{
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) failures++;
}

/* --- constants: d and sqrt(-1) must match what the field arithmetic computes --- */
static void test_constants(void)
{
    fe16 a, b, c, one, pm1;
    uint8_t bytes[32];
    static const uint8_t d_bytes[32] = {
        0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,0xab,0xd8,0x41,0x41,0x4d,0x0a,0x70,0x00,
        0x98,0xe8,0x79,0x77,0x79,0x40,0xc7,0x8c,0x73,0xfe,0x6f,0x2b,0xee,0x6c,0x03,0x52 };
    static const uint8_t sqrtm1_bytes[32] = {
        0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
        0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b };
    int i;
    /* d = -121665 / 121666 */
    for (i = 0; i < 16; i++) { a[i] = 0; b[i] = 0; one[i] = 0; }
    one[0] = 1;
    a[0] = 121665 & 0xffff; a[1] = 121665 >> 16;
    b[0] = 121666 & 0xffff; b[1] = 121666 >> 16;
    fe16_invert(b, b);
    fe16_mul(c, a, b);
    for (i = 0; i < 16; i++) a[i] = 0;
    fe16_sub(c, a, c);    /* d = 0 - 121665/121666 */
    fe16_tobytes(bytes, c);
    result(memcmp(bytes, d_bytes, 32) == 0, "constant d = -121665/121666");
    if (memcmp(bytes, d_bytes, 32) != 0) dump("got", bytes, 32);
    /* sqrt(-1)^2 == p - 1 */
    fe16_frombytes(a, sqrtm1_bytes);
    fe16_sqr(a, a);
    for (i = 0; i < 16; i++) pm1[i] = 0xffff;
    pm1[0] = 0xffec; pm1[15] = 0x7fff;   /* p - 1 */
    fe16_tobytes(bytes, a);
    fe16_tobytes((uint8_t *)b, pm1);     /* reuse b as byte buffer */
    result(memcmp(bytes, (uint8_t *)b, 32) == 0, "constant sqrt(-1)^2 = -1");
}

/* --- group: basepoint decode/encode roundtrip, [L]B = identity, 2B = B + B --- */
static void test_group(void)
{
    static const uint8_t B[32] = { 0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
                                   0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66 };
    static const uint8_t L[32] = { 0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
                                   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10 };
    static const uint8_t two[32] = { 2 };
    static const uint8_t id[32] = { 1 };
    ge_p3 P, Q, R;
    uint8_t out[32];
    result(ge_frombytes(&P, B), "basepoint decodes");
    ge_tobytes(out, &P);
    result(memcmp(out, B, 32) == 0, "basepoint encode roundtrip");
    ge_dbl(&Q, &P);
    ge_add(&R, &P, &P);
    ge_tobytes(out, &Q);
    { uint8_t out2[32]; ge_tobytes(out2, &R); result(memcmp(out, out2, 32) == 0, "2B via dbl == B + B"); }
    ge_scalarmult(&Q, two, &P);
    { uint8_t out2[32]; ge_tobytes(out2, &Q); result(memcmp(out, out2, 32) == 0, "[2]B == 2B"); }
    ge_scalarmult(&Q, L, &P);
    ge_tobytes(out, &Q);
    result(memcmp(out, id, 32) == 0, "[L]B == identity");
    if (memcmp(out, id, 32) != 0) dump("got", out, 32);
    { uint8_t bad[32] = { 2 }; result(ge_frombytes(&Q, bad) == 0, "decode rejects y = 2 (not on curve)"); }
    { uint8_t m1[32]; memset(m1, 0xff, 32); m1[0] = 0xec; m1[31] = 0x7f; result(ge_frombytes(&Q, m1) == 1, "decode accepts y = -1 (order-2 point)"); m1[31] |= 0x80; result(ge_frombytes(&Q, m1) == 0, "decode rejects x = 0 with sign bit"); }
}

/* --- RFC 8032 section 7.1 --- */
static void rfc_vector(const char *name, const char *pk_hex, const char *msg_hex, const char *sig_hex)
{
    uint8_t pk[32], sig[64], msg[128];
    int mlen = unhex(msg, msg_hex, 128);
    unhex(pk, pk_hex, 32); unhex(sig, sig_hex, 64);
    result(ed25519_verify(sig, msg, (uint32_t)mlen, pk), name);
    sig[0] ^= 1;
    result(!ed25519_verify(sig, msg, (uint32_t)mlen, pk), "  ... rejects flipped R bit");
    sig[0] ^= 1; sig[40] ^= 0x10;
    result(!ed25519_verify(sig, msg, (uint32_t)mlen, pk), "  ... rejects flipped S bit");
}

static void test_rfc8032(void)
{
    rfc_vector("RFC 8032 TEST 1 (empty)",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    rfc_vector("RFC 8032 TEST 2 (1 byte)",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    rfc_vector("RFC 8032 TEST 3 (2 bytes)",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
        "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
    rfc_vector("RFC 8032 TEST SHA(abc)",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");
}

/* --- vector files --- */
static void test_sha512_file(const char *path)
{
    FILE *f = fopen(path, "r"); char line[4096]; int n = 0, bad = 0;
    if (!f) { printf("SKIP %s\n", path); return; }
    while (fgets(line, sizeof line, f)) {
        uint8_t msg[1024], want[64], got[64]; int mlen; char *sp = strchr(line, ' ');
        if (!sp) continue;
        *sp = 0; mlen = unhex(msg, line, 1024); unhex(want, sp + 1, 64);
        sha512(got, msg, (uint32_t)mlen); n++;
        if (memcmp(got, want, 64)) { bad++; if (bad < 3) { printf("FAIL sha512 vector %d (len %d)\n", n, mlen); dump("want", want, 64); dump("got", got, 64); } }
    }
    fclose(f); if (bad) failures++;
    printf("%s sha512 random vectors: %d checked, %d mismatches\n", bad ? "FAIL" : "PASS", n, bad);
}

static void test_sig_file(const char *path, int (*verify)(const uint8_t *, const uint8_t *, uint32_t, const uint8_t *), const char *name)
{
    FILE *f = fopen(path, "r"); char line[4096]; int n = 0, bad = 0, valid = 0;
    if (!f) { printf("SKIP %s\n", path); return; }
    while (fgets(line, sizeof line, f)) {
        uint8_t pk[32], msg[512], sig[64]; int mlen, want, got;
        char *f1 = strchr(line, ' '), *f2, *f3;
        if (!f1) continue; *f1++ = 0;
        f2 = strchr(f1, ' '); if (!f2) continue; *f2++ = 0;
        f3 = strchr(f2, ' '); if (!f3) continue; *f3++ = 0;
        unhex(pk, line, 32); mlen = unhex(msg, f1, 512); unhex(sig, f2, 64); want = atoi(f3);
        got = verify(sig, msg, (uint32_t)mlen, pk); n++; valid += want;
        if (got != want) { bad++; if (bad < 3) { printf("FAIL %s vector %d: want %d got %d (msg len %d)\n", name, n, want, got, mlen); dump("pk", pk, 32); dump("sig", sig, 64); } }
    }
    fclose(f); if (bad) failures++;
    printf("%s %s random vectors: %d checked (%d valid, %d invalid), %d mismatches\n", bad ? "FAIL" : "PASS", name, n, valid, n - valid, bad);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : "tests/vectors";
    char path[512];
    test_constants();
    test_group();
    test_rfc8032();
    snprintf(path, sizeof path, "%s/sha512_random.txt", dir); test_sha512_file(path);
    snprintf(path, sizeof path, "%s/ed25519_random.txt", dir); test_sig_file(path, ed25519_verify, "ed25519");
    snprintf(path, sizeof path, "%s/xeddsa_random.txt", dir); test_sig_file(path, xeddsa_verify, "xeddsa");
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
