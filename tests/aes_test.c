/* AES (FIPS 197 appendix C), AES-GCM (McGrew/Viega test cases 1-4, 13-16) and Go vectors */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"

static int failures;
static int hexval(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }
static int unhex(uint8_t *o, const char *h) { int n = 0; while (h[0] && h[1] && h[0] != ' ' && h[0] != '\n') { o[n++] = (uint8_t)(hexval(h[0]) * 16 + hexval(h[1])); h += 2; } return n; }
static void dump(const char *t, const uint8_t *b, int n) { int i; printf("  %-4s", t); for (i = 0; i < n; i++) printf("%02x", b[i]); printf("\n"); }
static void result(int ok, const char *name) { printf("%s %s\n", ok ? "PASS" : "FAIL", name); if (!ok) failures++; }

static void gcm_case(const char *name, int bits, const char *key_hex, const char *iv_hex, const char *aad_hex,
                     const char *pt_hex, const char *ct_hex, const char *tag_hex)
{
    uint8_t key[32], iv[12], aad[64], pt[128], ct[128], want_ct[128], tag[16], want_tag[16], back[128];
    int aadlen = unhex(aad, aad_hex), len = unhex(pt, pt_hex), ok;
    aes_gcm_key k;
    unhex(key, key_hex); unhex(iv, iv_hex); unhex(want_ct, ct_hex); unhex(want_tag, tag_hex);
    aes_gcm_set_key(&k, key, bits);
    aes_gcm_encrypt(&k, iv, aad, (uint32_t)aadlen, pt, (uint32_t)len, ct, tag);
    ok = memcmp(ct, want_ct, (size_t)len) == 0 && memcmp(tag, want_tag, 16) == 0;
    result(ok, name);
    if (!ok) { dump("ct", ct, len); dump("tag", tag, 16); }
    result(aes_gcm_decrypt(&k, iv, aad, (uint32_t)aadlen, ct, (uint32_t)len, tag, back) == 1 && memcmp(back, pt, (size_t)len) == 0, "  ... decrypt roundtrip");
    tag[3] ^= 0x80;
    result(aes_gcm_decrypt(&k, iv, aad, (uint32_t)aadlen, ct, (uint32_t)len, tag, back) == 0, "  ... rejects bad tag");
}

static void go_file(const char *path)
{
    FILE *f = fopen(path, "r"); char line[8192]; int n = 0, bad = 0;
    if (!f) { printf("SKIP %s\n", path); return; }
    while (fgets(line, sizeof line, f)) {
        /* <keybits> <key> <iv> <aad> <pt> <ct> <tag> ; empty fields are "-" */
        char *fld[7]; int i, bits, aadlen, len; uint8_t key[32], iv[12], aad[256], pt[2048], ct[2048], want_ct[2048], tag[16], want_tag[16];
        aes_gcm_key k;
        fld[0] = strtok(line, " \n"); for (i = 1; i < 7; i++) fld[i] = strtok(NULL, " \n");
        if (!fld[6]) continue;
        bits = atoi(fld[0]); unhex(key, fld[1]); unhex(iv, fld[2]);
        aadlen = strcmp(fld[3], "-") ? unhex(aad, fld[3]) : 0;
        len = strcmp(fld[4], "-") ? unhex(pt, fld[4]) : 0;
        unhex(want_ct, fld[5]); unhex(want_tag, fld[6]);
        aes_gcm_set_key(&k, key, bits);
        aes_gcm_encrypt(&k, iv, aad, (uint32_t)aadlen, pt, (uint32_t)len, ct, tag);
        n++;
        if (memcmp(ct, want_ct, (size_t)len) || memcmp(tag, want_tag, 16)) { bad++; if (bad < 3) printf("FAIL aes-gcm vector %d (bits %d, len %d, aad %d)\n", n, bits, len, aadlen); }
    }
    fclose(f); if (bad) failures++;
    printf("%s aes-gcm Go vectors: %d checked, %d mismatches\n", bad ? "FAIL" : "PASS", n, bad);
}

int main(int argc, char **argv)
{
    uint8_t key[32], pt[16], ct[16], want[16], back[16];
    aes_key k;
    /* FIPS 197 C.1 / C.3 */
    unhex(key, "000102030405060708090a0b0c0d0e0f"); unhex(pt, "00112233445566778899aabbccddeeff"); unhex(want, "69c4e0d86a7b0430d8cdb78070b4c55a");
    aes_set_key(&k, key, 128); aes_encrypt_block(&k, pt, ct); result(memcmp(ct, want, 16) == 0, "AES-128 FIPS 197 C.1 encrypt");
    aes_decrypt_block(&k, ct, back); result(memcmp(back, pt, 16) == 0, "AES-128 decrypt");
    unhex(key, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"); unhex(want, "8ea2b7ca516745bfeafc49904b496089");
    aes_set_key(&k, key, 256); aes_encrypt_block(&k, pt, ct); result(memcmp(ct, want, 16) == 0, "AES-256 FIPS 197 C.3 encrypt");
    aes_decrypt_block(&k, ct, back); result(memcmp(back, pt, 16) == 0, "AES-256 decrypt");

    gcm_case("GCM test case 1 (AES-128, empty)", 128, "00000000000000000000000000000000", "000000000000000000000000", "", "", "", "58e2fccefa7e3061367f1d57a4e7455a");
    gcm_case("GCM test case 2 (AES-128, 1 zero block)", 128, "00000000000000000000000000000000", "000000000000000000000000", "", "00000000000000000000000000000000", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf");
    gcm_case("GCM test case 3 (AES-128, 4 blocks)", 128, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985", "4d5c2af327cd64a62cf35abd2ba6fab4");
    gcm_case("GCM test case 4 (AES-128, AAD, 60 bytes)", 128, "feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091", "5bc94fbc3221a5db94fae95ae7121a47");
    gcm_case("GCM test case 14 (AES-256, 1 zero block)", 256, "0000000000000000000000000000000000000000000000000000000000000000", "000000000000000000000000", "", "00000000000000000000000000000000", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919");

    {   /* table-driven GHASH against the bitwise reference, random H / y / x */
        static aes_gcm_key g;
        uint8_t y1[16], y2[16], x[16], kk[32];
        int t, i, bad = 0;
        uint32_t st = 0x12345678u;
        for (t = 0; t < 300; t++) {
            for (i = 0; i < 32; i++) { st = st * 1103515245u + 12345u; kk[i] = (uint8_t)(st >> 16); }
            for (i = 0; i < 16; i++) { st = st * 1103515245u + 12345u; y1[i] = (uint8_t)(st >> 16); y2[i] = y1[i]; }
            for (i = 0; i < 16; i++) { st = st * 1103515245u + 12345u; x[i] = (uint8_t)(st >> 16); }
            aes_gcm_set_key(&g, kk, 256);
            ghash_mul_bit(y1, x, g.h);
            ghash_mul_tab_c(y2, x, &g);
            if (memcmp(y1, y2, 16)) bad++;
        }
        result(bad == 0, "GHASH Shoup tables == bitwise reference (300 random)");
    }
    go_file(argc > 1 ? argv[1] : "tests/vectors/aesgcm_random.txt");
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
