/* SHA-256 (FIPS 180-4 examples), HMAC-SHA256 (RFC 4231), HKDF-SHA256 (RFC 5869) */
#include <stdio.h>
#include <string.h>
#include "sha256.h"

static int failures;
static int hexval(char c) { return c <= '9' ? c - '0' : (c | 32) - 'a' + 10; }
static int unhex(uint8_t *o, const char *h) { int n = 0; while (h[0] && h[1]) { o[n++] = (uint8_t)(hexval(h[0]) * 16 + hexval(h[1])); h += 2; } return n; }
static void check(const char *name, const uint8_t *got, const char *want_hex, int n)
{
    uint8_t want[128]; unhex(want, want_hex);
    int ok = memcmp(got, want, n) == 0, i;
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) { printf("  got "); for (i = 0; i < n; i++) printf("%02x", got[i]); printf("\n"); failures++; }
}

int main(void)
{
    uint8_t out[128], key[131], data[256], salt[16], info[16];
    int i, n, kl, dl;

    sha256(out, (const uint8_t *)"abc", 3);
    check("sha256(abc)", out, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", 32);
    sha256(out, (const uint8_t *)"", 0);
    check("sha256()", out, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 32);
    sha256(out, (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
    check("sha256(448-bit)", out, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", 32);

    /* RFC 4231 test case 2 */
    hmac_sha256(out, (const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?", 28);
    check("hmac-sha256 RFC4231 #2", out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", 32);
    /* RFC 4231 test case 7: 131-byte key, long data */
    memset(key, 0xaa, 131);
    dl = (int)strlen("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.");
    hmac_sha256(out, key, 131, (const uint8_t *)"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.", (uint32_t)dl);
    check("hmac-sha256 RFC4231 #7", out, "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", 32);

    /* RFC 5869 test case 1 */
    for (i = 0; i < 22; i++) data[i] = 0x0b;
    for (i = 0; i < 13; i++) salt[i] = (uint8_t)i;
    for (i = 0; i < 10; i++) info[i] = (uint8_t)(0xf0 + i);
    hkdf_sha256(out, 42, salt, 13, data, 22, info, 10);
    check("hkdf-sha256 RFC5869 #1", out, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865", 42);
    /* RFC 5869 test case 3: empty salt and info */
    hkdf_sha256(out, 42, 0, 0, data, 22, info, 0);
    check("hkdf-sha256 RFC5869 #3", out, "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8", 42);

    (void)n; (void)kl;
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
