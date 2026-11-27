/* RSA-2048 public operations against Go crypto/rsa vectors (tools/genvectors -mode rsa) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rsa.h"

static int failures;
static int unhex(uint8_t *out, const char *h, int maxlen)
{
    int n = 0;
    while (h[0] && h[1] && n < maxlen) { char t[3] = { h[0], h[1], 0 }; out[n++] = (uint8_t)strtoul(t, 0, 16); h += 2; }
    return n;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/vectors/rsa_random.txt", "r");
    static char line[8192];
    int n = 0, bad = 0;
    if (!f) { printf("FAIL cannot open vector file\n"); return 1; }
    while (fgets(line, sizeof line, f)) {
        char *tok[7]; char *p = line; int i;
        static uint8_t nn[256], msg[1024], sig[256], x[256], xe[256], got[256];
        static rsa_pub k;
        int msgl, valid;
        uint32_t e;
        for (i = 0; i < 7; i++) { tok[i] = p; p = strpbrk(p, " \n"); if (!p) { i++; break; } *p++ = 0; }
        if (i < 7) break;
        unhex(nn, tok[0], 256); e = (uint32_t)strtoul(tok[1], 0, 16); msgl = unhex(msg, tok[2], 1024); unhex(sig, tok[3], 256);
        valid = atoi(tok[4]); unhex(x, tok[5], 256); unhex(xe, tok[6], 256);
        if (!rsa_pub_set(&k, nn, 256, e)) { printf("  vector %d: rsa_pub_set failed\n", n); bad++; n++; continue; }
        if (!rsa_public_op(&k, x, got) || memcmp(got, xe, 256)) { printf("  vector %d: x^e mod n\n", n); bad++; }
        if (rsa_verify_pkcs1_sha256(&k, msg, (uint32_t)msgl, sig, 256) != valid) { printf("  vector %d: verify (expected %d)\n", n, valid); bad++; }
        msg[0] ^= 1;
        if (valid && rsa_verify_pkcs1_sha256(&k, msg, (uint32_t)msgl, sig, 256)) { printf("  vector %d: accepts modified message\n", n); bad++; }
        n++;
    }
    fclose(f);
    printf("%s rsa-2048 Go vectors: %d keys, %d mismatches\n", bad ? "FAIL" : "PASS", n, bad);
    if (bad || n == 0) failures++;

    /* RSASSA-PSS (SHA-256, MGF1-SHA256, salt 32 = TLS 1.3 rsa_pss_rsae_sha256): tools/genvectors -mode rsapss */
    f = fopen(argc > 2 ? argv[2] : "tests/vectors/rsa_pss.txt", "r");
    if (!f) { printf("FAIL cannot open PSS vector file\n"); return 1; }
    n = bad = 0;
    while (fgets(line, sizeof line, f)) {
        char *tok[5]; char *p = line; int i;
        static uint8_t nn[256], msg[1024], sig[256];
        static rsa_pub k;
        int msgl, valid;
        uint32_t e;
        for (i = 0; i < 5; i++) { tok[i] = p; p = strpbrk(p, " \n"); if (!p) { i++; break; } *p++ = 0; }
        if (i < 5) break;
        unhex(nn, tok[0], 256); e = (uint32_t)strtoul(tok[1], 0, 16); msgl = unhex(msg, tok[2], 1024); unhex(sig, tok[3], 256);
        valid = atoi(tok[4]);
        if (!rsa_pub_set(&k, nn, 256, e)) { printf("  pss vector %d: rsa_pub_set failed\n", n); bad++; n++; continue; }
        if (rsa_verify_pss_sha256(&k, msg, (uint32_t)msgl, sig, 256) != valid) { printf("  pss vector %d: verify (expected %d)\n", n, valid); bad++; }
        msg[0] ^= 1;
        if (valid && rsa_verify_pss_sha256(&k, msg, (uint32_t)msgl, sig, 256)) { printf("  pss vector %d: accepts modified message\n", n); bad++; }
        msg[0] ^= 1; sig[255] ^= 1;
        if (valid && rsa_verify_pss_sha256(&k, msg, (uint32_t)msgl, sig, 256)) { printf("  pss vector %d: accepts modified signature\n", n); bad++; }
        if (rsa_verify_pss_sha256(&k, msg, (uint32_t)msgl, sig, 255)) { printf("  pss vector %d: accepts short signature\n", n); bad++; }
        n++;
    }
    fclose(f);
    printf("%s rsa-pss-sha256 Go vectors: %d keys, %d mismatches\n", bad ? "FAIL" : "PASS", n, bad);
    if (bad || n == 0) failures++;
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
