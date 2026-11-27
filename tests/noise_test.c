/* Noise_XX (WhatsApp dialect) client path against vectors from whatsmeow's NoiseHandshake
 * (tools/genvectors -mode noise). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "noise.h"
#include "x25519.h"
#include "ed25519.h"
#include "../bench/xeddsa_vector.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }

static int unhex(uint8_t *out, const char *h, int maxlen)
{
    int n = 0;
    while (h[0] && h[1] && n < maxlen) {
        char t[3] = { h[0], h[1], 0 };
        out[n++] = (uint8_t)strtoul(t, 0, 16); h += 2;
    }
    return n;
}

int main(int argc, char **argv)
{
    FILE *f = fopen(argc > 1 ? argv[1] : "tests/vectors/noise_random.txt", "r");
    static char line[16384];
    int n = 0, bad = 0;
    if (!f) { printf("FAIL cannot open vector file\n"); return 1; }
    while (fgets(line, sizeof line, f)) {
        char *tok[17]; char *p = line; int i;
        static uint8_t header[8], ceph[32], cst[32], seph[32], sst[32], cert[1024], cpl[1024];
        static uint8_t sephpub[32], sstct[64], certct[1100], sstpub[32], cstct[64], cplct[1100], wk[32], rk[32], frame[1024], framect[1100];
        static uint8_t cephpub[32], cstpub[32], st_out[32], cert_out[1100], cstct_out[48], cplct_out[1100], fct[1100], fpt[1100];
        int hl, certl, cpll, certctl, cplctl, framel, framectl;
        noise_hs hs; noise_transport t;
        for (i = 0; i < 17; i++) { tok[i] = p; p = strpbrk(p, " \n"); if (!p) { i++; break; } *p++ = 0; }
        if (i < 17) break;
        hl = unhex(header, tok[0], 8); unhex(ceph, tok[1], 32); unhex(cst, tok[2], 32); unhex(seph, tok[3], 32); unhex(sst, tok[4], 32);
        certl = unhex(cert, tok[5], 1024); cpll = unhex(cpl, tok[6], 1024);
        unhex(sephpub, tok[7], 32); unhex(sstct, tok[8], 64); certctl = unhex(certct, tok[9], 1100);
        unhex(sstpub, tok[10], 32); unhex(cstct, tok[11], 64); cplctl = unhex(cplct, tok[12], 1100);
        unhex(wk, tok[13], 32); unhex(rk, tok[14], 32); framel = unhex(frame, tok[15], 1024); framectl = unhex(framect, tok[16], 1100);

        x25519_ref_base(cephpub, ceph);
        x25519_ref_base(cstpub, cst);
        noise_client_hello(&hs, header, (uint32_t)hl, cephpub);
        if (!noise_client_finish(&hs, ceph, cst, cstpub, sephpub, sstct, 48, certct, (uint32_t)certctl,
                                 cpl, (uint32_t)cpll, st_out, cert_out, cstct_out, cplct_out, &t, 0, 0)) { bad++; printf("  vector %d: handshake failed\n", n); n++; continue; }
        {   /* es computed before the connection from the (correct / wrong / absent) stored server static: same
             * ciphertexts and transport keys in every case, the precomputed DH used only on a match */
            noise_es_pre pre; noise_hs hs2; noise_transport t2; int used = -1, k;
            static uint8_t c2[48], p2[1100], s2[32], o2[1024], f2[1100];
            noise_es_precompute(&pre, ceph, sstpub);
            noise_client_hello(&hs2, header, (uint32_t)hl, cephpub);
            if (!noise_client_finish(&hs2, ceph, cst, cstpub, sephpub, sstct, 48, certct, (uint32_t)certctl, cpl, (uint32_t)cpll,
                                     s2, o2, c2, p2, &t2, &pre, &used) || used != 1) { bad++; printf("  vector %d: precomputed es not used\n", n); }
            if (memcmp(c2, cstct, 48) || memcmp(p2, cplct, (size_t)cplctl)) { bad++; printf("  vector %d: precomputed es: ciphertexts differ\n", n); }
            noise_transport_encrypt(&t2, frame, (uint32_t)framel, f2);
            if (memcmp(f2, framect, (size_t)framectl)) { bad++; printf("  vector %d: precomputed es: transport differs\n", n); }
            pre.server_static[7] ^= 1;                                   /* stored key differs: ladder runs, result identical */
            noise_client_hello(&hs2, header, (uint32_t)hl, cephpub);
            if (!noise_client_finish(&hs2, ceph, cst, cstpub, sephpub, sstct, 48, certct, (uint32_t)certctl, cpl, (uint32_t)cpll,
                                     s2, o2, c2, p2, &t2, &pre, &used) || used != 0) { bad++; printf("  vector %d: stale es taken\n", n); }
            if (memcmp(c2, cstct, 48) || memcmp(p2, cplct, (size_t)cplctl)) { bad++; printf("  vector %d: stale es fallback: ciphertexts differ\n", n); }
            pre.valid = 0; used = -1;
            noise_client_hello(&hs2, header, (uint32_t)hl, cephpub);
            if (!noise_client_finish(&hs2, ceph, cst, cstpub, sephpub, sstct, 48, certct, (uint32_t)certctl, cpl, (uint32_t)cpll,
                                     s2, o2, c2, p2, &t2, &pre, &used) || used != 0 || memcmp(p2, cplct, (size_t)cplctl)) { bad++; printf("  vector %d: invalid pre\n", n); }
            (void)k;
        }
        if (memcmp(st_out, sstpub, 32)) { bad++; printf("  vector %d: server static\n", n); }
        if (memcmp(cert_out, cert, (size_t)certl)) { bad++; printf("  vector %d: cert payload\n", n); }
        if (memcmp(cstct_out, cstct, 48)) { bad++; printf("  vector %d: client static ct\n", n); }
        if (memcmp(cplct_out, cplct, (size_t)cplctl)) { bad++; printf("  vector %d: client payload ct\n", n); }
        /* transport: first frame client -> server, and the server -> client direction decrypts what the
         * read key encrypts (sanity, both sides derived here) */
        noise_transport_encrypt(&t, frame, (uint32_t)framel, fct);
        if (memcmp(fct, framect, (size_t)framectl)) { bad++; printf("  vector %d: transport frame\n", n); }
        {
            aes_gcm_key rkk; uint8_t iv[12] = { 0 };
            aes_gcm_set_key(&rkk, rk, 256);
            aes_gcm_encrypt(&rkk, iv, (const uint8_t *)"", 0, frame, (uint32_t)framel, fct, fct + framel);
            if (!noise_transport_decrypt(&t, fct, (uint32_t)framel + 16, fpt) || memcmp(fpt, frame, (size_t)framel)) { bad++; printf("  vector %d: transport read\n", n); }
            fct[0] ^= 1;
            if (noise_transport_decrypt(&t, fct, (uint32_t)framel + 16, fpt)) { bad++; printf("  vector %d: corrupted frame accepted\n", n); }
        }
        n++;
    }
    fclose(f);
    printf("%s noise_xx whatsmeow vectors: %d handshakes, %d mismatches\n", bad ? "FAIL" : "PASS", n, bad);
    if (bad || n == 0) failures++;
    {   /* a corrupted ServerHello static must be rejected before any key is mixed further */
        static uint8_t z[32], hdr[4] = { 'W', 'A', 6, 3 }, ct[48], cert[16], o1[32], o2[16], o3[48], o4[32];
        noise_hs hs; noise_transport t;
        memset(ct, 0, 48);
        noise_client_hello(&hs, hdr, 4, z);
        result(noise_client_finish(&hs, z, z, z, z, ct, 48, cert, 16, z, 16, o1, o2, o3, o4, &t, 0, 0) == 0, "garbage ServerHello rejected");
    }
    {   /* certificate cache: a verified (root key, details, signature) triple is remembered as one fingerprint; any
         * change to one of the three is a miss, an empty cache is a miss, and a hit does not alter the entry */
        noise_cert_cache c; uint8_t sig2[64], pk2[32], msg2[2]; int i;
        c.valid = 0;
        result(xeddsa_verify(xeddsa_sig, xeddsa_msg, XEDDSA_MSG_LEN, xeddsa_pk), "cache test vector verifies");
        result(!noise_cert_cache_match(&c, xeddsa_pk, xeddsa_msg, XEDDSA_MSG_LEN, xeddsa_sig), "empty cache: miss");
        noise_cert_cache_store(&c, xeddsa_pk, xeddsa_msg, XEDDSA_MSG_LEN, xeddsa_sig);
        result(c.valid && noise_cert_cache_match(&c, xeddsa_pk, xeddsa_msg, XEDDSA_MSG_LEN, xeddsa_sig), "stored entry: hit");
        memcpy(sig2, xeddsa_sig, 64); sig2[5] ^= 1;
        result(!noise_cert_cache_match(&c, xeddsa_pk, xeddsa_msg, XEDDSA_MSG_LEN, sig2), "changed signature: miss");
        memcpy(pk2, xeddsa_pk, 32); pk2[0] ^= 1;
        result(!noise_cert_cache_match(&c, pk2, xeddsa_msg, XEDDSA_MSG_LEN, xeddsa_sig), "different root key: miss");
        msg2[0] = xeddsa_msg[0] ^ 1;
        result(!noise_cert_cache_match(&c, xeddsa_pk, msg2, 1, xeddsa_sig), "changed details: miss");
        msg2[0] = xeddsa_msg[0]; msg2[1] = 0;
        result(!noise_cert_cache_match(&c, xeddsa_pk, msg2, 2, xeddsa_sig), "longer details: miss (length-prefixed)");
        for (i = 0; i < 32; i++) if (c.fp[i]) break;
        result(i < 32 && noise_cert_cache_match(&c, xeddsa_pk, xeddsa_msg, XEDDSA_MSG_LEN, xeddsa_sig), "entry unchanged after misses");
        result(!noise_cert_cache_match(0, xeddsa_pk, xeddsa_msg, XEDDSA_MSG_LEN, xeddsa_sig), "no cache: miss");
    }
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
