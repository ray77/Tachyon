/* Tachyon - wa_nextkeys: record round trip, single-bit corruption, truncation, version, key consistency */
#include <stdio.h>
#include <string.h>
#include "nextkeys.h"
#include "x25519.h"

static int fails;
static void check(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) fails++; }

int main(void)
{
    static const uint8_t seed[48] = { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    static uint8_t sstat[32] = { 0x1f, 0x1a, 0x11 }, rec[WA_NEXTKEYS_SIZE], bad[WA_NEXTKEYS_SIZE], pub[32], es[32];
    wa_nextkeys k, k2; hmac_drbg rng; uint32_t i, n, rejected = 0;

    drbg_instantiate(&rng, seed, sizeof seed);
    wa_nextkeys_compute(&k, &rng, sstat);
    x25519_ref_base(pub, k.tls_priv); check(memcmp(pub, k.tls_pub, 32) == 0, "tls_pub = base * tls_priv");
    x25519_ref_base(pub, k.eph_priv); check(memcmp(pub, k.eph_pub, 32) == 0, "eph_pub = base * eph_priv");
    x25519_ref(es, k.eph_priv, sstat); check(k.have_es && memcmp(es, k.es, 32) == 0 && memcmp(k.server_static, sstat, 32) == 0, "es = eph_priv * server static");
    check(memcmp(k.tls_priv, k.eph_priv, 32) != 0, "two different key pairs");

    n = wa_nextkeys_write(rec, sizeof rec, &k);
    check(n == WA_NEXTKEYS_SIZE, "record size 226");
    check(wa_nextkeys_write(rec, WA_NEXTKEYS_SIZE - 1, &k) == 0, "no room: refused");
    memset(&k2, 0xAA, sizeof k2);
    check(wa_nextkeys_read(&k2, rec, n) && memcmp(&k2.tls_priv, &k.tls_priv, 6 * 32) == 0 && k2.have_es == 1, "round trip");
    for (i = 0; i < n; i++) { memcpy(bad, rec, n); bad[i] ^= 1; if (!wa_nextkeys_read(&k2, bad, n)) rejected++; }
    check(rejected == n, "every single-bit corruption rejected");
    check(!wa_nextkeys_read(&k2, rec, n - 1) && !wa_nextkeys_read(&k2, rec, 0), "truncation rejected");
    memcpy(bad, rec, n); bad[1] = 2; check(!wa_nextkeys_read(&k2, bad, n), "unknown flag rejected (checksum)");

    wa_nextkeys_compute(&k, &rng, 0);
    check(!k.have_es, "no server static: no es");
    n = wa_nextkeys_write(rec, sizeof rec, &k);
    check(n && wa_nextkeys_read(&k2, rec, n) && k2.have_es == 0, "round trip without es");
    wa_nextkeys_wipe(&k);
    for (i = 0, n = 0; i < 32; i++) n |= k.tls_priv[i] | k.eph_priv[i] | k.es[i];
    check(n == 0, "wipe clears the private material");

    printf("%s: nextkeys\n", fails ? "FAIL" : "ALL PASSED");
    return fails ? 1 : 0;
}
