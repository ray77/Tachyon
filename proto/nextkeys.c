/* Tachyon - key material for the next connection: see nextkeys.h */
#include "nextkeys.h"
#include "sha256.h"
#include "x25519.h"
#include "ed25519.h"

static void nk_cp(uint8_t *d, const uint8_t *s, uint32_t n) { uint32_t i; for (i = 0; i < n; i++) d[i] = s[i]; }

void wa_nextkeys_compute(wa_nextkeys *k, hmac_drbg *rng, const uint8_t *server_static)
{
    uint32_t i;
    drbg_generate(rng, k->tls_priv, 32);
    x25519_base_comb(k->tls_pub, k->tls_priv);
    drbg_generate(rng, k->eph_priv, 32);
    x25519_base_comb(k->eph_pub, k->eph_priv);
    if (server_static) {
        nk_cp(k->server_static, server_static, 32);
        x25519_ref(k->es, k->eph_priv, server_static);
        k->have_es = 1;
    } else {
        for (i = 0; i < 32; i++) k->server_static[i] = k->es[i] = 0;
        k->have_es = 0;
    }
}

uint32_t wa_nextkeys_write(uint8_t *out, uint32_t cap, const wa_nextkeys *k)
{
    uint8_t h[32];
    if (cap < WA_NEXTKEYS_SIZE) return 0;
    out[0] = WA_NEXTKEYS_VERSION;
    out[1] = k->have_es ? 1u : 0u;
    nk_cp(out + 2, k->tls_priv, 32); nk_cp(out + 34, k->tls_pub, 32);
    nk_cp(out + 66, k->eph_priv, 32); nk_cp(out + 98, k->eph_pub, 32);
    nk_cp(out + 130, k->server_static, 32); nk_cp(out + 162, k->es, 32);
    sha256(h, out, WA_NEXTKEYS_SIZE - 32);
    nk_cp(out + WA_NEXTKEYS_SIZE - 32, h, 32);
    return WA_NEXTKEYS_SIZE;
}

int wa_nextkeys_read(wa_nextkeys *k, const uint8_t *in, uint32_t len)
{
    uint8_t h[32]; uint32_t i, d = 0;
    if (len != WA_NEXTKEYS_SIZE || in[0] != WA_NEXTKEYS_VERSION || (in[1] & ~1u)) return 0;
    sha256(h, in, WA_NEXTKEYS_SIZE - 32);
    for (i = 0; i < 32; i++) d |= (uint32_t)(h[i] ^ in[WA_NEXTKEYS_SIZE - 32 + i]);
    if (d) return 0;
    nk_cp(k->tls_priv, in + 2, 32); nk_cp(k->tls_pub, in + 34, 32);
    nk_cp(k->eph_priv, in + 66, 32); nk_cp(k->eph_pub, in + 98, 32);
    nk_cp(k->server_static, in + 130, 32); nk_cp(k->es, in + 162, 32);
    k->have_es = in[1] & 1u;
    return 1;
}

void wa_nextkeys_wipe(wa_nextkeys *k)
{
    volatile uint8_t *p = (volatile uint8_t *)k; uint32_t i;
    for (i = 0; i < sizeof *k; i++) p[i] = 0;
}
