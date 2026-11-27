/* Companion identity (see identity.h). */
#include "identity.h"
#include "ed25519.h"

static void clamp(uint8_t k[32]) { k[0] &= 248; k[31] &= 127; k[31] |= 64; }

static void keypair(uint8_t priv[32], uint8_t pub[32], hmac_drbg *rng)
{
    drbg_generate(rng, priv, 32);
    clamp(priv);
    x25519_base_comb(pub, priv);
}

static void spk_message(uint8_t m[33], const uint8_t pub[32]) { int i; m[0] = 0x05; for (i = 0; i < 32; i++) m[1 + i] = pub[i]; }

void wa_identity_generate(wa_identity *id, hmac_drbg *rng)
{
    uint8_t rnd[64], m[33], two[2];
    keypair(id->noise_priv, id->noise_pub, rng);
    keypair(id->ident_priv, id->ident_pub, rng);
    keypair(id->spk_priv, id->spk_pub, rng);
    id->spk_id = WA_SPK_ID;
    spk_message(m, id->spk_pub);
    drbg_generate(rng, rnd, 64);
    xeddsa_sign(id->spk_sig, m, 33, id->ident_priv, rnd);
    drbg_generate(rng, two, 2);
    id->reg_id = ((uint32_t)two[0] << 8) | two[1];
    if (id->reg_id == 0) id->reg_id = 1;
    drbg_generate(rng, id->adv_secret, 32);
}

int wa_identity_check(const wa_identity *id)
{
    uint8_t pub[32], m[33]; int i, d = 0;
    x25519_base_comb(pub, id->noise_priv); for (i = 0; i < 32; i++) d |= pub[i] ^ id->noise_pub[i];
    x25519_base_comb(pub, id->ident_priv); for (i = 0; i < 32; i++) d |= pub[i] ^ id->ident_pub[i];
    x25519_base_comb(pub, id->spk_priv);   for (i = 0; i < 32; i++) d |= pub[i] ^ id->spk_pub[i];
    if (d) return 0;
    spk_message(m, id->spk_pub);
    return xeddsa_verify(id->spk_sig, m, 33, id->ident_pub);
}

uint32_t wa_base64(char *out, const uint8_t *in, uint32_t n)
{
    static const char tab[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t i, o = 0;
    for (i = 0; i + 2 < n; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = tab[(v >> 18) & 63]; out[o++] = tab[(v >> 12) & 63]; out[o++] = tab[(v >> 6) & 63]; out[o++] = tab[v & 63];
    }
    if (i < n) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < n) v |= (uint32_t)in[i + 1] << 8;
        out[o++] = tab[(v >> 18) & 63]; out[o++] = tab[(v >> 12) & 63];
        out[o++] = i + 1 < n ? tab[(v >> 6) & 63] : '=';
        out[o++] = '=';
    }
    out[o] = 0;
    return o;
}
