/*
 * Host test of proto/clientpayload.c: the registration and login ClientPayload built here for the fixed test
 * identity must equal whatsmeow's proto.Marshal output byte for byte (tools/pairvectors -mode clientpayload,
 * make clientpayload-test). Also wa_parse_u64 and the identity generator's self-consistency.
 *   clientpayload_test build/clientpayload_ref.bin
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "clientpayload.h"
#include "identity.h"
#include "x25519.h"
#include "ed25519.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static void pattern(uint8_t *b, int mul, int add, int n) { int i; for (i = 0; i < n; i++) b[i] = (uint8_t)(i * mul + add); }
static void clamp(uint8_t *k) { k[0] &= 248; k[31] &= 127; k[31] |= 64; }

/* the fixed test identity of tools/pairvectors/main.go */
void test_identity(wa_identity *id)
{
    memset(id, 0, sizeof *id);
    pattern(id->noise_priv, 3, 1, 32); clamp(id->noise_priv); x25519_base_comb(id->noise_pub, id->noise_priv);
    pattern(id->ident_priv, 5, 2, 32); clamp(id->ident_priv); x25519_base_comb(id->ident_pub, id->ident_priv);
    pattern(id->spk_priv, 7, 3, 32);   clamp(id->spk_priv);   x25519_base_comb(id->spk_pub, id->spk_priv);
    pattern(id->spk_sig, 1, 0x40, 64);
    id->spk_id = 1; id->reg_id = 0x1234;
    pattern(id->adv_secret, 1, 0xA0, 32);
}

static uint8_t *read_chunk(FILE *f, uint32_t *len)
{
    uint8_t l[4]; uint8_t *p;
    if (fread(l, 1, 4, f) != 4) return 0;
    *len = ((uint32_t)l[0] << 24) | ((uint32_t)l[1] << 16) | ((uint32_t)l[2] << 8) | l[3];
    p = malloc(*len + 1);
    if (fread(p, 1, *len, f) != *len) return 0;
    return p;
}

static void compare(const char *name, const uint8_t *got, uint32_t glen, const uint8_t *want, uint32_t wlen)
{
    int ok = glen == wlen && memcmp(got, want, glen) == 0;
    CHECK(ok);
    if (!ok) {
        uint32_t i;
        printf("  %s: got %u bytes, want %u\n  got  ", name, glen, wlen);
        for (i = 0; i < glen; i++) printf("%02x", got[i]);
        printf("\n  want ");
        for (i = 0; i < wlen; i++) printf("%02x", want[i]);
        printf("\n");
        for (i = 0; i < glen && i < wlen && got[i] == want[i]; i++) ;
        printf("  first difference at byte %u\n", i);
    } else printf("ok: %s matches whatsmeow (%u bytes)\n", name, glen);
}

int main(int argc, char **argv)
{
    static uint8_t out[WA_CLIENTPAYLOAD_MAX];
    wa_identity id; FILE *f; uint8_t *ref; uint32_t rlen, n, hi, lo;
    if (argc != 2) { printf("usage: clientpayload_test <clientpayload_ref.bin>\n"); return 2; }
    f = fopen(argv[1], "rb");
    if (!f) { printf("cannot open %s\n", argv[1]); return 2; }
    test_identity(&id);

    n = wa_clientpayload_registration(out, sizeof out, &id);
    ref = read_chunk(f, &rlen); CHECK(ref != 0);
    if (ref) compare("registration ClientPayload", out, n, ref, rlen);
    n = wa_clientpayload_login(out, sizeof out, "4917612345678", 7);
    ref = read_chunk(f, &rlen); CHECK(ref != 0);
    if (ref) compare("login ClientPayload", out, n, ref, rlen);
    fclose(f);

    /* too small buffers report 0, not a partial payload */
    CHECK(wa_clientpayload_registration(out, 100, &id) == 0);
    CHECK(wa_clientpayload_login(out, 20, "4917612345678", 7) == 0);

    /* 64-bit decimal parsing with 32-bit arithmetic */
    CHECK(wa_parse_u64("4917612345678", &hi, &lo) && hi == 0x478u && lo == 0xf889794eu);  /* 4917612345678 = 0x478_F889794E */
    CHECK(wa_parse_u64("0", &hi, &lo) && hi == 0 && lo == 0);
    CHECK(wa_parse_u64("4294967296", &hi, &lo) && hi == 1 && lo == 0);
    CHECK(wa_parse_u64("18446744073709551615", &hi, &lo) && hi == 0xffffffffu && lo == 0xffffffffu);
    CHECK(!wa_parse_u64("18446744073709551616", &hi, &lo));
    CHECK(!wa_parse_u64("12a", &hi, &lo));
    CHECK(!wa_parse_u64("", &hi, &lo));

    /* a generated identity is self-consistent; a damaged one is not */
    {
        static const uint8_t seed[48] = "clientpayload_test seed, not a secret..........";
        hmac_drbg rng; wa_identity g;
        drbg_instantiate(&rng, seed, 48);
        wa_identity_generate(&g, &rng);
        CHECK(wa_identity_check(&g));
        CHECK(g.reg_id >= 1 && g.reg_id <= 0xffff && g.spk_id == 1);
        CHECK((g.ident_priv[0] & 7) == 0 && (g.ident_priv[31] & 0xc0) == 0x40);
        g.spk_sig[10] ^= 1; CHECK(!wa_identity_check(&g)); g.spk_sig[10] ^= 1;
        g.noise_pub[0] ^= 1; CHECK(!wa_identity_check(&g)); g.noise_pub[0] ^= 1;
        CHECK(wa_identity_check(&g));
        /* base64 */
        { char b[48]; uint8_t t[3] = { 'M', 'a', 'n' };
          CHECK(wa_base64(b, t, 3) == 4 && strcmp(b, "TWFu") == 0);
          CHECK(wa_base64(b, t, 2) == 4 && strcmp(b, "TWE=") == 0);
          CHECK(wa_base64(b, t, 1) == 4 && strcmp(b, "TQ==") == 0);
          CHECK(wa_base64(b, g.noise_pub, 32) == 44 && b[43] == '='); }
    }
    printf("%s: %d checks, %d failures\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails ? 1 : 0;
}
