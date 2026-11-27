/*
 * Offline test of the pairing protocol code (proto/pairing.c, proto/creds.c) against the synthetic pair-success IQ
 * from tools/pairvectors (-mode pairsuccess: a test account key signs our test identity, HMAC under the test ADV
 * secret) and the recorded pair-device IQ (tests/vectors/pair_device_iq.bin):
 *   pairing_test <pair_success_iq.bin> <pair_device_iq.bin> <out: pair_device_sign.bin>
 * 1. decode + parse pair-success, 2. HMAC and account signature verify, every negative case rejected, 3. device
 * signature, self-signed identity, the pair-device-sign IQ written for tools/pairvectors -mode verify-sign,
 * 4. refs and QR text, ack and error nodes round trip, 5. creds record round trip, corruption rejected.
 * make pairing-test runs it under ASan/UBSan and then the Go verification.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pairing.h"
#include "creds.h"
#include "clientpayload.h"
#include "pb.h"
#include "sha256.h"
#include "x25519.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

void test_identity(wa_identity *id);   /* tests/clientpayload_test.c's fixed identity (linked in) */
static uint8_t arena_mem[1 << 16];

static uint8_t *read_file(const char *path, uint32_t *len)
{
    FILE *f = fopen(path, "rb"); long n; uint8_t *p;
    if (!f) { printf("cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    p = malloc((size_t)n + 1);
    if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) exit(2);
    fclose(f); *len = (uint32_t)n;
    return p;
}
static int str_is(const wab_str *s, const char *c) { return wab_str_eq(s, c); }

/* rebuild the HMAC container around a (possibly altered) signed identity with a correct HMAC under `secret` */
static uint32_t rebuild_container(uint8_t *out, uint32_t cap, const uint8_t *signed_p, uint32_t signed_len, const uint8_t secret[32])
{
    uint8_t mac[32]; pb_writer w;
    hmac_sha256(mac, secret, 32, signed_p, signed_len);
    pb_w_init(&w, out, cap);
    pb_w_bytes(&w, 1, signed_p, signed_len);
    pb_w_bytes(&w, 2, mac, 32);
    return w.ok ? w.len : 0;
}

int main(int argc, char **argv)
{
    static wab_arena arena; static wa_identity id, other; static wa_adv_identity adv; static wa_pair_reply reply;
    static uint8_t self_signed[512], frame[2048], cont2[1024], signed_copy[512];
    const wab_node *n; wa_pair_success ps; uint8_t *ps_frame, *pd_frame; uint32_t ps_len, pd_len, sl, fl; int e;
    static const uint8_t rnd[64] = "pairing_test nonce bytes, fixed so the run is reproducible.....";
    if (argc != 4) { printf("usage: pairing_test <pair_success_iq.bin> <pair_device_iq.bin> <out.bin>\n"); return 2; }
    test_identity(&id);
    test_identity(&other); other.ident_pub[3] ^= 0x40;

    /* ---- 1. parse ---- */
    ps_frame = read_file(argv[1], &ps_len);
    wab_arena_init(&arena, arena_mem, sizeof arena_mem);
    e = wab_decode_frame(ps_frame, ps_len, &arena, &n);
    CHECK(e == WAB_OK);
    if (e != WAB_OK) { printf("decode: %s\n", wab_errstr(e)); return 1; }
    CHECK(wa_pair_parse_success(n, &ps));
    CHECK(str_is(&ps.id, "3EB0ABCDEF"));
    CHECK(ps.device_identity_len >= 140 && ps.device_identity_len < 300);
    CHECK(ps.have_jid && str_is(&ps.jid.user, "4917612345678") && ps.jid.device == 7 && str_is(&ps.jid.server, "s.whatsapp.net"));
    CHECK(ps.have_lid && str_is(&ps.lid.user, "123456789012345") && ps.lid.device == 7 && str_is(&ps.lid.server, "lid"));
    CHECK(str_is(&ps.platform, "android"));
    CHECK(str_is(&ps.biz, "Amiga Test"));

    /* ---- 2. verify ---- */
    e = wa_pair_verify(ps.device_identity, ps.device_identity_len, &id, &adv);
    CHECK(e == WA_PAIR_OK);
    if (e) printf("verify: %s\n", wa_pair_errstr(e));
    CHECK(adv.key_index == 3 && adv.raw_id == 1234567 && adv.account_type == WA_ADV_E2EE && adv.device_type == WA_ADV_E2EE);
    CHECK(adv.details_len > 5 && adv.details_len < 40);
    printf("ok: account key "); { uint32_t i; for (i = 0; i < 32; i++) printf("%02x", adv.account_sig_key[i]); } printf(", key-index %u, raw id %u, details %u bytes\n", adv.key_index, adv.raw_id, adv.details_len);
    /* wrong ADV secret -> HMAC */
    { wa_identity bad = id; wa_adv_identity a2; bad.adv_secret[0] ^= 1;
      CHECK(wa_pair_verify(ps.device_identity, ps.device_identity_len, &bad, &a2) == WA_PAIR_ERR_HMAC); }
    /* a changed byte anywhere in the container -> HMAC or parse, never OK */
    { uint32_t i; int ok_count = 0; uint8_t *m = malloc(ps.device_identity_len);
      for (i = 0; i < ps.device_identity_len; i++) { wa_adv_identity a2; memcpy(m, ps.device_identity, ps.device_identity_len); m[i] ^= 0x10;
          if (wa_pair_verify(m, ps.device_identity_len, &id, &a2) == WA_PAIR_OK) ok_count++; }
      CHECK(ok_count == 0); free(m); }
    /* the identity the account signed is not ours -> SIG */
    { wa_adv_identity a2; CHECK(wa_pair_verify(ps.device_identity, ps.device_identity_len, &other, &a2) == WA_PAIR_ERR_SIG); }
    /* correct HMAC, flipped account signature / details / key -> SIG (or PARSE for the key) */
    {   const uint8_t *p = ps.device_identity, *end = p + ps.device_identity_len, *d, *sp = 0; uint32_t f, w, v, l, spl = 0, k;
        while (pb_next(&p, end, &f, &w, &v, &d, &l)) if (f == 1) { sp = d; spl = l; }
        CHECK(sp != 0);
        memcpy(signed_copy, sp, spl);
        /* locate accountSignature (field 3) and details (field 1) inside */
        p = signed_copy; end = signed_copy + spl;
        while (pb_next(&p, end, &f, &w, &v, &d, &l)) {
            wa_adv_identity a2;
            if (f == 3) { ((uint8_t *)d)[5] ^= 1; k = rebuild_container(cont2, sizeof cont2, signed_copy, spl, id.adv_secret); CHECK(k && wa_pair_verify(cont2, k, &id, &a2) == WA_PAIR_ERR_SIG); ((uint8_t *)d)[5] ^= 1; }
            if (f == 1) { ((uint8_t *)d)[2] ^= 1; k = rebuild_container(cont2, sizeof cont2, signed_copy, spl, id.adv_secret); CHECK(k && wa_pair_verify(cont2, k, &id, &a2) != WA_PAIR_OK); ((uint8_t *)d)[2] ^= 1; }
            if (f == 2) { ((uint8_t *)d)[0] ^= 1; k = rebuild_container(cont2, sizeof cont2, signed_copy, spl, id.adv_secret); CHECK(k && wa_pair_verify(cont2, k, &id, &a2) == WA_PAIR_ERR_SIG); ((uint8_t *)d)[0] ^= 1; }
        }
        k = rebuild_container(cont2, sizeof cont2, signed_copy, spl, id.adv_secret);
        { wa_adv_identity a2; CHECK(k && wa_pair_verify(cont2, k, &id, &a2) == WA_PAIR_OK); }
        /* truncated */
        { wa_adv_identity a2; CHECK(wa_pair_verify(ps.device_identity, ps.device_identity_len - 1, &id, &a2) != WA_PAIR_OK);
          CHECK(wa_pair_verify(ps.device_identity, 0, &id, &a2) == WA_PAIR_ERR_PARSE); }
    }

    /* ---- 3. sign and answer ---- */
    wa_pair_sign(&adv, &id, rnd);
    CHECK(adv.signed_by_us && wa_pair_check_device_sig(&adv, &id));
    { wa_adv_identity a2 = adv; a2.device_sig[7] ^= 1; CHECK(!wa_pair_check_device_sig(&a2, &id)); }
    sl = wa_pair_self_signed(self_signed, sizeof self_signed, &adv);
    CHECK(sl == 2 + adv.details_len + 2 + 64 + 2 + 64);
    CHECK(self_signed[0] == 0x0a && self_signed[2 + adv.details_len] == 0x1a && self_signed[2 + adv.details_len + 66] == 0x22);
    n = wa_pair_sign_node(&reply, &ps.id, adv.key_index, self_signed, sl);
    e = wab_encode_frame(n, frame, sizeof frame, &fl);
    CHECK(e == WAB_OK);
    { FILE *o = fopen(argv[3], "wb"); CHECK(o != 0); if (o) { fwrite(frame, 1, fl, o); fclose(o); } }
    /* and read it back */
    { const wab_node *r; wab_arena a2; static uint8_t mem2[8192]; const wab_value *v; const wab_node *c, *di;
      wab_arena_init(&a2, mem2, sizeof mem2);
      CHECK(wab_decode_frame(frame, fl, &a2, &r) == WAB_OK);
      CHECK(str_is(&r->tag, "iq"));
      v = wab_get_attr(r, "type"); CHECK(v && v->kind == WAB_STR && str_is(&v->str, "result"));
      v = wab_get_attr(r, "id"); CHECK(v && v->kind == WAB_STR && str_is(&v->str, "3EB0ABCDEF"));
      v = wab_get_attr(r, "to"); CHECK(v && v->kind == WAB_JID && str_is(&v->jid.server, "s.whatsapp.net") && v->jid.user.len == 0);
      c = wab_get_child(r, "pair-device-sign"); CHECK(c != 0);
      di = c ? wab_get_child(c, "device-identity") : 0; CHECK(di != 0);
      if (di) { v = wab_get_attr(di, "key-index"); CHECK(v && v->kind == WAB_STR && str_is(&v->str, "3"));
                CHECK(di->val.kind == WAB_BYTES && di->val.str.len == sl && memcmp(di->val.str.p, self_signed, sl) == 0); } }

    /* ---- 4. refs, QR text, ack, error ---- */
    pd_frame = read_file(argv[2], &pd_len);
    {   static wab_arena arena2; static uint8_t arena2_mem[1 << 16];   /* ps still points into the first arena */
        wab_arena_init(&arena2, arena2_mem, sizeof arena2_mem);
        CHECK(wab_decode_frame(pd_frame, pd_len, &arena2, &n) == WAB_OK); }
    {   wab_str refs[8]; uint32_t k = wa_pair_refs(n, refs, 8); static char text[WA_PAIR_QR_MAX]; uint32_t tl, rl, commas = 0, i; char b64[48];
        CHECK(k == 6);
        CHECK(k && refs[0].len == 102 && refs[0].p[0] == '2' && refs[0].p[1] == '@');   /* "2@" + 96 base64 chars + "=" x4? the server's form */
        rl = refs[0].len;
        tl = wa_pair_qr_text(text, sizeof text, refs[0].p, rl, &id);
        CHECK(tl == 38 + rl + 1 + 44 + 1 + 44 + 1 + 44 + 2 && tl == strlen(text));
        CHECK(strncmp(text, "https://wa.me/settings/linked_devices#2@", 40) == 0);
        for (i = 0; i < tl; i++) commas += text[i] == ',';
        CHECK(commas == 4 && text[tl - 2] == ',' && text[tl - 1] == WA_PAIR_CLIENT_ID[0]);
        wa_base64(b64, id.noise_pub, 32); CHECK(strstr(text, b64) == text + 38 + rl + 1);
        wa_base64(b64, id.ident_pub, 32); CHECK(strstr(text, b64) == text + 38 + rl + 46);
        wa_base64(b64, id.adv_secret, 32); CHECK(strstr(text, b64) == text + 38 + rl + 91);
        CHECK(wa_pair_qr_text(text, 200, refs[0].p, refs[0].len, &id) == 0);
        printf("ok: QR text %u chars: %.60s...\n", tl, text);
        /* ack */
        { const wab_value *v = wab_get_attr(n, "id"); const wab_node *r; wab_arena a2; static uint8_t mem2[4096]; const wab_value *t;
          CHECK(v && v->kind == WAB_STR);
          CHECK(wab_encode_frame(wa_pair_ack_node(&reply, &v->str), frame, sizeof frame, &fl) == WAB_OK);
          wab_arena_init(&a2, mem2, sizeof mem2);
          CHECK(wab_decode_frame(frame, fl, &a2, &r) == WAB_OK && r->n_attrs == 3 && r->val.kind == WAB_NONE);
          t = wab_get_attr(r, "id"); CHECK(t && t->kind == WAB_STR && t->str.len == v->str.len && memcmp(t->str.p, v->str.p, v->str.len) == 0);
          t = wab_get_attr(r, "type"); CHECK(t && str_is(&t->str, "result"));
          /* error */
          CHECK(wab_encode_frame(wa_pair_error_node(&reply, &v->str, 401, "hmac-mismatch"), frame, sizeof frame, &fl) == WAB_OK);
          wab_arena_init(&a2, mem2, sizeof mem2);
          CHECK(wab_decode_frame(frame, fl, &a2, &r) == WAB_OK);
          t = wab_get_attr(r, "type"); CHECK(t && str_is(&t->str, "error"));
          { const wab_node *er = wab_get_child(r, "error"); CHECK(er != 0);
            if (er) { t = wab_get_attr(er, "code"); CHECK(t && str_is(&t->str, "401")); t = wab_get_attr(er, "text"); CHECK(t && str_is(&t->str, "hmac-mismatch")); } } }
    }

    /* ---- 5. creds ---- */
    {   static wa_creds c, back; static uint8_t rec[WA_CREDS_SIZE + 8]; uint32_t rl, i;
        memset(&c, 0, sizeof c);
        c.id = id; c.paired = 1; c.adv = adv;
        CHECK(wa_creds_set_user(c.jid_user, ps.jid.user.p, ps.jid.user.len)); c.jid_device = ps.jid.device;
        CHECK(wa_creds_set_user(c.lid_user, ps.lid.user.p, ps.lid.user.len)); c.lid_device = ps.lid.device;
        strcpy(c.platform, "android"); strcpy(c.business, "Amiga Test");
        memset(c.noise_cache_fp, 0x5a, 32); c.noise_cache_valid = 1;
        rl = wa_creds_write(rec, sizeof rec, &c);
        CHECK(rl == WA_CREDS_SIZE);
        CHECK(wa_creds_write(rec, WA_CREDS_SIZE - 1, &c) == 0);
        CHECK(wa_creds_read(&back, rec, rl));
        CHECK(memcmp(&back.id, &c.id, sizeof c.id) == 0);
        CHECK(back.paired == 1 && back.noise_cache_valid == 1 && strcmp(back.jid_user, "4917612345678") == 0 && back.jid_device == 7);
        CHECK(strcmp(back.lid_user, "123456789012345") == 0 && back.lid_device == 7 && strcmp(back.platform, "android") == 0 && strcmp(back.business, "Amiga Test") == 0);
        CHECK(back.adv.details_len == adv.details_len && memcmp(back.adv.details, adv.details, adv.details_len) == 0);
        CHECK(memcmp(back.adv.account_sig_key, adv.account_sig_key, 32) == 0 && memcmp(back.adv.account_sig, adv.account_sig, 64) == 0 && memcmp(back.adv.device_sig, adv.device_sig, 64) == 0);
        CHECK(back.adv.key_index == 3 && back.adv.raw_id == 1234567 && back.adv.signed_by_us);
        CHECK(memcmp(back.noise_cache_fp, c.noise_cache_fp, 32) == 0);
        CHECK(wa_pair_check_device_sig(&back.adv, &back.id));
        /* every single-byte corruption is rejected */
        { int accepted = 0; for (i = 0; i < rl; i++) { rec[i] ^= 0x80; if (wa_creds_read(&back, rec, rl)) accepted++; rec[i] ^= 0x80; } CHECK(accepted == 0); }
        CHECK(!wa_creds_read(&back, rec, rl - 1));
        CHECK(!wa_creds_read(&back, rec, rl + 1));
        CHECK(wa_creds_read(&back, rec, rl));
        /* unpaired record: identity only */
        memset(&c, 0, sizeof c); c.id = id;
        rl = wa_creds_write(rec, sizeof rec, &c);
        CHECK(rl == WA_CREDS_SIZE && wa_creds_read(&back, rec, rl) && !back.paired && back.jid_user[0] == 0 && memcmp(&back.id, &id, sizeof id) == 0);
        CHECK(!wa_creds_set_user(c.jid_user, (const uint8_t *)"12a", 3));
        CHECK(!wa_creds_set_user(c.jid_user, (const uint8_t *)"123456789012345678901234", 24));
    }

    printf("%s: %d checks, %d failures\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails ? 1 : 0;
}
