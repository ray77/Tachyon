/* Credentials record (see creds.h). */
#include "creds.h"
#include "sha256.h"

typedef struct { uint8_t *p; uint32_t o, cap; } cur;
static void cw_put(cur *c, const uint8_t *s, uint32_t n) { uint32_t i; for (i = 0; i < n; i++) if (c->o < c->cap) c->p[c->o++] = s[i]; else c->o++; }
static void cw_put_str(cur *c, const char *s, uint32_t n) { uint32_t i, l = 0; while (l < n && s[l]) l++; for (i = 0; i < n; i++) { uint8_t b = i < l ? (uint8_t)s[i] : 0; cw_put(c, &b, 1); } }
static void cw_put_u8(cur *c, uint32_t v) { uint8_t b = (uint8_t)v; cw_put(c, &b, 1); }
static void cw_put_u16(cur *c, uint32_t v) { uint8_t b[2]; b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v; cw_put(c, b, 2); }
static void cw_put_u32(cur *c, uint32_t v) { uint8_t b[4]; b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; cw_put(c, b, 4); }

typedef struct { const uint8_t *p; uint32_t o; } rcur;
static void cr_get(rcur *c, uint8_t *d, uint32_t n) { uint32_t i; for (i = 0; i < n; i++) d[i] = c->p[c->o++]; }
static void cr_get_str(rcur *c, char *d, uint32_t n) { uint32_t i; for (i = 0; i < n; i++) d[i] = (char)c->p[c->o++]; d[n - 1] = 0; }
static uint32_t cr_get_u8(rcur *c) { return c->p[c->o++]; }
static uint32_t cr_get_u16(rcur *c) { uint32_t v = ((uint32_t)c->p[c->o] << 8) | c->p[c->o + 1]; c->o += 2; return v; }
static uint32_t cr_get_u32(rcur *c) { uint32_t v = ((uint32_t)c->p[c->o] << 24) | ((uint32_t)c->p[c->o + 1] << 16) | ((uint32_t)c->p[c->o + 2] << 8) | c->p[c->o + 3]; c->o += 4; return v; }

uint32_t wa_creds_write(uint8_t *out, uint32_t cap, const wa_creds *c)
{
    cur w; uint8_t h[32];
    if (cap < WA_CREDS_SIZE) return 0;
    w.p = out; w.o = 0; w.cap = cap;
    cw_put_u8(&w, WA_CREDS_VERSION);
    cw_put_u8(&w, (c->paired ? 1u : 0u) | (c->noise_cache_valid ? 2u : 0u));
    cw_put(&w, c->id.noise_priv, 32); cw_put(&w, c->id.noise_pub, 32);
    cw_put(&w, c->id.ident_priv, 32); cw_put(&w, c->id.ident_pub, 32);
    cw_put(&w, c->id.spk_priv, 32); cw_put(&w, c->id.spk_pub, 32); cw_put(&w, c->id.spk_sig, 64);
    cw_put_u32(&w, c->id.spk_id); cw_put_u32(&w, c->id.reg_id);
    cw_put(&w, c->id.adv_secret, 32);
    cw_put_str(&w, c->jid_user, WA_JID_USER_MAX); cw_put_u16(&w, c->jid_device);
    cw_put_str(&w, c->lid_user, WA_JID_USER_MAX); cw_put_u16(&w, c->lid_device);
    cw_put_str(&w, c->platform, WA_CREDS_NAME_MAX); cw_put_str(&w, c->business, WA_CREDS_BIZ_MAX);
    cw_put_u16(&w, c->adv.details_len); cw_put(&w, c->adv.details, WA_ADV_DETAILS_MAX);
    cw_put(&w, c->adv.account_sig_key, 32); cw_put(&w, c->adv.account_sig, 64); cw_put(&w, c->adv.device_sig, 64);
    cw_put_u32(&w, c->adv.key_index); cw_put_u32(&w, c->adv.raw_id);
    cw_put_u8(&w, c->adv.account_type); cw_put_u8(&w, c->adv.device_type);
    cw_put(&w, c->noise_cache_fp, 32);
    if (w.o != WA_CREDS_SIZE - 32) return 0;      /* layout drifted from WA_CREDS_SIZE */
    sha256(h, out, w.o);
    cw_put(&w, h, 32);
    return w.o;
}

int wa_creds_read(wa_creds *c, const uint8_t *in, uint32_t len)
{
    rcur r; uint8_t h[32]; uint32_t i, flags, d = 0;
    uint8_t *z = (uint8_t *)c; for (i = 0; i < sizeof *c; i++) z[i] = 0;
    if (len != WA_CREDS_SIZE || in[0] != WA_CREDS_VERSION) return 0;
    sha256(h, in, WA_CREDS_SIZE - 32);
    for (i = 0; i < 32; i++) d |= h[i] ^ in[WA_CREDS_SIZE - 32 + i];
    if (d) return 0;
    r.p = in; r.o = 1;
    flags = cr_get_u8(&r);
    cr_get(&r, c->id.noise_priv, 32); cr_get(&r, c->id.noise_pub, 32);
    cr_get(&r, c->id.ident_priv, 32); cr_get(&r, c->id.ident_pub, 32);
    cr_get(&r, c->id.spk_priv, 32); cr_get(&r, c->id.spk_pub, 32); cr_get(&r, c->id.spk_sig, 64);
    c->id.spk_id = cr_get_u32(&r); c->id.reg_id = cr_get_u32(&r);
    cr_get(&r, c->id.adv_secret, 32);
    cr_get_str(&r, c->jid_user, WA_JID_USER_MAX); c->jid_device = cr_get_u16(&r);
    cr_get_str(&r, c->lid_user, WA_JID_USER_MAX); c->lid_device = cr_get_u16(&r);
    cr_get_str(&r, c->platform, WA_CREDS_NAME_MAX); cr_get_str(&r, c->business, WA_CREDS_BIZ_MAX);
    c->adv.details_len = cr_get_u16(&r); cr_get(&r, c->adv.details, WA_ADV_DETAILS_MAX);
    if (c->adv.details_len > WA_ADV_DETAILS_MAX) return 0;
    cr_get(&r, c->adv.account_sig_key, 32); cr_get(&r, c->adv.account_sig, 64); cr_get(&r, c->adv.device_sig, 64);
    c->adv.key_index = cr_get_u32(&r); c->adv.raw_id = cr_get_u32(&r);
    c->adv.account_type = (uint8_t)cr_get_u8(&r); c->adv.device_type = (uint8_t)cr_get_u8(&r);
    cr_get(&r, c->noise_cache_fp, 32);
    c->paired = (flags & 1) != 0; c->noise_cache_valid = (flags & 2) != 0;
    c->adv.signed_by_us = c->paired;
    return r.o == WA_CREDS_SIZE - 32;
}

int wa_creds_set_user(char *dst, const uint8_t *user, uint32_t len)
{
    uint32_t i;
    if (len == 0 || len >= WA_JID_USER_MAX) return 0;
    for (i = 0; i < len; i++) { if (user[i] < '0' || user[i] > '9') return 0; dst[i] = (char)user[i]; }
    dst[len] = 0;
    return 1;
}
