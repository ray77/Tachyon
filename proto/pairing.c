/* Companion pairing, protocol part (see pairing.h). */
#include "pairing.h"
#include "pb.h"
#include "clientpayload.h"
#include "sha256.h"
#include "ed25519.h"

static void pr_cp(uint8_t *d, const uint8_t *s, uint32_t n) { while (n--) *d++ = *s++; }
static void zero(void *p, uint32_t n) { uint8_t *d = p; while (n--) *d++ = 0; }

const char *wa_pair_errstr(int err)
{
    switch (err) {
    case WA_PAIR_OK: return "ok";
    case WA_PAIR_ERR_PARSE: return "malformed device identity";
    case WA_PAIR_ERR_HMAC: return "HMAC mismatch (ADV secret)";
    case WA_PAIR_ERR_SIG: return "account signature invalid";
    case WA_PAIR_ERR_SIZE: return "device identity details too long";
    default: return "?";
    }
}

/* message = prefix(2) || details || ident_pub [|| account key]; returns its length */
static uint32_t sig_message(uint8_t *m, uint8_t p0, uint8_t p1, const wa_adv_identity *adv, const uint8_t ident_pub[32], const uint8_t *acc_key)
{
    uint32_t n = 0;
    m[n++] = p0; m[n++] = p1;
    pr_cp(m + n, adv->details, adv->details_len); n += adv->details_len;
    pr_cp(m + n, ident_pub, 32); n += 32;
    if (acc_key) { pr_cp(m + n, acc_key, 32); n += 32; }
    return n;
}

int wa_pair_verify(const uint8_t *container, uint32_t len, const wa_identity *id, wa_adv_identity *adv)
{
    const uint8_t *p, *end, *d, *signed_p = 0, *mac = 0, *details = 0, *acc_key = 0, *acc_sig = 0;
    uint32_t f, wire, v, l, signed_len = 0, mac_len = 0, details_len = 0, acc_key_len = 0, acc_sig_len = 0, i;
    uint8_t h[32], hosted_prefix[2] = { 6, 5 }, msg[2 + WA_ADV_DETAILS_MAX + 32];
    hmac_sha256_ctx hc; int diff = 0;

    zero(adv, sizeof *adv);
    /* ADVSignedDeviceIdentityHMAC{details(1) bytes, HMAC(2) bytes, accountType(3) enum} */
    p = container; end = container + len;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
        if (f == 1 && wire == PB_BYTES) { signed_p = d; signed_len = l; }
        else if (f == 2 && wire == PB_BYTES) { mac = d; mac_len = l; }
        else if (f == 3 && wire == PB_VARINT) adv->account_type = (uint8_t)v;
    }
    if (p != end || !signed_p || mac_len != 32) return WA_PAIR_ERR_PARSE;

    hmac_sha256_init(&hc, id->adv_secret, 32);
    if (adv->account_type == WA_ADV_HOSTED) hmac_sha256_update(&hc, hosted_prefix, 2);
    hmac_sha256_update(&hc, signed_p, signed_len);
    hmac_sha256_final(&hc, h);
    for (i = 0; i < 32; i++) diff |= h[i] ^ mac[i];
    if (diff) return WA_PAIR_ERR_HMAC;

    /* ADVSignedDeviceIdentity{details(1), accountSignatureKey(2), accountSignature(3), deviceSignature(4)} */
    p = signed_p; end = signed_p + signed_len;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
        if (wire != PB_BYTES) continue;
        if (f == 1) { details = d; details_len = l; }
        else if (f == 2) { acc_key = d; acc_key_len = l; }
        else if (f == 3) { acc_sig = d; acc_sig_len = l; }
    }
    if (p != end || !details || acc_key_len != 32 || acc_sig_len != 64) return WA_PAIR_ERR_PARSE;
    if (details_len > WA_ADV_DETAILS_MAX) return WA_PAIR_ERR_SIZE;
    pr_cp(adv->details, details, details_len); adv->details_len = details_len;
    pr_cp(adv->account_sig_key, acc_key, 32); pr_cp(adv->account_sig, acc_sig, 64);

    /* ADVDeviceIdentity{rawId(1), timestamp(2), keyIndex(3), accountType(4), deviceType(5)} */
    p = details; end = details + details_len;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
        if (wire != PB_VARINT) continue;
        if (f == 1) adv->raw_id = v; else if (f == 3) adv->key_index = v; else if (f == 5) adv->device_type = (uint8_t)v;
    }
    if (p != end) return WA_PAIR_ERR_PARSE;

    l = sig_message(msg, 6, adv->device_type == WA_ADV_HOSTED ? 5 : 0, adv, id->ident_pub, 0);
    if (!xeddsa_verify(adv->account_sig, msg, l, adv->account_sig_key)) return WA_PAIR_ERR_SIG;
    return WA_PAIR_OK;
}

void wa_pair_sign(wa_adv_identity *adv, const wa_identity *id, const uint8_t random[64])
{
    uint8_t msg[2 + WA_ADV_DETAILS_MAX + 64]; uint32_t l;
    l = sig_message(msg, 6, 1, adv, id->ident_pub, adv->account_sig_key);
    xeddsa_sign(adv->device_sig, msg, l, id->ident_priv, random);
    adv->signed_by_us = 1;
}

int wa_pair_check_device_sig(const wa_adv_identity *adv, const wa_identity *id)
{
    uint8_t msg[2 + WA_ADV_DETAILS_MAX + 64]; uint32_t l;
    l = sig_message(msg, 6, 1, adv, id->ident_pub, adv->account_sig_key);
    return xeddsa_verify(adv->device_sig, msg, l, id->ident_pub);
}

uint32_t wa_pair_self_signed(uint8_t *out, uint32_t cap, const wa_adv_identity *adv)
{
    pb_writer w;
    pb_w_init(&w, out, cap);
    pb_w_bytes(&w, 1, adv->details, adv->details_len);
    pb_w_bytes(&w, 3, adv->account_sig, 64);
    pb_w_bytes(&w, 4, adv->device_sig, 64);
    return w.ok ? w.len : 0;
}

uint32_t wa_pair_qr_text(char *out, uint32_t cap, const uint8_t *ref, uint32_t ref_len, const wa_identity *id)
{
    static const char prefix[] = "https://wa.me/settings/linked_devices#";
    uint32_t o = 0, i;
    if (cap < sizeof prefix + ref_len + 3 * 45 + 2) return 0;
    for (i = 0; prefix[i]; i++) out[o++] = prefix[i];
    for (i = 0; i < ref_len; i++) out[o++] = (char)ref[i];
    out[o++] = ','; o += wa_base64(out + o, id->noise_pub, 32);
    out[o++] = ','; o += wa_base64(out + o, id->ident_pub, 32);
    out[o++] = ','; o += wa_base64(out + o, id->adv_secret, 32);
    out[o++] = ','; for (i = 0; WA_PAIR_CLIENT_ID[i]; i++) out[o++] = WA_PAIR_CLIENT_ID[i];   /* whatsmeow getQRClientType */
    out[o] = 0;
    return o;
}

/* ---- nodes ----------------------------------------------------------------------------------- */
int wa_pair_parse_success(const wab_node *iq, wa_pair_success *ps)
{
    const wab_node *s, *c; const wab_value *v;
    zero(ps, sizeof *ps);
    if (!wab_str_eq(&iq->tag, "iq")) return 0;
    v = wab_get_attr(iq, "id"); if (!v || v->kind != WAB_STR) return 0;
    ps->id = v->str;
    s = wab_get_child(iq, "pair-success"); if (!s) return 0;
    c = wab_get_child(s, "device-identity");
    if (!c || c->val.kind != WAB_BYTES) return 0;
    ps->device_identity = c->val.str.p; ps->device_identity_len = c->val.str.len;
    c = wab_get_child(s, "device");
    if (c) {
        v = wab_get_attr(c, "jid"); if (v && v->kind == WAB_JID) { ps->jid = v->jid; ps->have_jid = 1; }
        v = wab_get_attr(c, "lid"); if (v && v->kind == WAB_JID) { ps->lid = v->jid; ps->have_lid = 1; }
    }
    c = wab_get_child(s, "platform"); if (c && (v = wab_get_attr(c, "name")) != 0 && v->kind == WAB_STR) ps->platform = v->str;
    c = wab_get_child(s, "biz");      if (c && (v = wab_get_attr(c, "name")) != 0 && v->kind == WAB_STR) ps->biz = v->str;
    return ps->have_jid;
}

uint32_t wa_pair_refs(const wab_node *iq, wab_str *refs, uint32_t max)
{
    const wab_node *pd; uint32_t i, n = 0;
    if (!wab_str_eq(&iq->tag, "iq")) return 0;
    pd = wab_get_child(iq, "pair-device");
    if (!pd || pd->val.kind != WAB_LIST) return 0;
    for (i = 0; i < pd->n_children && n < max; i++) {
        const wab_node *r = &pd->children[i];
        if (wab_str_eq(&r->tag, "ref") && (r->val.kind == WAB_BYTES || r->val.kind == WAB_STR) && r->val.str.len) refs[n++] = r->val.str;
    }
    return n;
}

static void dec(char *d, uint32_t v) { char t[12]; int n = 0; do { t[n++] = (char)('0' + v % 10); v /= 10; } while (v); while (n) *d++ = t[--n]; *d = 0; }

static void iq_header(wa_pair_reply *r, const wab_str *id, const char *type)
{
    uint32_t i, n = id->len < sizeof r->id - 1 ? id->len : sizeof r->id - 1;
    for (i = 0; i < n; i++) r->id[i] = (char)id->p[i];
    r->id[n] = 0;
    wab_node_init(&r->iq, "iq");
    r->iq_attrs[0].key = wab_s("to");   r->iq_attrs[0].val = wab_jid_value("", WA_SERVER_JID, 0);
    r->iq_attrs[1].key = wab_s("type"); r->iq_attrs[1].val = wab_text(type);
    r->iq_attrs[2].key = wab_s("id");   r->iq_attrs[2].val = wab_text(r->id);
    r->iq.attrs = r->iq_attrs; r->iq.n_attrs = 3;
}

const wab_node *wa_pair_ack_node(wa_pair_reply *r, const wab_str *id)
{
    iq_header(r, id, "result");
    return &r->iq;
}

const wab_node *wa_pair_sign_node(wa_pair_reply *r, const wab_str *id, uint32_t key_index, const uint8_t *self_signed, uint32_t len)
{
    iq_header(r, id, "result");
    wab_node_init(&r->child, "pair-device-sign");
    wab_node_init(&r->devid, "device-identity");
    dec(r->key_index, key_index);
    r->devid_attrs[0].key = wab_s("key-index"); r->devid_attrs[0].val = wab_text(r->key_index);
    r->devid.attrs = r->devid_attrs; r->devid.n_attrs = 1;
    r->devid.val = wab_bytes(self_signed, len);
    r->child.val.kind = WAB_LIST; r->child.children = &r->devid; r->child.n_children = 1;
    r->iq.val.kind = WAB_LIST; r->iq.children = &r->child; r->iq.n_children = 1;
    return &r->iq;
}

const wab_node *wa_pair_error_node(wa_pair_reply *r, const wab_str *id, uint32_t code, const char *text)
{
    iq_header(r, id, "error");
    wab_node_init(&r->err, "error");
    dec(r->code, code);
    r->err_attrs[0].key = wab_s("code"); r->err_attrs[0].val = wab_text(r->code);
    r->err_attrs[1].key = wab_s("text"); r->err_attrs[1].val = wab_text(text);
    r->err.attrs = r->err_attrs; r->err.n_attrs = 2;
    r->iq.val.kind = WAB_LIST; r->iq.children = &r->err; r->iq.n_children = 1;
    return &r->iq;
}
