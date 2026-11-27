#include "prekeys.h"
#include "sha256.h"
#include "ed25519.h"

#ifndef WA_SERVER_JID
#define WA_SERVER_JID "s.whatsapp.net"
#endif

static void pk_clamp(uint8_t k[32]) { k[0] &= 248; k[31] &= 127; k[31] |= 64; }
static void be32(uint8_t *d, uint32_t v) { d[0] = (uint8_t)(v >> 24); d[1] = (uint8_t)(v >> 16); d[2] = (uint8_t)(v >> 8); d[3] = (uint8_t)v; }
static uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static void pk_cp(uint8_t *d, const uint8_t *s, uint32_t n) { while (n--) *d++ = *s++; }

void wa_prekeys_init(wa_prekeys *ps) { ps->n = 0; ps->next_id = 1; }

uint32_t wa_prekeys_generate(wa_prekeys *ps, uint32_t count, hmac_drbg *rng)
{
    uint32_t made = 0;
    while (made < count && ps->n < WA_PREKEYS_MAX) {
        wa_prekey *k = &ps->k[ps->n];
        drbg_generate(rng, k->priv, 32);
        pk_clamp(k->priv);
        x25519_base_comb(k->pub, k->priv);
        k->id = ps->next_id++ & 0xffffffu;
        if (k->id == 0) k->id = ps->next_id++;          /* 24-bit ids, never 0 */
        k->uploaded = 0;
        ps->n++; made++;
    }
    return made;
}

uint32_t wa_prekeys_pending(const wa_prekeys *ps) { uint32_t i, n = 0; for (i = 0; i < ps->n; i++) n += ps->k[i].uploaded == 0; return n; }
void wa_prekeys_mark_uploaded(wa_prekeys *ps) { uint32_t i; for (i = 0; i < ps->n; i++) ps->k[i].uploaded = 1; }

uint32_t wa_prekeys_write(uint8_t *out, uint32_t cap, const wa_prekeys *ps)
{
    uint32_t i, o = 0, size = WA_PREKEYS_SIZE(ps->n);
    if (ps->n > WA_PREKEYS_MAX || cap < size) return 0;
    out[o++] = 1;
    be32(out + o, ps->n); o += 4;
    be32(out + o, ps->next_id); o += 4;
    for (i = 0; i < ps->n; i++) {
        be32(out + o, ps->k[i].id); o += 4;
        pk_cp(out + o, ps->k[i].priv, 32); o += 32;
        pk_cp(out + o, ps->k[i].pub, 32); o += 32;
        out[o++] = ps->k[i].uploaded ? 1 : 0;
    }
    sha256(out + o, out, o);
    return size;
}

int wa_prekeys_read(wa_prekeys *ps, const uint8_t *in, uint32_t len)
{
    uint8_t h[32]; uint32_t i, o = 0, n, d = 0;
    if (len < WA_PREKEYS_SIZE(0) || in[0] != 1) return 0;
    n = rd32(in + 1);
    if (n > WA_PREKEYS_MAX || len != WA_PREKEYS_SIZE(n)) return 0;
    sha256(h, in, len - 32);
    for (i = 0; i < 32; i++) d |= h[i] ^ in[len - 32 + i];
    if (d) return 0;
    o = 1; ps->n = n; o += 4; ps->next_id = rd32(in + o); o += 4;
    for (i = 0; i < n; i++) {
        ps->k[i].id = rd32(in + o); o += 4;
        pk_cp(ps->k[i].priv, in + o, 32); o += 32;
        pk_cp(ps->k[i].pub, in + o, 32); o += 32;
        ps->k[i].uploaded = in[o++];
    }
    return 1;
}

const wa_prekey *wa_prekeys_find(const wa_prekeys *ps, uint32_t id) { uint32_t i; for (i = 0; i < ps->n; i++) if (ps->k[i].id == id) return &ps->k[i]; return 0; }

int wa_prekeys_remove(wa_prekeys *ps, uint32_t id)
{
    uint32_t i, j;
    for (i = 0; i < ps->n; i++) if (ps->k[i].id == id) {
        for (j = i + 1; j < ps->n; j++) ps->k[j - 1] = ps->k[j];
        ps->n--;
        for (j = 0; j < 32; j++) ps->k[ps->n].priv[j] = 0;        /* wipe the private half of the vacated slot */
        return 1;
    }
    return 0;
}

static void be24(uint8_t *d, uint32_t v) { d[0] = (uint8_t)(v >> 16); d[1] = (uint8_t)(v >> 8); d[2] = (uint8_t)v; }
static void bytes_node(wab_node *n, const char *tag, const uint8_t *p, uint32_t len) { wab_node_init(n, tag); n->val = wab_bytes(p, len); }
static void list_node(wab_node *n, const char *tag, const wab_node *children, uint32_t count) { wab_node_init(n, tag); n->val.kind = WAB_LIST; n->children = children; n->n_children = count; }

const wab_node *wa_prekeys_upload_node(wa_prekey_upload *u, const char *iq_id, const wa_identity *idn, const wa_prekeys *ps, uint32_t *n_included)
{
    uint32_t i, j = 0;
    for (i = 0; i < ps->n && j < WA_PREKEYS_MAX; i++) {
        const wa_prekey *k = &ps->k[i];
        if (k->uploaded) continue;
        be24(u->ids[j], k->id);
        bytes_node(&u->pair[2 * j], "id", u->ids[j], 3);
        bytes_node(&u->pair[2 * j + 1], "value", k->pub, 32);
        list_node(&u->key[j], "key", &u->pair[2 * j], 2);
        j++;
    }
    *n_included = j;
    be32(u->regid, idn->reg_id);
    u->typeb[0] = 5;                                                    /* ecc.DjbType */
    bytes_node(&u->iq_children[0], "registration", u->regid, 4);
    bytes_node(&u->iq_children[1], "type", u->typeb, 1);
    bytes_node(&u->iq_children[2], "identity", idn->ident_pub, 32);
    list_node(&u->iq_children[3], "list", u->key, j);
    be24(u->skid, idn->spk_id);
    bytes_node(&u->skey_children[0], "id", u->skid, 3);
    bytes_node(&u->skey_children[1], "value", idn->spk_pub, 32);
    bytes_node(&u->skey_children[2], "signature", idn->spk_sig, 64);
    list_node(&u->iq_children[4], "skey", u->skey_children, 3);
    wab_node_init(&u->iq, "iq");
    u->iq_attrs[0].key = wab_s("id");    u->iq_attrs[0].val = wab_text(iq_id);
    u->iq_attrs[1].key = wab_s("xmlns"); u->iq_attrs[1].val = wab_text("encrypt");
    u->iq_attrs[2].key = wab_s("type");  u->iq_attrs[2].val = wab_text("set");
    u->iq_attrs[3].key = wab_s("to");    u->iq_attrs[3].val = wab_jid_value("", WA_SERVER_JID, 0);
    u->iq.attrs = u->iq_attrs; u->iq.n_attrs = 4;
    u->iq.val.kind = WAB_LIST; u->iq.children = u->iq_children; u->iq.n_children = 5;
    return &u->iq;
}
