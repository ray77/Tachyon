/* Signal session layer (see signal.h). Reference: go.mau.fi/libsignal v0.2.3 session/, ratchet/, keys/, protocol/, serialize/. */
#include "signal.h"
#include "sha256.h"
#include "aes.h"
#include "x25519.h"
#include "ed25519.h"
#include "pb.h"
#include "prekeys.h"

#define SIG_BODY_MAX 2048                       /* padded plaintext / ciphertext body (texts; media travel as references) */
#define SIG_INNER_MAX (1 + 2 + 33 + 6 + 6 + 3 + SIG_BODY_MAX + SIG_MAC_LEN)

/* ---- helpers --------------------------------------------------------------------------------------- */
static void sig_cp(uint8_t *d, const uint8_t *s, uint32_t n) { while (n--) *d++ = *s++; }
static void sig_zero(void *p, uint32_t n) { uint8_t *d = (uint8_t *)p; while (n--) *d++ = 0; }
static int  ct_eq(const uint8_t *a, const uint8_t *b, uint32_t n) { uint32_t i; uint8_t d = 0; for (i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0; }
static void sig_clamp(uint8_t k[32]) { k[0] &= 248; k[31] &= 127; k[31] |= 64; }
static void sig_be32(uint8_t *d, uint32_t v) { d[0] = (uint8_t)(v >> 24); d[1] = (uint8_t)(v >> 16); d[2] = (uint8_t)(v >> 8); d[3] = (uint8_t)v; }
static uint32_t sig_rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

const char *sig_errstr(int err)
{
    switch (err) {
    case SIG_OK: return "ok";
    case SIG_ERR_FORMAT: return "malformed message";
    case SIG_ERR_VERSION: return "unsupported message version";
    case SIG_ERR_SIGNATURE: return "signed prekey signature invalid";
    case SIG_ERR_MAC: return "MAC mismatch";
    case SIG_ERR_OLD_COUNTER: return "old counter (duplicate)";
    case SIG_ERR_FUTURE: return "counter too far ahead";
    case SIG_ERR_NO_SESSION: return "no session";
    case SIG_ERR_NO_PREKEY: return "unknown prekey";
    case SIG_ERR_PADDING: return "bad padding";
    case SIG_ERR_BUFFER: return "buffer too small";
    default: return "?";
    }
}

/* ---- key derivation (libsignal kdf/, keys/chain, keys/root, ratchet/) ----------------------------- */
static const uint8_t info_text[] = "WhisperText", info_ratchet[] = "WhisperRatchet", info_mk[] = "WhisperMessageKeys";

/* message keys of the chain key: HKDF(HMAC(ck, 01), salt 0, "WhisperMessageKeys", 80) */
static void chain_message_keys(const uint8_t ck[32], uint8_t cipher[32], uint8_t mac[32], uint8_t iv[16])
{
    uint8_t one = 1, seed[32], out[80];
    hmac_sha256(seed, ck, 32, &one, 1);
    hkdf_sha256(out, 80, 0, 0, seed, 32, info_mk, 18);
    sig_cp(cipher, out, 32); sig_cp(mac, out + 32, 32); sig_cp(iv, out + 64, 16);
    sig_zero(out, sizeof out); sig_zero(seed, 32);
}
static void chain_next(uint8_t ck[32]) { uint8_t two = 2, out[32]; hmac_sha256(out, ck, 32, &two, 1); sig_cp(ck, out, 32); sig_zero(out, 32); }

/* root.CreateChain: root', chain = HKDF(DH(our, their), salt root, "WhisperRatchet", 64); one ladder */
static void root_create_chain(uint8_t root[32], uint8_t chain[32], const uint8_t our_priv[32], const uint8_t their_pub[32])
{
    uint8_t dh[32], out[64];
    x25519_ref(dh, our_priv, their_pub);
    hkdf_sha256(out, 64, root, 32, dh, 32, info_ratchet, 14);
    sig_cp(root, out, 32); sig_cp(chain, out + 32, 32);
    sig_zero(dh, 32); sig_zero(out, 64);
}

/* X3DH master secret -> root, chain (ratchet.CalculateSenderSession / CalculateReceiverSession) */
static void x3dh_derive(uint8_t root[32], uint8_t chain[32], const uint8_t dh1[32], const uint8_t dh2[32], const uint8_t dh3[32], const uint8_t *dh4)
{
    uint8_t master[160], out[64]; uint32_t i, n = 32;
    for (i = 0; i < 32; i++) master[i] = 0xff;           /* discontinuity bytes */
    sig_cp(master + n, dh1, 32); n += 32; sig_cp(master + n, dh2, 32); n += 32; sig_cp(master + n, dh3, 32); n += 32;
    if (dh4) { sig_cp(master + n, dh4, 32); n += 32; }
    hkdf_sha256(out, 64, 0, 0, master, n, info_text, 11);
    sig_cp(root, out, 32); sig_cp(chain, out + 32, 32);
    sig_zero(master, sizeof master); sig_zero(out, 64);
}

static void keygen(const sig_local *me, uint8_t priv[32], uint8_t pub[32])
{
    me->random(me->rctx, priv, 32);
    sig_clamp(priv);
    x25519_base_comb(pub, priv);
}

/* ---- bundle -------------------------------------------------------------------------------------- */
static const uint8_t *node_bytes(const wab_node *n, uint32_t *len)
{
    if (!n || (n->val.kind != WAB_BYTES && n->val.kind != WAB_STR)) { *len = 0; return 0; }
    *len = n->val.str.len;
    return n->val.str.p;
}
static int bytes_child(const wab_node *n, const char *tag, uint32_t want, uint8_t *dst)
{
    uint32_t l; const uint8_t *p = node_bytes(wab_get_child(n, tag), &l);
    if (!p || l != want) return 0;
    sig_cp(dst, p, want);
    return 1;
}

int sig_bundle_from_node(sig_bundle *b, const wab_node *user)
{
    const wab_node *keys, *skey, *key; uint8_t tmp[4];
    sig_zero(b, sizeof *b);
    if (!user || wab_get_child(user, "error")) return 0;
    if (!bytes_child(user, "registration", 4, tmp)) return 0;
    b->reg_id = sig_rd32(tmp);
    keys = wab_get_child(user, "keys"); if (!keys) keys = user;
    if (!bytes_child(keys, "identity", 32, b->ident)) return 0;
    skey = wab_get_child(keys, "skey");
    if (!skey || !bytes_child(skey, "id", 3, tmp) || !bytes_child(skey, "value", 32, b->spk) || !bytes_child(skey, "signature", 64, b->spk_sig)) return 0;
    b->spk_id = ((uint32_t)tmp[0] << 16) | ((uint32_t)tmp[1] << 8) | tmp[2];
    key = wab_get_child(keys, "key");
    if (key) {
        if (!bytes_child(key, "id", 3, tmp) || !bytes_child(key, "value", 32, b->opk)) return 0;
        b->opk_id = ((uint32_t)tmp[0] << 16) | ((uint32_t)tmp[1] << 8) | tmp[2];
        b->has_opk = 1;
    }
    return 1;
}

/* ---- session setup --------------------------------------------------------------------------------- */
void sig_session_init(sig_session *s) { sig_zero(s, sizeof *s); }
int  sig_session_has_state(const sig_session *s) { return s->cur.valid != 0; }

static void archive(sig_session *s)
{
    if (s->cur.valid) { s->prev = s->cur; s->has_prev = 1; }
    sig_zero(&s->cur, sizeof s->cur);
}

int sig_session_start(sig_session *s, const sig_local *me, const sig_bundle *b)
{
    uint8_t m[33], base_priv[32], base_pub[32], r_priv[32], r_pub[32], dh1[32], dh2[32], dh3[32], dh4[32], root[32], chain[32];
    sig_state *st;
    m[0] = 0x05; sig_cp(m + 1, b->spk, 32);
    if (!xeddsa_verify(b->spk_sig, m, 33, b->ident)) return SIG_ERR_SIGNATURE;
    keygen(me, base_priv, base_pub);
    x25519_ref(dh1, me->ident_priv, b->spk);            /* DH(I_a, SPK_b) */
    x25519_ref(dh2, base_priv, b->ident);               /* DH(E_a, I_b) */
    x25519_ref(dh3, base_priv, b->spk);                 /* DH(E_a, SPK_b) */
    if (b->has_opk) x25519_ref(dh4, base_priv, b->opk); /* DH(E_a, OPK_b) */
    x3dh_derive(root, chain, dh1, dh2, dh3, b->has_opk ? dh4 : 0);
    keygen(me, r_priv, r_pub);
    archive(s);
    st = &s->cur;
    st->valid = 1;
    sig_cp(st->local_ident, me->ident_pub, 32); sig_cp(st->remote_ident, b->ident, 32);
    st->local_regid = me->reg_id; st->remote_regid = b->reg_id;
    sig_cp(st->recv[0].ratchet_pub, b->spk, 32); sig_cp(st->recv[0].ck, chain, 32); st->recv[0].index = 0; st->n_recv = 1;
    sig_cp(st->root, root, 32);
    root_create_chain(st->root, st->send_ck, r_priv, b->spk);
    sig_cp(st->send_priv, r_priv, 32); sig_cp(st->send_pub, r_pub, 32); st->send_index = 0; st->prev_counter = 0;
    st->has_pending = 1; st->pend_opk_id = b->has_opk ? b->opk_id : 0; st->pend_spk_id = b->spk_id; sig_cp(st->pend_base_pub, base_pub, 32);
    sig_cp(st->base_key, base_pub, 32);
    sig_zero(base_priv, 32); sig_zero(r_priv, 32); sig_zero(dh1, 32); sig_zero(dh2, 32); sig_zero(dh3, 32); sig_zero(dh4, 32); sig_zero(root, 32); sig_zero(chain, 32);
    return SIG_OK;
}

/* ---- encrypt ----------------------------------------------------------------------------------------- */
static uint8_t inner[SIG_INNER_MAX], body_pt[SIG_BODY_MAX], body_ct[SIG_BODY_MAX];
static aes_key ak;

static void mac_update_ident(hmac_sha256_ctx *c, const uint8_t pub[32]) { uint8_t t = 0x05; hmac_sha256_update(c, &t, 1); hmac_sha256_update(c, pub, 32); }

int sig_encrypt(sig_session *s, const sig_local *me, const uint8_t *pt, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *outlen, int *is_pkmsg)
{
    sig_state *st = &s->cur; uint8_t ckey[32], mkey[32], iv[16], key33[33]; hmac_sha256_ctx hc; pb_writer w; uint32_t i, pad, blen, n;
    *outlen = 0; *is_pkmsg = 0; (void)me;
    if (!st->valid) return SIG_ERR_NO_SESSION;
    pad = 16 - (len & 15); blen = len + pad;
    if (blen > SIG_BODY_MAX) return SIG_ERR_BUFFER;
    chain_message_keys(st->send_ck, ckey, mkey, iv);
    sig_cp(body_pt, pt, len); for (i = len; i < blen; i++) body_pt[i] = (uint8_t)pad;     /* PKCS#7 */
    aes_set_key(&ak, ckey, 256);
    aes_cbc_encrypt(&ak, iv, body_pt, blen, body_ct);
    /* SignalMessage: version byte, protobuf, 8-byte MAC */
    inner[0] = (uint8_t)((SIG_VERSION << 4) | SIG_VERSION);
    pb_w_init(&w, inner + 1, sizeof inner - 1);
    key33[0] = 0x05; sig_cp(key33 + 1, st->send_pub, 32);
    pb_w_bytes(&w, 1, key33, 33);
    pb_w_uint(&w, 2, st->send_index);
    pb_w_uint(&w, 3, st->prev_counter);
    pb_w_bytes(&w, 4, body_ct, blen);
    if (!w.ok) return SIG_ERR_BUFFER;
    n = 1 + w.len;
    hmac_sha256_init(&hc, mkey, 32);
    mac_update_ident(&hc, st->local_ident); mac_update_ident(&hc, st->remote_ident);
    hmac_sha256_update(&hc, inner, n);
    hmac_sha256_final(&hc, ckey);                         /* ckey reused as scratch for the full MAC */
    sig_cp(inner + n, ckey, SIG_MAC_LEN); n += SIG_MAC_LEN;
    if (st->has_pending) {
        /* PreKeySignalMessage around it */
        if (cap < 1) return SIG_ERR_BUFFER;
        out[0] = inner[0];
        pb_w_init(&w, out + 1, cap - 1);
        if (st->pend_opk_id) pb_w_uint(&w, 1, st->pend_opk_id);
        key33[0] = 0x05; sig_cp(key33 + 1, st->pend_base_pub, 32); pb_w_bytes(&w, 2, key33, 33);
        key33[0] = 0x05; sig_cp(key33 + 1, st->local_ident, 32);   pb_w_bytes(&w, 3, key33, 33);
        pb_w_bytes(&w, 4, inner, n);
        pb_w_uint(&w, 5, st->local_regid);
        pb_w_uint(&w, 6, st->pend_spk_id);
        if (!w.ok) return SIG_ERR_BUFFER;
        *outlen = 1 + w.len; *is_pkmsg = 1;
    } else {
        if (cap < n) return SIG_ERR_BUFFER;
        sig_cp(out, inner, n); *outlen = n;
    }
    chain_next(st->send_ck); st->send_index++;
    sig_zero(ckey, 32); sig_zero(mkey, 32); sig_zero(iv, 16); sig_zero(body_pt, blen); sig_zero(&ak, sizeof ak);
    return SIG_OK;
}

/* ---- decrypt ------------------------------------------------------------------------------------------ */
typedef struct { const uint8_t *ratchet; uint32_t counter, prev; const uint8_t *ct; uint32_t ctlen; } sig_msg;

static int parse_message(const uint8_t *in, uint32_t len, sig_msg *m)
{
    const uint8_t *p, *end, *d; uint32_t f, wire, v, l;
    sig_zero(m, sizeof *m);
    if (len < 1 + SIG_MAC_LEN + 2) return SIG_ERR_FORMAT;
    if ((in[0] >> 4) != SIG_VERSION) return SIG_ERR_VERSION;
    p = in + 1; end = in + len - SIG_MAC_LEN;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
        if (f == 1 && wire == PB_BYTES) { if (l != 33 || d[0] != 0x05) return SIG_ERR_FORMAT; m->ratchet = d + 1; }
        else if (f == 2 && wire == PB_VARINT) m->counter = v;
        else if (f == 3 && wire == PB_VARINT) m->prev = v;
        else if (f == 4 && wire == PB_BYTES) { m->ct = d; m->ctlen = l; }
    }
    if (p != end) return SIG_ERR_FORMAT;
    if (!m->ratchet || !m->ct || m->ctlen < 16 || (m->ctlen & 15)) return SIG_ERR_FORMAT;
    return SIG_OK;
}

static sig_recv_chain *find_chain(sig_state *st, const uint8_t *pub)
{
    uint32_t i;
    for (i = 0; i < st->n_recv; i++) if (ct_eq(st->recv[i].ratchet_pub, pub, 32)) return &st->recv[i];
    return 0;
}

static void drop_skipped_of(sig_state *st, const uint8_t *pub)
{
    uint32_t i = 0;
    while (i < st->n_skipped) {
        if (ct_eq(st->skipped[i].ratchet_pub, pub, 32)) { uint32_t j; for (j = i + 1; j < st->n_skipped; j++) st->skipped[j - 1] = st->skipped[j]; st->n_skipped--; }
        else i++;
    }
}

static void push_skipped(sig_state *st, const uint8_t *pub, uint32_t counter, const uint8_t ck[32])
{
    sig_skipped_key *k;
    if (st->n_skipped == SIG_SKIPPED) { uint32_t j; for (j = 1; j < SIG_SKIPPED; j++) st->skipped[j - 1] = st->skipped[j]; st->n_skipped--; }
    k = &st->skipped[st->n_skipped++];
    sig_cp(k->ratchet_pub, pub, 32); k->counter = counter;
    chain_message_keys(ck, k->cipher, k->mac, k->iv);
}

/* SessionCipher.DecryptWithState on one state (the caller hands a copy and commits on success) */
static int decrypt_with_state(sig_state *st, const sig_local *me, const uint8_t *in, uint32_t len, uint8_t *pt, uint32_t cap, uint32_t *ptlen)
{
    sig_msg m; sig_recv_chain *ch; uint8_t ckey[32], mkey[32], iv[16], mac[32]; hmac_sha256_ctx hc; int r; uint32_t i, pad;
    if (!st->valid) return SIG_ERR_NO_SESSION;
    if ((r = parse_message(in, len, &m)) != SIG_OK) return r;
    ch = find_chain(st, m.ratchet);
    if (!ch) {
        /* DH ratchet (getOrCreateChainKey): receiver chain with our current ratchet key, then a fresh sending chain */
        uint8_t rck[32], np[32], npub[32];
        root_create_chain(st->root, rck, st->send_priv, m.ratchet);
        keygen(me, np, npub);
        if (st->n_recv == SIG_RECV_CHAINS) { drop_skipped_of(st, st->recv[0].ratchet_pub); for (i = 1; i < SIG_RECV_CHAINS; i++) st->recv[i - 1] = st->recv[i]; st->n_recv--; }
        ch = &st->recv[st->n_recv++];
        sig_cp(ch->ratchet_pub, m.ratchet, 32); sig_cp(ch->ck, rck, 32); ch->index = 0;
        st->prev_counter = st->send_index - 1;      /* libsignal-go: max(index-1, 0) on uint32 wraps to 0xFFFFFFFF for a fresh chain */
        root_create_chain(st->root, st->send_ck, np, m.ratchet);
        sig_cp(st->send_priv, np, 32); sig_cp(st->send_pub, npub, 32); st->send_index = 0;
        sig_zero(rck, 32); sig_zero(np, 32);
    }
    /* message keys (getOrCreateMessageKeys) */
    if (ch->index > m.counter) {
        for (i = 0; i < st->n_skipped; i++) if (st->skipped[i].counter == m.counter && ct_eq(st->skipped[i].ratchet_pub, m.ratchet, 32)) break;
        if (i == st->n_skipped) return SIG_ERR_OLD_COUNTER;
        sig_cp(ckey, st->skipped[i].cipher, 32); sig_cp(mkey, st->skipped[i].mac, 32); sig_cp(iv, st->skipped[i].iv, 16);
        for (i = i + 1; i < st->n_skipped; i++) st->skipped[i - 1] = st->skipped[i];
        st->n_skipped--;
    } else {
        if (m.counter - ch->index > SIG_MAX_FUTURE) return SIG_ERR_FUTURE;
        while (ch->index < m.counter) { push_skipped(st, m.ratchet, ch->index, ch->ck); chain_next(ch->ck); ch->index++; }
        chain_message_keys(ch->ck, ckey, mkey, iv);
        chain_next(ch->ck); ch->index++;
    }
    /* MAC over sender identity, receiver identity, version byte + protobuf */
    hmac_sha256_init(&hc, mkey, 32);
    mac_update_ident(&hc, st->remote_ident); mac_update_ident(&hc, st->local_ident);
    hmac_sha256_update(&hc, in, len - SIG_MAC_LEN);
    hmac_sha256_final(&hc, mac);
    r = ct_eq(mac, in + len - SIG_MAC_LEN, SIG_MAC_LEN) ? SIG_OK : SIG_ERR_MAC;
    sig_zero(mac, 32); sig_zero(mkey, 32);
    if (r != SIG_OK) { sig_zero(ckey, 32); return r; }
    if (m.ctlen > cap) { sig_zero(ckey, 32); return SIG_ERR_BUFFER; }
    aes_set_key(&ak, ckey, 256);
    aes_cbc_decrypt(&ak, iv, m.ct, m.ctlen, pt);
    sig_zero(ckey, 32); sig_zero(&ak, sizeof ak);
    pad = pt[m.ctlen - 1];
    if (pad == 0 || pad > 16 || pad > m.ctlen) { sig_zero(pt, m.ctlen); return SIG_ERR_PADDING; }
    for (i = 0; i < pad; i++) if (pt[m.ctlen - 1 - i] != pad) { sig_zero(pt, m.ctlen); return SIG_ERR_PADDING; }
    *ptlen = m.ctlen - pad;
    st->has_pending = 0;                                    /* ClearUnackPreKeyMessage */
    return SIG_OK;
}

typedef struct { uint32_t opk_id, reg_id, spk_id; const uint8_t *base, *ident, *msg; uint32_t msg_len; } sig_pkmsg;

static int parse_pkmsg(const uint8_t *in, uint32_t len, sig_pkmsg *m)
{
    const uint8_t *p, *end, *d; uint32_t f, wire, v, l;
    sig_zero(m, sizeof *m);
    if (len < 2) return SIG_ERR_FORMAT;
    if ((in[0] >> 4) != SIG_VERSION) return SIG_ERR_VERSION;
    p = in + 1; end = in + len;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
        if (f == 1 && wire == PB_VARINT) m->opk_id = v;
        else if (f == 2 && wire == PB_BYTES) { if (l != 33 || d[0] != 0x05) return SIG_ERR_FORMAT; m->base = d + 1; }
        else if (f == 3 && wire == PB_BYTES) { if (l != 33 || d[0] != 0x05) return SIG_ERR_FORMAT; m->ident = d + 1; }
        else if (f == 4 && wire == PB_BYTES) { m->msg = d; m->msg_len = l; }
        else if (f == 5 && wire == PB_VARINT) m->reg_id = v;
        else if (f == 6 && wire == PB_VARINT) m->spk_id = v;
    }
    if (p != end || !m->base || !m->ident || !m->msg) return SIG_ERR_FORMAT;
    return SIG_OK;
}

static sig_state work; static sig_session backup;

int sig_decrypt(sig_session *s, const sig_local *me, int is_pkmsg, const uint8_t *in, uint32_t len, uint8_t *pt, uint32_t cap, uint32_t *ptlen, uint32_t *used_opk_id)
{
    const uint8_t *inner_p = in; uint32_t inner_len = len, opk_used = 0; int r, fresh = 0;
    *ptlen = 0; *used_opk_id = 0;
    if (is_pkmsg) {
        sig_pkmsg pk;
        if ((r = parse_pkmsg(in, len, &pk)) != SIG_OK) return r;
        if (!((s->cur.valid && ct_eq(s->cur.base_key, pk.base, 32)) || (s->has_prev && s->prev.valid && ct_eq(s->prev.base_key, pk.base, 32)))) {
            /* X3DH as responder (Builder.processV3) with our signed prekey and the named one-time prekey */
            uint8_t dh1[32], dh2[32], dh3[32], dh4[32], root[32], chain[32]; const uint8_t *opk_priv = 0; sig_state *st;
            if (pk.spk_id != me->spk_id) return SIG_ERR_NO_PREKEY;
            if (pk.opk_id) {
                const wa_prekey *k = me->prekeys ? wa_prekeys_find(me->prekeys, pk.opk_id) : 0;
                if (!k) return SIG_ERR_NO_PREKEY;
                opk_priv = k->priv;
            }
            x25519_ref(dh1, me->spk_priv, pk.ident);           /* DH(SPK_a, I_b) */
            x25519_ref(dh2, me->ident_priv, pk.base);          /* DH(I_a, E_b) */
            x25519_ref(dh3, me->spk_priv, pk.base);            /* DH(SPK_a, E_b) */
            if (opk_priv) x25519_ref(dh4, opk_priv, pk.base);  /* DH(OPK_a, E_b) */
            x3dh_derive(root, chain, dh1, dh2, dh3, opk_priv ? dh4 : 0);
            backup = *s; fresh = 1;
            archive(s);
            st = &s->cur;
            st->valid = 1;
            sig_cp(st->local_ident, me->ident_pub, 32); sig_cp(st->remote_ident, pk.ident, 32);
            st->local_regid = me->reg_id; st->remote_regid = pk.reg_id;
            sig_cp(st->root, root, 32);
            sig_cp(st->send_priv, me->spk_priv, 32); sig_cp(st->send_pub, me->spk_pub, 32); sig_cp(st->send_ck, chain, 32); st->send_index = 0; st->prev_counter = 0;
            sig_cp(st->base_key, pk.base, 32);
            opk_used = pk.opk_id;
            sig_zero(dh1, 32); sig_zero(dh2, 32); sig_zero(dh3, 32); sig_zero(dh4, 32); sig_zero(root, 32); sig_zero(chain, 32);
        }
        inner_p = pk.msg; inner_len = pk.msg_len;
    }
    /* the current state, on a copy; committed only after the MAC verified */
    work = s->cur;
    r = decrypt_with_state(&work, me, inner_p, inner_len, pt, cap, ptlen);
    if (r == SIG_OK) {
        s->cur = work;
        if (opk_used && me->prekeys) { wa_prekeys_remove(me->prekeys, opk_used); *used_opk_id = opk_used; }
        sig_zero(&work, sizeof work);
        return SIG_OK;
    }
    if (r != SIG_ERR_OLD_COUNTER && s->has_prev && s->prev.valid && !fresh) {
        /* the archived state (DecryptWithRecord): success promotes it */
        int r2;
        work = s->prev;
        r2 = decrypt_with_state(&work, me, inner_p, inner_len, pt, cap, ptlen);
        if (r2 == SIG_OK) { s->prev = s->cur; s->cur = work; sig_zero(&work, sizeof work); return SIG_OK; }
        if (r2 == SIG_ERR_OLD_COUNTER) r = r2;
    }
    if (fresh) { *s = backup; sig_zero(&backup, sizeof backup); }   /* the new state is not kept when its first message fails */
    sig_zero(&work, sizeof work);
    return r;
}

/* ---- store ------------------------------------------------------------------------------------------- */
void sig_store_init(sig_store *st) { sig_zero(st, sizeof *st); }

static int user_eq(const char *a, const char *b) { uint32_t i; for (i = 0; i < SIG_USER_MAX; i++) { if (a[i] != b[i]) return 0; if (!a[i]) return 1; } return 1; }

sig_session *sig_store_get(sig_store *st, const char *user, uint32_t device, int lid, int create)
{
    uint32_t i, idx = 0, best = 0xffffffffu;
    for (i = 0; i < st->n; i++) if (st->e[i].device == device && st->e[i].lid == (lid ? 1 : 0) && user_eq(st->e[i].user, user)) { st->e[i].stamp = ++st->stamp; return &st->e[i].s; }
    if (!create) return 0;
    if (st->n < SIG_STORE_MAX) idx = st->n++;
    else for (i = 0; i < st->n; i++) if (st->e[i].stamp < best) { best = st->e[i].stamp; idx = i; }
    sig_zero(&st->e[idx], sizeof st->e[idx]);
    for (i = 0; i < SIG_USER_MAX - 1 && user[i]; i++) st->e[idx].user[i] = user[i];
    st->e[idx].device = device; st->e[idx].lid = lid ? 1 : 0; st->e[idx].stamp = ++st->stamp;
    return &st->e[idx].s;
}

typedef struct { uint8_t *p; uint32_t o; } sig_wcur;
static void w8(sig_wcur *c, uint32_t v) { c->p[c->o++] = (uint8_t)v; }
static void w32(sig_wcur *c, uint32_t v) { sig_be32(c->p + c->o, v); c->o += 4; }
static void wb(sig_wcur *c, const uint8_t *s, uint32_t n) { sig_cp(c->p + c->o, s, n); c->o += n; }
static void write_state(sig_wcur *c, const sig_state *s)
{
    uint32_t i;
    w8(c, s->valid); w8(c, s->has_pending); wb(c, s->local_ident, 32); wb(c, s->remote_ident, 32); w32(c, s->local_regid); w32(c, s->remote_regid);
    wb(c, s->root, 32); wb(c, s->send_priv, 32); wb(c, s->send_pub, 32); wb(c, s->send_ck, 32); w32(c, s->send_index); w32(c, s->prev_counter);
    w32(c, s->n_recv); for (i = 0; i < SIG_RECV_CHAINS; i++) { wb(c, s->recv[i].ratchet_pub, 32); wb(c, s->recv[i].ck, 32); w32(c, s->recv[i].index); }
    w32(c, s->n_skipped); for (i = 0; i < SIG_SKIPPED; i++) { const sig_skipped_key *k = &s->skipped[i]; wb(c, k->ratchet_pub, 32); w32(c, k->counter); wb(c, k->cipher, 32); wb(c, k->mac, 32); wb(c, k->iv, 16); }
    w32(c, s->pend_opk_id); w32(c, s->pend_spk_id); wb(c, s->pend_base_pub, 32); wb(c, s->base_key, 32);
}
typedef struct { const uint8_t *p; uint32_t o; } sig_rcur;
static uint32_t r8(sig_rcur *c) { return c->p[c->o++]; }
static uint32_t r32(sig_rcur *c) { uint32_t v = sig_rd32(c->p + c->o); c->o += 4; return v; }
static void rb(sig_rcur *c, uint8_t *d, uint32_t n) { sig_cp(d, c->p + c->o, n); c->o += n; }
static int read_state(sig_rcur *c, sig_state *s)
{
    uint32_t i;
    s->valid = (uint8_t)r8(c); s->has_pending = (uint8_t)r8(c); rb(c, s->local_ident, 32); rb(c, s->remote_ident, 32); s->local_regid = r32(c); s->remote_regid = r32(c);
    rb(c, s->root, 32); rb(c, s->send_priv, 32); rb(c, s->send_pub, 32); rb(c, s->send_ck, 32); s->send_index = r32(c); s->prev_counter = r32(c);
    s->n_recv = r32(c); for (i = 0; i < SIG_RECV_CHAINS; i++) { rb(c, s->recv[i].ratchet_pub, 32); rb(c, s->recv[i].ck, 32); s->recv[i].index = r32(c); }
    s->n_skipped = r32(c); for (i = 0; i < SIG_SKIPPED; i++) { sig_skipped_key *k = &s->skipped[i]; rb(c, k->ratchet_pub, 32); k->counter = r32(c); rb(c, k->cipher, 32); rb(c, k->mac, 32); rb(c, k->iv, 16); }
    s->pend_opk_id = r32(c); s->pend_spk_id = r32(c); rb(c, s->pend_base_pub, 32); rb(c, s->base_key, 32);
    return s->valid <= 1 && s->has_pending <= 1 && s->n_recv <= SIG_RECV_CHAINS && s->n_skipped <= SIG_SKIPPED;
}

uint32_t sig_store_write(uint8_t *out, uint32_t cap, const sig_store *st)
{
    sig_wcur c; uint32_t i, size = SIG_STORE_SIZE(st->n);
    if (st->n > SIG_STORE_MAX || cap < size) return 0;
    c.p = out; c.o = 0;
    w8(&c, 1); w32(&c, st->n); w32(&c, st->stamp);
    for (i = 0; i < st->n; i++) {
        const sig_entry *e = &st->e[i];
        wb(&c, (const uint8_t *)e->user, SIG_USER_MAX); w32(&c, e->device); w8(&c, e->lid); w32(&c, e->stamp);
        write_state(&c, &e->s.cur); write_state(&c, &e->s.prev); w8(&c, e->s.has_prev);
    }
    if (c.o != size - 32) return 0;
    sha256(out + c.o, out, c.o);
    return size;
}

int sig_store_read(sig_store *st, const uint8_t *in, uint32_t len)
{
    sig_rcur c; uint8_t h[32]; uint32_t i, n;
    sig_store_init(st);
    if (len < SIG_STORE_SIZE(0) || in[0] != 1) return 0;
    n = sig_rd32(in + 1);
    if (n > SIG_STORE_MAX || len != SIG_STORE_SIZE(n)) return 0;
    sha256(h, in, len - 32);
    if (!ct_eq(h, in + len - 32, 32)) return 0;
    c.p = in; c.o = 1; st->n = r32(&c); st->stamp = r32(&c);
    for (i = 0; i < n; i++) {
        sig_entry *e = &st->e[i];
        rb(&c, (uint8_t *)e->user, SIG_USER_MAX); e->user[SIG_USER_MAX - 1] = 0; e->device = r32(&c); e->lid = (uint8_t)r8(&c); e->stamp = r32(&c);
        if (!read_state(&c, &e->s.cur) || !read_state(&c, &e->s.prev)) { sig_store_init(st); return 0; }
        e->s.has_prev = (uint8_t)r8(&c);
        if (e->s.has_prev > 1 || e->lid > 1) { sig_store_init(st); return 0; }
    }
    return c.o == len - 32;
}
