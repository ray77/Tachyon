/*
 * Tachyon - proto/signal.c against go.mau.fi/libsignal (tools/signalvectors -> tests/vectors/signal_vectors.txt).
 * Both parties are run with OUR code: Alice (the companion) and Bob (the phone), with the key pairs the library drew
 * fed through a scripted RNG, so every PreKeySignalMessage / SignalMessage must come out byte for byte as libsignal
 * produced it, every libsignal ciphertext must decrypt to the vector's plaintext, and the rejections (MAC, replay,
 * tampered bundle, unknown prekey) must match. Then the session store: round trip, every single-bit corruption rejected.
 * ASan/UBSan: make signal-test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "signal.h"
#include "prekeys.h"
#include "x25519.h"

static int fails, checks;
static void check(int ok, const char *what) { checks++; printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) fails++; }

/* ---- vectors ---------------------------------------------------------------------------------------------- */
typedef struct { char name[64]; uint8_t *data; uint32_t len; } vec;
static vec vecs[256]; static int nvecs;
static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
static void load(const char *path)
{
    FILE *f = fopen(path, "r"); static char line[16384];
    if (!f) { printf("cannot open %s\n", path); exit(1); }
    while (fgets(line, sizeof line, f)) {
        char *eq, *h; uint32_t i, n;
        if (line[0] == '#' || line[0] == '\n') continue;
        eq = strchr(line, '='); if (!eq) continue;
        *eq = 0; h = eq + 1; n = (uint32_t)strcspn(h, "\r\n"); h[n] = 0;
        strncpy(vecs[nvecs].name, line, 63);
        vecs[nvecs].len = n / 2; vecs[nvecs].data = malloc(n / 2 + 1);
        for (i = 0; i < n / 2; i++) vecs[nvecs].data[i] = (uint8_t)(hexval(h[2 * i]) * 16 + hexval(h[2 * i + 1]));
        nvecs++;
    }
    fclose(f);
}
static const vec *V(const char *name) { int i; for (i = 0; i < nvecs; i++) if (strcmp(vecs[i].name, name) == 0) return &vecs[i]; printf("missing vector %s\n", name); exit(1); }
static const uint8_t *B(const char *name) { return V(name)->data; }
static uint32_t U(const char *name) { const vec *v = V(name); return ((uint32_t)v->data[0] << 24) | ((uint32_t)v->data[1] << 16) | ((uint32_t)v->data[2] << 8) | v->data[3]; }
static int eqv(const uint8_t *p, uint32_t n, const char *name) { const vec *v = V(name); return v->len == n && memcmp(p, v->data, n) == 0; }

/* ---- scripted randomness: the key pairs libsignal drew, in the order our code asks for them ----------------- */
typedef struct { const uint8_t *q[16]; int n, head; const char *who; } script;
static void push(script *s, const char *name) { s->q[s->n++] = B(name); }
static void scripted_random(void *ctx, uint8_t *out, uint32_t n)
{
    script *s = ctx;
    if (n != 32 || s->head >= s->n) { printf("FAIL %s asked for randomness beyond the script (%u bytes, item %d of %d)\n", s->who, n, s->head, s->n); fails++; memset(out, 0x55, n); return; }
    memcpy(out, s->q[s->head++], 32);
}

static wa_prekeys alice_pk, bob_pk;
static void add_prekey(wa_prekeys *ps, uint32_t id, const uint8_t *priv, const uint8_t *pub) { wa_prekey *k = &ps->k[ps->n++]; k->id = id; memcpy(k->priv, priv, 32); memcpy(k->pub, pub, 32); k->uploaded = 1; }

static sig_bundle bundle_of(const char *who)
{
    sig_bundle b; char n[64]; memset(&b, 0, sizeof b);
    sprintf(n, "%s_regid", who); b.reg_id = U(n);
    sprintf(n, "%s_ident_pub", who); memcpy(b.ident, B(n), 32);
    sprintf(n, "%s_spk_id", who); b.spk_id = U(n);
    sprintf(n, "%s_spk_pub", who); memcpy(b.spk, B(n), 32);
    sprintf(n, "%s_spk_sig", who); memcpy(b.spk_sig, B(n), 64);
    sprintf(n, "%s_opk_id", who); b.opk_id = U(n); b.has_opk = 1;
    sprintf(n, "%s_opk_pub", who); memcpy(b.opk, B(n), 32);
    return b;
}

static uint8_t out[4096], pt[4096]; static uint32_t outlen, ptlen, used;
static char what[160];

static int enc_eq(sig_session *s, const sig_local *me, const char *name, int want_pk)
{
    int is_pk, r; char n[80];
    sprintf(n, "%s_pt", name);
    r = sig_encrypt(s, me, B(n), V(n)->len, out, sizeof out, &outlen, &is_pk);
    sprintf(what, "%s encrypts byte-exact as libsignal (%s, %u bytes)", name, want_pk ? "pkmsg" : "msg", outlen);
    check(r == SIG_OK && is_pk == want_pk && eqv(out, outlen, name), what);
    if (r == SIG_OK && !eqv(out, outlen, name)) { uint32_t i; const vec *v = V(name); printf("      ours:   "); for (i = 0; i < outlen; i++) printf("%02x", out[i]); printf("\n      vector: "); for (i = 0; i < v->len; i++) printf("%02x", v->data[i]); printf("\n"); }
    return r == SIG_OK;
}
static int dec_eq(sig_session *s, const sig_local *me, const char *name, int is_pk, const char *who)
{
    int r; char n[80];
    sprintf(n, "%s_pt", name);
    r = sig_decrypt(s, me, is_pk, B(name), V(name)->len, pt, sizeof pt, &ptlen, &used);
    sprintf(what, "%s decrypts %s to the vector plaintext (%u bytes)", who, name, ptlen);
    check(r == SIG_OK && eqv(pt, ptlen, n), what);
    if (r != SIG_OK) printf("      error: %s\n", sig_errstr(r));
    return r == SIG_OK;
}
static void state_eq(const sig_state *st, const char *prefix, const char *who)
{
    char n[80];
    sprintf(n, "%s_root", prefix);
    sprintf(what, "%s: root key, ratchet key pair, sending chain and counters as libsignal after %s", who, prefix);
    check(eqv(st->root, 32, n) && (sprintf(n, "%s_ratchet_priv", prefix), eqv(st->send_priv, 32, n)) && (sprintf(n, "%s_ratchet_pub", prefix), eqv(st->send_pub, 32, n))
          && (sprintf(n, "%s_send_chain", prefix), eqv(st->send_ck, 32, n)) && (sprintf(n, "%s_send_index", prefix), st->send_index == U(n))
          && (sprintf(n, "%s_prev_counter", prefix), st->prev_counter == U(n)), what);
}

int main(int argc, char **argv)
{
    static sig_session alice, bob, saved, probe; static script ra, rb; static sig_store store, store2; static uint8_t rec[SIG_STORE_MAX_SIZE], bad[SIG_STORE_MAX_SIZE];
    sig_local la, lb; sig_bundle b; int r, is_pk; uint32_t i, n, rejected;
    load(argc > 1 ? argv[1] : "tests/vectors/signal_vectors.txt");
    printf("%d vectors\n", nvecs);

    /* the two parties */
    wa_prekeys_init(&alice_pk); add_prekey(&alice_pk, U("alice_opk_id"), B("alice_opk_priv"), B("alice_opk_pub"));
    wa_prekeys_init(&bob_pk); add_prekey(&bob_pk, U("bob_opk_id"), B("bob_opk_priv"), B("bob_opk_pub"));
    ra.who = "alice"; rb.who = "bob";
    la.ident_priv = B("alice_ident_priv"); la.ident_pub = B("alice_ident_pub"); la.reg_id = U("alice_regid"); la.spk_id = U("alice_spk_id");
    la.spk_priv = B("alice_spk_priv"); la.spk_pub = B("alice_spk_pub"); la.prekeys = &alice_pk; la.random = scripted_random; la.rctx = &ra;
    lb.ident_priv = B("bob_ident_priv"); lb.ident_pub = B("bob_ident_pub"); lb.reg_id = U("bob_regid"); lb.spk_id = U("bob_spk_id");
    lb.spk_priv = B("bob_spk_priv"); lb.spk_pub = B("bob_spk_pub"); lb.prekeys = &bob_pk; lb.random = scripted_random; lb.rctx = &rb;
    { uint8_t pub[32]; x25519_ref_base(pub, la.ident_priv); check(memcmp(pub, la.ident_pub, 32) == 0, "vector identity key pair consistent"); }
    sig_session_init(&alice); sig_session_init(&bob);
    check(!sig_session_has_state(&alice), "fresh session has no state");

    /* ---- scenario 1: Alice initiates ---------------------------------------------------------------------- */
    push(&ra, "s1_alice_base_priv"); push(&ra, "s1_alice_ratchet1_priv");
    b = bundle_of("bob");
    r = sig_session_start(&alice, &la, &b);
    check(r == SIG_OK, "alice: X3DH from Bob's bundle (signature verified)");
    check(eqv(alice.cur.recv[0].ck, 32, "s1_x3dh_chain") && alice.cur.n_recv == 1 && eqv(alice.cur.recv[0].ratchet_pub, 32, "bob_spk_pub"), "alice: X3DH chain key == libsignal (receiver chain on Bob's signed prekey)");
    check(eqv(alice.cur.root, 32, "s1_send_root") && eqv(alice.cur.send_ck, 32, "s1_send_chain"), "alice: root key and sending chain after the first DH ratchet == libsignal");
    check(alice.cur.has_pending && alice.cur.pend_opk_id == U("bob_opk_id") && alice.cur.pend_spk_id == U("bob_spk_id") && eqv(alice.cur.pend_base_pub, 32, "s1_alice_base_pub"), "alice: pending prekey message items");
    check(alice.cur.remote_regid == U("bob_regid") && alice.cur.local_regid == U("alice_regid"), "alice: registration ids");
    enc_eq(&alice, &la, "s1_pkmsg1", 1);
    enc_eq(&alice, &la, "s1_pkmsg2", 1);
    check(alice.cur.send_index == 2 && alice.cur.has_pending, "alice: chain stepped twice, prekey message still unacknowledged");
    { static uint8_t big[SIG_BODY_MAX + 32]; check(sig_encrypt(&alice, &la, big, SIG_BODY_MAX + 1, out, sizeof out, &outlen, &is_pk) == SIG_ERR_BUFFER, "oversize plaintext refused"); }

    push(&rb, "s1_bob1_ratchet_priv");
    dec_eq(&bob, &lb, "s1_pkmsg1", 1, "bob");
    check(used == U("bob_opk_id") && bob_pk.n == 0, "bob: one-time prekey 42 consumed and removed from the record");
    state_eq(&bob.cur, "s1_bob1", "bob");
    check(bob.cur.remote_regid == U("alice_regid") && eqv(bob.cur.remote_ident, 32, "alice_ident_pub") && eqv(bob.cur.base_key, 32, "s1_alice_base_pub"), "bob: remote identity, registration id, base key");
    dec_eq(&bob, &lb, "s1_pkmsg2", 1, "bob");
    check(used == 0, "bob: second prekey message for the same base key reuses the session (no X3DH, no prekey)");
    saved = bob;
    r = sig_decrypt(&bob, &lb, 1, B("s1_pkmsg1"), V("s1_pkmsg1")->len, pt, sizeof pt, &ptlen, &used);
    check(r == SIG_ERR_OLD_COUNTER && memcmp(&saved, &bob, sizeof bob) == 0, "bob: replayed prekey message rejected (old counter), state untouched");

    enc_eq(&bob, &lb, "s1_msg1", 0); enc_eq(&bob, &lb, "s1_msg2", 0); enc_eq(&bob, &lb, "s1_msg3", 0);

    push(&ra, "s1_alice2_ratchet_priv");
    dec_eq(&alice, &la, "s1_msg2", 0, "alice");
    check(alice.cur.n_skipped == 1 && alice.cur.skipped[0].counter == 0 && !alice.cur.has_pending, "alice: key for counter 0 kept, prekey message acknowledged by Bob's answer");
    state_eq(&alice.cur, "s1_alice2", "alice");
    dec_eq(&alice, &la, "s1_msg1", 0, "alice (skipped key)");
    check(alice.cur.n_skipped == 0, "alice: skipped key consumed");
    dec_eq(&alice, &la, "s1_msg3", 0, "alice");
    saved = alice;
    r = sig_decrypt(&alice, &la, 0, B("s1_msg1"), V("s1_msg1")->len, pt, sizeof pt, &ptlen, &used);
    check(r == SIG_ERR_OLD_COUNTER && memcmp(&saved, &alice, sizeof alice) == 0, "alice: replayed msg1 rejected (old counter), state untouched");

    enc_eq(&alice, &la, "s1_msg4", 0);
    push(&rb, "s1_bob2_ratchet_priv");
    dec_eq(&bob, &lb, "s1_msg4", 0, "bob");
    state_eq(&bob.cur, "s1_bob2", "bob");
    enc_eq(&bob, &lb, "s1_msg5", 0);
    push(&ra, "s1_alice3_ratchet_priv");
    dec_eq(&alice, &la, "s1_msg5", 0, "alice");
    state_eq(&alice.cur, "s1_alice3", "alice");

    /* rejections: the state must not move (s1_msg6 is Bob's next message on this chain, not seen by Alice yet) */
    saved = alice;
    memcpy(out, B("s1_msg6"), V("s1_msg6")->len); n = V("s1_msg6")->len; out[n - 1] ^= 1;
    r = sig_decrypt(&alice, &la, 0, out, n, pt, sizeof pt, &ptlen, &used);
    check(r == SIG_ERR_MAC && memcmp(&saved, &alice, sizeof alice) == 0, "tampered MAC rejected, state untouched");
    memcpy(out, B("s1_msg6"), n); out[n - 12] ^= 1;
    r = sig_decrypt(&alice, &la, 0, out, n, pt, sizeof pt, &ptlen, &used);
    check(r == SIG_ERR_MAC && memcmp(&saved, &alice, sizeof alice) == 0, "tampered ciphertext rejected (MAC), state untouched");
    r = sig_decrypt(&alice, &la, 0, B("s1_msg5"), V("s1_msg5")->len, pt, sizeof pt, &ptlen, &used);
    check(r == SIG_ERR_OLD_COUNTER && memcmp(&saved, &alice, sizeof alice) == 0, "replayed msg5 rejected (old counter)");
    memcpy(out, B("s1_msg6"), n); out[0] = 0x22;
    check(sig_decrypt(&alice, &la, 0, out, n, pt, sizeof pt, &ptlen, &used) == SIG_ERR_VERSION, "version 2 rejected");
    check(sig_decrypt(&alice, &la, 0, B("s1_msg6"), n - 1, pt, sizeof pt, &ptlen, &used) != SIG_OK, "truncated message rejected");
    check(sig_decrypt(&alice, &la, 0, B("s1_msg6"), 5, pt, sizeof pt, &ptlen, &used) == SIG_ERR_FORMAT, "short message rejected");
    memcpy(out, B("s1_msg6"), n); out[3] = 0x06;
    check(sig_decrypt(&alice, &la, 0, out, n, pt, sizeof pt, &ptlen, &used) == SIG_ERR_FORMAT, "ratchet key type byte != 05 rejected");
    check(memcmp(&saved, &alice, sizeof alice) == 0, "state untouched by all rejections");
    { sig_bundle bb = bundle_of("bob"); bb.spk_sig[5] ^= 0x40; check(sig_session_start(&probe, &la, &bb) == SIG_ERR_SIGNATURE, "bundle with a flipped signature bit rejected"); }
    { sig_bundle bb = bundle_of("bob"); bb.ident[0] ^= 1; check(sig_session_start(&probe, &la, &bb) == SIG_ERR_SIGNATURE, "bundle with a changed identity key rejected (signature)"); }
    { sig_bundle bb = bundle_of("bob"); bb.spk[31] ^= 1; check(sig_session_start(&probe, &la, &bb) == SIG_ERR_SIGNATURE, "bundle with a changed signed prekey rejected (signature)"); }
    check(sig_decrypt(&probe, &la, 0, B("s1_msg5"), n, pt, sizeof pt, &ptlen, &used) == SIG_ERR_NO_SESSION, "plain message without a session rejected");
    check(sig_encrypt(&probe, &la, pt, 4, out, sizeof out, &outlen, &is_pk) == SIG_ERR_NO_SESSION, "encrypt without a session refused");

    /* Bob's last message under this session, read later through the archived state */
    enc_eq(&bob, &lb, "s1_msg6", 0);

    /* ---- scenario 2: Bob initiates with Alice's bundle (our one-time prekey 5 and signed prekey 1) ------------------- */
    push(&rb, "s2_bob_base_priv"); push(&rb, "s2_bob_ratchet1_priv");
    b = bundle_of("alice");
    check(sig_session_start(&bob, &lb, &b) == SIG_OK && bob.has_prev && bob.prev.valid, "bob: new session from Alice's bundle, old state archived");
    check(eqv(bob.cur.recv[0].ck, 32, "s2_x3dh_chain") && eqv(bob.cur.root, 32, "s2_send_root") && eqv(bob.cur.send_ck, 32, "s2_send_chain"), "bob: X3DH + first chain == libsignal");
    enc_eq(&bob, &lb, "s2_pkmsg1", 1);
    push(&ra, "s2_alice1_ratchet_priv");
    saved = alice;
    dec_eq(&alice, &la, "s2_pkmsg1", 1, "alice (responder)");
    check(used == U("alice_opk_id") && alice_pk.n == 0, "alice: one-time prekey 5 consumed and removed");
    check(alice.has_prev && memcmp(&alice.prev, &saved.cur, sizeof saved.cur) == 0, "alice: the s1 state is archived unchanged");
    state_eq(&alice.cur, "s2_alice1", "alice");
    {   /* the old session's last message arrives late: decrypted through the archived state, which is promoted */
        sig_session copy = alice;
        push(&ra, "s1_alice_base_priv");       /* the attempt on the current state ratchets on a copy (draws a key) before the archived state is tried */
        dec_eq(&copy, &la, "s1_msg6", 0, "alice (archived state)");
        check(copy.cur.send_index == saved.cur.send_index && memcmp(copy.prev.base_key, alice.cur.base_key, 32) == 0, "alice: archived state promoted, the new one archived");
    }
    enc_eq(&alice, &la, "s2_msg1", 0);
    push(&rb, "s2_bob2_ratchet_priv");
    dec_eq(&bob, &lb, "s2_msg1", 0, "bob");
    state_eq(&bob.cur, "s2_bob2", "bob");
    enc_eq(&bob, &lb, "s2_msg2", 0);
    push(&ra, "s2_alice2_ratchet_priv");
    dec_eq(&alice, &la, "s2_msg2", 0, "alice");
    state_eq(&alice.cur, "s2_alice2", "alice");
    check(ra.head == ra.n && rb.head == rb.n, "every scripted key pair consumed, none left: the RNG call order is libsignal's");

    /* a prekey message naming a one-time prekey we do not hold */
    saved = alice;
    r = sig_decrypt(&alice, &la, 1, B("s3_pkmsg_unknown_opk"), V("s3_pkmsg_unknown_opk")->len, pt, sizeof pt, &ptlen, &used);
    check(r == SIG_ERR_NO_PREKEY && memcmp(&saved, &alice, sizeof alice) == 0, "prekey message with unknown one-time prekey 999 rejected, state untouched");
    {   /* a prekey message whose inner message fails: the fresh state must be rolled back */
        static sig_session fresh; sig_local lf = la; static wa_prekeys pk2; uint8_t *m; uint32_t l = V("s2_pkmsg1")->len;
        wa_prekeys_init(&pk2); add_prekey(&pk2, U("alice_opk_id"), B("alice_opk_priv"), B("alice_opk_pub")); lf.prekeys = &pk2;
        sig_session_init(&fresh);
        m = malloc(l); memcpy(m, B("s2_pkmsg1"), l); m[l - 7] ^= 1;       /* last byte of the inner message's MAC (then registrationId and signedPreKeyId follow) */
        push(&ra, "s2_alice1_ratchet_priv");
        r = sig_decrypt(&fresh, &lf, 1, m, l, pt, sizeof pt, &ptlen, &used);
        check(r == SIG_ERR_MAC && !fresh.cur.valid && !fresh.has_prev && pk2.n == 1, "prekey message with a bad inner MAC: X3DH state rolled back, prekey kept");
        free(m);
    }

    /* ---- skipped keys: bounded, oldest dropped -------------------------------------------------------------------- */
    {
        static sig_session a2, b2; static script r2a, r2b; sig_local l2a = la, l2b = lb; static wa_prekeys pkb; static uint8_t msgs[SIG_SKIPPED + 4][256]; uint32_t ml[SIG_SKIPPED + 4]; int k;
        wa_prekeys_init(&pkb); add_prekey(&pkb, U("bob_opk_id"), B("bob_opk_priv"), B("bob_opk_pub")); l2b.prekeys = &pkb;
        r2a.who = "alice2"; r2b.who = "bob2"; l2a.rctx = &r2a; l2b.rctx = &r2b;
        push(&r2a, "s1_alice_base_priv"); push(&r2a, "s1_alice_ratchet1_priv"); push(&r2b, "s1_bob1_ratchet_priv");
        sig_session_init(&a2); sig_session_init(&b2);
        b = bundle_of("bob"); sig_session_start(&a2, &l2a, &b);
        for (k = 0; k < SIG_SKIPPED + 4; k++) { uint8_t t[8] = { 'n', (uint8_t)k, 1, 1, 1, 1, 1, 1 }; sig_encrypt(&a2, &l2a, t, 8, msgs[k], 256, &ml[k], &is_pk); }
        r = sig_decrypt(&b2, &l2b, 1, msgs[SIG_SKIPPED + 3], ml[SIG_SKIPPED + 3], pt, sizeof pt, &ptlen, &used);
        check(r == SIG_OK && ptlen == 8 && pt[1] == SIG_SKIPPED + 3 && b2.cur.n_skipped == SIG_SKIPPED, "last of 16 messages first: SIG_SKIPPED keys kept");
        r = sig_decrypt(&b2, &l2b, 1, msgs[3], ml[3], pt, sizeof pt, &ptlen, &used);
        check(r == SIG_OK && pt[1] == 3, "message 3 (within the kept window) decrypts from a skipped key");
        r = sig_decrypt(&b2, &l2b, 1, msgs[0], ml[0], pt, sizeof pt, &ptlen, &used);
        check(r == SIG_ERR_OLD_COUNTER, "message 0 (dropped, oldest) is rejected as old");
        for (k = 4; k < SIG_SKIPPED + 3; k++) if (sig_decrypt(&b2, &l2b, 1, msgs[k], ml[k], pt, sizeof pt, &ptlen, &used) != SIG_OK) break;
        check(k == SIG_SKIPPED + 3 && b2.cur.n_skipped == 0, "every other kept message decrypts, the skipped list empties");
    }

    /* ---- the store ------------------------------------------------------------------------------------------- */
    sig_store_init(&store);
    check(sig_store_get(&store, "4917612345678", 0, 0, 0) == 0, "store: unknown device, no create -> 0");
    *sig_store_get(&store, "4917612345678", 0, 0, 1) = alice;
    *sig_store_get(&store, "123456789012345", 0, 1, 1) = bob;
    check(store.n == 2 && sig_store_get(&store, "4917612345678", 0, 0, 0) == &store.e[0].s && sig_store_get(&store, "4917612345678", 0, 1, 0) == 0, "store: lookup by user, device and server kind");
    n = sig_store_write(rec, sizeof rec, &store);
    check(n == SIG_STORE_SIZE(2) && n == 1 + 8 + 2 * SIG_ENTRY_SIZE + 32, "store: record written");
    printf("      store record: %u bytes for 2 sessions, %u max (%u per session)\n", n, (unsigned)SIG_STORE_MAX_SIZE, (unsigned)SIG_ENTRY_SIZE);
    check(sig_store_read(&store2, rec, n) && memcmp(&store2, &store, sizeof store) == 0, "store: round trip bit-identical");
    rejected = 0;
    for (i = 0; i < n; i++) { memcpy(bad, rec, n); bad[i] ^= 1; if (!sig_store_read(&store2, bad, n)) rejected++; }
    check(rejected == n, "store: every single-bit corruption rejected");
    check(!sig_store_read(&store2, rec, n - 1) && !sig_store_read(&store2, rec, 0) && !sig_store_read(&store2, rec, n + 1), "store: wrong sizes rejected");
    check(sig_store_write(rec, n - 1, &store) == 0, "store: too small a buffer refused");
    for (i = 0; i < SIG_STORE_MAX + 2; i++) { char u[24]; sprintf(u, "49%010u", i); sig_store_get(&store, u, 3, 0, 1); }
    check(store.n == SIG_STORE_MAX && sig_store_get(&store, "4917612345678", 0, 0, 0) == 0 && sig_store_get(&store, "490000000007", 3, 0, 0) != 0, "store: full -> least recently used evicted");
    {   /* a session read back from the record keeps working */
        sig_store_read(&store2, rec, n);
        push(&rb, "s2_bob2_ratchet_priv");  /* not consumed: same-direction message */
        r = sig_encrypt(sig_store_get(&store2, "123456789012345", 0, 1, 0), &lb, (const uint8_t *)"abc\x01", 4, out, sizeof out, &outlen, &is_pk);
        r |= sig_decrypt(sig_store_get(&store2, "4917612345678", 0, 0, 0), &la, 0, out, outlen, pt, sizeof pt, &ptlen, &used);
        check(r == SIG_OK && ptlen == 4 && memcmp(pt, "abc\x01", 4) == 0, "store: sessions restored from the record encrypt and decrypt");
        rb.head--;
    }

    printf("%d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
