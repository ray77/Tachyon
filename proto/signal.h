/*
 * Tachyon - the Signal session layer: X3DH session setup and the Double Ratchet exactly as go.mau.fi/libsignal v0.2.3
 * (the library whatsmeow uses) does it, so a message encrypted here decrypts on the phone and vice versa.
 * docs/SIGNAL.md has the byte layouts; tools/signalvectors (libsignal running both parties) produces the vectors
 * that tests/signal_test.c compares bit for bit.
 *
 *   X3DH initiator (we fetched a prekey bundle):   SK = HKDF(FF*32 || DH(I_a, SPK_b) || DH(E_a, I_b) || DH(E_a, SPK_b)
 *                                                  [|| DH(E_a, OPK_b)], salt 0, "WhisperText") -> root || recv chain
 *   X3DH responder (a pkmsg arrived):              SK = HKDF(FF*32 || DH(SPK_a, I_b) || DH(I_a, E_b) || DH(SPK_a, E_b)
 *                                                  [|| DH(OPK_a, E_b)], ...) -> root || send chain (ratchet key = SPK)
 *   DH ratchet:    root', chain = HKDF(DH(ratchet), salt root, "WhisperRatchet", 64)
 *   message keys:  HKDF(HMAC(chain, 01), salt 0, "WhisperMessageKeys", 80) = AES-256 key || MAC key || IV; chain = HMAC(chain, 02)
 *   SignalMessage: 33 || protobuf{ratchetKey 05||pub, counter, previousCounter, ciphertext AES-256-CBC/PKCS#7}
 *                  || HMAC-SHA256(macKey, 05||senderIdentity || 05||receiverIdentity || the 1 + protobuf bytes)[0..8)
 *   PreKeySignalMessage: 33 || protobuf{preKeyId, baseKey, identityKey, message=SignalMessage, registrationId, signedPreKeyId}
 *
 * Differences to libsignal-go, all on failure paths: decryption works on a copy of the state and commits only after
 * the MAC verified (libsignal-go ratchets the live state first), PKCS#7 padding bytes are all checked, and the
 * bounds are smaller (3 receiver chains, SIG_SKIPPED skipped message keys, one archived state) - the A500 holds
 * everything in static memory. Everything secret-dependent runs in constant time where the primitive allows
 * (X25519 ladder, comb, HMAC compare); the XEdDSA verification of a bundle handles public data only.
 *
 * Cost on the 68000 (7.7 s per ladder, 3.1 s per key pair, 9.4 s per XEdDSA verification): a new session as initiator
 * 1 verify + 3-4 ladders + 2 key pairs + 1 ladder = 46-54 s; as responder 3-4 ladders, then 2 ladders + 1 key pair
 * for the first message; afterwards one ladder + one key pair per direction change, nothing for same-direction messages.
 * Freestanding C, 32-bit arithmetic, no allocation.
 */
#ifndef TACHYON_SIGNAL_H
#define TACHYON_SIGNAL_H

#include <stdint.h>
#include "wabinary.h"

struct wa_prekeys;

#define SIG_VERSION      3
#define SIG_MAC_LEN      8
#define SIG_RECV_CHAINS  3        /* libsignal: 5 */
#define SIG_SKIPPED      12       /* skipped message keys kept per state; libsignal: 2000 */
#define SIG_MAX_FUTURE   2000     /* libsignal maxFutureMessages */
#define SIG_BODY_MAX     6144     /* padded plaintext / ciphertext body; the phone's first message to a new device (app state
                                     keys) was 2757 bytes on the wire in the second live attempt */
#define SIG_USER_MAX     24
#define SIG_STORE_MAX    6        /* sessions (one per remote device) */

enum {
    SIG_OK = 0,
    SIG_ERR_FORMAT,          /* protobuf / key type / length */
    SIG_ERR_VERSION,         /* message version not 3 */
    SIG_ERR_SIGNATURE,       /* the bundle's signed prekey signature does not verify */
    SIG_ERR_MAC,             /* MAC mismatch (with the current and the archived state) */
    SIG_ERR_OLD_COUNTER,     /* counter below the chain and no stored key: duplicate or too old */
    SIG_ERR_FUTURE,          /* counter more than SIG_MAX_FUTURE ahead */
    SIG_ERR_NO_SESSION,      /* a plain message, but no session (or no sender chain) */
    SIG_ERR_NO_PREKEY,       /* pkmsg names a one-time or signed prekey we do not hold */
    SIG_ERR_PADDING,         /* PKCS#7 padding invalid */
    SIG_ERR_BUFFER           /* output buffer too small */
};
const char *sig_errstr(int err);

typedef struct sig_recv_chain { uint8_t ratchet_pub[32], ck[32]; uint32_t index; } sig_recv_chain;
typedef struct sig_skipped_key { uint8_t ratchet_pub[32]; uint32_t counter; uint8_t cipher[32], mac[32], iv[16]; } sig_skipped_key;

typedef struct sig_state {
    uint8_t valid;                              /* has a sender chain */
    uint8_t has_pending;                        /* our prekey message is unacknowledged: keep sending pkmsg */
    uint8_t local_ident[32], remote_ident[32];
    uint32_t local_regid, remote_regid;
    uint8_t root[32];
    uint8_t send_priv[32], send_pub[32], send_ck[32]; uint32_t send_index, prev_counter;
    sig_recv_chain recv[SIG_RECV_CHAINS]; uint32_t n_recv;      /* newest last; the oldest is dropped */
    sig_skipped_key skipped[SIG_SKIPPED]; uint32_t n_skipped;   /* oldest first; the oldest is dropped */
    uint32_t pend_opk_id, pend_spk_id; uint8_t pend_base_pub[32];   /* pend_opk_id 0 = none */
    uint8_t base_key[32];                       /* the initiator's base key: a repeated pkmsg does not rebuild the session */
} sig_state;

typedef struct sig_session { sig_state cur, prev; uint8_t has_prev; } sig_session;

/* what the remote published (whatsmeow nodeToPreKeyBundle) */
typedef struct sig_bundle {
    uint32_t reg_id; uint8_t ident[32];
    uint32_t spk_id; uint8_t spk[32], spk_sig[64];
    int has_opk; uint32_t opk_id; uint8_t opk[32];
} sig_bundle;

/* our side */
typedef struct sig_local {
    const uint8_t *ident_priv, *ident_pub; uint32_t reg_id;
    uint32_t spk_id; const uint8_t *spk_priv, *spk_pub;
    struct wa_prekeys *prekeys;                 /* one-time prekeys with their private halves, or 0 */
    void (*random)(void *ctx, uint8_t *out, uint32_t n); void *rctx;   /* fresh ratchet / base keys */
} sig_local;

/* <user jid=..><registration/><type/><identity/><skey><id/><value/><signature/></skey>[<key><id/><value/></key>]</user>
 * (optionally wrapped in <keys>) from the encrypt/key IQ result; 1 = complete, 0 = malformed or <error> */
int sig_bundle_from_node(sig_bundle *b, const wab_node *user);

void sig_session_init(sig_session *s);                                           /* empty: no state */
int  sig_session_has_state(const sig_session *s);
/* X3DH as initiator: verifies the signed prekey signature (mandatory), draws the base key and the first ratchet key,
 * archives a current state; the next sig_encrypt produces a pkmsg */
int  sig_session_start(sig_session *s, const sig_local *me, const sig_bundle *b);
/* pt (already WhatsApp-padded by the caller) -> SignalMessage or PreKeySignalMessage bytes; *is_pkmsg says which */
int  sig_encrypt(sig_session *s, const sig_local *me, const uint8_t *pt, uint32_t len, uint8_t *out, uint32_t cap, uint32_t *outlen, int *is_pkmsg);
/* pkmsg (is_pkmsg = 1: X3DH as responder if the base key is new) or msg -> plaintext (still WhatsApp-padded).
 * *used_opk_id receives the one-time prekey a successful pkmsg consumed (0 = none): the caller removes it from the record. */
int  sig_decrypt(sig_session *s, const sig_local *me, int is_pkmsg, const uint8_t *in, uint32_t len, uint8_t *pt, uint32_t cap, uint32_t *ptlen, uint32_t *used_opk_id);

/* ---- the store: one session per remote device, serialised as one record with SHA-256 ------------------- */
typedef struct sig_entry { char user[SIG_USER_MAX]; uint32_t device; uint8_t lid; uint32_t stamp; sig_session s; } sig_entry;
typedef struct sig_store { uint32_t n, stamp; sig_entry e[SIG_STORE_MAX]; } sig_store;

#define SIG_STATE_SIZE   (2u + 64u + 8u + 32u + 96u + 8u + 4u + SIG_RECV_CHAINS * 68u + 4u + SIG_SKIPPED * 116u + 8u + 32u + 32u)
#define SIG_SESSION_SIZE (2u * SIG_STATE_SIZE + 1u)
#define SIG_ENTRY_SIZE   (SIG_USER_MAX + 4u + 1u + 4u + SIG_SESSION_SIZE)
#define SIG_STORE_SIZE(n) (1u + 4u + 4u + (n) * SIG_ENTRY_SIZE + 32u)
#define SIG_STORE_MAX_SIZE SIG_STORE_SIZE(SIG_STORE_MAX)

void         sig_store_init(sig_store *st);
/* the session of user:device (lid = 1 for @lid users); create = 1 makes an empty one, evicting the least recently used */
sig_session *sig_store_get(sig_store *st, const char *user, uint32_t device, int lid, int create);
uint32_t     sig_store_write(uint8_t *out, uint32_t cap, const sig_store *st);   /* bytes, 0 = does not fit */
int          sig_store_read(sig_store *st, const uint8_t *in, uint32_t len);     /* 1 = version, size and checksum ok */

#endif
