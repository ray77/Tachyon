/*
 * Tachyon - the companion device's identity: everything WhatsApp's multi-device pairing needs on our side
 * (whatsmeow store.Device, c2ce5c3): the Noise static key pair (the server knows us by its public key after
 * pairing), the Signal identity key pair (Curve25519; signs with XEdDSA), the signed prekey (id 1, signature =
 * XEdDSA over 0x05 || public key under the identity key, keys.KeyPair.Sign), the registration id and the
 * 32-byte ADV secret the phone uses to HMAC our device identity. All private scalars are stored clamped,
 * as libsignal does. Freestanding; docs/PROTOCOL.md section 11.
 */
#ifndef TACHYON_IDENTITY_H
#define TACHYON_IDENTITY_H

#include <stdint.h>
#include "drbg.h"

#define WA_SPK_ID 1u

typedef struct wa_identity {
    uint8_t noise_priv[32], noise_pub[32];
    uint8_t ident_priv[32], ident_pub[32];
    uint8_t spk_priv[32], spk_pub[32], spk_sig[64];
    uint32_t spk_id;
    uint32_t reg_id;                /* random 16-bit (libsignal uses 14, whatsmeow 32; the server takes all) */
    uint8_t adv_secret[32];
} wa_identity;

/* Fresh identity from the DRBG: 3 X25519 key pairs through the constant-time comb and one XEdDSA signature
 * (2 more comb multiplications) - about 18 s on the 68000, nothing of it needs the connection. */
void wa_identity_generate(wa_identity *id, hmac_drbg *rng);

/* Recompute the public keys from the private ones and check the prekey signature: 1 = consistent. For a record
 * read from storage (proto/creds.c) before it is trusted. Costs 3 comb multiplications + 1 XEdDSA verify. */
int  wa_identity_check(const wa_identity *id);

/* Standard base64 with padding (RFC 4648), NUL terminated; returns the length written (4 * ceil(n / 3)).
 * out must hold that many + 1 bytes. */
uint32_t wa_base64(char *out, const uint8_t *in, uint32_t n);

#endif
