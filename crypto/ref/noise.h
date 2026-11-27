/*
 * WhatsA500 - Noise_XX_25519_AESGCM_SHA256 in the WhatsApp dialect
 * (whatsmeow socket/noisehandshake.go, verified 2026-11-26):
 *   h = pattern (32 bytes, "Noise_XX_25519_AESGCM_SHA256" + 4 NUL), ck = h, k = AES-256-GCM(h)
 *   MixHash(header "WA" 6 dictversion), MixHash(client e), MixHash(server e)
 *   MixKey(dh): ck, k = HKDF-SHA256(salt = ck, ikm = dh), counter = 0
 *   Encrypt/Decrypt: AES-256-GCM, iv = 8 zero bytes || BE32 counter, ad = h; then MixHash(ciphertext)
 *   Finish: write, read = HKDF(salt = ck, ikm = empty)
 * Transport frames: AES-256-GCM with the write/read key, iv counter per direction, no AD.
 */
#ifndef WHATSA500_NOISE_H
#define WHATSA500_NOISE_H

#include <stdint.h>
#include "aes.h"

typedef struct {
    uint8_t h[32];
    uint8_t ck[32];
    aes_gcm_key k;
    uint32_t counter;
} noise_hs;

typedef struct {
    aes_gcm_key write, read;
    uint32_t write_counter, read_counter;
} noise_transport;

void noise_start(noise_hs *n, const uint8_t *header, uint32_t header_len);
void noise_mix_hash(noise_hs *n, const uint8_t *data, uint32_t len);
void noise_mix_key(noise_hs *n, const uint8_t priv[32], const uint8_t pub[32]);   /* X25519 then HKDF */
/* ct = pt || tag (len + 16 bytes); pt may alias ct */
void noise_encrypt(noise_hs *n, const uint8_t *pt, uint32_t len, uint8_t *ct);
/* returns 1 and writes len-16 bytes of plaintext, 0 on tag mismatch (state untouched) */
int  noise_decrypt(noise_hs *n, const uint8_t *ct, uint32_t len, uint8_t *pt);
void noise_finish(noise_hs *n, noise_transport *t);

void noise_transport_encrypt(noise_transport *t, const uint8_t *pt, uint32_t len, uint8_t *ct);
int  noise_transport_decrypt(noise_transport *t, const uint8_t *ct, uint32_t len, uint8_t *pt);

/* Full client handshake, steps split so the caller can interleave network I/O:
 *   noise_client_hello:  after this, send client_eph_pub in ClientHello
 *   noise_client_finish: given ServerHello, produces the ClientFinish ciphertexts and the transport.
 * server_static_out / cert_out receive the decrypted server static key and certificate payload
 * (the caller verifies the certificate chain; this function does not). Returns 0 on any AEAD failure.
 *
 * es before the connection (docs/PROTOCOL.md section 6): of the client's three X25519 ladders only
 * es = DH(client_eph_priv, server_static) has a public input that is known beforehand - the server's static key
 * is the leaf certificate's key, verified on every connection and stable across them. The caller may compute
 * es from a stored copy of that key with noise_es_precompute (one ladder, ~7.7 s on the 68000, off the server's
 * clock) and pass it as `pre`: the DH result is used only if the static key decrypted from ServerHello is
 * byte-for-byte the one it was computed from (constant-time compare); otherwise the ladder runs as usual.
 * The decrypted key is authenticated by the ee AEAD, and the caller's leaf check (leaf key == server static)
 * is unchanged, so a wrong stored key can only cost the precomputation. *es_used (may be 0) tells which path ran. */
typedef struct { uint8_t server_static[32]; uint8_t dh[32]; int valid; } noise_es_pre;
void noise_es_precompute(noise_es_pre *p, const uint8_t client_eph_priv[32], const uint8_t server_static[32]);
void noise_client_hello(noise_hs *n, const uint8_t *header, uint32_t header_len, const uint8_t client_eph_pub[32]);
int  noise_client_finish(noise_hs *n,
                         const uint8_t client_eph_priv[32], const uint8_t client_static_priv[32], const uint8_t client_static_pub[32],
                         const uint8_t server_eph_pub[32], const uint8_t *server_static_ct, uint32_t server_static_ct_len,
                         const uint8_t *cert_ct, uint32_t cert_ct_len,
                         const uint8_t *client_payload, uint32_t client_payload_len,
                         uint8_t server_static_out[32], uint8_t *cert_out,
                         uint8_t client_static_ct_out[48], uint8_t *client_payload_ct_out,
                         noise_transport *t, const noise_es_pre *pre, int *es_used);

/* Cache for a verified NoiseCertificate (docs/PROTOCOL.md section 6, "Zertifikatscache"): WhatsApp's intermediate
 * certificate is stable (serial 3, signed by the root key), yet its XEdDSA verification costs ~11 s on the 68000.
 * One entry is SHA-256 over the root public key, the certificate details and its signature (each length-prefixed),
 * 32 bytes, meant to be stored (ENVARC: on the Amiga). A hit means exactly these details with exactly this
 * signature were verified under exactly this root key before; the caller still verifies the leaf under the
 * cached intermediate's key every time. Compare in constant time; a mismatch is a miss (full verification,
 * then the entry is overwritten), so a rotated intermediate or a changed root key is re-verified. */
typedef struct { uint8_t fp[32]; int valid; } noise_cert_cache;
void noise_cert_cache_fingerprint(uint8_t fp[32], const uint8_t root_pub[32],
                                  const uint8_t *details, uint32_t details_len, const uint8_t sig[64]);
int  noise_cert_cache_match(const noise_cert_cache *c, const uint8_t root_pub[32],
                            const uint8_t *details, uint32_t details_len, const uint8_t sig[64]);
void noise_cert_cache_store(noise_cert_cache *c, const uint8_t root_pub[32],
                            const uint8_t *details, uint32_t details_len, const uint8_t sig[64]);

#endif
