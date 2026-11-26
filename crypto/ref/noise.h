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
 * (the caller verifies the certificate chain; this function does not). Returns 0 on any AEAD failure. */
void noise_client_hello(noise_hs *n, const uint8_t *header, uint32_t header_len, const uint8_t client_eph_pub[32]);
int  noise_client_finish(noise_hs *n,
                         const uint8_t client_eph_priv[32], const uint8_t client_static_priv[32], const uint8_t client_static_pub[32],
                         const uint8_t server_eph_pub[32], const uint8_t *server_static_ct, uint32_t server_static_ct_len,
                         const uint8_t *cert_ct, uint32_t cert_ct_len,
                         const uint8_t *client_payload, uint32_t client_payload_len,
                         uint8_t server_static_out[32], uint8_t *cert_out,
                         uint8_t client_static_ct_out[48], uint8_t *client_payload_ct_out,
                         noise_transport *t);

#endif
