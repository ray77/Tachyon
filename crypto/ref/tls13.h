/*
 * Tachyon (WhatsA500) - TLS 1.3 client, one profile: TLS_AES_128_GCM_SHA256, key share
 * X25519, server authenticated by an RSA certificate chain (rsa_pkcs1_sha256 in the chain,
 * rsa_pss_rsae_sha256 in CertificateVerify). This is what the web.whatsapp.com edge completes
 * (docs/PROTOCOL.md section 7). I/O agnostic like tls12: the caller moves bytes between the
 * socket and tls13_input / the output buffer.
 *
 * Not supported, by design: PSK/tickets (NewSessionTicket is ignored), HelloRetryRequest (clean
 * error), 0-RTT, client certificates (CertificateRequest is an error), KeyUpdate (error).
 *
 * Trust: the Certificate message is verified against the pinned root key and `host` before
 * anything else from the server is believed; the CertificateVerify signature and the server
 * Finished are checked before application keys are derived.
 *
 * Cost on the 68000: one X25519 (the shared secret; the key pair can be precomputed with
 * tls13_keypair_generate and passed to tls13_client_start_kp), one RSA-PSS verification, the
 * RSA chain as in tls12, HKDF-SHA256. All long loops call CRYPTO_YIELD() (heartbeat).
 */
#ifndef WHATSA500_TLS13_H
#define WHATSA500_TLS13_H

#include <stdint.h>
#include "aes.h"
#include "sha256.h"
#include "drbg.h"
#include "x509.h"

#define TLS13_IN_MAX   (16384 + 256 + 5 + 64) /* one protected record: 2^14 + 256 ciphertext (RFC 8446 5.2) */
#define TLS13_HS_MAX   8192                  /* reassembled handshake message (certificate chain) */
#define TLS13_OUT_MAX  (16384 + 5 + 17 + 512) /* one full application record plus a handshake flight */
#define TLS13_APP_MAX  (16384 + 256)

enum { TLS13_ST_START, TLS13_ST_WAIT_SH, TLS13_ST_WAIT_EE, TLS13_ST_WAIT_CERT, TLS13_ST_WAIT_CV, TLS13_ST_WAIT_FIN,
       TLS13_ST_CONNECTED, TLS13_ST_ERROR };

typedef struct { uint8_t priv[32], pub[32]; } tls13_keypair;

typedef struct {
    int state;
    int error;                      /* nonzero: tls13_errstr(error) */
    int alert;                      /* alert description received (valid when error is "alert from server") */
    const char *host;
    const uint8_t *root_n; uint32_t root_n_len; uint32_t root_e;
    const char *now;                /* "YYYYMMDDHHMMSSZ" or 0 */
    hmac_drbg *rng;

    uint8_t client_random[32];
    tls13_keypair kp;
    sha256_ctx transcript;
    uint8_t hs_secret[32], master_secret[32];
    uint8_t c_hs[32], s_hs[32];     /* handshake traffic secrets */
    uint8_t wr_iv[12], rd_iv[12];
    aes_gcm_key wr, rd;
    uint32_t wr_seq_hi, wr_seq_lo, rd_seq_hi, rd_seq_lo;
    int rd_encrypted, wr_encrypted;

    /* incoming record reassembly */
    uint8_t in[TLS13_IN_MAX]; uint32_t in_len;
    /* incoming handshake message reassembly (handshake messages may span records) */
    uint8_t hs[TLS13_HS_MAX]; uint32_t hs_len;
    /* bytes to send */
    uint8_t out[TLS13_OUT_MAX]; uint32_t out_len;
    /* decrypted application data from the last tls13_input */
    uint8_t app[TLS13_APP_MAX]; uint32_t app_len;
    /* server certificate chain (points into hs while the Certificate message is processed; kept for diagnostics) */
    x509_cert chain[4]; int chain_len;
    rsa_pub server_key;
    /* trust anchors: pins[0] is the root key given to tls13_client_start*, tls13_add_pin appends more (e.g. the
     * intermediate that signs the live leaf: one RSA verification instead of two); cert_pin = index of the pin
     * that completed the chain, -1 when the certificate came from the cache */
    x509_pin pins[X509_MAX_PINS]; int npins; int cert_pin;
    /* optional certificate cache (x509.h); cert_cached = 1 when the chain verification was skipped on a hit */
    x509_cache *cache; int cert_cached;
    uint32_t tickets;           /* NewSessionTicket messages seen after the handshake (resumption not implemented) */
} tls13;

/* Fresh X25519 key pair from the DRBG (fixed-base comb; can run long before the connection). */
int  tls13_keypair_generate(tls13_keypair *kp, hmac_drbg *rng);
/* Starts a handshake with a precomputed key pair; the ClientHello is in t->out. root key: n big-endian. */
int  tls13_client_start_kp(tls13 *t, const char *host, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                           const char *now, hmac_drbg *rng, const tls13_keypair *kp);
/* Same, generating the key pair now (same shape as tls12_client_start). */
int  tls13_client_start(tls13 *t, const char *host, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                        const char *now, hmac_drbg *rng);
/* Add a trust anchor by key (after tls13_client_start*, before the server flight arrives); 0 if the table is full. */
int  tls13_add_pin(tls13 *t, const uint8_t *n, uint32_t n_len, uint32_t e);
/* Attach a certificate cache (after tls13_client_start*, which clears the struct). On a hit the chain verification
 * is skipped (t->cert_cached = 1); after a full verification the leaf is stored in the cache. 0 detaches. */
void tls13_set_cert_cache(tls13 *t, x509_cache *cache);
/* Feed bytes from the network. Returns 0 on fatal error (t->error set). Output to send accumulates in
 * t->out (caller sends and resets out_len); decrypted application data lands in t->app. */
int  tls13_input(tls13 *t, const uint8_t *data, uint32_t len);
/* Encrypt application data into t->out (state must be CONNECTED). Returns the number of bytes consumed
 * (one record of at most 16 KiB per call while it fits in t->out; 0 when t->out must be flushed first),
 * or -1 on error. */
int  tls13_send(tls13 *t, const uint8_t *pt, uint32_t len);
const char *tls13_errstr(int e);

#endif
