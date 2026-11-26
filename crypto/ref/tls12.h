/*
 * WhatsA500 - TLS 1.2 client, one cipher suite: TLS_RSA_WITH_AES_128_GCM_SHA256
 * (RFC 5246, 5288). RSA key transport keeps elliptic curves out of the TLS layer
 * (docs/PROTOCOL.md section 7). I/O agnostic: the caller moves bytes between
 * the socket and tls12_input / the output buffer.
 *
 * Trust: the server certificate chain (1..3 certificates) must verify against
 * the pinned root key and match `host`; chains that do not verify abort the
 * handshake before any secret is derived.
 */
#ifndef WHATSA500_TLS12_H
#define WHATSA500_TLS12_H

#include <stdint.h>
#include "aes.h"
#include "sha256.h"
#include "drbg.h"
#include "x509.h"

#define TLS_IN_MAX   (16384 + 2048)  /* one record (RFC max 16 KiB plaintext + overhead) */
#define TLS_HS_MAX   8192            /* reassembled handshake message (certificate chain) */
#define TLS_OUT_MAX  (TLS_IN_MAX + 64)

enum { TLS_ST_START, TLS_ST_WAIT_SH, TLS_ST_WAIT_CERT, TLS_ST_WAIT_SHD, TLS_ST_WAIT_CCS, TLS_ST_WAIT_FIN, TLS_ST_CONNECTED, TLS_ST_ERROR };

typedef struct {
    int state;
    int error;                      /* nonzero: tls12_errstr(error) */
    const char *host;
    const uint8_t *root_n; uint32_t root_n_len; uint32_t root_e;
    const char *now;                /* "YYYYMMDDHHMMSSZ" or 0 */
    hmac_drbg *rng;

    uint8_t client_random[32], server_random[32];
    uint8_t master[48];
    sha256_ctx transcript;
    uint8_t wr_key[16], rd_key[16], wr_iv[4], rd_iv[4];
    aes_gcm_key wr, rd;
    uint32_t wr_seq_hi, wr_seq_lo, rd_seq_hi, rd_seq_lo;
    int rd_encrypted, wr_encrypted;

    /* incoming record reassembly */
    uint8_t in[TLS_IN_MAX]; uint32_t in_len;
    /* incoming handshake message reassembly (handshake messages may span records) */
    uint8_t hs[TLS_HS_MAX]; uint32_t hs_len;
    /* bytes to send */
    uint8_t out[TLS_OUT_MAX]; uint32_t out_len;
    /* decrypted application data from the last tls12_input */
    uint8_t app[TLS_IN_MAX]; uint32_t app_len;
    /* server certificate chain (points into hs while WAIT_SHD) */
    x509_cert chain[3]; int chain_len;
    rsa_pub server_key;
} tls12;

/* Starts a handshake; the ClientHello is in t->out. root key: n big-endian. */
int  tls12_client_start(tls12 *t, const char *host, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                        const char *now, hmac_drbg *rng);
/* Feed bytes from the network. Returns 0 on fatal error (t->error set). Output to send accumulates in
 * t->out (caller sends and resets out_len); decrypted application data lands in t->app. */
int  tls12_input(tls12 *t, const uint8_t *data, uint32_t len);
/* Encrypt application data into t->out (state must be CONNECTED). Returns the number of bytes consumed
 * (one record of at most 16 KiB per call while it fits in t->out; 0 when t->out must be flushed first),
 * or -1 on error. */
int  tls12_send(tls12 *t, const uint8_t *pt, uint32_t len);
const char *tls12_errstr(int e);

#endif
