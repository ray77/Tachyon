/*
 * WhatsA500 - minimal X.509 (DER) for the TLS 1.2 RSA path: parse what the
 * handshake needs (RSA public key, tbsCertificate range, signature, SAN,
 * validity, basicConstraints), verify sha256WithRSAEncryption chains against a
 * pinned root key. Everything else is skipped by length; every read is bounds
 * checked. No other algorithms are accepted.
 */
#ifndef WHATSA500_X509_H
#define WHATSA500_X509_H

#include <stdint.h>
#include "rsa.h"

typedef struct {
    const uint8_t *der; uint32_t len;
    const uint8_t *tbs; uint32_t tbs_len;           /* signed range */
    const uint8_t *sig; uint32_t sig_len;           /* raw RSA signature */
    const uint8_t *n;   uint32_t n_len;             /* RSA modulus, leading zero stripped */
    uint32_t e;
    const uint8_t *issuer;  uint32_t issuer_len;    /* Name DER, for issuer == subject matching */
    const uint8_t *subject; uint32_t subject_len;
    const uint8_t *san; uint32_t san_len;           /* GeneralNames DER (inside the OCTET STRING), or 0 */
    char not_before[16], not_after[16];             /* "YYYYMMDDHHMMSSZ" */
    int is_ca;                                      /* basicConstraints cA */
    int sig_sha256_rsa;                             /* signatureAlgorithm is sha256WithRSAEncryption */
} x509_cert;

int x509_parse(x509_cert *c, const uint8_t *der, uint32_t len);
/* 1 if the certificate's signature verifies under the issuer key (n_be, e) */
int x509_verify_signature(const x509_cert *c, const uint8_t *n_be, uint32_t n_len, uint32_t e);
/* 1 if host matches a dNSName in the SAN (exact or single leading wildcard label) */
int x509_match_host(const x509_cert *c, const char *host);
/* Chain: certs[0] = leaf ... certs[k-1]; root is pinned by key. Checks issuer/subject links,
 * cA flags, signatures and the host name; the chain is complete at the first certificate signed by
 * (root_n, root_e) or carrying that key itself (servers often append their cross-signed root; it is
 * not verified, only skipped). now may be 0 (no clock: validity not checked, see docs/PROTOCOL.md). */
int x509_verify_chain(const x509_cert *certs, int count, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                      const char *host, const char *now);
/* Pin set: several trust anchors by key (e.g. the DigiCert G2 root and the G2 TLS RSA 2020 CA1 intermediate that
 * signs web.whatsapp.com's leaf). The chain is complete at the first certificate signed by any pinned key, so with
 * the intermediate pinned the live leaf costs one RSA verification instead of two, and a rotated intermediate still
 * verifies through the root. pin_used (may be 0) receives the index of the anchor that completed the chain. */
typedef struct { const uint8_t *n; uint32_t n_len; uint32_t e; } x509_pin;
#define X509_MAX_PINS 4
int x509_verify_chain_pins(const x509_cert *certs, int count, const x509_pin *pins, int npins,
                           const char *host, const char *now, int *pin_used);
/* 1 if `now` ("YYYYMMDDHHMMSSZ") lies within the validity period; now == 0 (no clock) counts as valid */
int x509_valid_at(const x509_cert *c, const char *now);

/* Certificate cache (docs/PROTOCOL.md section 7): one entry is SHA-256 over the pin set, the host name and the
 * leaf certificate's DER. A client presented with a leaf whose fingerprint matches may skip the chain
 * verification (two RSA-2048 operations, 19.5 s on the 68000): exactly this leaf was verified against exactly this
 * root for exactly this host before. The cheap checks stay on every connection - validity period against the clock,
 * host name against the SAN - and so does the CertificateVerify signature, which is what proves the server holds
 * the leaf's private key now. `key` is the leaf's prepared RSA public key (Montgomery constants, rsa.h); on a hit the
 * TLS client checks it against the presented leaf with rsa_pub_check instead of recomputing it (1.9 s saved on the
 * 68000); a mismatch is treated as a cache miss. About 1.1 KiB, meant to be stored (ENVARC: on the Amiga) and
 * refreshed on each full verification. */
typedef struct { uint8_t fp[32]; int valid; rsa_pub key; } x509_cache;
/* portable file form (big-endian, version byte, SHA-256 at the end): the host primes it, the A500 loads it */
#define X509_CACHE_FILE_MAX (1u + 32u + 2u + 4u + 2u + 4u * RSA_MAX_LIMBS + 32u)
uint32_t x509_cache_write(uint8_t *out, uint32_t cap, const x509_cache *c);   /* bytes written, 0 = invalid / no room */
int      x509_cache_read(x509_cache *c, const uint8_t *in, uint32_t len);     /* 1 = a valid record (c->valid = 1) */
void x509_cache_fingerprint(uint8_t fp[32], const x509_pin *pins, int npins,
                            const char *host, const uint8_t *leaf_der, uint32_t leaf_len);
/* 1 if the cache holds exactly this (pin set, host, leaf); constant-time compare */
int  x509_cache_match(const x509_cache *c, const x509_pin *pins, int npins,
                      const char *host, const uint8_t *leaf_der, uint32_t leaf_len);
void x509_cache_store(x509_cache *c, const x509_pin *pins, int npins,
                      const char *host, const uint8_t *leaf_der, uint32_t leaf_len);

#endif
