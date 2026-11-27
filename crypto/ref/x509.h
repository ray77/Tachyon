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
/* 1 if `now` ("YYYYMMDDHHMMSSZ") lies within the validity period; now == 0 (no clock) counts as valid */
int x509_valid_at(const x509_cert *c, const char *now);

/* Certificate cache (docs/PROTOCOL.md section 7): one entry is SHA-256 over the pinned root key, the host name
 * and the leaf certificate's DER. A client presented with a leaf whose fingerprint matches may skip the chain
 * verification (two RSA-2048 operations, 19.5 s on the 68000): exactly this leaf was verified against exactly this
 * root for exactly this host before. The cheap checks stay on every connection - validity period against the clock,
 * host name against the SAN - and so does the CertificateVerify signature, which is what proves the server holds
 * the leaf's private key now. 36 bytes, meant to be stored (ENVARC: on the Amiga) and refreshed on each full verify. */
typedef struct { uint8_t fp[32]; int valid; } x509_cache;
void x509_cache_fingerprint(uint8_t fp[32], const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                            const char *host, const uint8_t *leaf_der, uint32_t leaf_len);
/* 1 if the cache holds exactly this (root key, host, leaf); constant-time compare */
int  x509_cache_match(const x509_cache *c, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                      const char *host, const uint8_t *leaf_der, uint32_t leaf_len);
void x509_cache_store(x509_cache *c, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                      const char *host, const uint8_t *leaf_der, uint32_t leaf_len);

#endif
