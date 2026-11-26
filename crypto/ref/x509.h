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
 * cA flags, signatures, that the last certificate is signed by (root_n, root_e), and the
 * host name. now may be 0 (no clock: validity not checked, see docs/PROTOCOL.md). */
int x509_verify_chain(const x509_cert *certs, int count, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                      const char *host, const char *now);

#endif
