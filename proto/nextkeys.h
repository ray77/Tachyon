/*
 * Tachyon - the key material for the NEXT connection, computed in idle time (docs/PROTOCOL.md section 6).
 *
 * A connection needs the TLS 1.3 X25519 key pair, the Noise ephemeral key pair and, with the server's Noise
 * static key known (noise cache), es = DH(ephemeral, static): three fixed-base multiplications and one ladder,
 * ~15 s on the 68000 that have nothing to do with the server. The client computes them after a login while it
 * is online anyway (post_login), stores the record, and the next start connects at once.
 *
 * Record (WA_NEXTKEYS_SIZE bytes): version 1, flags (bit 0: es present), tls_priv, tls_pub, eph_priv, eph_pub,
 * server_static, es, SHA-256 over everything before it. Private keys on disk: the same disk already holds the
 * long-term identity (creds), so this adds no new exposure; the record is single use - the caller consumes
 * (deletes) it BEFORE the keys go on the wire, so a key pair is never offered twice, crash or not.
 */
#ifndef TACHYON_NEXTKEYS_H
#define TACHYON_NEXTKEYS_H

#include <stdint.h>
#include "drbg.h"

#define WA_NEXTKEYS_VERSION 1u
#define WA_NEXTKEYS_SIZE (1u + 1u + 6u * 32u + 32u)   /* 226 */

typedef struct wa_nextkeys {
    uint8_t tls_priv[32], tls_pub[32];
    uint8_t eph_priv[32], eph_pub[32];
    uint8_t server_static[32], es[32];
    int have_es;                            /* es and server_static valid */
} wa_nextkeys;

/* generate both key pairs from rng (fixed-base comb) and, when server_static is not 0, es by one ladder */
void     wa_nextkeys_compute(wa_nextkeys *k, hmac_drbg *rng, const uint8_t *server_static);
uint32_t wa_nextkeys_write(uint8_t *out, uint32_t cap, const wa_nextkeys *k);   /* WA_NEXTKEYS_SIZE, or 0 */
int      wa_nextkeys_read(wa_nextkeys *k, const uint8_t *in, uint32_t len);     /* 1 = version, size, checksum ok */
void     wa_nextkeys_wipe(wa_nextkeys *k);                                       /* zero the private material */

#endif
