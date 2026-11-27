/*
 * Tachyon - the WhatsApp connection probe, transport agnostic.
 *
 * TCP -> TLS 1.3 (tls13.c, pins {DigiCert G2 root, G2 TLS RSA 2020 CA1 intermediate} from
 * tests/certs/wa_rsa_chain.h, optional certificate cache) -> WebSocket upgrade (ws.c) -> Noise XX
 * ClientHello / ServerHello / ClientFinish (noise.c, WhatsApp's certificate chain checked with XEdDSA
 * against the WA root key) with the pong heartbeat armed during `gap_ms` of X25519 ladders, then the
 * first encrypted server frame is decrypted. The caller supplies the socket (send / recv with timeout /
 * reconnect), a millisecond clock, a line logger, the DRBG seed and the clock string; the same code runs
 * on the host (tests/wa_probe.c, POSIX) and on the Amiga (bench/wa_probe_amiga.c, bsdsocket.library).
 * No libc: freestanding like crypto/ref (own copy/compare/format helpers).
 *
 * Two steps: wa_probe_prepare does everything that needs no connection - DRBG, the TLS 1.3 X25519 key pair and
 * the two Noise X25519 key pairs (static + ephemeral, fixed-base comb) - so the caller can run it before the TCP
 * connect (on the A500 ~10 s, while the stack is still starting); wa_probe_run then takes the open socket.
 * WhatsApp's intermediate Noise certificate is verified once and remembered as a fingerprint
 * (noise_cert_cache, noise.h): the caller may pass a stored fingerprint in and gets the current one out.
 */
#ifndef TACHYON_WA_PROBE_CORE_H
#define TACHYON_WA_PROBE_CORE_H

#include <stdint.h>
#include "tls13.h"

#define WA_PROBE_MSG_MAX 16384      /* reassembled WebSocket message / decrypted frame (handshake frames are < 1 KiB) */

typedef struct wa_probe_io {
    void *ctx;
    int      (*send)(void *ctx, const uint8_t *p, uint32_t n);                     /* 1 = all bytes on the wire */
    int32_t  (*recv)(void *ctx, uint8_t *p, uint32_t cap, uint32_t timeout_ms);   /* >0 bytes, 0 timeout, -1 closed */
    int      (*reconnect)(void *ctx);           /* new TCP connection to the same server (use_cache only; may be 0) */
    uint32_t (*now_ms)(void);                    /* monotonic milliseconds (the heartbeat takes it without ctx) */
    void     (*log)(void *ctx, const char *line);

    const char *host;           /* "web.whatsapp.com" */
    const char *now;            /* "YYYYMMDDHHMMSSZ" for the certificate validity check, or 0 (no clock) */
    const uint8_t *seed; uint32_t seed_len;     /* DRBG seed: at least 32 bytes of real entropy */
    uint32_t gap_ms;            /* X25519 ladders between ServerHello and ClientFinish (the A500's computing time) */
    uint32_t hold_ms;           /* TLS_HOLD: delay our Finished and watch for the server closing; 0 = off */
    int tunnel;                 /* the transport already is TLS (openssl s_client): skip tls13 */
    int use_cache;              /* prime the certificate cache on a first connection, the real one must hit it */
    int debug;                  /* dump reads and messages */
    const uint8_t *noise_cache_in;  /* 32-byte fingerprint of the verified Noise intermediate from an earlier run, or 0 */

    /* results, milliseconds since wa_probe_run started (0 = not reached) */
    uint32_t t_tls, t_ws, t_hello, t_finish, t_accepted;
    uint32_t t_tls_key, t_noise_keys;   /* durations of the key pair computations in wa_probe_prepare */
    uint32_t pongs, ladders;
    int noise_cert_cached;              /* 1 = the intermediate's XEdDSA verification was skipped on a cache hit */
    uint8_t noise_cache_fp[32]; int noise_cache_valid;   /* the fingerprint after the run (store it for the next one) */
    char result[200];           /* "RESULT: ..." */
} wa_probe_io;

int wa_probe_prepare(wa_probe_io *io); /* offline part: DRBG + 3 X25519 key pairs; 0 = io->result tells why */
int wa_probe_run(wa_probe_io *io);     /* 1 = handshake ACCEPTED by the server; io->result tells the rest
                                          (calls wa_probe_prepare itself if the caller did not) */
tls13 *wa_probe_tls(void);             /* the TLS state (diagnostics after a failure) */

/* tiny formatter shared with the glue code: %s %u %d %x %c %% with optional 0-flag and width, %T = uint32_t
 * milliseconds as "s.cc". Always NUL-terminates; returns the length written. */
uint32_t wa_fmt(char *dst, uint32_t cap, const char *fmt, ...);

#endif
