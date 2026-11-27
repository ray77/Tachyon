/*
 * WhatsA500 - WebSocket pong heartbeat driven by the crypto progress hook.
 *
 * WhatsApp's server closes a WebSocket after 10.0 s without a frame, also in the middle of
 * the Noise handshake; an unsolicited empty pong frame resets that timer and is ignored by
 * the WA layer (measured 2026-11-27, docs/PROTOCOL.md section 8). The A500 needs 35-45 s
 * between ServerHello and ClientFinish, so every long computation (X25519, XEdDSA, comb,
 * RSA) calls CRYPTO_YIELD() every 20-50 ms; with a heartbeat armed, that hook sends a pong
 * through the TLS record layer whenever `interval_ms` has passed. Cooperative by design:
 * no interrupt context, so a future bsdsocket-style network layer can be used as is, and
 * the TLS writer never runs re-entrantly (the hook only fires between field operations,
 * never inside tls12_send or the AES-GCM code).
 */
#ifndef WHATSA500_HEARTBEAT_H
#define WHATSA500_HEARTBEAT_H
#include <stdint.h>
#include "tls12.h"
#include "ws.h"

typedef int (*heartbeat_flush_fn)(void *io, const uint8_t *data, uint32_t len);   /* 1 = sent */

typedef struct {
    tls12 *tls;                 /* 0: plain WebSocket (tests) */
    ws_client *ws;
    uint32_t (*now_ms)(void);   /* monotonic milliseconds; on the A500 DateStamp ticks * 20 */
    uint32_t interval_ms, last_ms;
    heartbeat_flush_fn flush; void *io;
    uint32_t sent;              /* pongs sent */
    int error;                  /* a send failed; the connection is gone */
} heartbeat;

void heartbeat_init(heartbeat *h, tls12 *t, ws_client *w, uint32_t (*now_ms)(void), uint32_t interval_ms,
                    heartbeat_flush_fn flush, void *io);
/* sends one pong now (ws must be open, tls connected); 1 on success */
int  heartbeat_pong(heartbeat *h);
/* the hook: pong if interval_ms have passed since the last one */
void heartbeat_tick(void *ctx);
void heartbeat_arm(heartbeat *h);      /* installs heartbeat_tick as the CRYPTO_YIELD hook */
void heartbeat_disarm(void);

#endif
