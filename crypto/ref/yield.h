/*
 * WhatsA500 - cooperative progress hook for long computations.
 *
 * The A500 spends 35-45 s in X25519 / XEdDSA / RSA during a login, while WhatsApp's server
 * closes an idle WebSocket after 10 s (docs/PROTOCOL.md section 8). Every long loop calls
 * CRYPTO_YIELD() between field operations (every 20-50 ms on the 68000); when a hook is
 * installed (crypto/ref/heartbeat.c) it sends a pong frame when one is due. No hook: a
 * single predictable branch per call. The hook must not call back into the crypto code
 * that yielded.
 */
#ifndef WHATSA500_YIELD_H
#define WHATSA500_YIELD_H

typedef void (*crypto_yield_fn)(void *ctx);
extern crypto_yield_fn crypto_yield_hook;
extern void *crypto_yield_ctx;
#define CRYPTO_YIELD() do { if (crypto_yield_hook) crypto_yield_hook(crypto_yield_ctx); } while (0)

#endif
