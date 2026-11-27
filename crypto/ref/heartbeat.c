#include "heartbeat.h"
#include "yield.h"

void heartbeat_init(heartbeat *h, tls12 *t, ws_client *w, uint32_t (*now_ms)(void), uint32_t interval_ms,
                    heartbeat_flush_fn flush, void *io)
{
    h->tls = t; h->ws = w; h->now_ms = now_ms; h->interval_ms = interval_ms;
    h->flush = flush; h->io = io; h->sent = 0; h->error = 0;
    h->last_ms = now_ms();
}

int heartbeat_pong(heartbeat *h)
{
    uint8_t frame[16];
    uint32_t n;
    if (h->error || !h->ws || h->ws->state != WS_OPEN) return 0;
    if (h->tls && h->tls->state != TLS_ST_CONNECTED) return 0;
    n = ws_frame_pong(h->ws, frame, sizeof frame);
    if (!n) return 0;
    if (h->tls) {
        /* flush whatever the caller already queued (complete records), then the pong record */
        if (h->tls->out_len && !h->flush(h->io, h->tls->out, h->tls->out_len)) { h->error = 1; return 0; }
        h->tls->out_len = 0;
        if (tls12_send(h->tls, frame, n) != (int)n) { h->error = 1; return 0; }
        if (!h->flush(h->io, h->tls->out, h->tls->out_len)) { h->error = 1; return 0; }
        h->tls->out_len = 0;
    } else if (!h->flush(h->io, frame, n)) { h->error = 1; return 0; }
    h->sent++;
    return 1;
}

void heartbeat_tick(void *ctx)
{
    heartbeat *h = (heartbeat *)ctx;
    uint32_t now = h->now_ms();
    if (now - h->last_ms >= h->interval_ms) {
        h->last_ms = now;
        heartbeat_pong(h);
    }
}

void heartbeat_arm(heartbeat *h) { crypto_yield_ctx = h; crypto_yield_hook = heartbeat_tick; }
void heartbeat_disarm(void) { crypto_yield_hook = 0; crypto_yield_ctx = 0; }
