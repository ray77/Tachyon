#include "heartbeat.h"
#include "yield.h"

void heartbeat_init(heartbeat *h, ws_client *w, uint32_t (*now_ms)(void), uint32_t interval_ms,
                    heartbeat_send_fn send, void *io)
{
    h->ws = w; h->now_ms = now_ms; h->interval_ms = interval_ms;
    h->send = send; h->io = io; h->sent = 0; h->error = 0;
    h->last_ms = now_ms();
}

int heartbeat_pong(heartbeat *h)
{
    uint8_t frame[16];
    uint32_t n;
    if (h->error || !h->ws || h->ws->state != WS_OPEN) return 0;
    n = ws_frame_pong(h->ws, frame, sizeof frame);
    if (!n) return 0;
    if (!h->send(h->io, frame, n)) { h->error = 1; return 0; }
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
