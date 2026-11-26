/*
 * WhatsA500 - WebSocket client framing (RFC 6455) for wss://web.whatsapp.com/ws/chat.
 * Transport agnostic: bytes go through the TLS layer. Client frames are masked
 * (4-byte XOR, mask from the DRBG as the RFC requires unpredictability); server
 * frames are unmasked. Only binary/close/ping/pong frames are handled; text frames
 * are rejected (WhatsApp never sends them).
 */
#ifndef WHATSA500_WS_H
#define WHATSA500_WS_H
#include <stdint.h>
#include "drbg.h"

#define WS_MAX_FRAME (1 << 20)      /* 1 MiB: WhatsApp frames are below 16 MiB but media goes over HTTPS, not the socket */

enum { WS_WAIT_HTTP, WS_OPEN, WS_CLOSED, WS_ERROR };

typedef struct {
    int state;
    hmac_drbg *rng;
    uint8_t key_b64[25];                 /* Sec-WebSocket-Key we sent */
    uint8_t http[2048]; uint32_t http_len;   /* upgrade response accumulation */
    /* current incoming frame */
    uint8_t hdr[14]; uint32_t hdr_len;
    uint32_t need;                       /* payload bytes still expected */
    uint8_t opcode; int fin;
    uint8_t *msg; uint32_t msg_len, msg_cap;    /* reassembled message (caller-provided buffer) */
    int msg_ready;                       /* a complete binary message is in msg[0..msg_len) */
    uint16_t close_code;
} ws_client;

/* Builds the HTTP upgrade request into out (returns its length); msgbuf receives reassembled messages. */
uint32_t ws_client_start(ws_client *w, const char *host, const char *path, const char *origin,
                         uint8_t *msgbuf, uint32_t msgcap, hmac_drbg *rng, uint8_t *out, uint32_t outcap);
/* Feed decrypted bytes from TLS; returns 0 on protocol error. Sets msg_ready when a message completes
 * (caller consumes msg and clears msg_ready before feeding more). Pong replies / close frames to send
 * are appended to out (outlen updated). */
int ws_input(ws_client *w, const uint8_t *data, uint32_t len, uint8_t *out, uint32_t *outlen, uint32_t outcap);
/* Masked binary frame around payload into out; returns frame length or 0 if it does not fit. */
uint32_t ws_frame_binary(ws_client *w, const uint8_t *payload, uint32_t len, uint8_t *out, uint32_t outcap);
uint32_t ws_frame_close(ws_client *w, uint16_t code, uint8_t *out, uint32_t outcap);

#endif
