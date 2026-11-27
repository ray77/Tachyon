#include "ws.h"
#include "sha1.h"

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static uint32_t b64(uint8_t *out, const uint8_t *in, uint32_t len)
{
    uint32_t i, o = 0;
    for (i = 0; i + 2 < len; i += 3) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i+1] << 8) | in[i+2];
        out[o++] = (uint8_t)B64[v >> 18]; out[o++] = (uint8_t)B64[(v >> 12) & 63]; out[o++] = (uint8_t)B64[(v >> 6) & 63]; out[o++] = (uint8_t)B64[v & 63];
    }
    if (i < len) {
        uint32_t v = (uint32_t)in[i] << 16; if (i + 1 < len) v |= (uint32_t)in[i+1] << 8;
        out[o++] = (uint8_t)B64[v >> 18]; out[o++] = (uint8_t)B64[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? (uint8_t)B64[(v >> 6) & 63] : '='; out[o++] = '=';
    }
    return o;
}

static uint32_t cat(uint8_t *out, uint32_t o, uint32_t cap, const char *s)
{
    while (*s && o < cap) out[o++] = (uint8_t)*s++;
    return o;
}

uint32_t ws_client_start(ws_client *w, const char *host, const char *path, const char *origin,
                         uint8_t *msgbuf, uint32_t msgcap, hmac_drbg *rng, uint8_t *out, uint32_t outcap)
{
    uint8_t nonce[16];
    uint32_t o = 0, i;
    for (i = 0; i < sizeof(*w); i++) ((uint8_t *)w)[i] = 0;
    w->rng = rng; w->msg = msgbuf; w->msg_cap = msgcap; w->state = WS_WAIT_HTTP;
    if (!drbg_generate(rng, nonce, 16)) { w->state = WS_ERROR; return 0; }
    w->key_b64[b64(w->key_b64, nonce, 16)] = 0;
    o = cat(out, o, outcap, "GET "); o = cat(out, o, outcap, path); o = cat(out, o, outcap, " HTTP/1.1\r\nHost: ");
    o = cat(out, o, outcap, host); o = cat(out, o, outcap, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
    o = cat(out, o, outcap, (const char *)w->key_b64); o = cat(out, o, outcap, "\r\nSec-WebSocket-Version: 13\r\n");
    if (origin) { o = cat(out, o, outcap, "Origin: "); o = cat(out, o, outcap, origin); o = cat(out, o, outcap, "\r\n"); }
    o = cat(out, o, outcap, "\r\n");
    return o < outcap ? o : 0;
}

static int ieq(const uint8_t *a, const char *b, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) { int x = a[i], y = (uint8_t)b[i]; if (x >= 'A' && x <= 'Z') x += 32; if (y >= 'A' && y <= 'Z') y += 32; if (x != y) return 0; }
    return 1;
}

static int check_http(ws_client *w)
{
    static const char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    uint8_t cat_[24 + 36], dig[20], acc[32];
    uint32_t i, acclen, p, found = 0;
    const uint8_t *h = w->http; uint32_t n = w->http_len;
    if (n < 12 || !ieq(h, "HTTP/1.1 101", 12)) return 0;
    for (i = 0; i < 24; i++) cat_[i] = w->key_b64[i];
    for (i = 0; i < 36; i++) cat_[24 + i] = (uint8_t)GUID[i];
    sha1(dig, cat_, 60);
    acclen = b64(acc, dig, 20);
    /* scan header lines for Sec-WebSocket-Accept */
    p = 0;
    while (p < n) {
        uint32_t e = p; while (e < n && h[e] != '\n') e++;
        if (e - p >= 22 && ieq(h + p, "sec-websocket-accept:", 21)) {
            uint32_t v = p + 21; while (v < e && h[v] == ' ') v++;
            if (e - v >= acclen) { uint32_t k, d = 0; for (k = 0; k < acclen; k++) d |= h[v + k] ^ acc[k]; if (!d) found = 1; }
        }
        p = e + 1;
    }
    return found;
}

static int mask_and_emit(ws_client *w, uint8_t opcode, const uint8_t *payload, uint32_t len, uint8_t *out, uint32_t outcap, uint32_t *flen)
{
    uint8_t mask[4];
    uint32_t o = 0, i;
    if (!drbg_generate(w->rng, mask, 4)) return 0;
    if (outcap < 14 + len) return 0;
    out[o++] = (uint8_t)(0x80 | opcode);
    if (len < 126) out[o++] = (uint8_t)(0x80 | len);
    else if (len < 65536) { out[o++] = 0x80 | 126; out[o++] = (uint8_t)(len >> 8); out[o++] = (uint8_t)len; }
    else { out[o++] = 0x80 | 127; for (i = 0; i < 4; i++) out[o++] = 0; out[o++] = (uint8_t)(len >> 24); out[o++] = (uint8_t)(len >> 16); out[o++] = (uint8_t)(len >> 8); out[o++] = (uint8_t)len; }
    for (i = 0; i < 4; i++) out[o++] = mask[i];
    /* unrolled by four: cheaper on the 68000 and sidesteps a clang -O2 vectorisation fault seen with mask[i & 3] */
    for (i = 0; i + 4 <= len; i += 4) {
        out[o] = (uint8_t)(payload[i] ^ mask[0]); out[o + 1] = (uint8_t)(payload[i + 1] ^ mask[1]);
        out[o + 2] = (uint8_t)(payload[i + 2] ^ mask[2]); out[o + 3] = (uint8_t)(payload[i + 3] ^ mask[3]);
        o += 4;
    }
    for (; i < len; i++) out[o++] = (uint8_t)(payload[i] ^ mask[i & 3]);
    *flen = o;
    return 1;
}

uint32_t ws_frame_binary(ws_client *w, const uint8_t *payload, uint32_t len, uint8_t *out, uint32_t outcap)
{
    uint32_t f = 0;
    if (w->state != WS_OPEN) return 0;
    return mask_and_emit(w, 2, payload, len, out, outcap, &f) ? f : 0;
}

uint32_t ws_frame_pong(ws_client *w, uint8_t *out, uint32_t outcap)
{
    uint32_t f = 0;
    if (w->state != WS_OPEN) return 0;
    return mask_and_emit(w, 10, 0, 0, out, outcap, &f) ? f : 0;
}

uint32_t ws_frame_close(ws_client *w, uint16_t code, uint8_t *out, uint32_t outcap)
{
    uint8_t body[2] = { (uint8_t)(code >> 8), (uint8_t)code };
    uint32_t f = 0;
    if (!mask_and_emit(w, 8, body, 2, out, outcap, &f)) return 0;
    w->state = WS_CLOSED;
    return f;
}

int ws_input(ws_client *w, const uint8_t *data, uint32_t len, uint8_t *out, uint32_t *outlen, uint32_t outcap)
{
    uint32_t i;
    if (w->state == WS_ERROR) return 0;
    if (w->state == WS_WAIT_HTTP) {
        while (len && w->http_len < sizeof w->http) {
            w->http[w->http_len++] = *data++; len--;
            if (w->http_len >= 4 && w->http[w->http_len-4] == '\r' && w->http[w->http_len-3] == '\n' && w->http[w->http_len-2] == '\r' && w->http[w->http_len-1] == '\n') {
                if (!check_http(w)) { w->state = WS_ERROR; return 0; }
                w->state = WS_OPEN;
                break;
            }
        }
        if (w->state != WS_OPEN) { if (w->http_len >= sizeof w->http) { w->state = WS_ERROR; return 0; } return 1; }
    }
    while (len) {
        if (w->need == 0) {
            /* collecting a header */
            uint32_t hl;
            w->hdr[w->hdr_len++] = *data++; len--;
            if (w->hdr_len < 2) continue;
            if (w->hdr[1] & 0x80) { w->state = WS_ERROR; return 0; }       /* server frames must not be masked */
            hl = 2 + ((w->hdr[1] & 127) == 126 ? 2 : (w->hdr[1] & 127) == 127 ? 8 : 0);
            if (w->hdr_len < hl) continue;
            {
                uint32_t plen = w->hdr[1] & 127;
                if (plen == 126) plen = ((uint32_t)w->hdr[2] << 8) | w->hdr[3];
                else if (plen == 127) { if (w->hdr[2] | w->hdr[3] | w->hdr[4] | w->hdr[5]) { w->state = WS_ERROR; return 0; } plen = ((uint32_t)w->hdr[6] << 24) | ((uint32_t)w->hdr[7] << 16) | ((uint32_t)w->hdr[8] << 8) | w->hdr[9]; }
                w->opcode = w->hdr[0] & 15; w->fin = (w->hdr[0] & 0x80) != 0;
                if (w->hdr[0] & 0x70) { w->state = WS_ERROR; return 0; }     /* no extensions negotiated */
                if (w->opcode == 1) { w->state = WS_ERROR; return 0; }       /* text frames: not used by WhatsApp */
                if (w->opcode >= 8 && (plen > 125 || !w->fin)) { w->state = WS_ERROR; return 0; }
                if (w->opcode < 8) {
                    if (w->opcode == 0 && !w->in_msg) { /* continuation without start */ w->state = WS_ERROR; return 0; }
                    if (w->opcode == 2) { w->msg_len = 0; w->skipping = 0; w->in_msg = 1; }
                    if (plen > WS_MAX_FRAME) { w->state = WS_ERROR; return 0; }
                    if (w->stream) { /* delivered in pieces below, nothing is dropped */ }
                    else if (w->skipping || w->msg_len + plen > w->msg_cap) {
                        /* too big for the caller's buffer: swallow the whole message and report it (WhatsApp sends
                           large app-state / history stanzas after login; the probe only needs the small ones) */
                        if (!w->skipping) { w->skipping = 1; w->dropped++; w->dropped_len = w->msg_len; }
                        w->dropped_len += plen;
                    }
                } else {
                    w->msg_len = w->msg_len;                                  /* control frames are collected separately below */
                }
                w->hdr_len = 0;
                w->need = plen;
                if (plen == 0) goto frame_done;
            }
            continue;
        }
        {
            uint32_t take = len < w->need ? len : w->need;
            if (w->opcode < 8 && w->stream) {
                /* stream mode: fill the buffer; when it is full and the message goes on, hand it over (the caller
                   consumes whole WA frames before feeding more; one byte at a time keeps this exact) */
                uint32_t room = w->msg_cap - w->msg_len, c = take < room ? take : room;
                for (i = 0; i < c; i++) w->msg[w->msg_len + i] = data[i];
                w->msg_len += c; data += c; len -= c; w->need -= c;
                if (w->need) { if (w->msg_len == w->msg_cap) { w->msg_partial = 1; return 1; } break; }
                goto frame_done;
            }
            if (w->opcode < 8) { if (!w->skipping) { for (i = 0; i < take; i++) w->msg[w->msg_len + i] = data[i]; w->msg_len += take; } }
            else { for (i = 0; i < take && w->hdr_len < 14; i++) w->hdr[w->hdr_len++] = data[i]; }   /* control payload (<=125, we keep 14) */
            data += take; len -= take; w->need -= take;
            if (w->need) break;
        }
frame_done:
        if (w->opcode < 8) {
            if (w->fin) w->in_msg = 0;
            if (w->fin && w->skipping) { w->skipping = 0; w->msg_len = 0; continue; }   /* discarded, no message */
            if (w->fin) { w->msg_ready = 1; return 1; }       /* caller consumes before feeding more */
        } else if (w->opcode == 9) {                          /* ping -> pong with the same payload */
            uint32_t f = 0;
            if (!mask_and_emit(w, 10, w->hdr, w->hdr_len, out + *outlen, outcap - *outlen, &f)) { w->state = WS_ERROR; return 0; }
            *outlen += f; w->hdr_len = 0;
        } else if (w->opcode == 8) {
            w->close_code = w->hdr_len >= 2 ? (uint16_t)(((uint16_t)w->hdr[0] << 8) | w->hdr[1]) : 1005;
            w->hdr_len = 0;
            if (w->state == WS_OPEN) { uint32_t f = 0; if (mask_and_emit(w, 8, 0, 0, out + *outlen, outcap - *outlen, &f)) *outlen += f; }
            w->state = WS_CLOSED;
            return 1;
        } else if (w->opcode == 10) {
            w->hdr_len = 0;                                   /* pong: ignore */
        } else { w->state = WS_ERROR; return 0; }
    }
    return 1;
}
