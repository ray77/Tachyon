/* WebSocket client framing against the loopback coder/websocket echo server (tools/wsserver). Host only. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "ws.h"
#include "sha1.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }
static int send_all(int fd, const uint8_t *p, uint32_t n) { while (n) { ssize_t w = write(fd, p, n); if (w <= 0) return 0; p += w; n -= (uint32_t)w; } return 1; }

static int wait_msg(int fd, ws_client *w, uint8_t *out, uint32_t outcap)
{
    uint8_t buf[4096];
    while (!w->msg_ready && w->state == WS_OPEN) {
        uint32_t ol = 0;
        ssize_t r = read(fd, buf, sizeof buf);
        if (r <= 0) return 0;
        if (!ws_input(w, buf, (uint32_t)r, out, &ol, outcap)) return 0;
        if (ol && !send_all(fd, out, ol)) return 0;
    }
    return w->msg_ready;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 4434, fd, ok;
    static uint8_t msgbuf[1 << 18], out[1 << 18], big[70000], seed[64];
    static ws_client w;
    hmac_drbg rng;
    struct sockaddr_in sa;
    uint32_t n, i;
    {   /* SHA-1 sanity: RFC 3174 "abc" */
        static const uint8_t want[20] = { 0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d };
        uint8_t d[20]; sha1(d, (const uint8_t *)"abc", 3);
        result(memcmp(d, want, 20) == 0, "sha1(abc)");
        sha1(d, (const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
        { static const uint8_t w2[20] = { 0x84,0x98,0x3e,0x44,0x1c,0x3b,0xd2,0x6e,0xba,0xae,0x4a,0xa1,0xf9,0x51,0x29,0xe5,0xe5,0x46,0x70,0xf1 };
          result(memcmp(d, w2, 20) == 0, "sha1(two-block message)"); }
    }
    FILE *f = fopen("/dev/urandom", "rb"); if (!f || fread(seed, 1, 64, f) != 64) return 1; fclose(f);
    rng.instantiated = 0; drbg_instantiate(&rng, seed, 64);
    {   /* offline: a server message larger than the caller's buffer is discarded as a whole, the next one arrives */
        static uint8_t small[64], frame[140], o2[64]; uint32_t ol = 0, k;
        ws_client_start(&w, "x", "/", "o", small, sizeof small, &rng, out, sizeof out); w.state = WS_OPEN;
        frame[0] = 0x02; frame[1] = 50; for (k = 0; k < 50; k++) frame[2 + k] = (uint8_t)k;            /* first fragment, 50 bytes */
        result(ws_input(&w, frame, 52, o2, &ol, sizeof o2) == 1 && !w.msg_ready && !w.skipping, "fragment 1 of a message fits");
        frame[0] = 0x80; frame[1] = 50;                                                                 /* final fragment: 100 > 64 */
        result(ws_input(&w, frame, 52, o2, &ol, sizeof o2) == 1 && !w.msg_ready && w.dropped == 1 && w.dropped_len == 100 && !w.skipping, "oversize message discarded, parser alive");
        frame[0] = 0x82; frame[1] = 100;                                                                /* a single oversize frame, fed byte by byte */
        for (k = 0; k < 102; k++) if (ws_input(&w, frame + k, 1, o2, &ol, sizeof o2) != 1) break;
        result(k == 102 && !w.msg_ready && w.dropped == 2 && w.dropped_len == 100, "oversize single frame discarded byte by byte");
        frame[0] = 0x82; frame[1] = 10;
        result(ws_input(&w, frame, 12, o2, &ol, sizeof o2) == 1 && w.msg_ready && w.msg_len == 10 && w.msg[9] == 9, "the next message arrives intact");
        w.msg_ready = 0;
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port); sa.sin_addr.s_addr = htonl(0x7f000001);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { printf("FAIL connect\n"); return 1; }
    n = ws_client_start(&w, "127.0.0.1", "/ws/chat", "https://web.whatsapp.com", msgbuf, sizeof msgbuf, &rng, out, sizeof out);
    result(n > 0 && send_all(fd, out, n), "upgrade request sent");
    {   /* read until open */
        uint8_t buf[2048]; uint32_t ol = 0; ssize_t r;
        while (w.state == WS_WAIT_HTTP && (r = read(fd, buf, sizeof buf)) > 0) if (!ws_input(&w, buf, (uint32_t)r, out, &ol, sizeof out)) break;
        result(w.state == WS_OPEN, "101 response with matching Sec-WebSocket-Accept");
    }
    n = ws_frame_binary(&w, (const uint8_t *)"WA\x06\x03", 4, out, sizeof out);
    ok = n == 4 + 6 && send_all(fd, out, n) && wait_msg(fd, &w, out, sizeof out);
    result(ok && w.msg_len == 9 && memcmp(w.msg, "echo:WA\x06\x03", 9) == 0, "small masked binary frame echoed");
    w.msg_ready = 0; w.msg_len = 0;
    for (i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 13 + 1);
    n = ws_frame_binary(&w, big, sizeof big, out, sizeof out);       /* 64-bit length header */
    ok = n == sizeof big + 14 && send_all(fd, out, n) && wait_msg(fd, &w, out, sizeof out);
    result(ok && w.msg_len == sizeof big + 5 && memcmp(w.msg + 5, big, sizeof big) == 0, "70000-byte frame echoed (64-bit length header)");
    {   /* synthetic server ping with payload "hi" -> masked pong with the same payload */
        static const uint8_t ping[4] = { 0x89, 0x02, 'h', 'i' };
        uint8_t o2[64]; uint32_t ol = 0, k;
        int r = ws_input(&w, ping, 4, o2, &ol, sizeof o2);
        result(r && ol == 8 && o2[0] == 0x8a && o2[1] == 0x82 && (o2[6] ^ o2[2]) == 'h' && (o2[7] ^ o2[3]) == 'i', "ping answered with masked pong");
        for (k = 0; k < 0; k++) ;
    }
    w.msg_ready = 0; w.msg_len = 0;
    n = ws_frame_binary(&w, big, 300, out, sizeof out);               /* 16-bit length header */
    ok = n == 300 + 8 && send_all(fd, out, n) && wait_msg(fd, &w, out, sizeof out);
    result(ok && w.msg_len == 305, "300-byte frame echoed");
    w.msg_ready = 0;
    n = ws_frame_close(&w, 1000, out, sizeof out);
    result(n > 0 && send_all(fd, out, n), "close frame sent");
    close(fd);
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
