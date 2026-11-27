/* Pong heartbeat from the crypto progress hook, against the loopback echo server (tools/wsserver),
 * which counts the pong frames it receives. Plain WebSocket (no TLS) on the host; a fake clock makes
 * the hook fire deterministically while real X25519 / XEdDSA computations run with the hook armed. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "heartbeat.h"
#include "x25519.h"
#include "ed25519.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }
static int send_all(int fd, const uint8_t *p, uint32_t n) { while (n) { ssize_t w = write(fd, p, n); if (w <= 0) return 0; p += w; n -= (uint32_t)w; } return 1; }
static int flush_fd(void *io, const uint8_t *p, uint32_t n) { return send_all(*(int *)io, p, n); }
static uint32_t fake_ms;
static uint32_t fake_now(void) { return fake_ms; }
static uint32_t yields;
static void count_yields(void *ctx) { (void)ctx; yields++; }

static int wait_msg(int fd, ws_client *w)
{
    uint8_t buf[4096], out[256]; uint32_t ol = 0;
    while (!w->msg_ready) {
        ssize_t r = read(fd, buf, sizeof buf);
        if (r <= 0) return 0;
        if (!ws_input(w, buf, (uint32_t)r, out, &ol, sizeof out)) return 0;
    }
    return 1;
}

int main(int argc, char **argv)
{
    int port = argc > 1 ? atoi(argv[1]) : 4435, fd, i;
    static ws_client w;
    static uint8_t msgbuf[4096], out[4096], seed[64], sk[32], pk1[32], pk2[32];
    hmac_drbg rng;
    heartbeat hb;
    uint32_t n;
    struct sockaddr_in sa;
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(seed, 1, 64, f) != 64) { printf("FAIL urandom\n"); return 1; }
    fclose(f);
    rng.instantiated = 0; drbg_instantiate(&rng, seed, 64);

    /* the hook itself: counted calls per operation (the A500 fires every 20-50 ms at these counts) */
    crypto_yield_hook = count_yields;
    for (i = 0; i < 32; i++) sk[i] = (uint8_t)(i * 37 + 1);
    yields = 0; x25519_ref_base(pk1, sk);
    printf("  yields per X25519 ladder + inversion: %u\n", yields);
    result(yields >= 255, "X25519 calls the progress hook at every ladder step (plus the inversion)");
    yields = 0; x25519_base_comb(pk2, sk);
    printf("  yields per comb keygen: %u\n", yields);
    result(yields >= 64 && memcmp(pk1, pk2, 32) == 0, "comb keygen calls the hook per window, result unchanged");
    {
        static const uint8_t sig[64] = { 0 }, msg[4] = { 0x61, 0x62, 0x63, 0x64 };
        yields = 0; (void)xeddsa_verify(sig, msg, 4, pk1);
        printf("  yields per xeddsa_verify (invalid signature path): %u\n", yields);
    }
    crypto_yield_hook = 0;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port); sa.sin_addr.s_addr = htonl(0x7f000001);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { printf("FAIL connect\n"); return 1; }
    n = ws_client_start(&w, "127.0.0.1", "/ws/chat", "https://web.whatsapp.com", msgbuf, sizeof msgbuf, &rng, out, sizeof out);
    send_all(fd, out, n);
    {   uint8_t buf[2048]; ssize_t r; uint32_t ol = 0;
        while (w.state == WS_WAIT_HTTP && (r = read(fd, buf, sizeof buf)) > 0) if (!ws_input(&w, buf, (uint32_t)r, out, &ol, sizeof out)) break; }
    result(w.state == WS_OPEN, "WebSocket open");

    heartbeat_init(&hb, 0, &w, fake_now, 8000, flush_fd, &fd);
    /* not yet armed: a computation sends nothing */
    fake_ms = 20000; x25519_ref_base(pk1, sk);
    result(hb.sent == 0, "no pong without an armed heartbeat");
    heartbeat_arm(&hb);
    /* ten "A500 ladder steps" of 5 s each: pongs are due at 8 s intervals -> 5 pongs (at 10, 20, 30, 40, 50 s) */
    hb.last_ms = 0; fake_ms = 0;
    for (i = 1; i <= 10; i++) { fake_ms = (uint32_t)i * 5000; x25519_ref_base(pk1, sk); }
    printf("  pongs sent: %u\n", hb.sent);
    result(hb.sent == 5 && !hb.error, "heartbeat sends one pong per elapsed interval during the ladders");
    result(memcmp(pk1, pk2, 32) == 0, "X25519 result unchanged with the heartbeat armed");
    heartbeat_disarm();
    /* closed socket state: pong refused */
    w.state = WS_CLOSED; fake_ms += 100000; heartbeat_tick(&hb); w.state = WS_OPEN;
    result(hb.sent == 5, "no pong while the WebSocket is not open");
    /* the server's count */
    n = ws_frame_binary(&w, (const uint8_t *)"pongs?", 6, out, sizeof out);
    send_all(fd, out, n);
    result(wait_msg(fd, &w) && w.msg_len == 7 && memcmp(w.msg, "pongs:5", 7) == 0, "server received exactly 5 pong frames");
    if (w.msg_ready) printf("  server says: %.*s\n", (int)w.msg_len, w.msg);
    w.msg_ready = 0;
    n = ws_frame_close(&w, 1000, out, sizeof out);
    send_all(fd, out, n);
    close(fd);
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
