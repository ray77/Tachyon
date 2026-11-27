/*
 * End-to-end probe of the Tachyon stack against the real server, host side: our TLS 1.3 client
 * (X25519, TLS_AES_128_GCM_SHA256, RSA-PSS CertificateVerify, chain pinned to the DigiCert G2 key and the
 * CA1 intermediate from tests/certs/wa_rsa_chain.h), our WebSocket client, our Noise_XX handshake
 * (ClientHello, ServerHello, certificate chain verified with XEdDSA against WhatsApp's root key,
 * ClientFinish) and the pong heartbeat from crypto/ref/heartbeat.c. Between ServerHello and ClientFinish
 * the probe burns `gap` seconds in X25519 ladders, as the A500 would, with the heartbeat armed at 4 s:
 * the server must still accept the ClientFinish and answer with its first encrypted frame (the
 * pair-device IQ), which we decrypt with the transport keys. Network required: make wa-probe GAP=30.
 * No pairing is completed; the ClientPayload is a throwaway registration payload from tools/watimeout.
 *
 * The protocol logic lives in tests/wa_probe_core.c and is shared with the Amiga build
 * (bench/wa_probe_amiga.c over bsdsocket.library); this file is the POSIX transport, clock and logging.
 *   TLS_CACHE=1: prime the certificate cache on a first connection, the real one must hit it (chain skipped).
 *   TLS_HOLD=<seconds>: hold our TLS Finished that long after the server flight and report whether the server
 *   closes (measured 2026-11-27: close_notify after 60.0 s; 50 s accepted).
 *   WA_PROBE_DEBUG=1 dumps reads and messages, WA_PROBE_DUMP=1 writes a rejected chain to build/wa_live_cert*.der.
 *
 * Tunnel mode (third argument "tunnel"): the TLS layer is replaced by `openssl s_client` with the same
 * parameters (TLS 1.3, X25519, TLS_AES_128_GCM_SHA256, rsa_pss_rsae_sha256) as a reference transport;
 * kept from the days before tls13.c existed (docs/PROTOCOL.md 7).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include "wa_probe_core.h"

static int fd = -1, tunnel, tun_in = -1, tun_out = -1;
static struct timespec t0;
static struct addrinfo *ai;

static uint32_t now_ms(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((ts.tv_sec - t0.tv_sec) * 1000 + (ts.tv_nsec - t0.tv_nsec) / 1000000);
}
static void log_line(void *ctx, const char *s) { (void)ctx; printf("+%7.2fs  %s\n", now_ms() / 1000.0, s); fflush(stdout); }

static int tcp_connect(void)
{
    fd = socket(ai->ai_family, SOCK_STREAM, 0);
    if (fd < 0 || connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) { printf("connect failed\n"); return 0; }
    return 1;
}
static int io_send(void *ctx, const uint8_t *p, uint32_t n)
{
    int o = tunnel ? tun_out : fd; (void)ctx;
    while (n) { ssize_t r = write(o, p, n); if (r <= 0) return 0; p += r; n -= (uint32_t)r; }
    return 1;
}
static int32_t io_recv(void *ctx, uint8_t *p, uint32_t cap, uint32_t timeout_ms)
{
    int in = tunnel ? tun_in : fd; fd_set rf; struct timeval tv; int sel; ssize_t r; (void)ctx;
    FD_ZERO(&rf); FD_SET(in, &rf);
    tv.tv_sec = timeout_ms / 1000; tv.tv_usec = (timeout_ms % 1000) * 1000;
    sel = select(in + 1, &rf, 0, 0, &tv);
    if (sel == 0) return 0;
    if (sel < 0) return -1;
    r = read(in, p, cap);
    return r <= 0 ? -1 : (int32_t)r;
}
static int io_reconnect(void *ctx) { (void)ctx; close(fd); return tcp_connect(); }

int main(int argc, char **argv)
{
    static wa_probe_io io; static uint8_t seed[64]; static char nowstr[16];
    double gap = argc > 1 ? atof(argv[1]) : 30.0;
    struct addrinfo hints;
    time_t tt = time(0); struct tm *tm = gmtime(&tt);
    FILE *rf = fopen("/dev/urandom", "rb");
    if (!rf || fread(seed, 1, 64, rf) != 64) { printf("no urandom\n"); return 1; }
    fclose(rf);
    strftime(nowstr, sizeof nowstr, "%Y%m%d%H%M%SZ", tm);
    clock_gettime(CLOCK_MONOTONIC, &t0);

    memset(&hints, 0, sizeof hints); hints.ai_socktype = SOCK_STREAM;
    tunnel = argc > 3 && strcmp(argv[3], "tunnel") == 0;
    if (tunnel) {
        /* openssl s_client as the TLS 1.3 transport, stdin/stdout piped to us */
        int to_child[2], from_child[2]; pid_t pid; char target[64];
        snprintf(target, sizeof target, "%s:443", argc > 2 ? argv[2] : "web.whatsapp.com");
        if (pipe(to_child) || pipe(from_child)) return 1;
        pid = fork();
        if (pid == 0) {
            dup2(to_child[0], 0); dup2(from_child[1], 1); close(to_child[1]); close(from_child[0]);
            { int devnull = open("/dev/null", 1); if (devnull >= 0) dup2(devnull, 2); }
            execlp("openssl", "openssl", "s_client", "-quiet", "-nocommands", "-connect", target, "-servername", "web.whatsapp.com",
                   "-tls1_3", "-groups", "X25519", "-ciphersuites", "TLS_AES_128_GCM_SHA256", "-sigalgs", "rsa_pss_rsae_sha256", (char *)0);
            _exit(127);
        }
        close(to_child[0]); close(from_child[1]); tun_out = to_child[1]; tun_in = from_child[0];
        log_line(0, "tunnel: openssl s_client -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -sigalgs rsa_pss_rsae_sha256 (the planned A500 TLS parameters)");
    }
    /* optional argv[2]: numeric address (the Makefile resolves it with dig; some sandboxes block the system resolver) */
    if (argc > 2) hints.ai_flags = AI_NUMERICHOST;
    { int ge = getaddrinfo(argc > 2 ? argv[2] : "web.whatsapp.com", "443", &hints, &ai); if (ge != 0) { printf("dns failed: %s\n", gai_strerror(ge)); return 1; } }
    if (!tunnel) {
        if (!tcp_connect()) return 1;
        { char l[96]; snprintf(l, sizeof l, "tcp: connected to web.whatsapp.com:443 (%s)", argc > 2 ? argv[2] : "resolved"); log_line(0, l); }
    }

    io.ctx = 0; io.send = io_send; io.recv = io_recv; io.reconnect = io_reconnect; io.now_ms = now_ms; io.log = log_line;
    io.host = "web.whatsapp.com"; io.now = nowstr; io.seed = seed; io.seed_len = 64;
    io.gap_ms = (uint32_t)(gap * 1000); io.tunnel = tunnel;
    io.use_cache = getenv("TLS_CACHE") != 0; io.debug = getenv("WA_PROBE_DEBUG") != 0;
    io.hold_ms = getenv("TLS_HOLD") ? (uint32_t)(atof(getenv("TLS_HOLD")) * 1000) : 0;
    {
        int ok = wa_probe_run(&io);
        if (!ok && getenv("WA_PROBE_DUMP")) {
            tls13 *t = wa_probe_tls(); int i;
            for (i = 0; i < t->chain_len; i++) { char fn[64]; FILE *o; snprintf(fn, sizeof fn, "build/wa_live_cert%d.der", i); o = fopen(fn, "wb"); if (o) { fwrite(t->chain[i].der, 1, t->chain[i].len, o); fclose(o); } }
        }
        if (ok) printf("TIMING: tls %u ms, ws %u ms, server hello %u ms, client finish %u ms, accepted %u ms\n", io.t_tls, io.t_ws, io.t_hello, io.t_finish, io.t_accepted);
        if (tunnel) { close(tun_out); close(tun_in); wait(0); } else close(fd);
        printf("%s\n", io.result);
        return ok ? 0 : 1;
    }
}
