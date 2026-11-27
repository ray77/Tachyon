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
 *   NOISE_CACHE=<file>: 32-byte fingerprint of WhatsApp's verified intermediate Noise certificate; read before
 *   the run (hit = XEdDSA of the intermediate skipped), written after a successful one (make wa-probe uses
 *   build/wa_noise_cache.bin, which tools/run-fsuae-net.sh hands to the Amiga as SYS:noisecache.bin).
 *   TLS_HOLD=<seconds>: hold our TLS Finished that long after the server flight and report whether the server
 *   closes (measured 2026-11-27: close_notify after 60.0 s; 50 s accepted).
 *   WA_PROBE_DEBUG=1 dumps reads and messages, WA_PROBE_DUMP=1 writes a rejected chain to build/wa_live_cert*.der.
 *
 * Pairing mode (third argument "pair", make wa-pair): the companion pairing of docs/PROTOCOL.md 11 with the identity
 * and credentials in CREDS (default build/tachyon.creds). No record: a new identity is generated, the QR codes are
 * printed with Unicode half blocks (light modules as blocks for a dark terminal; WA_QR_INVERT=1 flips) and written to
 * build/wa_qr.pbm, after pair-success the probe signs, expects the 515 restart and logs in ONCE with the stored
 * record. Record present: login only. No retry loop anywhere; the pacing rule is the user's (docs/PROTOCOL.md 11).
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
#include "creds.h"
#include "prekeys.h"

static int fd = -1, tunnel, tun_in = -1, tun_out = -1;
static wa_creds creds; static const char *creds_path;
static wa_prekeys prekeys; static const char *prekeys_path;
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

/* ---- pairing glue ------------------------------------------------------------------------------ */
static void write_prekeys(void *ctx)
{
    static uint8_t rec[WA_PREKEYS_MAX_SIZE]; uint32_t n; FILE *f; (void)ctx;
    if (!prekeys_path || !(n = wa_prekeys_write(rec, sizeof rec, &prekeys))) return;
    f = fopen(prekeys_path, "wb");
    if (f) { fwrite(rec, 1, n, f); fclose(f); printf("prekeys: %s written (%u keys, %u pending upload)\n", prekeys_path, prekeys.n, wa_prekeys_pending(&prekeys)); }
}
static void write_creds(void *ctx)
{
    static uint8_t rec[WA_CREDS_SIZE]; FILE *f; (void)ctx;
    if (!creds_path || wa_creds_write(rec, sizeof rec, &creds) != WA_CREDS_SIZE) return;
    f = fopen(creds_path, "wb");
    if (f) { fwrite(rec, 1, sizeof rec, f); fclose(f); printf("creds: %s written (%u bytes, %s)\n", creds_path, (unsigned)WA_CREDS_SIZE, creds.paired ? "paired" : "identity only"); }
    else printf("creds: cannot write %s\n", creds_path);
}
static void show_qr(void *ctx, const char *text, const qr *code, uint32_t valid_ms, uint32_t index, uint32_t count)
{
    static char pbm[QR_MAX_SIZE * QR_MAX_SIZE + 64]; uint32_t x, y, n = code->size, inv = getenv("WA_QR_INVERT") != 0; FILE *f; (void)ctx;
    printf("\n=== QR code %u/%u, valid %u s: scan it with WhatsApp > Linked devices > Link a device ===\n%s\n\n", index, count, valid_ms / 1000, text);
    /* two module rows per text line; light modules are drawn as blocks (dark terminal), dark ones stay black */
    for (y = 0; y + 0 < n + 8; y += 2) {
        printf("    ");
        for (x = 0; x < n + 8; x++) {
            int top = y >= 4 && y - 4 < n && x >= 4 && x - 4 < n ? (int)qr_module(code, x - 4, y - 4) : 0;
            int bot = y + 1 >= 4 && y + 1 - 4 < n && x >= 4 && x - 4 < n ? (int)qr_module(code, x - 4, y + 1 - 4) : 0;
            if (!inv) { top = !top; bot = !bot; }
            printf("%s", top && bot ? "\xe2\x96\x88" : top ? "\xe2\x96\x80" : bot ? "\xe2\x96\x84" : " ");
        }
        printf("\n");
    }
    printf("\n");
    fflush(stdout);
    n = qr_render_pbm(code, pbm, sizeof pbm, 1);
    if (n && (f = fopen("build/wa_qr.pbm", "wb")) != 0) { fwrite(pbm, 1, n, f); fclose(f); }
}
static void qr_tick(void *ctx, uint32_t remaining_ms)
{
    static uint32_t last = 0xffffffffu; uint32_t s = (remaining_ms + 500) / 1000; (void)ctx;
    if (s / 10 != last / 10 || s <= 5) { if (s != last) { log_line(0, s <= 5 ? "qr: code expires in a moment" : "qr: waiting for the scan"); last = s; } }
}
static void qr_hide(void *ctx, const char *status) { char l[160]; (void)ctx; snprintf(l, sizeof l, "qr: %s", status); log_line(0, l); }

int main(int argc, char **argv)
{
    static wa_probe_io io; static uint8_t seed[64], ncache[32]; static char nowstr[16];
    const char *ncache_path = getenv("NOISE_CACHE");
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
    io.mode = argc > 3 && strcmp(argv[3], "pair") == 0 ? WA_MODE_PAIR : WA_MODE_PROBE;
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
    io.ctx = 0; io.send = io_send; io.recv = io_recv; io.reconnect = io_reconnect; io.now_ms = now_ms; io.log = log_line;
    io.host = "web.whatsapp.com"; io.now = nowstr; io.seed = seed; io.seed_len = 64;
    io.gap_ms = (uint32_t)(gap * 1000); io.tunnel = tunnel;
    io.use_cache = getenv("TLS_CACHE") != 0; io.debug = getenv("WA_PROBE_DEBUG") != 0;
    io.hold_ms = getenv("TLS_HOLD") ? (uint32_t)(atof(getenv("TLS_HOLD")) * 1000) : 0;
    io.noise_cache_in = 0;
    if (ncache_path && *ncache_path) {
        FILE *cf = fopen(ncache_path, "rb");
        if (cf) { if (fread(ncache, 1, 32, cf) == 32) io.noise_cache_in = ncache; fclose(cf); }
        { char l[160]; snprintf(l, sizeof l, "noise: certificate cache %s (%s)", io.noise_cache_in ? "loaded" : "empty", ncache_path); log_line(0, l); }
    }
    if (io.mode == WA_MODE_PAIR) {
        static uint8_t rec[WA_CREDS_SIZE + 1]; FILE *cf;
        creds_path = getenv("CREDS") && *getenv("CREDS") ? getenv("CREDS") : "build/tachyon.creds";
        io.creds = &creds; io.creds_loaded = 0; io.qr_mask = QR_MASK_AUTO;
        io.show_qr = show_qr; io.qr_tick = qr_tick; io.qr_hide = qr_hide; io.save_creds = write_creds;
        cf = fopen(creds_path, "rb");
        if (cf) {
            size_t n = fread(rec, 1, sizeof rec, cf); fclose(cf);
            if (!wa_creds_read(&creds, rec, (uint32_t)n)) { printf("creds: %s is not a valid credentials record (%zu bytes) - refusing to continue; delete it to pair anew\n", creds_path, n); return 1; }
            if (!wa_identity_check(&creds.id)) { printf("creds: %s: identity inconsistent (public keys / prekey signature) - refusing to continue\n", creds_path); return 1; }
            io.creds_loaded = 1;
            { char l[200]; snprintf(l, sizeof l, "creds: %s loaded: %s", creds_path, creds.paired ? "paired, will log in" : "identity only, will pair"); log_line(0, l); }
        } else { char l[200]; snprintf(l, sizeof l, "creds: no %s: a new identity will be generated, QR pairing follows", creds_path); log_line(0, l); }
        /* one-time prekeys: PREKEYS file (default build/tachyon.prekeys), PREKEY_COUNT pending before the connection, LINGER seconds online after <active/> */
        prekeys_path = getenv("PREKEYS") && *getenv("PREKEYS") ? getenv("PREKEYS") : "build/tachyon.prekeys";
        io.prekeys = &prekeys; io.prekeys_loaded = 0; io.save_prekeys = write_prekeys;
        io.prekeys_wanted = getenv("PREKEY_COUNT") ? (uint32_t)atoi(getenv("PREKEY_COUNT")) : 10;
        io.linger_ms = getenv("LINGER") ? (uint32_t)(atof(getenv("LINGER")) * 1000) : 15000;
        {   static uint8_t prec[WA_PREKEYS_MAX_SIZE + 1]; FILE *pf = fopen(prekeys_path, "rb");
            if (pf) {
                size_t n = fread(prec, 1, sizeof prec, pf); fclose(pf);
                if (!wa_prekeys_read(&prekeys, prec, (uint32_t)n)) { printf("prekeys: %s is not a valid prekey record (%zu bytes) - refusing to continue; delete it to start a new batch\n", prekeys_path, n); return 1; }
                io.prekeys_loaded = 1;
                { char l[200]; snprintf(l, sizeof l, "prekeys: %s loaded: %u keys, %u pending upload", prekeys_path, prekeys.n, wa_prekeys_pending(&prekeys)); log_line(0, l); }
            }
        }
    }
    /* the offline part (key pairs) before the connection, as the A500 does it */
    if (!wa_probe_prepare(&io)) { printf("%s\n", io.result); return 1; }
    if (!tunnel) {
        if (!tcp_connect()) return 1;
        { char l[96]; snprintf(l, sizeof l, "tcp: connected to web.whatsapp.com:443 (%s)", argc > 2 ? argv[2] : "resolved"); log_line(0, l); }
    }
    {
        int ok = wa_probe_run(&io);
        if (ok && io.noise_cache_valid && ncache_path && *ncache_path) {
            FILE *cf = fopen(ncache_path, "wb");
            if (cf) { fwrite(io.noise_cache_fp, 1, 32, cf); fclose(cf); }
        }
        if (!ok && getenv("WA_PROBE_DUMP")) {
            tls13 *t = wa_probe_tls(); int i;
            for (i = 0; i < t->chain_len; i++) { char fn[64]; FILE *o; snprintf(fn, sizeof fn, "build/wa_live_cert%d.der", i); o = fopen(fn, "wb"); if (o) { fwrite(t->chain[i].der, 1, t->chain[i].len, o); fclose(o); } }
        }
        if (ok || io.mode == WA_MODE_PAIR) printf("TIMING: keys tls %u ms + noise %u ms (offline); tls %u ms, ws %u ms, server hello %u ms, client finish %u ms, accepted %u ms (since connect)%s\n",
                       io.t_tls_key, io.t_noise_keys, io.t_tls, io.t_ws, io.t_hello, io.t_finish, io.t_accepted, io.noise_cert_cached ? ", Noise cert cache hit" : "");
        if (io.mode == WA_MODE_PAIR) {
            printf("PAIRING: codes shown %u, first code at %u ms, pair-success at %u ms, verify %u ms, sign %u ms, pair-device-sign at %u ms, stream:error 515 at %u ms, login connect at %u ms, login success at %u ms, pongs %u\n",
                   io.qr_shown, io.t_qr_shown, io.t_pair_success, io.d_verify, io.d_sign, io.t_sign_sent, io.t_515, io.t_login_connect, io.t_login_accepted, io.pongs);
            printf("LOGIN: server prekeys %u (answered %d), uploaded %u, active %d at %u ms, stanzas %u, acks %u, messages %u, prekey generation %u ms\n",
                   io.server_prekeys, io.have_server_prekeys, io.prekeys_uploaded, io.active_set, io.t_active, io.frames_after_login, io.acks_sent, io.messages_seen, io.d_prekeys);
            if (io.creds_loaded) write_creds(0);     /* identity (so a second attempt reuses it), JID after pairing, Noise cache fingerprint */
            if (io.prekeys_loaded) write_prekeys(0);
        }
        if (tunnel) { close(tun_out); close(tun_in); wait(0); } else close(fd);
        printf("%s\n", io.result);
        return ok ? 0 : 1;
    }
}
