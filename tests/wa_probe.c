/*
 * End-to-end probe of the WhatsA500 C stack against the real server: our TLS 1.3 client
 * (X25519, TLS_AES_128_GCM_SHA256, RSA-PSS CertificateVerify, chain pinned to the DigiCert G2 key
 * from tests/certs/wa_rsa_chain.h), our WebSocket client,
 * our Noise_XX handshake (ClientHello, ServerHello, certificate chain verified with XEdDSA
 * against WhatsApp's root key, ClientFinish) and the pong heartbeat from crypto/ref/heartbeat.c.
 * Between ServerHello and ClientFinish the probe burns `gap` seconds in X25519 ladders, as the
 * A500 would, with the heartbeat armed at 4 s: the server must still accept the ClientFinish and
 * answer with its first encrypted frame (the pair-device IQ), which we decrypt with the transport
 * keys. Host only, network required: make wa-probe GAP=30. No pairing is completed; the
 * ClientPayload is a throwaway registration payload from tools/watimeout -dump-payload.
 * TLS_HOLD=<seconds>: hold our TLS Finished that long after the server flight and report whether the server closes
 * (measured 2026-11-27: close_notify after 60.0 s; 50 s accepted).
 *
 * Tunnel mode (third argument "tunnel"): the TLS layer is replaced by `openssl s_client` with the same
 * parameters (TLS 1.3, X25519, TLS_AES_128_GCM_SHA256, rsa_pss_rsae_sha256) as a reference transport;
 * kept from the days before tls13.c existed (docs/PROTOCOL.md 7). Everything above TLS - WebSocket,
 * Noise, certificate chain, heartbeat - is our code in both modes.
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include "tls13.h"
#include "ws.h"
#include "noise.h"
#include "heartbeat.h"
#include "x25519.h"
#include "ed25519.h"
#include "../tests/certs/wa_rsa_chain.h"
#include "../tests/vectors/wa_client_payload.h"

/* whatsmeow socket/constants.go */
static const uint8_t wa_header[4] = { 'W', 'A', 6, 3 };
static const uint8_t wa_cert_pub[32] = { 0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
                                         0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b };
#define WA_CERT_ISSUER_SERIAL 0

static int fd, tunnel, tun_in = -1, tun_out = -1;
static tls13 t;
static ws_client w;
static uint8_t msgbuf[65536], pend[65536]; static uint32_t pend_len;
static struct timespec t0;

static uint32_t now_ms(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)((ts.tv_sec - t0.tv_sec) * 1000 + (ts.tv_nsec - t0.tv_nsec) / 1000000);
}
static void logf_(const char *fmt, ...)
{
    va_list ap; va_start(ap, fmt);
    printf("+%7.2fs  ", now_ms() / 1000.0); vprintf(fmt, ap); printf("\n"); fflush(stdout);
    va_end(ap);
}

static int send_all(const uint8_t *p, uint32_t n) { int o = tunnel ? tun_out : fd; while (n) { ssize_t r = write(o, p, n); if (r <= 0) return 0; p += r; n -= (uint32_t)r; } return 1; }
static int flush_tls(void) { if (tunnel || !t.out_len) return 1; if (!send_all(t.out, t.out_len)) return 0; t.out_len = 0; return 1; }
/* plaintext towards the server: through our TLS record layer, or straight into the tunnel */
static int app_send(const uint8_t *p, uint32_t n)
{
    uint32_t off = 0;
    if (tunnel) return send_all(p, n);
    while (off < n) {
        int c = tls13_send(&t, p + off, n - off);
        if (c < 0) return 0;
        if (c == 0) { if (!flush_tls()) return 0; continue; }
        off += (uint32_t)c;
    }
    return flush_tls();
}
static int hb_send(void *io, const uint8_t *p, uint32_t n) { (void)io; return app_send(p, n); }

/* send one WebSocket binary message through TLS */
static int ws_send(const uint8_t *payload, uint32_t len)
{
    static uint8_t frame[65536];
    uint32_t n = ws_frame_binary(&w, payload, len, frame, sizeof frame);
    return n ? app_send(frame, n) : 0;
}

/* read from the socket until the TLS state machine reaches want_tls_state, or (want_msg == 2) the WebSocket
 * upgrade completes, or (want_msg == 1) a WebSocket message is complete */
static int pump(int want_tls_state, int want_msg, double timeout_s)
{
    uint8_t buf[8192], out[256]; uint32_t ol;
    uint32_t deadline = now_ms() + (uint32_t)(timeout_s * 1000);
    for (;;) {
        ssize_t r;
        /* the TLS-state wait returns before flushing, so the caller can hold the client Finished (TLS_HOLD) */
        if (want_tls_state >= 0 && (tunnel || t.state == want_tls_state)) return 1;
        if (!flush_tls()) return 0;
        if (want_msg == 2 && w.state == WS_OPEN) return 1;
        if (want_msg) {
            /* feed pending decrypted bytes one at a time so nothing after a complete message is lost */
            while (pend_len && !w.msg_ready) {
                ol = 0;
                if (!ws_input(&w, pend, 1, out, &ol, sizeof out)) { logf_("ws error, state %d", w.state); return 0; }
                if (ol && !app_send(out, ol)) return 0;
                memmove(pend, pend + 1, --pend_len);
            }
            if (w.msg_ready) { if (getenv("WA_PROBE_DEBUG")) logf_("  ws message %u bytes: %02x %02x %02x %02x", w.msg_len, w.msg[0], w.msg[1], w.msg[2], w.msg[3]); return 1; }
            if (w.state == WS_CLOSED) { logf_("server closed the WebSocket (code %u)", w.close_code); return 0; }
        }
        if (now_ms() > deadline) { logf_("timeout"); return 0; }
        r = read(tunnel ? tun_in : fd, buf, sizeof buf);
        if (r <= 0) { logf_("socket closed by server (read %zd)", r); return 0; }
        if (tunnel) {
            if (w.state == WS_WAIT_HTTP) { ol = 0; if (!ws_input(&w, buf, (uint32_t)r, out, &ol, sizeof out)) { logf_("ws upgrade failed"); return 0; } }
            else { if (pend_len + (uint32_t)r > sizeof pend) return 0; memcpy(pend + pend_len, buf, (size_t)r); pend_len += (uint32_t)r; }
            continue;
        }
        if (getenv("WA_PROBE_DEBUG")) { ssize_t k, m = r < 100 ? r : 100; logf_("  read %zd bytes:", r); printf("    "); for (k = 0; k < m; k++) printf("%02x", buf[k]); printf("\n"); }
        if (!tls13_input(&t, buf, (uint32_t)r)) {
            int i;
            logf_("tls error: %s (state %d, alert %d), chain of %d:", tls13_errstr(t.error), t.state, t.alert, t.chain_len);
            for (i = 0; i < t.chain_len; i++) {
                const x509_cert *c = &t.chain[i]; uint32_t k;
                printf("    cert %d: %u bytes, n %u bytes e %u, ca %d, sha256RSA %d, %s..%s, subject ", i, c->len, c->n_len, c->e, c->is_ca, c->sig_sha256_rsa, c->not_before, c->not_after);
                for (k = 0; k < c->subject_len; k++) if (c->subject[k] >= 32 && c->subject[k] < 127) putchar(c->subject[k]);
                printf(" | issuer ");
                for (k = 0; k < c->issuer_len; k++) if (c->issuer[k] >= 32 && c->issuer[k] < 127) putchar(c->issuer[k]);
                printf("\n");
                if (getenv("WA_PROBE_DUMP")) { char fn[64]; FILE *o; snprintf(fn, sizeof fn, "build/wa_live_cert%d.der", i); o = fopen(fn, "wb"); if (o) { fwrite(c->der, 1, c->len, o); fclose(o); } }
            }
            return 0;
        }
        if (t.app_len) {
            if (w.state == WS_WAIT_HTTP) {
                ol = 0;
                if (!ws_input(&w, t.app, t.app_len, out, &ol, sizeof out)) { logf_("ws upgrade failed"); return 0; }
            } else {
                if (pend_len + t.app_len > sizeof pend) return 0;
                memcpy(pend + pend_len, t.app, t.app_len); pend_len += t.app_len;
            }
            t.app_len = 0;
        }
    }
}

/* protobuf: next field; returns 0 at end/error. varints in val, length-delimited fields in data and len */
static int pb_next(const uint8_t **pp, const uint8_t *end, uint32_t *field, uint32_t *wire, uint64_t *val, const uint8_t **data, uint32_t *len)
{
    const uint8_t *p = *pp; uint64_t tag = 0, v = 0; int sh = 0;
    if (p >= end) return 0;
    do { if (p >= end) return 0; tag |= (uint64_t)(*p & 0x7f) << sh; sh += 7; } while (*p++ & 0x80);
    *field = (uint32_t)(tag >> 3); *wire = (uint32_t)(tag & 7); *data = 0; *len = 0; *val = 0;
    if (*wire == 0) { sh = 0; do { if (p >= end) return 0; v |= (uint64_t)(*p & 0x7f) << sh; sh += 7; } while (*p++ & 0x80); *val = v; }
    else if (*wire == 2) { sh = 0; do { if (p >= end) return 0; v |= (uint64_t)(*p & 0x7f) << sh; sh += 7; } while (*p++ & 0x80);
                           if (v > (uint64_t)(end - p)) return 0; *data = p; *len = (uint32_t)v; p += v; }
    else if (*wire == 1) { if (end - p < 8) return 0; p += 8; }
    else if (*wire == 5) { if (end - p < 4) return 0; p += 4; }
    else return 0;
    *pp = p; return 1;
}
static uint32_t pb_varint(uint8_t *o, uint32_t v) { uint32_t n = 0; while (v >= 0x80) { o[n++] = (uint8_t)(v | 0x80); v >>= 7; } o[n++] = (uint8_t)v; return n; }

typedef struct { const uint8_t *details; uint32_t details_len; const uint8_t *sig; uint32_t sig_len;
                 uint64_t serial, issuer_serial; const uint8_t *key; uint32_t key_len; int have_key; } wa_cert;
static int parse_cert(wa_cert *c, const uint8_t *p, uint32_t len)
{
    const uint8_t *end = p + len, *d; uint32_t f, wire, l; uint64_t v;
    memset(c, 0, sizeof *c);
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) { if (f == 1 && wire == 2) { c->details = d; c->details_len = l; } else if (f == 2 && wire == 2) { c->sig = d; c->sig_len = l; } }
    if (!c->details || c->sig_len != 64) return 0;
    p = c->details; end = p + c->details_len;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
        if (f == 1 && wire == 0) c->serial = v; else if (f == 2 && wire == 0) c->issuer_serial = v;
        else if (f == 3 && wire == 2) { c->key = d; c->key_len = l; c->have_key = 1; }
    }
    return c->have_key && c->key_len == 32;
}

static void spin_ladders(double seconds, uint32_t *count)
{
    static uint8_t sk[32], pk[32]; int i;
    uint32_t until = now_ms() + (uint32_t)(seconds * 1000);
    for (i = 0; i < 32; i++) sk[i] = (uint8_t)(i * 11 + 3);
    while (now_ms() < until) { x25519_ref_base(pk, sk); (*count)++; }
}

int main(int argc, char **argv)
{
    double gap = argc > 1 ? atof(argv[1]) : 30.0;
    static uint8_t seed[64], out[4096], eph_priv[32], eph_pub[32], st_priv[32], st_pub[32];
    static uint8_t server_eph[32], server_static[32], server_static_ct[64], cert_ct[4096], cert_pt[4096];
    static uint8_t cstatic_ct[48], payload_ct[1024], finish[2048], plain[65536];
    uint32_t server_static_ct_len = 0, cert_ct_len = 0, n, ladders = 0;
    const uint8_t *p, *end, *d; uint32_t f, wire, l; uint64_t v;
    noise_hs hs; noise_transport tr; heartbeat hb; tls13_keypair kp;
    hmac_drbg rng;
    x509_cert root;
    char nowstr[16];
    time_t tt = time(0); struct tm *tm = gmtime(&tt);
    struct addrinfo hints, *ai = 0;
    FILE *rf = fopen("/dev/urandom", "rb");
    if (!rf || fread(seed, 1, 64, rf) != 64) { printf("no urandom\n"); return 1; }
    fclose(rf);
    rng.instantiated = 0; drbg_instantiate(&rng, seed, 64);
    strftime(nowstr, sizeof nowstr, "%Y%m%d%H%M%SZ", tm);
    clock_gettime(CLOCK_MONOTONIC, &t0);
    if (!x509_parse(&root, wa_cert2, sizeof wa_cert2)) { printf("root parse failed\n"); return 1; }

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
        logf_("tunnel: openssl s_client -tls1_3 -groups X25519 -ciphersuites TLS_AES_128_GCM_SHA256 -sigalgs rsa_pss_rsae_sha256 (the planned A500 TLS parameters)");
    }
    /* optional argv[2]: numeric address (the Makefile resolves it with dig; some sandboxes block the system resolver) */
    if (argc > 2) hints.ai_flags = AI_NUMERICHOST;
    { int ge = getaddrinfo(argc > 2 ? argv[2] : "web.whatsapp.com", "443", &hints, &ai); if (ge != 0) { printf("dns failed: %s\n", gai_strerror(ge)); return 1; } }
    if (!tunnel) {
        fd = socket(ai->ai_family, SOCK_STREAM, 0);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) != 0) { printf("connect failed\n"); return 1; }
        logf_("tcp: connected to web.whatsapp.com:443 (%s)", argc > 2 ? argv[2] : "resolved");

        /* TLS 1.3 with our own client, X25519 key pair precomputed (as the A500 does it), root pinned to the G2 key */
        if (!tls13_keypair_generate(&kp, &rng)) { printf("keypair failed\n"); return 1; }
        if (!tls13_client_start_kp(&t, "web.whatsapp.com", root.n, root.n_len, root.e, nowstr, &rng, &kp)) { printf("tls start failed\n"); return 1; }
        if (!pump(TLS13_ST_CONNECTED, 0, 20)) { printf("RESULT: TLS handshake failed\n"); return 1; }
        if (getenv("TLS_HOLD")) {
            /* timeout measurement: our Finished sits in t.out; hold it and watch whether the server closes the socket.
             * pump() flushed t.out before reading, so CONNECTED is reached with the Finished record still unsent only
             * because tls13_input produced it during the last read: check that, then hold. */
            double hold = atof(getenv("TLS_HOLD")); uint32_t start = now_ms(); fd_set rf; struct timeval tv; int sel; uint8_t probe[64];
            if (!t.out_len) { printf("RESULT: nothing to hold (Finished already sent)\n"); return 1; }
            logf_("tls: server flight done, holding our Finished (%u bytes) for %.0f s", t.out_len, hold);
            tv.tv_sec = (long)hold; tv.tv_usec = (long)((hold - (long)hold) * 1e6);
            FD_ZERO(&rf); FD_SET(fd, &rf);
            sel = select(fd + 1, &rf, 0, 0, &tv);
            if (sel > 0) { ssize_t r = read(fd, probe, sizeof probe); logf_("tls: SERVER CLOSED after %.1f s of silence (read %zd bytes%s)", (now_ms() - start) / 1000.0, r, r > 0 ? ", data follows" : "");
                           if (r > 0) { ssize_t k; printf("    "); for (k = 0; k < r; k++) printf("%02x", probe[k]); printf("\n");
                                        /* a protected record under the server application key: decrypt it to see the alert */
                                        tls13_input(&t, probe, (uint32_t)r);
                                        logf_("tls: record decodes as: %s%s (alert description %d)", tls13_errstr(t.error), t.error ? "" : " (no error?)", t.alert); }
                           printf("RESULT: TLS 1.3 flight closed by the server after %.1f s\n", (now_ms() - start) / 1000.0); return 1; }
            logf_("tls: server still silent after %.1f s, sending our Finished now", (now_ms() - start) / 1000.0);
        }
        if (!flush_tls()) { printf("RESULT: send failed\n"); return 1; }
        logf_("tls: TLS 1.3 TLS_AES_128_GCM_SHA256 / X25519 connected, %d certificates verified against the pinned G2 key, RSA-PSS CertificateVerify and Finished verified", t.chain_len);
    }

    /* WebSocket upgrade */
    n = ws_client_start(&w, "web.whatsapp.com", "/ws/chat", "https://web.whatsapp.com", msgbuf, sizeof msgbuf, &rng, out, sizeof out);
    if (!app_send(out, n)) return 1;
    if (!pump(-1, 2, 20)) { printf("RESULT: WebSocket upgrade failed (state %d)\n", w.state); return 1; }
    logf_("ws: wss://web.whatsapp.com/ws/chat open");

    /* Noise ClientHello: WA header + 3-byte length + HandshakeMessage{clientHello{ephemeral}} */
    drbg_generate(&rng, eph_priv, 32); drbg_generate(&rng, st_priv, 32);
    x25519_base_comb(st_pub, st_priv);
    noise_start(&hs, wa_header, 4);                      /* done inside noise_client_hello as well; harmless */
    {
        uint8_t pb[64 + 7 + 4]; uint32_t k = 0;
        x25519_base_comb(eph_pub, eph_priv);
        noise_client_hello(&hs, wa_header, 4, eph_pub);
        memcpy(pb, wa_header, 4); k = 4;
        pb[k++] = 0; pb[k++] = 0; pb[k++] = 36;         /* frame length 36 */
        pb[k++] = 0x12; pb[k++] = 34; pb[k++] = 0x0a; pb[k++] = 32; memcpy(pb + k, eph_pub, 32); k += 32;
        if (!ws_send(pb, k)) return 1;
    }
    logf_("noise: ClientHello sent");
    if (!pump(-1, 1, 30)) { printf("RESULT: no ServerHello\n"); return 1; }
    logf_("noise: ServerHello received (%u bytes)", w.msg_len);
    {
        uint32_t flen = ((uint32_t)w.msg[0] << 16) | ((uint32_t)w.msg[1] << 8) | w.msg[2];
        const uint8_t *sh = 0; uint32_t shl = 0;
        if (w.msg_len < 3 || flen != w.msg_len - 3) { printf("RESULT: bad frame length\n"); return 1; }
        p = w.msg + 3; end = p + flen;
        while (pb_next(&p, end, &f, &wire, &v, &d, &l)) if (f == 3 && wire == 2) { sh = d; shl = l; }
        if (!sh) { printf("RESULT: no serverHello in frame\n"); return 1; }
        p = sh; end = sh + shl;
        while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
            if (f == 1 && l == 32) memcpy(server_eph, d, 32);
            else if (f == 2 && l <= 64) { memcpy(server_static_ct, d, l); server_static_ct_len = l; }
            else if (f == 3 && l <= sizeof cert_ct) { memcpy(cert_ct, d, l); cert_ct_len = l; }
        }
        w.msg_ready = 0;
        if (server_static_ct_len != 48 || !cert_ct_len) { printf("RESULT: incomplete ServerHello\n"); return 1; }
    }
    {
        uint32_t t_hello = now_ms();
        /* the A500's computing time: X25519 ladders with the heartbeat armed */
        heartbeat_init(&hb, &w, now_ms, 4000, hb_send, 0);
        heartbeat_arm(&hb);
        logf_("noise: holding ClientFinish for %.0f s of X25519 ladders, pong heartbeat every 4 s", gap);
        spin_ladders(gap, &ladders);
        /* the real work (the A500 does this inside the gap; here it takes milliseconds) */
        if (!noise_client_finish(&hs, eph_priv, st_priv, st_pub, server_eph, server_static_ct, 48, cert_ct, cert_ct_len,
                                 wa_client_payload, sizeof wa_client_payload, server_static, cert_pt, cstatic_ct, payload_ct, &tr)) {
            printf("RESULT: Noise AEAD failure on ServerHello\n"); return 1;
        }
        {   /* certificate chain: CertChain{leaf=1, intermediate=2}, each NoiseCertificate{details=1, signature=2} */
            wa_cert leaf, inter; const uint8_t *lp = 0, *ip = 0; uint32_t ll = 0, il = 0; int ok;
            p = cert_pt; end = cert_pt + cert_ct_len - 16;
            while (pb_next(&p, end, &f, &wire, &v, &d, &l)) { if (f == 1 && wire == 2) { lp = d; ll = l; } else if (f == 2 && wire == 2) { ip = d; il = l; } }
            if (!lp || !ip || !parse_cert(&leaf, lp, ll) || !parse_cert(&inter, ip, il)) { printf("RESULT: cert chain parse failed\n"); return 1; }
            ok = inter.issuer_serial == WA_CERT_ISSUER_SERIAL;
            ok = ok && xeddsa_verify(inter.sig, inter.details, inter.details_len, wa_cert_pub);
            logf_("noise: intermediate certificate serial %llu signed by WhatsApp's root key: %s", (unsigned long long)inter.serial, ok ? "VERIFIED" : "FAILED");
            if (!ok) { printf("RESULT: intermediate certificate rejected\n"); return 1; }
            ok = leaf.issuer_serial == inter.serial && xeddsa_verify(leaf.sig, leaf.details, leaf.details_len, inter.key);
            ok = ok && memcmp(leaf.key, server_static, 32) == 0;
            logf_("noise: leaf certificate serial %llu signed by the intermediate, key == server static: %s", (unsigned long long)leaf.serial, ok ? "VERIFIED" : "FAILED");
            if (!ok) { printf("RESULT: leaf certificate rejected\n"); return 1; }
        }
        heartbeat_disarm();
        logf_("noise: %u X25519 ladders during the hold, %u pongs sent, heartbeat error %d", ladders, hb.sent, hb.error);
        if (hb.error) { printf("RESULT: heartbeat send failed\n"); return 1; }
        /* ClientFinish: 3-byte length + HandshakeMessage{clientFinish(4){static(1)=48, payload(2)=ct}} */
        {
            uint8_t inner[2048]; uint32_t k = 0, pl = sizeof wa_client_payload + 16, m;
            inner[k++] = 0x0a; inner[k++] = 48; memcpy(inner + k, cstatic_ct, 48); k += 48;
            inner[k++] = 0x12; k += pb_varint(inner + k, pl); memcpy(inner + k, payload_ct, pl); k += pl;
            m = 3; finish[m++] = 0x22; m += pb_varint(finish + m, k); memcpy(finish + m, inner, k); m += k;
            finish[0] = (uint8_t)((m - 3) >> 16); finish[1] = (uint8_t)((m - 3) >> 8); finish[2] = (uint8_t)(m - 3);
            if (!ws_send(finish, m)) { printf("RESULT: ClientFinish send failed\n"); return 1; }
        }
        logf_("noise: ClientFinish sent %.1f s after ServerHello", (now_ms() - t_hello) / 1000.0);
    }
    if (!pump(-1, 1, 20)) { printf("RESULT: handshake REJECTED (no encrypted frame after ClientFinish, gap %.0f s)\n", gap); return 1; }
    {
        uint32_t flen = ((uint32_t)w.msg[0] << 16) | ((uint32_t)w.msg[1] << 8) | w.msg[2];
        if (w.msg_len < 3 + 16 || flen != w.msg_len - 3) { printf("RESULT: bad encrypted frame\n"); return 1; }
        if (!noise_transport_decrypt(&tr, w.msg + 3, flen, plain)) { printf("RESULT: first server frame does not decrypt\n"); return 1; }
        logf_("noise: first encrypted server frame: %u bytes ciphertext -> %u bytes plaintext, first bytes %02x %02x %02x %02x (binary node, pair-device IQ)",
              flen, flen - 16, plain[0], plain[1], plain[2], plain[3]);
    }
    {   uint8_t cl[16]; n = ws_frame_close(&w, 1000, cl, sizeof cl); if (n) app_send(cl, n); }
    if (tunnel) { close(tun_out); close(tun_in); wait(0); } else close(fd);
    printf("RESULT: handshake ACCEPTED by web.whatsapp.com with our %s/WS/Noise stack, %.0f s hold, %u pongs\n", tunnel ? "(openssl TLS 1.3 tunnel)" : "TLS 1.3", gap, hb.sent);
    return 0;
}
