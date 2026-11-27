#include <stdarg.h>
#include "wa_probe_core.h"
#include "ws.h"
#include "noise.h"
#include "heartbeat.h"
#include "x25519.h"
#include "ed25519.h"
#include "certs/wa_rsa_chain.h"
#include "vectors/wa_client_payload.h"
#include "wabinary.h"
#include "identity.h"
#include "clientpayload.h"
#include "pairing.h"
#include "creds.h"
#include "pb.h"
#include "prekeys.h"
#include "inflate.h"

/* whatsmeow socket/constants.go */
static const uint8_t wa_header[4] = { 'W', 'A', 6, 3 };
static const uint8_t wa_cert_pub[32] = { 0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
                                         0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b };
#define WA_CERT_ISSUER_SERIAL 0

static wa_probe_io *io;
static tls13 t;
static ws_client w;
static uint8_t msgbuf[WA_PROBE_MSG_MAX], pend[WA_PROBE_MSG_MAX]; static uint32_t pend_len;
static uint8_t rdbuf[8192];
static uint32_t t_start;
static char line[640];

/* prepared offline (wa_probe_prepare), consumed by wa_probe_run */
static hmac_drbg rng; static x509_cert root, inter; static tls13_keypair kp;
static uint8_t eph_priv[32], eph_pub[32], st_priv[32], st_pub[32];
static noise_cert_cache ncache, lcache;   /* intermediate and leaf certificate fingerprints */
static int prepared;
static noise_transport tr;            /* transport keys of the current connection */
static int pump_quiet;                /* suppress the "timeout" log line (QR wait loop) */
static uint32_t msg_off, msg_have;    /* one WebSocket message may carry several WA frames (3-byte length each,
                                         whatsmeow socket/framesocket.go processData): the ones not taken yet */

/* ---- freestanding helpers ------------------------------------------------------------------------ */
static void cp(uint8_t *d, const uint8_t *s, uint32_t n) { while (n--) *d++ = *s++; }
static int  eq(const uint8_t *a, const uint8_t *b, uint32_t n) { uint32_t i; int d = 0; for (i = 0; i < n; i++) d |= a[i] ^ b[i]; return d == 0; }
static uint32_t ms(void) { return io->now_ms() - t_start; }
static void logl(const char *s) { io->log(io->ctx, s); }

static uint32_t put_u(char *d, uint32_t cap, uint32_t v, int width, char pad, int hex, int neg)
{
    char tmp[12]; int n = 0; uint32_t o = 0;
    do { uint32_t r = hex ? (v & 15) : (v % 10); tmp[n++] = (char)(r < 10 ? '0' + r : 'a' + r - 10); v = hex ? v >> 4 : v / 10; } while (v);
    if (neg) tmp[n++] = '-';
    while (n < width && o < cap) { d[o++] = pad; width--; }
    while (n && o < cap) d[o++] = tmp[--n];
    return o;
}

uint32_t wa_fmt(char *dst, uint32_t cap, const char *fmt, ...)
{
    va_list ap; uint32_t o = 0;
    va_start(ap, fmt);
    cap--;                                   /* room for the NUL */
    while (*fmt && o < cap) {
        int width = 0; char pad = ' ';
        if (*fmt != '%') { dst[o++] = *fmt++; continue; }
        fmt++;
        if (*fmt == '0') { pad = '0'; fmt++; }
        while (*fmt >= '0' && *fmt <= '9') width = width * 10 + (*fmt++ - '0');
        switch (*fmt++) {
        case 's': { const char *s = va_arg(ap, const char *); if (!s) s = "(null)"; while (*s && o < cap) dst[o++] = *s++; break; }
        case 'u': o += put_u(dst + o, cap - o, va_arg(ap, uint32_t), width, pad, 0, 0); break;
        case 'x': o += put_u(dst + o, cap - o, va_arg(ap, uint32_t), width, pad, 1, 0); break;
        case 'd': { int32_t v = va_arg(ap, int32_t); o += put_u(dst + o, cap - o, v < 0 ? (uint32_t)-v : (uint32_t)v, width, pad, 0, v < 0); break; }
        case 'c': dst[o++] = (char)va_arg(ap, int); break;
        case 'T': { uint32_t v = va_arg(ap, uint32_t);                     /* ms -> "s.cc" */
                    o += put_u(dst + o, cap - o, v / 1000, width > 3 ? width - 3 : 0, pad, 0, 0);
                    if (o < cap) dst[o++] = '.';
                    o += put_u(dst + o, cap - o, (v % 1000) / 10, 2, '0', 0, 0); break; }
        case '%': dst[o++] = '%'; break;
        default: break;
        }
    }
    va_end(ap);
    dst[o] = 0;
    return o;
}

static void log_hex(const char *prefix, const uint8_t *b, uint32_t n)
{
    uint32_t o = wa_fmt(line, sizeof line, "%s", prefix), i;
    for (i = 0; i < n && o + 3 < sizeof line; i++) o += wa_fmt(line + o, sizeof line - o, "%02x", (uint32_t)b[i]);
    logl(line);
}

/* ---- transport glue -------------------------------------------------------------------------- */
static int send_all(const uint8_t *p, uint32_t n) { return io->send(io->ctx, p, n); }
static int flush_tls(void) { if (io->tunnel || !t.out_len) return 1; if (!send_all(t.out, t.out_len)) return 0; t.out_len = 0; return 1; }
/* plaintext towards the server: through our TLS record layer, or straight into the tunnel */
static int app_send(const uint8_t *p, uint32_t n)
{
    uint32_t off = 0;
    if (io->tunnel) return send_all(p, n);
    while (off < n) {
        int c = tls13_send(&t, p + off, n - off);
        if (c < 0) return 0;
        if (c == 0) { if (!flush_tls()) return 0; continue; }
        off += (uint32_t)c;
    }
    return flush_tls();
}
static int hb_send(void *hio, const uint8_t *p, uint32_t n) { (void)hio; return app_send(p, n); }

/* one WebSocket binary message through TLS */
static int ws_send(const uint8_t *payload, uint32_t len)
{
    static uint8_t frame[4096];
    uint32_t n = ws_frame_binary(&w, payload, len, frame, sizeof frame);
    return n ? app_send(frame, n) : 0;
}

static void log_tls_error(void)
{
    int i; uint32_t k, o;
    wa_fmt(line, sizeof line, "tls error: %s (state %d, alert %d), chain of %d:", tls13_errstr(t.error), t.state, t.alert, t.chain_len);
    logl(line);
    for (i = 0; i < t.chain_len; i++) {
        const x509_cert *c = &t.chain[i];
        o = wa_fmt(line, sizeof line, "    cert %d: %u bytes, n %u bytes e %u, ca %d, sha256RSA %d, %s..%s, subject ",
                   i, c->len, c->n_len, c->e, c->is_ca, c->sig_sha256_rsa, c->not_before, c->not_after);
        for (k = 0; k < c->subject_len && o + 1 < sizeof line; k++) if (c->subject[k] >= 32 && c->subject[k] < 127) line[o++] = (char)c->subject[k];
        o += wa_fmt(line + o, sizeof line - o, " | issuer ");
        for (k = 0; k < c->issuer_len && o + 1 < sizeof line; k++) if (c->issuer[k] >= 32 && c->issuer[k] < 127) line[o++] = (char)c->issuer[k];
        line[o] = 0;
        logl(line);
    }
}

/* read until the TLS state machine reaches want_tls_state, or (want_msg == 2) the WebSocket upgrade completes,
 * or (want_msg == 1) a WebSocket message is complete */
static int pump(int want_tls_state, int want_msg, uint32_t timeout_ms)
{
    uint8_t out[256]; uint32_t ol;
    uint32_t deadline = ms() + timeout_ms;
    for (;;) {
        int32_t r; uint32_t now;
        /* the TLS-state wait returns before flushing, so the caller can hold the client Finished (TLS_HOLD) */
        if (want_tls_state >= 0 && (io->tunnel || t.state == want_tls_state)) return 1;
        if (!flush_tls()) return 0;
        if (want_msg == 2 && w.state == WS_OPEN) return 1;
        if (want_msg) {
            /* feed pending decrypted bytes one at a time so nothing after a complete message is lost */
            while (pend_len && !w.msg_ready) {
                uint32_t i;
                ol = 0;
                { uint32_t d = w.dropped;
                  if (!ws_input(&w, pend, 1, out, &ol, sizeof out)) { wa_fmt(line, sizeof line, "ws error, state %d", w.state); logl(line); return 0; }
                  if (w.dropped != d) { wa_fmt(line, sizeof line, "ws: a %u-byte message was dropped (larger than the %u-byte buffer)", w.dropped_len, (uint32_t)sizeof msgbuf); logl(line); } }
                if (ol && !app_send(out, ol)) return 0;
                pend_len--; for (i = 0; i < pend_len; i++) pend[i] = pend[i + 1];
            }
            if (w.msg_ready) { if (io->debug) { wa_fmt(line, sizeof line, "  ws message %u bytes:", w.msg_len); log_hex(line, w.msg, w.msg_len < 4 ? w.msg_len : 4); } return 1; }
            if (w.state == WS_CLOSED) { wa_fmt(line, sizeof line, "server closed the WebSocket (code %u)", (uint32_t)w.close_code); logl(line); return 0; }
        }
        now = ms();
        if (now > deadline) { if (!pump_quiet) logl("timeout"); return 0; }
        r = io->recv(io->ctx, rdbuf, sizeof rdbuf, deadline - now);
        if (r == 0) { if (!pump_quiet) logl("timeout"); return 0; }
        if (r < 0) { logl("socket closed by server"); return 0; }
        if (io->tunnel) {
            if (w.state == WS_WAIT_HTTP) { ol = 0; if (!ws_input(&w, rdbuf, (uint32_t)r, out, &ol, sizeof out)) { logl("ws upgrade failed"); return 0; } }
            else { if (pend_len + (uint32_t)r > sizeof pend) return 0; cp(pend + pend_len, rdbuf, (uint32_t)r); pend_len += (uint32_t)r; }
            continue;
        }
        if (io->debug) { wa_fmt(line, sizeof line, "  read %d bytes: ", r); log_hex(line, rdbuf, r < 100 ? (uint32_t)r : 100); }
        if (!tls13_input(&t, rdbuf, (uint32_t)r)) { log_tls_error(); return 0; }
        if (t.app_len) {
            if (w.state == WS_WAIT_HTTP) {
                ol = 0;
                if (!ws_input(&w, t.app, t.app_len, out, &ol, sizeof out)) { logl("ws upgrade failed"); return 0; }
            } else {
                if (pend_len + t.app_len > sizeof pend) return 0;
                cp(pend + pend_len, t.app, t.app_len); pend_len += t.app_len;
            }
            t.app_len = 0;
        }
    }
}

/* ---- protobuf: reader from proto/pb.h; one bare varint writer for the handshake frames ---------- */
static uint32_t pb_varint(uint8_t *o, uint32_t v) { uint32_t n = 0; while (v >= 0x80) { o[n++] = (uint8_t)(v | 0x80); v >>= 7; } o[n++] = (uint8_t)v; return n; }

typedef struct { const uint8_t *details; uint32_t details_len; const uint8_t *sig; uint32_t sig_len;
                 uint32_t serial, issuer_serial; const uint8_t *key; uint32_t key_len; int have_key; } wa_cert;
static int parse_cert(wa_cert *c, const uint8_t *p, uint32_t len)
{
    const uint8_t *end = p + len, *d; uint32_t f, wire, l, v, i;
    for (i = 0; i < sizeof *c; i++) ((uint8_t *)c)[i] = 0;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) { if (f == 1 && wire == 2) { c->details = d; c->details_len = l; } else if (f == 2 && wire == 2) { c->sig = d; c->sig_len = l; } }
    if (!c->details || c->sig_len != 64) return 0;
    p = c->details; end = p + c->details_len;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
        if (f == 1 && wire == 0) c->serial = v; else if (f == 2 && wire == 0) c->issuer_serial = v;
        else if (f == 3 && wire == 2) { c->key = d; c->key_len = l; c->have_key = 1; }
    }
    return c->have_key && c->key_len == 32;
}

static void spin_ladders(uint32_t gap_ms, uint32_t *count)
{
    static uint8_t sk[32], pk[32]; int i;
    uint32_t until = ms() + gap_ms;
    for (i = 0; i < 32; i++) sk[i] = (uint8_t)(i * 11 + 3);
    while (ms() < until) { x25519_ref_base(pk, sk); (*count)++; }
}

tls13 *wa_probe_tls(void) { return &t; }

static int fail(const char *fmt, const char *a, uint32_t b) { wa_fmt(io->result, sizeof io->result, fmt, a, b); return 0; }

static int tls_connect(x509_cert *root, x509_cert *inter, hmac_drbg *rng, tls13_keypair *kp, x509_cache *cache)
{
    if (!tls13_client_start_kp(&t, io->host, root->n, root->n_len, root->e, io->now, rng, kp)) return fail("RESULT: tls start failed", 0, 0);
    tls13_set_cert_cache(&t, cache);                 /* empty: filled after the full verification; loaded: a hit skips the chain */
    tls13_add_pin(&t, inter->n, inter->n_len, inter->e);   /* pins: {G2 root, G2 TLS RSA 2020 CA1 intermediate} */
    if (!pump(TLS13_ST_CONNECTED, 0, 60000)) return fail("RESULT: TLS handshake failed", 0, 0);
    return 1;
}

/* Everything that needs no connection: the DRBG, the pinned TLS chain, the TLS 1.3 X25519 key pair and the two
 * Noise X25519 key pairs (static + ephemeral). On the A500 this is ~10 s of fixed-base comb multiplications that
 * used to sit inside the connected window; now the caller runs it before the TCP connect. In WA_MODE_PAIR the Noise
 * static key is the identity's (the server knows a paired companion by it), and a missing identity is generated
 * here (3 more comb multiplications + 1 XEdDSA signature, ~18 s on the 68000). */
static int connection_keys(void)
{
    uint32_t t0 = ms();
    if (!tls13_keypair_generate(&kp, &rng)) return fail("RESULT: keypair failed", 0, 0);
    io->t_tls_key = ms() - t0;
    t0 = ms();
    drbg_generate(&rng, eph_priv, 32);
    x25519_base_comb(eph_pub, eph_priv);
    if (io->mode == WA_MODE_PAIR) { cp(st_priv, io->creds->id.noise_priv, 32); cp(st_pub, io->creds->id.noise_pub, 32); }
    else { drbg_generate(&rng, st_priv, 32); x25519_base_comb(st_pub, st_priv); }
    io->t_noise_keys = ms() - t0;
    return 1;
}

int wa_probe_prepare(wa_probe_io *pio)
{
    io = pio; t_start = io->now_ms(); prepared = 0;
    io->t_tls_key = io->t_noise_keys = 0; io->result[0] = 0;
    io->noise_cert_cached = 0; io->noise_cache_valid = 0;
    if (!io->seed || io->seed_len < 32) return fail("RESULT: no seed", 0, 0);
    rng.instantiated = 0; drbg_instantiate(&rng, io->seed, io->seed_len);
    if (!x509_parse(&root, wa_cert2, sizeof wa_cert2) || !x509_parse(&inter, wa_cert1, sizeof wa_cert1)) return fail("RESULT: root/intermediate parse failed", 0, 0);
    /* the stored fingerprint of WhatsApp's intermediate Noise certificate, if the caller kept one */
    ncache.valid = 0; lcache.valid = 0; io->noise_leaf_cached = 0; io->noise_leaf_valid = 0; io->tls_cert_cached = 0; io->tls_cache_out_len = 0; io->tls_tickets = 0;
    if (io->noise_leaf_cache_in) { cp(lcache.fp, io->noise_leaf_cache_in, 32); lcache.valid = 1; }
    if (io->noise_cache_in) { cp(ncache.fp, io->noise_cache_in, 32); ncache.valid = 1; }
    else if (io->mode == WA_MODE_PAIR && io->creds && io->creds_loaded && io->creds->noise_cache_valid) { cp(ncache.fp, io->creds->noise_cache_fp, 32); ncache.valid = 1; logl("noise: certificate cache fingerprint taken from the credentials"); }
    if (io->mode == WA_MODE_PAIR) {
        uint32_t t0 = ms();
        if (!io->creds) return fail("RESULT: pair mode without a credentials record", 0, 0);
        if (!io->creds_loaded) {
            uint32_t i; uint8_t *z = (uint8_t *)io->creds; for (i = 0; i < sizeof *io->creds; i++) z[i] = 0;
            wa_identity_generate(&io->creds->id, &rng);
            io->creds_loaded = 1;
            wa_fmt(line, sizeof line, "identity: new companion identity generated (Noise static, Signal identity, signed prekey id %u, registration id %u) in %T s, before the connection",
                   io->creds->id.spk_id, io->creds->id.reg_id, ms() - t0); logl(line);
        } else {
            wa_fmt(line, sizeof line, "identity: stored companion identity loaded (registration id %u, %s)", io->creds->id.reg_id,
                   io->creds->paired ? "paired: login" : "not paired yet: QR pairing"); logl(line);
        }
        if (io->prekeys) {
            uint32_t pending, made;
            if (!io->prekeys_loaded) { wa_prekeys_init(io->prekeys); io->prekeys_loaded = 1; }
            pending = wa_prekeys_pending(io->prekeys);
            if (pending < io->prekeys_wanted) {
                t0 = ms();
                made = wa_prekeys_generate(io->prekeys, io->prekeys_wanted - pending, &rng);
                io->d_prekeys = ms() - t0;
                wa_fmt(line, sizeof line, "prekeys: %u new one-time prekeys (X25519, ids up to %u) in %T s, before the connection; %u pending upload",
                       made, io->prekeys->next_id - 1, io->d_prekeys, wa_prekeys_pending(io->prekeys)); logl(line);
                if (made && io->save_prekeys) io->save_prekeys(io->ctx);
            } else { wa_fmt(line, sizeof line, "prekeys: %u one-time prekeys pending upload (stored batch)", pending); logl(line); }
        }
    }
    if (!connection_keys()) return 0;
    wa_fmt(line, sizeof line, "tls: X25519 key pair ready (%T s, before the connection)", io->t_tls_key); logl(line);
    wa_fmt(line, sizeof line, "noise: static + ephemeral X25519 key pairs ready (%T s, before the connection)", io->t_noise_keys); logl(line);
    prepared = 1;
    return 1;
}

static int recv_frame(uint32_t timeout_ms, uint8_t *plain, uint32_t *plen);

/* TCP is connected: TLS -> WebSocket -> Noise XX with `payload` as the ClientPayload; the first decrypted server
 * frame lands in plain[0..*plain_len). Shared by the probe, the pairing connection and the login connection. */
static int handshake(const uint8_t *payload, uint32_t payload_len, uint8_t *plain, uint32_t *plain_len)
{
    static uint8_t out[4096];
    static uint8_t server_eph[32], server_static[32], server_static_ct[64], cert_ct[4096], cert_pt[4096];
    static uint8_t cstatic_ct[48], payload_ct[WA_CLIENTPAYLOAD_MAX + 16], finish[2048], inner[2048];
    static noise_hs hs; static heartbeat hb; static x509_cache cache;
    uint32_t server_static_ct_len = 0, cert_ct_len = 0, n, ladders = 0;
    const uint8_t *p, *end, *d; uint32_t f, wire, l, v;

    pend_len = 0; pump_quiet = 0; msg_have = 0; msg_off = 0;
    if (payload_len + 16 > sizeof payload_ct) return fail("RESULT: ClientPayload too long", 0, 0);
    if (!io->tunnel) {
        /* use_cache: a first connection fills the certificate cache (full chain verification), then the real one
         * must hit it and skip the chain - as a second A500 session would after storing the entry in ENVARC: */
        if (!io->use_cache && !cache.valid) {
            /* the stored certificate cache (host: TLS_CACHE_FILE, A500: SYS:tlscache.bin); within one run the cache
             * filled by the pairing connection serves the login connection */
            if (io->tls_cache_in && x509_cache_read(&cache, io->tls_cache_in, io->tls_cache_in_len)) logl("tls: certificate cache loaded (leaf fingerprint + prepared RSA key)");
            else if (io->tls_cache_in) logl("tls: stored certificate cache invalid, ignored");
        }
        if (io->use_cache) {
            cache.valid = 0;
            if (!tls_connect(&root, &inter, &rng, &kp, &cache) || !flush_tls()) { wa_fmt(io->result, sizeof io->result, "RESULT: TLS handshake (cache priming) failed"); return 0; }
            wa_fmt(line, sizeof line, "tls: priming connection: %d certificates verified, leaf fingerprint cached (cert_cached %d)", t.chain_len, t.cert_cached); logl(line);
            if (!io->reconnect || !io->reconnect(io->ctx)) return fail("RESULT: reconnect failed", 0, 0);
            logl("tcp: second connection");
        }
        if (!tls_connect(&root, &inter, &rng, &kp, &cache)) return 0;
        if (!t.cert_cached) { wa_fmt(line, sizeof line, "tls: chain completed at pin %d (%s), %d RSA verification%s", t.cert_pin, t.cert_pin == 1 ? "CA1 intermediate" : "G2 root",
                                     t.cert_pin == 1 ? 1 : 2, t.cert_pin == 1 ? "" : "s"); logl(line); }
        if (io->use_cache) {
            wa_fmt(line, sizeof line, "tls: certificate cache %s on the second connection", t.cert_cached ? "HIT - chain verification skipped, CertificateVerify checked" : "MISS (different leaf?)"); logl(line);
            if (!t.cert_cached) return fail("RESULT: certificate cache missed", 0, 0);
        } else if (t.cert_cached) { logl("tls: certificate cache HIT - chain verification and rsa_pub_set skipped, CertificateVerify checked"); io->tls_cert_cached = 1; }
        if (cache.valid) io->tls_cache_out_len = x509_cache_write(io->tls_cache_out, sizeof io->tls_cache_out, &cache);
        if (io->hold_ms) {
            /* timeout measurement: our Finished sits in t.out; hold it and watch whether the server closes the socket.
             * pump() flushed t.out before reading, so CONNECTED is reached with the Finished record still unsent only
             * because tls13_input produced it during the last read: check that, then hold. */
            uint32_t start = ms(); int32_t r; uint8_t probe[64];
            if (!t.out_len) return fail("RESULT: nothing to hold (Finished already sent)", 0, 0);
            wa_fmt(line, sizeof line, "tls: server flight done, holding our Finished (%u bytes) for %T s", t.out_len, io->hold_ms); logl(line);
            r = io->recv(io->ctx, probe, sizeof probe, io->hold_ms);
            if (r != 0) {
                wa_fmt(line, sizeof line, "tls: SERVER CLOSED after %T s of silence (read %d bytes%s)", ms() - start, r, r > 0 ? ", data follows" : ""); logl(line);
                if (r > 0) { log_hex("    ", probe, (uint32_t)r);
                             /* a protected record under the server application key: decrypt it to see the alert */
                             tls13_input(&t, probe, (uint32_t)r);
                             wa_fmt(line, sizeof line, "tls: record decodes as: %s%s (alert description %d)", tls13_errstr(t.error), t.error ? "" : " (no error?)", t.alert); logl(line); }
                wa_fmt(io->result, sizeof io->result, "RESULT: TLS 1.3 flight closed by the server after %T s", ms() - start); return 0;
            }
            wa_fmt(line, sizeof line, "tls: server still silent after %T s, sending our Finished now", ms() - start); logl(line);
        }
        if (!flush_tls()) return fail("RESULT: send failed", 0, 0);
        io->t_tls = ms();
        wa_fmt(line, sizeof line, "tls: TLS 1.3 TLS_AES_128_GCM_SHA256 / X25519 connected, %d certificates %s, RSA-PSS CertificateVerify and Finished verified", t.chain_len,
               t.cert_cached ? "accepted from the cache" : "verified against the pin set {G2 root, CA1 intermediate}"); logl(line);
    }

    /* WebSocket upgrade */
    n = ws_client_start(&w, io->host, "/ws/chat", "https://web.whatsapp.com", msgbuf, sizeof msgbuf, &rng, out, sizeof out);
    if (!n || !app_send(out, n)) return fail("RESULT: WebSocket request failed", 0, 0);
    if (!pump(-1, 2, 20000)) { wa_fmt(io->result, sizeof io->result, "RESULT: WebSocket upgrade failed (state %u)", (uint32_t)w.state); return 0; }
    io->t_ws = ms();
    wa_fmt(line, sizeof line, "ws: wss://%s/ws/chat open", io->host); logl(line);

    /* Noise ClientHello: WA header + 3-byte length + HandshakeMessage{clientHello{ephemeral}}; the key pairs
     * come from wa_probe_prepare / connection_keys */
    {
        uint8_t pb[64 + 7 + 4]; uint32_t k = 0;
        noise_client_hello(&hs, wa_header, 4, eph_pub);
        cp(pb, wa_header, 4); k = 4;
        pb[k++] = 0; pb[k++] = 0; pb[k++] = 36;         /* frame length 36 */
        pb[k++] = 0x12; pb[k++] = 34; pb[k++] = 0x0a; pb[k++] = 32; cp(pb + k, eph_pub, 32); k += 32;
        if (!ws_send(pb, k)) return fail("RESULT: ClientHello send failed", 0, 0);
    }
    logl("noise: ClientHello sent");
    if (!pump(-1, 1, 30000)) return fail("RESULT: no ServerHello", 0, 0);
    io->t_hello = ms();
    wa_fmt(line, sizeof line, "noise: ServerHello received (%u bytes)", w.msg_len); logl(line);
    {
        uint32_t flen = ((uint32_t)w.msg[0] << 16) | ((uint32_t)w.msg[1] << 8) | w.msg[2];
        const uint8_t *sh = 0; uint32_t shl = 0;
        if (w.msg_len < 3 || flen != w.msg_len - 3) return fail("RESULT: bad frame length", 0, 0);
        p = w.msg + 3; end = p + flen;
        while (pb_next(&p, end, &f, &wire, &v, &d, &l)) if (f == 3 && wire == 2) { sh = d; shl = l; }
        if (!sh) return fail("RESULT: no serverHello in frame", 0, 0);
        p = sh; end = sh + shl;
        while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
            if (f == 1 && l == 32) cp(server_eph, d, 32);
            else if (f == 2 && l <= 64) { cp(server_static_ct, d, l); server_static_ct_len = l; }
            else if (f == 3 && l <= sizeof cert_ct) { cp(cert_ct, d, l); cert_ct_len = l; }
        }
        w.msg_ready = 0;
        if (server_static_ct_len != 48 || !cert_ct_len) return fail("RESULT: incomplete ServerHello", 0, 0);
    }
    {
        uint32_t t_hello = ms();
        /* the A500's computing time: X25519 ladders with the heartbeat armed */
        heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0);
        heartbeat_arm(&hb);
        if (io->gap_ms) { wa_fmt(line, sizeof line, "noise: holding ClientFinish for %T s of X25519 ladders, pong heartbeat every 4 s", io->gap_ms); logl(line); }
        spin_ladders(io->gap_ms, &ladders);
        /* the real work (the A500 does this inside the gap; here it takes milliseconds) */
        if (!noise_client_finish(&hs, eph_priv, st_priv, st_pub, server_eph, server_static_ct, 48, cert_ct, cert_ct_len,
                                 payload, payload_len, server_static, cert_pt, cstatic_ct, payload_ct, &tr)) {
            heartbeat_disarm(); return fail("RESULT: Noise AEAD failure on ServerHello", 0, 0);
        }
        {   /* certificate chain: CertChain{leaf=1, intermediate=2}, each NoiseCertificate{details=1, signature=2} */
            wa_cert leaf, interc; const uint8_t *lp = 0, *ip = 0; uint32_t ll = 0, il = 0; int ok;
            p = cert_pt; end = cert_pt + cert_ct_len - 16;
            while (pb_next(&p, end, &f, &wire, &v, &d, &l)) { if (f == 1 && wire == 2) { lp = d; ll = l; } else if (f == 2 && wire == 2) { ip = d; il = l; } }
            if (!lp || !ip || !parse_cert(&leaf, lp, ll) || !parse_cert(&interc, ip, il)) { heartbeat_disarm(); return fail("RESULT: cert chain parse failed", 0, 0); }
            /* intermediate: issuer must be the root; the XEdDSA verification (~11 s on the 68000) is skipped when the
             * cache holds the fingerprint of exactly these details + signature under exactly this root key */
            ok = interc.issuer_serial == WA_CERT_ISSUER_SERIAL;
            if (ok && noise_cert_cache_match(&ncache, wa_cert_pub, interc.details, interc.details_len, interc.sig)) {
                io->noise_cert_cached = 1;
                wa_fmt(line, sizeof line, "noise: intermediate certificate serial %u: cache HIT (details + signature verified under WhatsApp's root key before), XEdDSA skipped", interc.serial); logl(line);
            } else {
                ok = ok && xeddsa_verify(interc.sig, interc.details, interc.details_len, wa_cert_pub);
                wa_fmt(line, sizeof line, "noise: intermediate certificate serial %u signed by WhatsApp's root key: %s%s", interc.serial, ok ? "VERIFIED" : "FAILED",
                       ok ? (ncache.valid ? " (cache MISS, entry replaced)" : " (cache empty, entry stored)") : ""); logl(line);
                if (ok) noise_cert_cache_store(&ncache, wa_cert_pub, interc.details, interc.details_len, interc.sig);
            }
            if (!ok) { heartbeat_disarm(); return fail("RESULT: intermediate certificate rejected", 0, 0); }
            cp(io->noise_cache_fp, ncache.fp, 32); io->noise_cache_valid = 1;
            if (io->mode == WA_MODE_PAIR && io->creds) { cp(io->creds->noise_cache_fp, ncache.fp, 32); io->creds->noise_cache_valid = 1; }
            /* leaf: issuer must be this intermediate; its XEdDSA (another ~11 s) is skipped when the leaf cache holds
             * the fingerprint of exactly these details + signature under exactly this intermediate key */
            ok = leaf.issuer_serial == interc.serial;
            if (ok && noise_cert_cache_match(&lcache, interc.key, leaf.details, leaf.details_len, leaf.sig)) io->noise_leaf_cached = 1;
            else { ok = ok && xeddsa_verify(leaf.sig, leaf.details, leaf.details_len, interc.key); if (ok) noise_cert_cache_store(&lcache, interc.key, leaf.details, leaf.details_len, leaf.sig); }
            ok = ok && eq(leaf.key, server_static, 32);
            wa_fmt(line, sizeof line, "noise: leaf certificate serial %u signed by the intermediate%s, key == server static: %s", leaf.serial,
                   io->noise_leaf_cached ? " (cache HIT, XEdDSA skipped)" : "", ok ? "VERIFIED" : "FAILED"); logl(line);
            if (ok) { cp(io->noise_leaf_fp, lcache.fp, 32); io->noise_leaf_valid = 1; }
            if (!ok) { heartbeat_disarm(); return fail("RESULT: leaf certificate rejected", 0, 0); }
        }
        heartbeat_disarm();
        io->pongs += hb.sent; io->ladders += ladders;
        wa_fmt(line, sizeof line, "noise: %u X25519 ladders during the hold, %u pongs sent, heartbeat error %d", ladders, hb.sent, hb.error); logl(line);
        if (hb.error) return fail("RESULT: heartbeat send failed", 0, 0);
        /* ClientFinish: 3-byte length + HandshakeMessage{clientFinish(4){static(1)=48, payload(2)=ct}} */
        {
            uint32_t k = 0, pl = payload_len + 16, m;
            inner[k++] = 0x0a; inner[k++] = 48; cp(inner + k, cstatic_ct, 48); k += 48;
            inner[k++] = 0x12; k += pb_varint(inner + k, pl); cp(inner + k, payload_ct, pl); k += pl;
            m = 3; finish[m++] = 0x22; m += pb_varint(finish + m, k); cp(finish + m, inner, k); m += k;
            finish[0] = (uint8_t)((m - 3) >> 16); finish[1] = (uint8_t)((m - 3) >> 8); finish[2] = (uint8_t)(m - 3);
            if (!ws_send(finish, m)) return fail("RESULT: ClientFinish send failed", 0, 0);
        }
        io->t_finish = ms();
        wa_fmt(line, sizeof line, "noise: ClientFinish sent %T s after ServerHello (%u-byte ClientPayload)", ms() - t_hello, payload_len); logl(line);
    }
    msg_have = 0; msg_off = 0;
    {
        int r = recv_frame(20000, plain, plain_len);
        if (r == 0) { wa_fmt(io->result, sizeof io->result, "RESULT: handshake REJECTED (no encrypted frame after ClientFinish, gap %T s)", io->gap_ms); return 0; }
        if (r < 0) return fail("RESULT: first server frame rejected (see log)", 0, 0);
        wa_fmt(line, sizeof line, "noise: first encrypted server frame: %u bytes ciphertext -> %u bytes plaintext, first bytes %02x %02x %02x %02x (binary node)",
               *plain_len + 16, *plain_len, (uint32_t)plain[0], (uint32_t)plain[1], (uint32_t)plain[2], (uint32_t)plain[3]); logl(line);
    }
    io->t_accepted = ms();
    return 1;
}

/* ---- pairing session ----------------------------------------------------------------------------- */
static uint8_t arena_mem[12288]; static wab_arena arena;   /* post-login stanzas (inflated) are larger than the pairing IQs */
static uint8_t refbuf[WA_QR_REFS_MAX][128]; static uint32_t reflen[WA_QR_REFS_MAX], nrefs;
static char qr_text[WA_PAIR_QR_MAX]; static qr qr_code; static qr_work qr_scratch;
static uint32_t iq_counter; static char iq_prefix[16];

static void close_ws(void) { uint8_t cl[16]; uint32_t n = ws_frame_close(&w, 1000, cl, sizeof cl); if (n) app_send(cl, n); }

/* one binary node, encrypted with the transport keys: 3-byte length + ciphertext */
static int send_node(const wab_node *n, const char *what)
{
    static uint8_t pt[2048], ct[2048 + 16 + 3]; uint32_t len; int e;
    e = wab_encode_frame(n, pt, sizeof pt, &len);
    if (e != WAB_OK) { wa_fmt(line, sizeof line, "wab: encoding %s failed: %s", what, wab_errstr(e)); logl(line); return 0; }
    noise_transport_encrypt(&tr, pt, len, ct + 3);
    ct[0] = (uint8_t)((len + 16) >> 16); ct[1] = (uint8_t)((len + 16) >> 8); ct[2] = (uint8_t)(len + 16);
    if (io->debug) { wa_fmt(line, sizeof line, "  send %s, %u bytes node:", what, len); log_hex(line, pt, len < 64 ? len : 64); }
    return ws_send(ct, len + 16 + 3);
}

/* next WA frame: 1 = decrypted into plain (*plen), 0 = nothing within timeout_ms, -1 = connection gone or a malformed
 * frame. A WebSocket message holds one or more frames (3-byte big-endian length each; the server sends e.g.
 * <stream:error code=515> and <xmlstreamend> in one message), so the frames not taken yet are served first. */
static int recv_frame(uint32_t timeout_ms, uint8_t *plain, uint32_t *plen)
{
    uint32_t flen;
    if (!msg_have) {
        pump_quiet = 1;
        if (!pump(-1, 1, timeout_ms)) { pump_quiet = 0; return w.state == WS_CLOSED || w.state == WS_ERROR || t.error ? -1 : 0; }
        pump_quiet = 0;
        w.msg_ready = 0; msg_off = 0; msg_have = 1;
        if (io->debug && w.msg_len) { wa_fmt(line, sizeof line, "  ws message %u bytes", w.msg_len); logl(line); }
    }
    if (w.msg_len - msg_off < 3 + 16) { logl("wab: bad encrypted frame (short)"); msg_have = 0; return -1; }
    flen = ((uint32_t)w.msg[msg_off] << 16) | ((uint32_t)w.msg[msg_off + 1] << 8) | w.msg[msg_off + 2];
    if (flen < 16 || flen > w.msg_len - msg_off - 3 || flen - 16 > WA_PROBE_MSG_MAX) { wa_fmt(line, sizeof line, "wab: bad encrypted frame (length %u in a %u-byte message at %u)", flen, w.msg_len, msg_off); logl(line); msg_have = 0; return -1; }
    if (!noise_transport_decrypt(&tr, w.msg + msg_off + 3, flen, plain)) { logl("wab: frame does not decrypt"); msg_have = 0; return -1; }
    *plen = flen - 16;
    msg_off += 3 + flen;
    if (msg_off >= w.msg_len) msg_have = 0;
    else { wa_fmt(line, sizeof line, "ws: %u more bytes of frames in this message", w.msg_len - msg_off); logl(line); }
    return 1;
}

static void log_node(const char *prefix, const wab_node *n)
{
    uint32_t o = wa_fmt(line, sizeof line, "%s<", prefix), i;
    for (i = 0; i < n->tag.len && o + 1 < sizeof line; i++) line[o++] = (char)n->tag.p[i];
    for (i = 0; i < n->n_attrs && o + 4 < sizeof line; i++) {
        const wab_attr *a = &n->attrs[i]; uint32_t k;
        line[o++] = ' ';
        for (k = 0; k < a->key.len && o + 3 < sizeof line; k++) line[o++] = (char)a->key.p[k];
        line[o++] = '=';
        if (a->val.kind == WAB_JID) { for (k = 0; k < a->val.jid.user.len && o + 2 < sizeof line; k++) line[o++] = (char)a->val.jid.user.p[k];
                                      if (a->val.jid.device) o += wa_fmt(line + o, sizeof line - o, ":%u", (uint32_t)a->val.jid.device);
                                      line[o++] = '@'; for (k = 0; k < a->val.jid.server.len && o + 2 < sizeof line; k++) line[o++] = (char)a->val.jid.server.p[k]; }
        else for (k = 0; k < a->val.str.len && o + 2 < sizeof line; k++) line[o++] = a->val.str.p[k] >= 32 && a->val.str.p[k] < 127 ? (char)a->val.str.p[k] : '.';
    }
    o += wa_fmt(line + o, sizeof line - o, n->val.kind == WAB_LIST ? "> [%u children]" : n->val.kind == WAB_BYTES ? "> [%u bytes]" : ">", n->val.kind == WAB_LIST ? n->n_children : n->val.str.len);
    line[o] = 0;
    logl(line);
}

/* decode a decrypted frame into the arena; 0 on error (logged) */
static const wab_node *decode(const uint8_t *plain, uint32_t plen)
{
    const wab_node *n; int e;
    wab_arena_init(&arena, arena_mem, sizeof arena_mem);
    if (plen && (plain[0] & WAB_FLAG_COMPRESSED)) {
        /* whatsmeow message.go: flags bit 1 = the node is a zlib stream (proto/inflate.c) */
        static uint8_t inflated[WA_PROBE_MSG_MAX]; uint32_t ilen = 0, t0 = ms();
        e = wa_inflate(plain + 1, plen - 1, inflated, sizeof inflated, &ilen);
        if (e != WA_INFLATE_OK) { wa_fmt(line, sizeof line, "wab: compressed frame: %s (%u bytes in, %u out)", wa_inflate_errstr(e), plen - 1, ilen); logl(line); return 0; }
        wa_fmt(line, sizeof line, "wab: inflated %u -> %u bytes in %T s", plen - 1, ilen, ms() - t0); logl(line);
        e = wab_decode_node(inflated, ilen, &arena, &n);
    } else e = wab_decode_frame(plain, plen, &arena, &n);
    if (e != WAB_OK) { wa_fmt(line, sizeof line, "wab: %s (flags %02x, %u bytes)", wab_errstr(e), (uint32_t)plain[0], plen); logl(line); return 0; }
    log_node("recv: ", n);
    return n;
}

static const char *attr_cstr(const wab_node *n, const char *key, char *buf, uint32_t cap)
{
    const wab_value *v = wab_get_attr(n, key); uint32_t i, l, o = 0;
    if (!v) return "";
    if (v->kind == WAB_JID) {
        for (i = 0; i < v->jid.user.len && o + 2 < cap; i++) buf[o++] = (char)v->jid.user.p[i];
        if (v->jid.device) o += wa_fmt(buf + o, cap - o, ":%u", (uint32_t)v->jid.device);
        if (o + 2 < cap) buf[o++] = '@';
        for (i = 0; i < v->jid.server.len && o + 1 < cap; i++) buf[o++] = (char)v->jid.server.p[i];
        buf[o] = 0;
        return buf;
    }
    if (v->kind != WAB_STR) return "";
    l = v->str.len < cap - 1 ? v->str.len : cap - 1;
    for (i = 0; i < l; i++) buf[i] = (char)v->str.p[i];
    buf[l] = 0;
    return buf;
}

/* request ids like whatsmeow's uniqueID + counter */
static void next_iq_id(char *id, uint32_t cap)
{
    if (!iq_prefix[0]) { uint8_t r[2]; drbg_generate(&rng, r, 2); wa_fmt(iq_prefix, sizeof iq_prefix, "%u.%u-", (uint32_t)r[0], (uint32_t)r[1]); }
    wa_fmt(id, cap, "%s%u", iq_prefix, ++iq_counter);
}

/* <iq id xmlns type to=s.whatsapp.net><child/></iq> */
static int send_iq1(const char *id, const char *xmlns, const char *type, const char *child_tag, const char *what)
{
    static wab_node iq, child; static wab_attr a[4];
    wab_node_init(&iq, "iq"); wab_node_init(&child, child_tag);
    a[0].key = wab_s("id"); a[0].val = wab_text(id);
    a[1].key = wab_s("xmlns"); a[1].val = wab_text(xmlns);
    a[2].key = wab_s("type"); a[2].val = wab_text(type);
    a[3].key = wab_s("to"); a[3].val = wab_jid_value("", WA_SERVER_JID, 0);
    iq.attrs = a; iq.n_attrs = 4; iq.val.kind = WAB_LIST; iq.children = &child; iq.n_children = 1;
    return send_node(&iq, what);
}

/* whatsmeow keepAliveLoop: <iq id=.. xmlns=w:p type=get to=s.whatsapp.net><ping/></iq> every 20-30 s */
static int send_keepalive(void)
{
    static char id[32];
    next_iq_id(id, sizeof id);
    return send_iq1(id, "w:p", "get", "ping", "keepalive ping");
}

/* whatsmeow sendAck (receipt.go): <ack class=tag id to=from [participant] [type]/> for receipts and notifications.
 * Messages are not acknowledged: there is no Signal session layer yet, so the server keeps them for a later client. */
static int send_ack(const wab_node *n)
{
    static wab_node ack; static wab_attr a[5]; uint32_t k = 0;
    const wab_value *id = wab_get_attr(n, "id"), *from = wab_get_attr(n, "from"), *part = wab_get_attr(n, "participant"), *type = wab_get_attr(n, "type");
    if (!id || !from) return 1;
    wab_node_init(&ack, "ack");
    a[k].key = wab_s("class"); a[k].val.kind = WAB_STR; a[k].val.str = n->tag; a[k].val.str.form = WAB_F_AUTO; k++;
    a[k].key = wab_s("id"); a[k].val = *id; k++;
    a[k].key = wab_s("to"); a[k].val = *from; k++;
    if (part) { a[k].key = wab_s("participant"); a[k].val = *part; k++; }
    if (type && !wab_str_eq(&n->tag, "message")) { a[k].key = wab_s("type"); a[k].val = *type; k++; }
    ack.attrs = a; ack.n_attrs = k;
    io->acks_sent++;
    return send_node(&ack, "ack");
}

/* one decoded node from the server; 0 = nothing within timeout_ms (or a malformed frame, logged) or *gone = 1 */
static const wab_node *recv_node(uint32_t timeout_ms, int *gone)
{
    static uint8_t plain[WA_PROBE_MSG_MAX]; uint32_t plen; int r = recv_frame(timeout_ms, plain, &plen);
    *gone = 0;
    if (r < 0) { *gone = 1; return 0; }
    if (r == 0) return 0;
    io->frames_after_login++;
    return decode(plain, plen);
}

/* a server stanza that arrives while we wait for something else; 1 = keep going, 0 = the stream ended */
static int handle_async(const wab_node *n)
{
    if (wab_str_eq(&n->tag, "stream:error") || wab_str_eq(&n->tag, "xmlstreamend") || wab_str_eq(&n->tag, "failure")) { logl("login: the server ended the stream"); return 0; }
    if (wab_str_eq(&n->tag, "receipt") || wab_str_eq(&n->tag, "notification")) return send_ack(n);
    if (wab_str_eq(&n->tag, "message")) { io->messages_seen++; logl("login: an encrypted message waits for us (left unacknowledged: no Signal session layer yet)"); }
    if (wab_str_eq(&n->tag, "ib") && n->val.kind == WAB_LIST) { uint32_t i; for (i = 0; i < n->n_children; i++) log_node("  ib: ", &n->children[i]); }
    return 1;                                   /* ib (offline_preview, offline, dirty, edge_routing), iq from the server, ...: logged only */
}

/* the result of our IQ `id`; other stanzas in between are handled; 0 = none within timeout_ms or the stream ended */
static const wab_node *wait_result(const char *id, uint32_t timeout_ms)
{
    uint32_t deadline = ms() + timeout_ms;
    for (;;) {
        int gone; const wab_node *n; uint32_t now = ms();
        if (now >= deadline) return 0;
        n = recv_node(deadline - now, &gone);
        if (gone) return 0;
        if (!n) continue;
        if (wab_str_eq(&n->tag, "iq")) {
            const wab_value *v = wab_get_attr(n, "id");
            if (v && v->kind == WAB_STR && wab_str_eq(&v->str, id)) return n;
            continue;
        }
        if (!handle_async(n)) return 0;
    }
}

static uint32_t dec_value(const wab_value *v)
{
    uint32_t i, r = 0;
    if (!v || v->kind != WAB_STR) return 0;
    for (i = 0; i < v->str.len; i++) { if (v->str.p[i] < '0' || v->str.p[i] > '9') break; r = r * 10 + (uint32_t)(v->str.p[i] - '0'); }
    return r;
}

static int iq_is_result(const wab_node *r) { const wab_value *ty = r ? wab_get_attr(r, "type") : 0; return ty && ty->kind == WAB_STR && wab_str_eq(&ty->str, "result"); }

/* after <success>: whatsmeow handleConnectSuccess - prekey count, upload when the server runs low, <active/>, then
 * linger_ms online (receipts and notifications acknowledged, keepalive every 25 s), then close. 1 = done. */
static int post_login(void)
{
    char id[32]; const wab_node *r; uint32_t t_end, last_ka; int gone;
    /* 1. how many one-time prekeys of ours does the server hold */
    next_iq_id(id, sizeof id);
    if (!send_iq1(id, "encrypt", "get", "count", "prekey count query")) return fail("RESULT: logged in, but sending the prekey count query failed", 0, 0);
    r = wait_result(id, 30000);
    if (!r) return fail("RESULT: logged in, but no answer to the prekey count query", 0, 0);
    { const wab_node *c = wab_get_child(r, "count"); io->have_server_prekeys = c != 0; io->server_prekeys = c ? dec_value(wab_get_attr(c, "value")) : 0; }
    wa_fmt(line, sizeof line, "login: the server holds %u one-time prekeys of ours (whatsmeow uploads below %u)", io->server_prekeys, (uint32_t)WA_PREKEYS_MIN_SERVER); logl(line);
    /* 2. upload the pending batch when the server runs low */
    if (io->prekeys && io->have_server_prekeys && io->server_prekeys < WA_PREKEYS_MIN_SERVER && wa_prekeys_pending(io->prekeys)) {
        static wa_prekey_upload up; uint32_t n; const wab_node *iq;
        next_iq_id(id, sizeof id);
        iq = wa_prekeys_upload_node(&up, id, &io->creds->id, io->prekeys, &n);
        if (!send_node(iq, "prekey upload")) return fail("RESULT: logged in, but sending the prekey upload failed", 0, 0);
        r = wait_result(id, 30000);
        if (!iq_is_result(r)) return fail("RESULT: logged in, but the prekey upload was not accepted (see recv: line)", 0, 0);
        wa_prekeys_mark_uploaded(io->prekeys); io->prekeys_uploaded = n;
        if (io->save_prekeys) io->save_prekeys(io->ctx);
        wa_fmt(line, sizeof line, "login: %u one-time prekeys uploaded and accepted (registration id %u, signed prekey id %u)", n, io->creds->id.reg_id, io->creds->id.spk_id); logl(line);
    }
    /* 3. passive -> active */
    next_iq_id(id, sizeof id);
    if (!send_iq1(id, "passive", "set", "active", "passive/active")) return fail("RESULT: logged in, but sending <active/> failed", 0, 0);
    r = wait_result(id, 30000);
    if (!iq_is_result(r)) return fail("RESULT: logged in, but <active/> was not accepted (see recv: line)", 0, 0);
    io->active_set = 1; io->t_active = ms();
    wa_fmt(line, sizeof line, "login: <active/> accepted %T s after <success>; staying online for %T s", io->t_active - io->t_login_accepted, io->linger_ms); logl(line);
    /* 4. linger */
    t_end = ms() + io->linger_ms; last_ka = ms();
    while (ms() < t_end) {
        const wab_node *n; uint32_t now = ms(), left = t_end - now;
        if (now - last_ka >= 25000) { if (!send_keepalive()) break; last_ka = now; }
        n = recv_node(left < 1000 ? left : 1000, &gone);
        if (gone) { logl("login: connection closed by the server"); break; }
        if (n && !handle_async(n)) break;
    }
    close_ws();
    return 1;
}

static const char *post_summary(void)
{
    static char s[120];
    wa_fmt(s, sizeof s, "; server prekeys %u + %u uploaded, %s, %u stanzas, %u acks%s", io->server_prekeys, io->prekeys_uploaded,
           io->active_set ? "active" : "not active", io->frames_after_login, io->acks_sent, io->messages_seen ? ", messages waiting" : "");
    return s;
}

static int take_refs(const wab_node *iq)
{
    wab_str refs[WA_QR_REFS_MAX]; uint32_t i, n = wa_pair_refs(iq, refs, WA_QR_REFS_MAX);
    nrefs = 0;
    for (i = 0; i < n; i++) { if (refs[i].len > sizeof refbuf[0]) continue; cp(refbuf[nrefs], refs[i].p, refs[i].len); reflen[nrefs++] = refs[i].len; }
    return nrefs != 0;
}

static int show_code(uint32_t index)
{
    uint32_t tl = wa_pair_qr_text(qr_text, sizeof qr_text, refbuf[index], reflen[index], &io->creds->id), t0 = ms();
    if (!tl) return fail("RESULT: QR text does not fit", 0, 0);
    if (qr_encode_ex(&qr_code, &qr_scratch, (const uint8_t *)qr_text, tl, QR_ECC_L, 1, io->qr_mask) != 0) return fail("RESULT: QR encoding failed", 0, 0);
    wa_fmt(line, sizeof line, "qr: code %u/%u, %u chars -> version %u, %u x %u modules, mask %u, encoded in %T s", index + 1, nrefs, tl,
           (uint32_t)qr_code.version, (uint32_t)qr_code.size, (uint32_t)qr_code.size, (uint32_t)qr_code.mask, ms() - t0); logl(line);
    return 1;
}

/* the first frame of a login connection must be <success>; anything else ends the session */
static int expect_success(const uint8_t *plain, uint32_t plen)
{
    const wab_node *n = decode(plain, plen); char b1[48], b2[48];
    if (!n) return fail("RESULT: login: first frame undecodable", 0, 0);
    if (wab_str_eq(&n->tag, "success")) {
        io->logged_in = 1; io->t_login_accepted = ms();
        wa_fmt(line, sizeof line, "login: <success> - logged in as %s:%u@%s (lid %s, server time %s)", io->creds->jid_user, io->creds->jid_device, WA_SERVER_JID,
               attr_cstr(n, "lid", b1, sizeof b1), attr_cstr(n, "t", b2, sizeof b2)); logl(line);
        return 1;
    }
    if (wab_str_eq(&n->tag, "failure") || wab_str_eq(&n->tag, "stream:error")) {
        const wab_node *c = n->val.kind == WAB_LIST && n->n_children ? &n->children[0] : 0;
        wa_fmt(io->result, sizeof io->result, "RESULT: login REJECTED: <%s%s reason/code %s%s%s>", wab_str_eq(&n->tag, "failure") ? "failure" : "stream:error",
               "", attr_cstr(n, "reason", b1, sizeof b1), attr_cstr(n, "code", b2, sizeof b2), c ? " (child present)" : "");
        return 0;
    }
    return fail("RESULT: login: unexpected first frame (see recv: line)", 0, 0);
}

/* after the handshake with the registration payload: pair-device -> QR codes -> pair-success -> pair-device-sign
 * -> stream:error 515 -> ONE reconnect with the login payload -> <success>. No retry loop anywhere. */
static int pair_session(uint8_t *plain, uint32_t plen)
{
    static wa_pair_reply reply; static heartbeat hb; static wa_adv_identity adv; static wa_pair_success ps;
    static uint8_t self_signed[512], rnd[64];
    const wab_node *n; int r, scanned = 0; uint32_t idx = 0, sl, first_ms = io->qr_first_ms ? io->qr_first_ms : 60000, next_ms = io->qr_next_ms ? io->qr_next_ms : 20000;

    /* 1. the pair-device IQ (the first frame, as a rule) */
    n = decode(plain, plen);
    if (!n) return fail("RESULT: first frame undecodable", 0, 0);
    while (!take_refs(n)) {
        logl("pair: not a pair-device IQ, waiting for one");
        r = recv_frame(20000, plain, &plen);
        if (r <= 0) return fail(r ? "RESULT: connection lost before pair-device" : "RESULT: no pair-device IQ within 20 s", 0, 0);
        n = decode(plain, plen);
        if (!n) return fail("RESULT: frame undecodable", 0, 0);
    }
    {   const wab_value *idv = wab_get_attr(n, "id");
        if (!idv) return fail("RESULT: pair-device IQ without id", 0, 0);
        if (!send_node(wa_pair_ack_node(&reply, &idv->str), "pair-device ack")) return fail("RESULT: ack send failed", 0, 0); }
    wa_fmt(line, sizeof line, "pair: %u refs received, ack sent; showing code 1 for %T s, then %T s each", nrefs, first_ms, next_ms); logl(line);

    /* 2. show codes, wait for the phone */
    while (idx < nrefs && !scanned) {
        uint32_t valid = idx == 0 ? first_ms : next_ms, shown, last_pong, last_ping;
        if (!show_code(idx)) return 0;
        shown = ms(); last_pong = shown; last_ping = shown;
        if (!io->t_qr_shown) io->t_qr_shown = shown;
        io->qr_shown++;
        if (io->show_qr) io->show_qr(io->ctx, qr_text, &qr_code, valid, idx + 1, nrefs);
        for (;;) {
            uint32_t now = ms(), slice;
            if (now - shown >= valid) break;
            slice = valid - (now - shown); if (slice > 1000) slice = 1000;
            r = recv_frame(slice, plain, &plen);
            if (r < 0) { if (io->qr_hide) io->qr_hide(io->ctx, "connection lost"); return fail("RESULT: connection lost while showing code %u", 0, idx + 1); }
            if (r == 0) {
                now = ms();
                if (io->qr_tick) io->qr_tick(io->ctx, valid - (now - shown));
                if (now - last_pong >= 4000) { uint8_t pf[16]; uint32_t pn = ws_frame_pong(&w, pf, sizeof pf); if (!pn || !app_send(pf, pn)) return fail("RESULT: pong send failed", 0, 0); last_pong = now; io->pongs++; }
                if (now - last_ping >= 25000) { if (!send_keepalive()) return fail("RESULT: keepalive send failed", 0, 0); last_ping = now; }
                continue;
            }
            n = decode(plain, plen);
            if (!n) continue;
            if (wab_str_eq(&n->tag, "iq") && wab_get_child(n, "pair-success")) { scanned = 1; break; }
            if (wab_str_eq(&n->tag, "iq") && wab_get_child(n, "pair-device")) {
                const wab_value *idv = wab_get_attr(n, "id");
                if (take_refs(n) && idv) { send_node(wa_pair_ack_node(&reply, &idv->str), "pair-device ack"); idx = 0; logl("pair: new refs from the server, starting over with code 1"); goto next_code; }
            }
            if (wab_str_eq(&n->tag, "stream:error")) { if (io->qr_hide) io->qr_hide(io->ctx, "stream error"); return fail("RESULT: stream:error while showing the code (see recv: line)", 0, 0); }
            if (wab_str_eq(&n->tag, "ib")) { logl("pair: <ib> from the server (downgrade_webclient = phone without multi-device?)"); }
            /* iq results (keepalive answers) and anything else: ignored */
        }
        if (!scanned) idx++;
next_code: ;
    }
    if (!scanned) {
        if (io->qr_hide) io->qr_hide(io->ctx, "no scan, codes exhausted");
        close_ws();
        wa_fmt(io->result, sizeof io->result, "RESULT: not scanned: %u codes shown over %T s, connection closed (no reconnect)", io->qr_shown, ms() - io->t_qr_shown);
        return 0;
    }

    /* 3. pair-success: verify, sign, answer */
    io->t_pair_success = ms();
    if (io->qr_hide) io->qr_hide(io->ctx, "code scanned - verifying the phone's signature");
    wa_fmt(line, sizeof line, "pair: pair-success %T s after the first code (code %u shown %T s ago)", io->t_pair_success - io->t_qr_shown, idx + 1, 0u); logl(line);
    if (!wa_pair_parse_success(n, &ps)) { send_node(wa_pair_error_node(&reply, &ps.id, 500, "internal-error"), "pair error"); close_ws(); return fail("RESULT: pair-success without device-identity / jid", 0, 0); }
    /* copy what the arena holds before anything else is decoded */
    if (!wa_creds_set_user(io->creds->jid_user, ps.jid.user.p, ps.jid.user.len)) { close_ws(); return fail("RESULT: JID user not numeric or too long", 0, 0); }
    io->creds->jid_device = ps.jid.device;
    if (ps.have_lid) { wa_creds_set_user(io->creds->lid_user, ps.lid.user.p, ps.lid.user.len); io->creds->lid_device = ps.lid.device; }
    { uint32_t i; for (i = 0; i < ps.platform.len && i < WA_CREDS_NAME_MAX - 1; i++) io->creds->platform[i] = (char)ps.platform.p[i]; io->creds->platform[i] = 0;
      for (i = 0; i < ps.biz.len && i < WA_CREDS_BIZ_MAX - 1; i++) io->creds->business[i] = (char)ps.biz.p[i]; io->creds->business[i] = 0; }
    wa_fmt(line, sizeof line, "pair: our JID %s:%u@%s, lid %s:%u, phone platform \"%s\"%s%s", io->creds->jid_user, io->creds->jid_device, WA_SERVER_JID, io->creds->lid_user, io->creds->lid_device,
           io->creds->platform, io->creds->business[0] ? ", business " : "", io->creds->business); logl(line);
    heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0);
    heartbeat_arm(&hb);
    {   uint32_t t0 = ms(), e;
        e = wa_pair_verify(ps.device_identity, ps.device_identity_len, &io->creds->id, &adv);
        io->d_verify = ms() - t0;
        wa_fmt(line, sizeof line, "pair: device identity %u bytes: HMAC under the ADV secret and account signature (XEdDSA) %s in %T s%s", ps.device_identity_len,
               e == WA_PAIR_OK ? "VERIFIED" : "REJECTED", io->d_verify, e == WA_PAIR_OK ? "" : ""); logl(line);
        if (e != WA_PAIR_OK) { wa_fmt(line, sizeof line, "pair: reason: %s", wa_pair_errstr((int)e)); logl(line); }
        if (e != WA_PAIR_OK) {
            heartbeat_disarm();
            send_node(wa_pair_error_node(&reply, &ps.id, e == WA_PAIR_ERR_HMAC ? 401 : e == WA_PAIR_ERR_SIG ? 401 : 500,
                                         e == WA_PAIR_ERR_HMAC ? "hmac-mismatch" : e == WA_PAIR_ERR_SIG ? "signature-mismatch" : "internal-error"), "pair error");
            close_ws();
            return fail("RESULT: pair-success REJECTED (%s), connection closed", wa_pair_errstr((int)e), 0);
        }
        wa_fmt(line, sizeof line, "pair: account type %u, device type %u, key index %u, raw id %u", (uint32_t)adv.account_type, (uint32_t)adv.device_type, adv.key_index, adv.raw_id); logl(line);
        t0 = ms();
        drbg_generate(&rng, rnd, 64);
        wa_pair_sign(&adv, &io->creds->id, rnd);
        io->d_sign = ms() - t0;
        wa_fmt(line, sizeof line, "pair: device signature (XEdDSA over 06 01 || details || identityPub || accountKey) in %T s, %u pongs during verify + sign", io->d_sign, hb.sent); logl(line);
    }
    heartbeat_disarm(); io->pongs += hb.sent;
    if (hb.error) return fail("RESULT: heartbeat send failed during the signature", 0, 0);
    sl = wa_pair_self_signed(self_signed, sizeof self_signed, &adv);
    if (!sl || !send_node(wa_pair_sign_node(&reply, &ps.id, adv.key_index, self_signed, sl), "pair-device-sign")) return fail("RESULT: pair-device-sign send failed", 0, 0);
    io->t_sign_sent = ms();
    io->creds->adv = adv; io->creds->paired = 1; io->paired_now = 1;
    if (io->save_creds) io->save_creds(io->ctx);
    wa_fmt(line, sizeof line, "pair: pair-device-sign sent %T s after pair-success (verify %T s + sign %T s); credentials complete", io->t_sign_sent - io->t_pair_success, io->d_verify, io->d_sign); logl(line);

    /* 4. the server answers with stream:error 515 and closes */
    for (;;) {
        r = recv_frame(30000, plain, &plen);
        if (r == 0) { logl("pair: no stream:error within 30 s of pair-device-sign, closing ourselves"); break; }
        if (r < 0) { logl("pair: server closed the connection (expected after pair-device-sign)"); break; }
        n = decode(plain, plen);
        if (n && wab_str_eq(&n->tag, "stream:error")) { char b[16]; io->t_515 = ms(); wa_fmt(line, sizeof line, "pair: stream:error code %s %T s after pair-device-sign: restart requested", attr_cstr(n, "code", b, sizeof b), io->t_515 - io->t_sign_sent); logl(line); break; }
    }
    close_ws();
    if (!io->reconnect) return fail("RESULT: paired, but no reconnect callback for the login connection", 0, 0);
    /* 5. the login connection: fresh TLS and Noise ephemeral keys (no server timer runs while we are disconnected) */
    { uint32_t t0 = ms(); if (!connection_keys()) return 0; wa_fmt(line, sizeof line, "login: new TLS + Noise ephemeral key pairs in %T s", ms() - t0); logl(line); }
    if (!io->reconnect(io->ctx)) return fail("RESULT: paired, but the TCP reconnect for the login failed", 0, 0);
    io->t_login_connect = ms();
    logl("login: TCP connected again, handshake with the login ClientPayload");
    {   static uint8_t payload[WA_CLIENTPAYLOAD_MAX]; uint32_t pl = wa_clientpayload_login(payload, sizeof payload, io->creds->jid_user, io->creds->jid_device);
        if (!pl) return fail("RESULT: login payload failed", 0, 0);
        if (!handshake(payload, pl, plain, &plen)) return 0; }
    r = expect_success(plain, plen);
    if (r) r = post_login(); else close_ws();
    if (r) wa_fmt(io->result, sizeof io->result, "RESULT: PAIRED and LOGGED IN as %s:%u (scan -> sign %T s, login connection %T s)%s", io->creds->jid_user, io->creds->jid_device,
                  io->t_sign_sent - io->t_pair_success, io->t_login_accepted - io->t_login_connect, post_summary());
    return r;
}

int wa_probe_run(wa_probe_io *pio)
{
    static uint8_t plain[WA_PROBE_MSG_MAX], payload[WA_CLIENTPAYLOAD_MAX];
    const uint8_t *pp = wa_client_payload; uint32_t pl = sizeof wa_client_payload, plen = 0;

    if (!prepared || io != pio) { if (!wa_probe_prepare(pio)) return 0; }
    prepared = 0;                               /* key pairs are used once */
    io = pio; t_start = io->now_ms(); pend_len = 0;
    io->t_tls = io->t_ws = io->t_hello = io->t_finish = io->t_accepted = 0; io->pongs = io->ladders = 0; io->result[0] = 0;
    io->paired_now = io->logged_in = 0; io->t_qr_shown = io->t_pair_success = io->d_verify = io->d_sign = io->t_sign_sent = io->t_515 = io->t_login_connect = io->t_login_accepted = 0; io->qr_shown = 0;
    io->server_prekeys = io->prekeys_uploaded = io->t_active = io->frames_after_login = io->acks_sent = io->messages_seen = 0; io->have_server_prekeys = io->active_set = 0;
    iq_counter = 0; iq_prefix[0] = 0;

    if (io->mode == WA_MODE_PAIR) {
        if (io->creds->paired) pl = wa_clientpayload_login(payload, sizeof payload, io->creds->jid_user, io->creds->jid_device);
        else pl = wa_clientpayload_registration(payload, sizeof payload, &io->creds->id);
        if (!pl) return fail("RESULT: ClientPayload failed", 0, 0);
        pp = payload;
        wa_fmt(line, sizeof line, "payload: %s ClientPayload, %u bytes", io->creds->paired ? "login" : "registration", pl); logl(line);
    }
    if (!handshake(pp, pl, plain, &plen)) return 0;
    if (!io->tunnel && t.tickets) { io->tls_tickets = t.tickets; wa_fmt(line, sizeof line, "tls: %u NewSessionTicket(s) received - PSK resumption would skip the certificate chain and CertificateVerify (not implemented)", t.tickets); logl(line); }
    if (io->mode != WA_MODE_PAIR) {
        close_ws();
        wa_fmt(io->result, sizeof io->result, "RESULT: handshake ACCEPTED by %s with our %s/WS/Noise stack, %T s hold, %u pongs%s", io->host,
               io->tunnel ? "(openssl TLS 1.3 tunnel)" : "TLS 1.3", io->gap_ms, io->pongs, io->noise_cert_cached ? ", Noise cert cache hit" : "");
        return 1;
    }
    if (io->creds->paired && !io->paired_now) {
        int r = expect_success(plain, plen);
        if (r) r = post_login(); else close_ws();
        if (r) wa_fmt(io->result, sizeof io->result, "RESULT: LOGGED IN with the stored credentials as %s:%u (%T s since connect)%s", io->creds->jid_user, io->creds->jid_device, io->t_login_accepted, post_summary());
        return r;
    }
    return pair_session(plain, plen);
}

#ifdef WA_PROBE_SIM
/* Offline simulation entry points (tests/wa_pair_sim.c, make pair-sim): the transport is the caller's fake WebSocket
 * server, noise_transport_encrypt/decrypt are replaced by pass-through stubs at compile time, the TLS layer is skipped
 * (tunnel mode) and the Noise handshake is not run - everything from the first decrypted frame on is the real code. */
static void sim_open(wa_probe_io *pio)
{
    static uint8_t out[1024]; uint32_t i;
    io = pio; t_start = io->now_ms(); pend_len = 0; io->tunnel = 1; io->result[0] = 0; msg_have = 0; msg_off = 0;
    io->paired_now = io->logged_in = 0; io->pongs = 0; io->qr_shown = 0;
    io->t_qr_shown = io->t_pair_success = io->d_verify = io->d_sign = io->t_sign_sent = io->t_515 = io->t_login_connect = io->t_login_accepted = 0;
    io->server_prekeys = io->prekeys_uploaded = io->t_active = io->frames_after_login = io->acks_sent = io->messages_seen = 0; io->have_server_prekeys = io->active_set = 0;
    iq_counter = 0; iq_prefix[0] = 0;
    if (!rng.instantiated) drbg_instantiate(&rng, io->seed, io->seed_len);
    ws_client_start(&w, io->host, "/ws/chat", "https://web.whatsapp.com", msgbuf, sizeof msgbuf, &rng, out, sizeof out);
    w.state = WS_OPEN;
    for (i = 0; i < sizeof tr; i++) ((uint8_t *)&tr)[i] = 0;
}
int wa_probe_sim_pair(wa_probe_io *pio, const uint8_t *first_frame, uint32_t len)
{
    static uint8_t plain[WA_PROBE_MSG_MAX];
    sim_open(pio);
    cp(plain, first_frame, len);
    return pair_session(plain, len);
}
int wa_probe_sim_login(wa_probe_io *pio, const uint8_t *first_frame, uint32_t len)
{
    static uint8_t plain[WA_PROBE_MSG_MAX];
    int r;
    sim_open(pio);
    cp(plain, first_frame, len);
    r = expect_success(plain, len);
    if (r) r = post_login(); else close_ws();
    if (r) wa_fmt(io->result, sizeof io->result, "RESULT: LOGGED IN (sim)%s", post_summary());
    return r;
}
#endif
