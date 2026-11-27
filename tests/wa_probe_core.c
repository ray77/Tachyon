#include <stdarg.h>
#include "wa_probe_core.h"
#include "ws.h"
#include "noise.h"
#include "heartbeat.h"
#include "x25519.h"
#include "ed25519.h"
#include "certs/wa_rsa_chain.h"
#include "vectors/wa_client_payload.h"

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
static noise_cert_cache ncache;
static int prepared;

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
                if (!ws_input(&w, pend, 1, out, &ol, sizeof out)) { wa_fmt(line, sizeof line, "ws error, state %d", w.state); logl(line); return 0; }
                if (ol && !app_send(out, ol)) return 0;
                pend_len--; for (i = 0; i < pend_len; i++) pend[i] = pend[i + 1];
            }
            if (w.msg_ready) { if (io->debug) { wa_fmt(line, sizeof line, "  ws message %u bytes:", w.msg_len); log_hex(line, w.msg, w.msg_len < 4 ? w.msg_len : 4); } return 1; }
            if (w.state == WS_CLOSED) { wa_fmt(line, sizeof line, "server closed the WebSocket (code %u)", (uint32_t)w.close_code); logl(line); return 0; }
        }
        now = ms();
        if (now > deadline) { logl("timeout"); return 0; }
        r = io->recv(io->ctx, rdbuf, sizeof rdbuf, deadline - now);
        if (r == 0) { logl("timeout"); return 0; }
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

/* ---- protobuf (32-bit values suffice: field numbers, lengths, serials) -------------------------- */
static int pb_next(const uint8_t **pp, const uint8_t *end, uint32_t *field, uint32_t *wire, uint32_t *val, const uint8_t **data, uint32_t *len)
{
    const uint8_t *p = *pp; uint32_t tag = 0, v = 0; int sh = 0;
    if (p >= end) return 0;
    do { if (p >= end) return 0; if (sh < 32) tag |= (uint32_t)(*p & 0x7f) << sh; sh += 7; } while (*p++ & 0x80);
    *field = tag >> 3; *wire = tag & 7; *data = 0; *len = 0; *val = 0;
    if (*wire == 0) { sh = 0; do { if (p >= end) return 0; if (sh < 32) v |= (uint32_t)(*p & 0x7f) << sh; sh += 7; } while (*p++ & 0x80); *val = v; }
    else if (*wire == 2) { sh = 0; do { if (p >= end) return 0; if (sh < 32) v |= (uint32_t)(*p & 0x7f) << sh; sh += 7; } while (*p++ & 0x80);
                           if (v > (uint32_t)(end - p)) return 0; *data = p; *len = v; p += v; }
    else if (*wire == 1) { if (end - p < 8) return 0; p += 8; }
    else if (*wire == 5) { if (end - p < 4) return 0; p += 4; }
    else return 0;
    *pp = p; return 1;
}
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
    if (io->use_cache) tls13_set_cert_cache(&t, cache);
    tls13_add_pin(&t, inter->n, inter->n_len, inter->e);   /* pins: {G2 root, G2 TLS RSA 2020 CA1 intermediate} */
    if (!pump(TLS13_ST_CONNECTED, 0, 60000)) return fail("RESULT: TLS handshake failed", 0, 0);
    return 1;
}

/* Everything that needs no connection: the DRBG, the pinned TLS chain, the TLS 1.3 X25519 key pair and the two
 * Noise X25519 key pairs (static + ephemeral). On the A500 this is ~10 s of fixed-base comb multiplications that
 * used to sit inside the connected window; now the caller runs it before the TCP connect. */
int wa_probe_prepare(wa_probe_io *pio)
{
    uint32_t t0;
    io = pio; t_start = io->now_ms(); prepared = 0;
    io->t_tls_key = io->t_noise_keys = 0; io->result[0] = 0;
    io->noise_cert_cached = 0; io->noise_cache_valid = 0;
    if (!io->seed || io->seed_len < 32) return fail("RESULT: no seed", 0, 0);
    rng.instantiated = 0; drbg_instantiate(&rng, io->seed, io->seed_len);
    if (!x509_parse(&root, wa_cert2, sizeof wa_cert2) || !x509_parse(&inter, wa_cert1, sizeof wa_cert1)) return fail("RESULT: root/intermediate parse failed", 0, 0);
    /* the stored fingerprint of WhatsApp's intermediate Noise certificate, if the caller kept one */
    ncache.valid = 0;
    if (io->noise_cache_in) { cp(ncache.fp, io->noise_cache_in, 32); ncache.valid = 1; }
    t0 = ms();
    if (!tls13_keypair_generate(&kp, &rng)) return fail("RESULT: keypair failed", 0, 0);
    io->t_tls_key = ms() - t0;
    wa_fmt(line, sizeof line, "tls: X25519 key pair ready (%T s, before the connection)", io->t_tls_key); logl(line);
    t0 = ms();
    drbg_generate(&rng, eph_priv, 32); drbg_generate(&rng, st_priv, 32);
    x25519_base_comb(st_pub, st_priv);
    x25519_base_comb(eph_pub, eph_priv);
    io->t_noise_keys = ms() - t0;
    wa_fmt(line, sizeof line, "noise: static + ephemeral X25519 key pairs ready (%T s, before the connection)", io->t_noise_keys); logl(line);
    prepared = 1;
    return 1;
}

int wa_probe_run(wa_probe_io *pio)
{
    static uint8_t out[4096];
    static uint8_t server_eph[32], server_static[32], server_static_ct[64], cert_ct[4096], cert_pt[4096];
    static uint8_t cstatic_ct[48], payload_ct[1024], finish[2048], inner[2048], plain[WA_PROBE_MSG_MAX];
    static noise_hs hs; static noise_transport tr; static heartbeat hb; static x509_cache cache;
    uint32_t server_static_ct_len = 0, cert_ct_len = 0, n, ladders = 0;
    const uint8_t *p, *end, *d; uint32_t f, wire, l, v;

    if (!prepared || io != pio) { if (!wa_probe_prepare(pio)) return 0; }
    prepared = 0;                               /* key pairs are used once */
    io = pio; t_start = io->now_ms(); pend_len = 0;
    io->t_tls = io->t_ws = io->t_hello = io->t_finish = io->t_accepted = 0; io->pongs = io->ladders = 0; io->result[0] = 0;

    if (!io->tunnel) {
        /* use_cache: a first connection fills the certificate cache (full chain verification), then the real one
         * must hit it and skip the chain - as a second A500 session would after storing the entry in ENVARC: */
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
        }
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
     * come from wa_probe_prepare */
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
        wa_fmt(line, sizeof line, "noise: holding ClientFinish for %T s of X25519 ladders, pong heartbeat every 4 s", io->gap_ms); logl(line);
        spin_ladders(io->gap_ms, &ladders);
        /* the real work (the A500 does this inside the gap; here it takes milliseconds) */
        if (!noise_client_finish(&hs, eph_priv, st_priv, st_pub, server_eph, server_static_ct, 48, cert_ct, cert_ct_len,
                                 wa_client_payload, sizeof wa_client_payload, server_static, cert_pt, cstatic_ct, payload_ct, &tr)) {
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
            ok = leaf.issuer_serial == interc.serial && xeddsa_verify(leaf.sig, leaf.details, leaf.details_len, interc.key);
            ok = ok && eq(leaf.key, server_static, 32);
            wa_fmt(line, sizeof line, "noise: leaf certificate serial %u signed by the intermediate, key == server static: %s", leaf.serial, ok ? "VERIFIED" : "FAILED"); logl(line);
            if (!ok) { heartbeat_disarm(); return fail("RESULT: leaf certificate rejected", 0, 0); }
        }
        heartbeat_disarm();
        io->pongs = hb.sent; io->ladders = ladders;
        wa_fmt(line, sizeof line, "noise: %u X25519 ladders during the hold, %u pongs sent, heartbeat error %d", ladders, hb.sent, hb.error); logl(line);
        if (hb.error) return fail("RESULT: heartbeat send failed", 0, 0);
        /* ClientFinish: 3-byte length + HandshakeMessage{clientFinish(4){static(1)=48, payload(2)=ct}} */
        {
            uint32_t k = 0, pl = sizeof wa_client_payload + 16, m;
            inner[k++] = 0x0a; inner[k++] = 48; cp(inner + k, cstatic_ct, 48); k += 48;
            inner[k++] = 0x12; k += pb_varint(inner + k, pl); cp(inner + k, payload_ct, pl); k += pl;
            m = 3; finish[m++] = 0x22; m += pb_varint(finish + m, k); cp(finish + m, inner, k); m += k;
            finish[0] = (uint8_t)((m - 3) >> 16); finish[1] = (uint8_t)((m - 3) >> 8); finish[2] = (uint8_t)(m - 3);
            if (!ws_send(finish, m)) return fail("RESULT: ClientFinish send failed", 0, 0);
        }
        io->t_finish = ms();
        wa_fmt(line, sizeof line, "noise: ClientFinish sent %T s after ServerHello", ms() - t_hello); logl(line);
    }
    if (!pump(-1, 1, 20000)) { wa_fmt(io->result, sizeof io->result, "RESULT: handshake REJECTED (no encrypted frame after ClientFinish, gap %T s)", io->gap_ms); return 0; }
    {
        uint32_t flen = ((uint32_t)w.msg[0] << 16) | ((uint32_t)w.msg[1] << 8) | w.msg[2];
        if (w.msg_len < 3 + 16 || flen != w.msg_len - 3 || flen - 16 > sizeof plain) return fail("RESULT: bad encrypted frame", 0, 0);
        if (!noise_transport_decrypt(&tr, w.msg + 3, flen, plain)) return fail("RESULT: first server frame does not decrypt", 0, 0);
        wa_fmt(line, sizeof line, "noise: first encrypted server frame: %u bytes ciphertext -> %u bytes plaintext, first bytes %02x %02x %02x %02x (binary node, pair-device IQ)",
               flen, flen - 16, (uint32_t)plain[0], (uint32_t)plain[1], (uint32_t)plain[2], (uint32_t)plain[3]); logl(line);
    }
    io->t_accepted = ms();
    {   uint8_t cl[16]; n = ws_frame_close(&w, 1000, cl, sizeof cl); if (n) app_send(cl, n); }
    wa_fmt(io->result, sizeof io->result, "RESULT: handshake ACCEPTED by %s with our %s/WS/Noise stack, %T s hold, %u pongs%s", io->host,
           io->tunnel ? "(openssl TLS 1.3 tunnel)" : "TLS 1.3", io->gap_ms, io->pongs, io->noise_cert_cached ? ", Noise cert cache hit" : "");
    return 1;
}
