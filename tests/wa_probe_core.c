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
#include "nextkeys.h"
#include "../proto/signal.h"      /* not "signal.h": vbcc would take the C library header of the same name first */

/* whatsmeow socket/constants.go */
static const uint8_t wa_header[4] = { 'W', 'A', 6, 3 };
static const uint8_t wa_cert_pub[32] = { 0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
                                         0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b };
#define WA_CERT_ISSUER_SERIAL 0

static wa_probe_io *io;
static tls13 t;
static ws_client w;
/* the big receive buffers: WebSocket message (176 KiB, frames are decrypted in place), pending TLS plaintext, inflated
 * node, node arena, the heartbeat's staging buffer: 228 KB. WA_PROBE_ALLOC (the Amiga unity build): all handed out by
 * io->alloc, so they live in Chip RAM (~410 KB free on the A500 after the screen; Fast RAM is the scarce one: the stack's
 * TCP pool and the code). Otherwise static. */
#define WA_PROBE_ARENA 12288
#define WA_PROBE_STAGE 65536        /* the heartbeat poll's staging buffer: the rest of the offline batch (33 stanzas,
                                       ~4 KB without the history frame) must fit while the 68000 computes an X3DH (54 s)
                                       - live attempt 6 lost the connection with 8 KB here (window closed for a minute).
                                       WA_PROBE_ALLOC: the largest of 64/32/16/8 KB that Chip RAM still gives (96 KB did
                                       not fit next to the screen and the GUI arena in live attempt 7), stage_cap says which */
static uint32_t stage_cap = WA_PROBE_STAGE;
#ifdef WA_PROBE_ALLOC
static uint8_t *msgbuf, *pend, *inflated, *arena_mem, *stage;
static int big_buffers(wa_probe_io *pio)
{
    if (msgbuf) return 1;
    if (!pio->alloc) return 0;
    msgbuf = pio->alloc(pio->ctx, WA_PROBE_MSGBUF); pend = pio->alloc(pio->ctx, WA_PROBE_MSG_MAX); inflated = pio->alloc(pio->ctx, WA_PROBE_MSG_MAX);
    arena_mem = pio->alloc(pio->ctx, WA_PROBE_ARENA);
    for (stage_cap = WA_PROBE_STAGE; stage_cap >= 8192 && !(stage = pio->alloc(pio->ctx, stage_cap)); stage_cap >>= 1) ;
    return msgbuf && pend && inflated && arena_mem && stage;
}
#else
static uint8_t msgbuf[WA_PROBE_MSGBUF], pend[WA_PROBE_MSG_MAX], inflated[WA_PROBE_MSG_MAX], arena_mem[WA_PROBE_ARENA], stage[WA_PROBE_STAGE];
static int big_buffers(wa_probe_io *pio) { (void)pio; return 1; }
#endif
static uint32_t pend_len;
/* raw socket bytes read during a long computation (heartbeat poll, once a second) wait here for the pump, so the
 * network side never backs up for tens of seconds: in live attempt 2 FS-UAE's A2065 emulation died with 170 KB queued
 * while the 68000 computed for 50 s. The pump takes staged bytes before reading the socket again. */
static char line[640];
static uint32_t stage_len, stage_peak; static int in_pump, stage_full_noted;   /* peak: the most the staging buffer held in this run (RESULT line) */
static int in_send;                        /* inside send_node/app_send: no nested application send from a yield hook */
static uint32_t ka_last; static char ka_id[32];   /* the last keepalive ping (<iq xmlns=w:p><ping/>) after login, and its id */
static void logl(const char *s);
static int keepalive_due(void);
static void drain_poll(void *hio)
{
    int32_t r; (void)hio;
    if (in_pump || !io) return;
    if (stage_len >= stage_cap) {                /* the window stays closed from here on: say so once per fill (live attempt 6 lost the line this way) */
        if (!stage_full_noted) { stage_full_noted = 1; wa_fmt(line, sizeof line, "ws: staging buffer full (%u bytes) while computing: the socket is not read until the pump runs", stage_len); logl(line); }
        return;
    }
    r = io->recv(io->ctx, stage + stage_len, stage_cap - stage_len, 0);
    if (r > 0) { stage_len += (uint32_t)r; io->rx_bytes += (uint32_t)r; if (stage_len > stage_peak) stage_peak = stage_len; }
    keepalive_due();                             /* the server wants application traffic, not only WebSocket pongs (live attempts 4-7b) */
}
static uint8_t rdbuf[8192];
static uint32_t t_start;

/* prepared offline (wa_probe_prepare), consumed by wa_probe_run */
static hmac_drbg rng; static x509_cert root, inter; static tls13_keypair kp;
static uint8_t eph_priv[32], eph_pub[32], st_priv[32], st_pub[32];
static noise_cert_cache ncache, lcache;   /* intermediate and leaf certificate fingerprints */
static noise_es_pre espre;                 /* es = DH(eph_priv, stored server static), computed with the ephemeral key */
static uint8_t cached_static[32]; static int have_cached_static;   /* the server static from a stored run or a verified handshake */
static int prepared;
static noise_transport tr;            /* transport keys of the current connection */
static int pump_quiet;                /* suppress the "timeout" log line (QR wait loop) */
static int offline_done, offline_preview;   /* <ib><offline_preview count/></ib> announces the batch, <ib><offline count/></ib> ends it */
static uint32_t msg_off, msg_have, skip_left;    /* one WebSocket message may carry several WA frames (3-byte length each,
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
    uint32_t off = 0; int r;
    in_send++;
    if (io->tunnel) { r = send_all(p, n); in_send--; return r; }
    while (off < n) {
        int c = tls13_send(&t, p + off, n - off);
        if (c < 0) { in_send--; return 0; }
        if (c == 0) { if (!flush_tls()) { in_send--; return 0; } continue; }
        off += (uint32_t)c;
    }
    r = flush_tls(); in_send--;
    return r;
}
static int hb_send(void *hio, const uint8_t *p, uint32_t n) { (void)hio; return app_send(p, n); }
static void gcm_yield(void) { CRYPTO_YIELD(); }       /* AES-GCM runs (TLS records, the Noise frames) reach the heartbeat too */

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
static int pump_inner(int want_tls_state, int want_msg, uint32_t timeout_ms);
static int pump(int want_tls_state, int want_msg, uint32_t timeout_ms) { int r; in_pump = 1; r = pump_inner(want_tls_state, want_msg, timeout_ms); in_pump = 0; return r; }
static int pump_inner(int want_tls_state, int want_msg, uint32_t timeout_ms)
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
            /* feed the pending decrypted bytes; ws_input stops at a complete message or a full buffer and says how
             * many bytes it used, the rest waits (feeding one byte at a time and shifting the buffer each time cost
             * minutes per 16 KiB on the 68000 - the first live chat attempts) */
            while (pend_len && !w.msg_ready && !w.msg_partial) {
                uint32_t i, c;
                ol = 0;
                { uint32_t d = w.dropped;
                  if (!ws_input(&w, pend, pend_len, out, &ol, sizeof out)) { wa_fmt(line, sizeof line, "ws error, state %d", w.state); logl(line); return 0; }
                  if (w.dropped != d) { wa_fmt(line, sizeof line, "ws: a %u-byte message was dropped (larger than the %u-byte buffer)", w.dropped_len, (uint32_t)WA_PROBE_MSGBUF); logl(line); } }
                if (ol && !app_send(out, ol)) return 0;
                c = w.consumed > pend_len ? pend_len : w.consumed;
                if (!c) break;
                pend_len -= c; for (i = 0; i < pend_len; i++) pend[i] = pend[i + c];
            }
            if (w.msg_ready || w.msg_partial) { if (io->debug) { wa_fmt(line, sizeof line, "  ws message %u bytes%s:", w.msg_len, w.msg_partial ? " (partial)" : ""); log_hex(line, w.msg, w.msg_len < 4 ? w.msg_len : 4); } return 1; }
            if (w.state == WS_CLOSED) { wa_fmt(line, sizeof line, "server closed the WebSocket (code %u)", (uint32_t)w.close_code); logl(line); return 0; }
        }
        now = ms();
        if (now > deadline) { if (!pump_quiet) logl("timeout"); return 0; }
        if (stage_len) { uint32_t i, c = stage_len < sizeof rdbuf ? stage_len : (uint32_t)sizeof rdbuf; cp(rdbuf, stage, c); stage_len -= c; for (i = 0; i < stage_len; i++) stage[i] = stage[i + c]; r = (int32_t)c; stage_full_noted = 0; }
        else { r = io->recv(io->ctx, rdbuf, sizeof rdbuf, deadline - now); if (r > 0) io->rx_bytes += (uint32_t)r; }
        if (r == 0) { if (!pump_quiet) logl("timeout"); return 0; }
        if (r < 0) { logl("socket closed by server"); return 0; }
        if (io->tunnel) {
            if (w.state == WS_WAIT_HTTP) { ol = 0; if (!ws_input(&w, rdbuf, (uint32_t)r, out, &ol, sizeof out)) { logl("ws upgrade failed"); return 0; } }
            else { if (pend_len + (uint32_t)r > WA_PROBE_MSG_MAX) return 0; cp(pend + pend_len, rdbuf, (uint32_t)r); pend_len += (uint32_t)r; }
            continue;
        }
        if (io->debug) { wa_fmt(line, sizeof line, "  read %d bytes: ", r); log_hex(line, rdbuf, r < 100 ? (uint32_t)r : 100); }
        if (!tls13_input(&t, rdbuf, (uint32_t)r)) { log_tls_error(); return 0; }
        if (t.app_len) {
            if (w.state == WS_WAIT_HTTP) {
                ol = 0;
                if (!ws_input(&w, t.app, t.app_len, out, &ol, sizeof out)) { logl("ws upgrade failed"); return 0; }
            } else {
                if (pend_len + t.app_len > WA_PROBE_MSG_MAX) return 0;
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

/* the chat interface's view of the connection (io->on_state) and of the server's clock (t= attributes, io->on_time) */
static void state(int s, const char *detail) { if (io->on_state) io->on_state(io->ctx, s, detail); }
static uint32_t dec_value(const wab_value *v);
static void server_time(const wab_node *n) { uint32_t t; if (io->on_time && n && !wab_get_attr(n, "offline") && (t = dec_value(wab_get_attr(n, "t"))) != 0) io->on_time(io->ctx, t); }   /* offline stanzas carry the time they were sent */
static int fail(const char *fmt, const char *a, uint32_t b) { wa_fmt(io->result, sizeof io->result, fmt, a, b); state(WA_CONN_ERROR, io->result); return 0; }

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
    if (io->mode == WA_MODE_PAIR) { cp(st_priv, io->creds->id.noise_priv, 32); cp(st_pub, io->creds->id.noise_pub, 32); }
    else { drbg_generate(&rng, st_priv, 32); x25519_base_comb(st_pub, st_priv); }
    espre.valid = 0; io->t_es_pre = 0;
    if (io->nextkeys && io->nextkeys_loaded) {
        /* the record computed in the previous session's idle time: consume it first (single use), then take the keys */
        wa_nextkeys *nk = io->nextkeys;
        io->nextkeys_loaded = 0;
        if (io->consume_nextkeys) io->consume_nextkeys(io->ctx);
        cp(kp.priv, nk->tls_priv, 32); cp(kp.pub, nk->tls_pub, 32);
        cp(eph_priv, nk->eph_priv, 32); cp(eph_pub, nk->eph_pub, 32);
        if (nk->have_es) { cp(espre.server_static, nk->server_static, 32); cp(espre.dh, nk->es, 32); espre.valid = 1; }
        wa_nextkeys_wipe(nk);
        io->t_tls_key = io->t_noise_keys = 0; io->nextkeys_used = 1;
        wa_fmt(line, sizeof line, "keys: TLS and Noise ephemeral key pairs%s taken from the stored record (computed in the previous session's idle time), %T s",
               espre.valid ? " and es" : "", ms() - t0); logl(line);
        return 1;
    }
    if (!tls13_keypair_generate(&kp, &rng)) return fail("RESULT: keypair failed", 0, 0);
    io->t_tls_key = ms() - t0;
    t0 = ms();
    drbg_generate(&rng, eph_priv, 32);
    x25519_base_comb(eph_pub, eph_priv);
    io->t_noise_keys = ms() - t0;
    /* es before the connection: one ladder off the server's clock when the server static is known (noise.h) */
    if (have_cached_static) {
        t0 = ms();
        noise_es_precompute(&espre, eph_priv, cached_static);
        io->t_es_pre = ms() - t0;
        wa_fmt(line, sizeof line, "noise: es = DH(ephemeral, stored server static) computed in %T s, before the connection", io->t_es_pre); logl(line);
    }
    return 1;
}

int wa_probe_prepare(wa_probe_io *pio)
{
    io = pio; t_start = io->now_ms(); prepared = 0;
    io->t_tls_key = io->t_noise_keys = 0; io->result[0] = 0;
    if (!big_buffers(pio)) return fail("RESULT: no memory for the receive buffers", 0, 0);
    io->noise_cert_cached = 0; io->noise_cache_valid = 0;
    if (!io->seed || io->seed_len < 32) return fail("RESULT: no seed", 0, 0);
    rng.instantiated = 0; drbg_instantiate(&rng, io->seed, io->seed_len);
    if (!x509_parse(&root, wa_cert2, sizeof wa_cert2) || !x509_parse(&inter, wa_cert1, sizeof wa_cert1)) return fail("RESULT: root/intermediate parse failed", 0, 0);
    /* the stored fingerprint of WhatsApp's intermediate Noise certificate, if the caller kept one */
    ncache.valid = 0; lcache.valid = 0; io->noise_leaf_cached = 0; io->noise_leaf_valid = 0; io->tls_cert_cached = 0; io->tls_cache_out_len = 0; io->tls_tickets = 0;
    if (io->noise_leaf_cache_in) { cp(lcache.fp, io->noise_leaf_cache_in, 32); lcache.valid = 1; }
    have_cached_static = 0; io->noise_static_valid = 0; io->noise_es_precomputed = 0; espre.valid = 0;
    io->nextkeys_used = 0; io->nextkeys_ready = 0; io->t_nextkeys = 0;
    if (io->noise_static_in) { cp(cached_static, io->noise_static_in, 32); have_cached_static = 1; }
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
            /* the batch is generated in idle time after a login (post_login), never before the connection */
            if (!io->prekeys_loaded) { wa_prekeys_init(io->prekeys); io->prekeys_loaded = 1; }
            wa_fmt(line, sizeof line, "prekeys: %u one-time prekeys pending upload (stored batch of %u)", wa_prekeys_pending(io->prekeys), io->prekeys->n); logl(line);
        }
    }
    if (!connection_keys()) return 0;
    if (!io->nextkeys_used) {
        wa_fmt(line, sizeof line, "tls: X25519 key pair ready (%T s, before the connection)", io->t_tls_key); logl(line);
        wa_fmt(line, sizeof line, "noise: static + ephemeral X25519 key pairs ready (%T s, before the connection)", io->t_noise_keys); logl(line);
    }
    prepared = 1;
    return 1;
}

static int recv_frame(uint32_t timeout_ms, uint8_t **plain, uint32_t *plen);
static void frames_reset(void);

/* TCP is connected: TLS -> WebSocket -> Noise XX with `payload` as the ClientPayload; the first decrypted server
 * frame is *plain[0..*plain_len) inside the message buffer. Shared by the probe, the pairing connection and the login connection. */
static int handshake(const uint8_t *payload, uint32_t payload_len, uint8_t **plain, uint32_t *plain_len)
{
    static uint8_t out[4096];
    static uint8_t server_eph[32], server_static[32], server_static_ct[64], cert_ct[4096], cert_pt[4096];
    static uint8_t cstatic_ct[48], payload_ct[WA_CLIENTPAYLOAD_MAX + 16], finish[2048], inner[2048];
    static noise_hs hs; static heartbeat hb; static x509_cache cache;
    uint32_t server_static_ct_len = 0, cert_ct_len = 0, n, ladders = 0;
    const uint8_t *p, *end, *d; uint32_t f, wire, l, v; int es_used = 0;

    pend_len = 0; pump_quiet = 0; frames_reset();
    if (payload_len + 16 > sizeof payload_ct) return fail("RESULT: ClientPayload too long", 0, 0);
    state(WA_CONN_TLS, "TLS 1.3");
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
    state(WA_CONN_WS, "WebSocket + Noise XX");
    n = ws_client_start(&w, io->host, "/ws/chat", "https://web.whatsapp.com", msgbuf, WA_PROBE_MSGBUF, &rng, out, sizeof out);
    w.stream = 1;                                   /* long messages (the offline batch after login) arrive frame by frame */
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
        heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0); hb.poll = drain_poll;
        heartbeat_arm(&hb);
        if (io->gap_ms) { wa_fmt(line, sizeof line, "noise: holding ClientFinish for %T s of X25519 ladders, pong heartbeat every 4 s", io->gap_ms); logl(line); }
        spin_ladders(io->gap_ms, &ladders);
        /* the real work (the A500 does this inside the gap; here it takes milliseconds) */
        if (!noise_client_finish(&hs, eph_priv, st_priv, st_pub, server_eph, server_static_ct, 48, cert_ct, cert_ct_len,
                                 payload, payload_len, server_static, cert_pt, cstatic_ct, payload_ct, &tr, &espre, &es_used)) {
            heartbeat_disarm(); return fail("RESULT: Noise AEAD failure on ServerHello", 0, 0);
        }
        if (espre.valid) {
            logl(es_used ? "noise: es taken from the precomputation (server static unchanged), 2 X25519 ladders online"
                         : "noise: server static differs from the stored one, es computed online (3 ladders)");
            espre.valid = 0;
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
            if (ok) {
                cp(io->noise_leaf_fp, lcache.fp, 32); io->noise_leaf_valid = 1;
                /* the verified server static: for the next connection (the login connection after a pairing, the next run) */
                cp(io->noise_static_out, server_static, 32); io->noise_static_valid = 1;
                cp(cached_static, server_static, 32); have_cached_static = 1;
                io->noise_es_precomputed = es_used;
            }
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
    frames_reset();
    {
        int r = recv_frame(20000, plain, plain_len);
        if (r == 0) { wa_fmt(io->result, sizeof io->result, "RESULT: handshake REJECTED (no encrypted frame after ClientFinish, gap %T s)", io->gap_ms); return 0; }
        if (r < 0) return fail("RESULT: first server frame rejected (see log)", 0, 0);
        wa_fmt(line, sizeof line, "noise: first encrypted server frame: %u bytes ciphertext -> %u bytes plaintext, first bytes %02x %02x %02x %02x (binary node)",
               *plain_len + 16, *plain_len, (uint32_t)(*plain)[0], (uint32_t)(*plain)[1], (uint32_t)(*plain)[2], (uint32_t)(*plain)[3]); logl(line);
    }
    io->t_accepted = ms();
    state(WA_CONN_NOISE, "Noise accepted");
    return 1;
}

/* ---- pairing session ----------------------------------------------------------------------------- */
static wab_arena arena;   /* over arena_mem: post-login stanzas (inflated) are larger than the pairing IQs */
static uint8_t refbuf[WA_QR_REFS_MAX][128]; static uint32_t reflen[WA_QR_REFS_MAX], nrefs;
static char qr_text[WA_PAIR_QR_MAX]; static qr qr_code; static qr_work qr_scratch;
static uint32_t iq_counter; static char iq_prefix[16];

static void close_ws(void)
{
    uint8_t cl[16]; uint32_t n = ws_frame_close(&w, 1000, cl, sizeof cl);
    if (n) app_send(cl, n);
    state(WA_CONN_CLOSED, "closed");
    if (stage_peak) { wa_fmt(line, sizeof line, "ws: the staging buffer held at most %u of %u bytes while the 68000 computed", stage_peak, stage_cap); logl(line); }
    /* tickets arrive after the handshake, interleaved with application data: report the final count here */
    if (!io->tunnel) { io->tls_tickets = t.tickets; wa_fmt(line, sizeof line, "tls: %u NewSessionTicket(s) received during the connection (PSK resumption not implemented)", t.tickets); logl(line); }
}

/* one binary node, encrypted with the transport keys: 3-byte length + ciphertext */
static int send_node(const wab_node *n, const char *what)
{
    static uint8_t pt[2048], ct[2048 + 16 + 3]; uint32_t len; int e, r;
    e = wab_encode_frame(n, pt, sizeof pt, &len);
    if (e != WAB_OK) { wa_fmt(line, sizeof line, "wab: encoding %s failed: %s", what, wab_errstr(e)); logl(line); return 0; }
    in_send++;                                   /* the Noise encryption below yields (AES-GCM): no keepalive from the hook meanwhile */
    noise_transport_encrypt(&tr, pt, len, ct + 3);
    ct[0] = (uint8_t)((len + 16) >> 16); ct[1] = (uint8_t)((len + 16) >> 8); ct[2] = (uint8_t)(len + 16);
    if (io->debug) { wa_fmt(line, sizeof line, "  send %s, %u bytes node:", what, len); log_hex(line, pt, len < 64 ? len : 64); }
    r = ws_send(ct, len + 16 + 3); in_send--;
    return r;
}

/* next WA frame: 1 = decrypted into plain (*plen), 0 = nothing within timeout_ms, -1 = connection gone or a malformed
 * frame. A WebSocket message holds one or more frames (3-byte big-endian length each; the server sends e.g.
 * <stream:error code=515> and <xmlstreamend> in one message), so the frames not taken yet are served first. */
/* the next WA frame (3-byte length + Noise ciphertext), decrypted into plain. A WebSocket message may carry many
 * frames and may be far longer than our buffer (the offline batch after login: 170 KB in one message): the WebSocket
 * layer hands the message over in pieces (ws.stream), complete frames are taken from the front, the remainder is moved
 * down and more is read. A single frame longer than the buffer cannot be decrypted and is skipped, the Noise read
 * counter advanced by one so the frames after it still decrypt. 1 = frame, 0 = timeout, -1 = connection gone or bad frame. */
/* a long frame (longer than a TLS record) in flight: progress every 32 KB, a note when the line falls silent (the live
 * chat attempts stalled inside the 166 KB history stanza; whether the bytes stopped at the server, in FS-UAE's A2065
 * emulation or in the stack is what these lines are for) */
static uint32_t long_total, long_next, long_t0, long_note_at, long_note_rx, skip_total, skip_done;
static void long_progress(uint32_t have)
{
    if (long_total && have >= long_next) { wa_fmt(line, sizeof line, "ws: %u of %u bytes of the long frame here after %T s", have, long_total, ms() - long_t0); logl(line); long_next = (have / 32768 + 1) * 32768; }
}
static void long_note(uint32_t have)
{
    if (!long_total || ms() - long_note_at < 10000) return;
    long_note_at = ms();
    if (io->rx_bytes != long_note_rx) { long_note_rx = io->rx_bytes; return; }      /* still arriving: the 32 KB progress lines say so */
    wa_fmt(line, sizeof line, "ws: the line is quiet with %u of %u bytes of the long frame here (%T s since its start, %u bytes received in this run)", have, long_total, ms() - long_t0, io->rx_bytes); logl(line);
}
static void long_begin(uint32_t total, uint32_t have)
{
    long_total = total; long_t0 = ms(); long_next = 32768; long_note_at = ms(); long_note_rx = io->rx_bytes;
    wa_fmt(line, sizeof line, "ws: a %u-byte frame begins (%u bytes of it here, %u bytes received in this run so far)", total, have, io->rx_bytes); logl(line);
}
static void frames_reset(void) { msg_off = 0; msg_have = 0; skip_left = 0; w.msg_len = 0; w.msg_ready = 0; w.msg_partial = 0; stage_len = 0; long_total = 0; skip_total = skip_done = 0; aes_gcm_yield = gcm_yield; }
static heartbeat frame_hb;                        /* armed around the decryption of a long frame (37 s for 166 KB live) */
static int recv_frame(uint32_t timeout_ms, uint8_t **plain, uint32_t *plen)
{
    uint32_t flen, avail, deadline = ms() + timeout_ms;
    for (;;) {
        avail = w.msg_len - msg_off;
        if (skip_left) {                                 /* discarding an oversize frame */
            uint32_t d = avail < skip_left ? avail : skip_left;
            msg_off += d; skip_left -= d; avail -= d; skip_done += d;
            long_progress(skip_done);
            if (!skip_left) { wa_fmt(line, sizeof line, "ws: oversize frame skipped (%u bytes in %T s), Noise read counter advanced", skip_total, ms() - long_t0); logl(line); tr.read_counter++; long_total = 0; }
        }
        if (!skip_left && avail >= 3) {
            flen = ((uint32_t)w.msg[msg_off] << 16) | ((uint32_t)w.msg[msg_off + 1] << 8) | w.msg[msg_off + 2];
            if (flen < 16) { wa_fmt(line, sizeof line, "wab: bad encrypted frame (length %u at %u)", flen, msg_off); logl(line); frames_reset(); return -1; }
            if (3 + flen > WA_PROBE_MSGBUF) {
                wa_fmt(line, sizeof line, "ws: a %u-byte frame is longer than the %u-byte buffer: skipping it (it cannot be acknowledged, the server will send it again)", flen, (uint32_t)WA_PROBE_MSGBUF); logl(line);
                skip_left = 3 + flen; skip_total = 3 + flen; skip_done = 0; long_begin(3 + flen, avail); continue;
            }
            if (avail >= 3 + flen) {
                uint8_t *ct = w.msg + msg_off + 3; int ok;
                /* in place: the GCM tag is checked over the whole ciphertext first, then the counter stream is applied
                 * byte by byte (crypto/ref/aes.c gcm_ctr reads each byte before writing it). A long frame takes the
                 * 68000 tens of seconds: the heartbeat (pongs, socket poll into the staging buffer) runs meanwhile */
                if (flen > 16384) { heartbeat_init(&frame_hb, &w, io->now_ms, 4000, hb_send, 0); frame_hb.poll = drain_poll; heartbeat_arm(&frame_hb); }
                ok = noise_transport_decrypt(&tr, ct, flen, ct);
                if (flen > 16384) { heartbeat_disarm(); io->pongs += frame_hb.sent; if (frame_hb.error) { wa_fmt(line, sizeof line, "ws: heartbeat send failed during the frame's decryption (%u pongs sent before)", frame_hb.sent); logl(line); frames_reset(); return -1; } }
                if (!ok) { logl("wab: frame does not decrypt"); frames_reset(); return -1; }
                if (long_total) { wa_fmt(line, sizeof line, "ws: the %u-byte frame is complete after %T s", 3 + flen, ms() - long_t0); logl(line); long_total = 0; }
                *plain = ct; *plen = flen - 16;
                msg_off += 3 + flen;
                if (msg_off >= w.msg_len) { msg_off = 0; w.msg_len = 0; if (w.msg_ready) { w.msg_ready = 0; msg_have = 0; } }
                else if (io->debug) { wa_fmt(line, sizeof line, "ws: %u more bytes of frames in this message", w.msg_len - msg_off); logl(line); }
                return 1;
            }
            if (3 + flen > 16384) { if (long_total != 3 + flen) long_begin(3 + flen, avail); long_progress(avail); }
        }
        /* more bytes needed: a complete message must not end inside a frame */
        if (w.msg_ready) {
            if (avail && !skip_left) { wa_fmt(line, sizeof line, "wab: bad encrypted frame (%u bytes left at the end of a %u-byte message)", avail, w.msg_len); logl(line); frames_reset(); return -1; }
            w.msg_ready = 0; msg_off = 0; w.msg_len = 0; avail = 0;
        }
        if (msg_off) { uint32_t i; for (i = 0; i < avail; i++) w.msg[i] = w.msg[msg_off + i]; w.msg_len = avail; msg_off = 0; }
        w.msg_partial = 0; msg_have = 1;
        {
            uint32_t now = ms();
            if (now >= deadline) { long_note(skip_left ? skip_done : avail); return 0; }
            if (!keepalive_due()) { logl("ws: keepalive send failed"); return -1; }
            pump_quiet = 1;
            if (!pump(-1, 1, deadline - now)) { pump_quiet = 0; if (w.state == WS_CLOSED || w.state == WS_ERROR || t.error) return -1; long_note(skip_left ? skip_done : avail); return 0; }
            pump_quiet = 0;
        }
    }
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
    wab_arena_init(&arena, arena_mem, WA_PROBE_ARENA);
    if (plen && (plain[0] & WAB_FLAG_COMPRESSED)) {
        /* whatsmeow message.go: flags bit 1 = the node is a zlib stream (proto/inflate.c) */
        uint32_t ilen = 0, t0 = ms();
        e = wa_inflate(plain + 1, plen - 1, inflated, WA_PROBE_MSG_MAX, &ilen);
        if (e != WA_INFLATE_OK) { wa_fmt(line, sizeof line, "wab: compressed frame: %s (%u bytes in, %u out, the inflate buffer holds %u): not decoded, not acknowledged", wa_inflate_errstr(e), plen - 1, ilen, (uint32_t)WA_PROBE_MSG_MAX); logl(line); return 0; }
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
    next_iq_id(ka_id, sizeof ka_id);
    ka_last = ms();
    return send_iq1(ka_id, "w:p", "get", "ping", "keepalive ping");
}
/* the server's answer to our keepalive: <iq type=result id=OURS> - not a sign of life of the offline batch */
static int is_ping_result(const wab_node *n)
{
    const wab_value *id = wab_get_attr(n, "id"), *ty = wab_get_attr(n, "type");
    return wab_str_eq(&n->tag, "iq") && ty && ty->kind == WAB_STR && wab_str_eq(&ty->str, "result") && id && id->kind == WAB_STR && wab_str_eq(&id->str, ka_id);
}
/* a keepalive ping every 20 s from login on, whatever the probe is doing (whatsmeow: 20-30 s, independent of traffic).
 * The server reset the connection 65-180 s after <active/> in live attempts 4-7b, every time while we were receiving
 * the offline batch or computing with only WebSocket pongs going out. Called from recv_frame (every wait), from the
 * heartbeat's poll (computations) and from the chat loop; never nested inside a send or the pump. 0 = send failed. */
static int keepalive_due(void)
{
    if (!io->logged_in || in_send || in_pump) return 1;
    if (ms() - ka_last < 20000) return 1;
    return send_keepalive();
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
    uint32_t plen; uint8_t *plain; int r = recv_frame(timeout_ms, &plain, &plen);
    *gone = 0;
    if (r < 0) { *gone = 1; return 0; }
    if (r == 0) return 0;
    io->frames_after_login++;
    return decode(plain, plen);
}

static int handle_message(const wab_node *n);
static char last_msg_id[24];

/* a server stanza that arrives while we wait for something else; 1 = keep going, 0 = the stream ended */
static int handle_async(const wab_node *n)
{
    if (wab_str_eq(&n->tag, "stream:error") || wab_str_eq(&n->tag, "xmlstreamend") || wab_str_eq(&n->tag, "failure")) { logl("login: the server ended the stream"); return 0; }
    server_time(n);
    if (wab_str_eq(&n->tag, "receipt")) {
        const wab_value *id = wab_get_attr(n, "id"), *rt = wab_get_attr(n, "type"); char ty[24], fr[64];
        if (io->on_ack && id && id->kind == WAB_STR && !wab_get_attr(n, "participant")) {
            attr_cstr(n, "id", fr, sizeof fr);                              /* the chat interface matches the id against its own messages */
            io->on_ack(io->ctx, fr, rt && rt->kind == WAB_STR && wab_str_eq(&rt->str, "read") ? WA_MSG_READ : WA_MSG_DELIVERED);
        }
        if (last_msg_id[0] && id && id->kind == WAB_STR && wab_str_eq(&id->str, last_msg_id)) {
            io->t_msg_receipt = ms();
            wa_fmt(line, sizeof line, "msg: receipt for our message %s from %s: %s (%T s after sending)", last_msg_id, attr_cstr(n, "from", fr, sizeof fr),
                   wab_get_attr(n, "type") ? attr_cstr(n, "type", ty, sizeof ty) : "delivered", io->t_msg_receipt - io->t_msg_sent); logl(line);
        }
        return send_ack(n);
    }
    if (wab_str_eq(&n->tag, "notification")) return send_ack(n);
    if (wab_str_eq(&n->tag, "ack")) {
        const wab_value *id = wab_get_attr(n, "id"), *cl = wab_get_attr(n, "class"); char er[16];
        if (io->on_ack && id && id->kind == WAB_STR && cl && cl->kind == WAB_STR && wab_str_eq(&cl->str, "message")) { char ib[32]; io->on_ack(io->ctx, attr_cstr(n, "id", ib, sizeof ib), wab_get_attr(n, "error") ? WA_MSG_FAILED : WA_MSG_SENT); }
        if (last_msg_id[0] && id && id->kind == WAB_STR && wab_str_eq(&id->str, last_msg_id) && cl && cl->kind == WAB_STR && wab_str_eq(&cl->str, "message")) {
            io->t_msg_ack = ms();
            wa_fmt(line, sizeof line, "msg: the server acknowledged our message %s %T s after sending%s%s", last_msg_id, io->t_msg_ack - io->t_msg_sent,
                   wab_get_attr(n, "error") ? ", ERROR " : "", wab_get_attr(n, "error") ? attr_cstr(n, "error", er, sizeof er) : ""); logl(line);
        }
        return 1;
    }
    if (wab_str_eq(&n->tag, "message")) {
        io->messages_seen++;
        if (io->sessions) return handle_message(n);
        logl("login: an encrypted message waits for us (left unacknowledged: no session store in this run)");
    }
    if (wab_str_eq(&n->tag, "ib") && n->val.kind == WAB_LIST) {
        uint32_t i;
        for (i = 0; i < n->n_children; i++) {
            log_node("  ib: ", &n->children[i]);
            if (wab_str_eq(&n->children[i].tag, "offline")) offline_done = 1;
            if (wab_str_eq(&n->children[i].tag, "offline_preview") && dec_value(wab_get_attr(&n->children[i], "count"))) offline_preview = 1;
        }
    }
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

/* ---- messages: Signal sessions, <message> in and out (docs/SIGNAL.md; whatsmeow send.go, message.go, receipt.go) ---- */
static sig_local me_local;
static uint8_t msg_pt[1024], msg_ct[1400], msg_plain[SIG_BODY_MAX], msg_devid[600];   /* the phone's first message to a new device was 2757 bytes (live attempt 2) */
static char chat_line[512];
/* the next typed line and its destination: chat_input_to (the chat interface: the selected chat) when set, else chat_input
 * (console, to chat_user); 1 = chat_line holds a line */
static int next_chat_line(const char **user, uint32_t *device, int *lid)
{
    static char ubuf[32];
    if (io->chat_input_to) {
        ubuf[0] = 0; *device = io->chat_device; *lid = io->chat_lid;
        if (!io->chat_input_to(io->ctx, ubuf, sizeof ubuf, device, lid, chat_line, sizeof chat_line)) return 0;
        *user = ubuf[0] ? ubuf : io->chat_user;
        return 1;
    }
    if (io->chat_input && io->chat_input(io->ctx, chat_line, sizeof chat_line)) { *user = io->chat_user; *device = io->chat_device; *lid = io->chat_lid; return 1; }
    return 0;
}

static void core_random(void *ctx, uint8_t *out, uint32_t n) { (void)ctx; drbg_generate(&rng, out, n); }
static void local_init(void)
{
    const wa_identity *id = &io->creds->id;
    me_local.ident_priv = id->ident_priv; me_local.ident_pub = id->ident_pub; me_local.reg_id = id->reg_id;
    me_local.spk_id = id->spk_id; me_local.spk_priv = id->spk_priv; me_local.spk_pub = id->spk_pub;
    me_local.prekeys = io->prekeys; me_local.random = core_random; me_local.rctx = 0;
}
static int user_is_ours(const char *user)
{
    uint32_t i;
    for (i = 0; user[i] && io->creds->jid_user[i] && user[i] == io->creds->jid_user[i]; i++) ;
    if (!user[i] && !io->creds->jid_user[i]) return 1;
    for (i = 0; user[i] && io->creds->lid_user[i] && user[i] == io->creds->lid_user[i]; i++) ;
    return !user[i] && !io->creds->lid_user[i] && io->creds->lid_user[0];
}
static void save_sessions(void) { if (io->save_sessions) io->save_sessions(io->ctx); }

/* <iq xmlns=encrypt type=get to=s.whatsapp.net><key><user jid=user[:device]@server reason=identity/></key></iq> -> the bundle */
static int fetch_bundle(const char *user, uint32_t device, int lid, sig_bundle *b)
{
    static wab_node iq, key, usr; static wab_attr a[4], ua[2]; char id[32]; const wab_node *r, *list; uint32_t i;
    next_iq_id(id, sizeof id);
    wab_node_init(&usr, "user");
    ua[0].key = wab_s("jid"); ua[0].val = wab_jid_value(user, lid ? "lid" : WA_SERVER_JID, device);
    ua[1].key = wab_s("reason"); ua[1].val = wab_text("identity");
    usr.attrs = ua; usr.n_attrs = 2;
    wab_node_init(&key, "key"); key.val.kind = WAB_LIST; key.children = &usr; key.n_children = 1;
    wab_node_init(&iq, "iq");
    a[0].key = wab_s("id"); a[0].val = wab_text(id);
    a[1].key = wab_s("xmlns"); a[1].val = wab_text("encrypt");
    a[2].key = wab_s("type"); a[2].val = wab_text("get");
    a[3].key = wab_s("to"); a[3].val = wab_jid_value("", WA_SERVER_JID, 0);
    iq.attrs = a; iq.n_attrs = 4; iq.val.kind = WAB_LIST; iq.children = &key; iq.n_children = 1;
    if (!send_node(&iq, "prekey bundle query")) return 0;
    r = wait_result(id, 120000);                    /* stanzas in between are handled; a message to us may cost a minute on the 68000 */
    if (!iq_is_result(r)) { logl("signal: no prekey bundle (no result or an error IQ, see recv: line)"); return 0; }
    list = wab_get_child(r, "list");
    if (!list || list->val.kind != WAB_LIST) { logl("signal: bundle result without <list>"); return 0; }
    for (i = 0; i < list->n_children; i++) {
        const wab_node *u = &list->children[i];
        if (!wab_str_eq(&u->tag, "user")) continue;
        if (sig_bundle_from_node(b, u)) {
            wa_fmt(line, sizeof line, "signal: bundle for %s:%u: registration id %u, signed prekey id %u, one-time prekey %s%u", user, device, b->reg_id, b->spk_id,
                   b->has_opk ? "id " : "none", b->has_opk ? b->opk_id : 0u); logl(line);
            return 1;
        }
        log_node("signal: unusable bundle: ", u);
    }
    return 0;
}

/* whatsmeow GenerateMessageID: "3EB0" + 18 upper-case hex digits of SHA-256(time || user@c.us || 16 random bytes) */
static void new_message_id(char *id)
{
    static const char hx[] = "0123456789ABCDEF"; uint8_t buf[8 + 32 + 16], h[32]; uint32_t n = 0, i, t = ms(); const char *u = io->creds->jid_user;
    for (i = 0; i < 4; i++) buf[n++] = 0; buf[n++] = (uint8_t)(t >> 24); buf[n++] = (uint8_t)(t >> 16); buf[n++] = (uint8_t)(t >> 8); buf[n++] = (uint8_t)t;
    for (i = 0; u[i] && n < 8 + 24; i++) buf[n++] = (uint8_t)u[i];
    for (i = 0; i < 5; i++) buf[n++] = (uint8_t)"@c.us"[i];
    drbg_generate(&rng, buf + n, 16); n += 16;
    sha256(h, buf, n);
    id[0] = '3'; id[1] = 'E'; id[2] = 'B'; id[3] = '0';
    for (i = 0; i < 9; i++) { id[4 + 2 * i] = hx[h[i] >> 4]; id[5 + 2 * i] = hx[h[i] & 15]; }
    id[22] = 0;
}

/* Message{conversation} (waE2E field 1), for our own devices wrapped as Message{deviceSentMessage(31){destinationJID(1), message(2)}} */
static uint32_t build_message(uint8_t *out, uint32_t cap, const char *text, const char *dest_user, int for_own_device)
{
    static uint8_t inner[600], dsm[700]; pb_writer w, wi, wd; char dest[64];
    pb_w_init(&wi, inner, sizeof inner); pb_w_str(&wi, 1, text); if (!wi.ok) return 0;
    pb_w_init(&w, out, cap);
    if (for_own_device) {
        wa_fmt(dest, sizeof dest, "%s@%s", dest_user, WA_SERVER_JID);
        pb_w_init(&wd, dsm, sizeof dsm); pb_w_str(&wd, 1, dest); pb_w_bytes(&wd, 2, inner, wi.len); if (!wd.ok) return 0;
        pb_w_bytes(&w, 31, dsm, wd.len);
    } else pb_w_raw(&w, inner, wi.len);
    return w.ok ? w.len : 0;
}

/* whatsmeow padMessage: 1..15 copies of the pad length (a random nibble, 0 -> 15) */
static uint32_t wa_pad(uint8_t *p, uint32_t len, uint32_t cap)
{
    uint8_t r; uint32_t i;
    drbg_generate(&rng, &r, 1); r &= 0x0f; if (!r) r = 0x0f;
    if (len + r > cap) return 0;
    for (i = 0; i < r; i++) p[len + i] = r;
    return len + r;
}
static int wa_unpad(const uint8_t *p, uint32_t *len)
{
    uint32_t i, n = *len, pad;
    if (!n) return 0;
    pad = p[n - 1];
    if (!pad || pad > n) return 0;
    for (i = 0; i < pad; i++) if (p[n - 1 - i] != pad) return 0;
    *len = n - pad;
    return 1;
}

/* UTF-8 -> printable Latin-1 for the log and the console (anything else becomes '?') */
static uint32_t text_latin1(char *dst, uint32_t cap, const uint8_t *s, uint32_t n)
{
    uint32_t i = 0, o = 0;
    while (i < n && o + 1 < cap) {
        uint8_t c = s[i];
        if (c < 0x80) { dst[o++] = c >= 32 ? (char)c : c == '\n' ? ' ' : '?'; i++; }
        else if ((c & 0xe0) == 0xc0 && i + 1 < n) { uint32_t cp = ((uint32_t)(c & 0x1f) << 6) | (s[i + 1] & 0x3f); dst[o++] = cp < 256 ? (char)cp : '?'; i += 2; }
        else if ((c & 0xf0) == 0xe0) { dst[o++] = '?'; i += 3; }
        else if ((c & 0xf8) == 0xf0) { dst[o++] = '?'; i += 4; }
        else { dst[o++] = '?'; i++; }
    }
    dst[o] = 0;
    return o;
}

/* the text of a decrypted Message: conversation(1), extendedTextMessage(6).text(1), deviceSentMessage(31).message(2) (recursive);
 * protocolMessage(12) and senderKeyDistributionMessage(2) are named; 1 = text found */
static const uint8_t *text_utf8; static uint32_t text_utf8_len;    /* the last text message_text found, as received (for on_text) */
static int message_text(const uint8_t *p, uint32_t len, char *out, uint32_t cap, int depth)
{
    const uint8_t *end = p + len, *d; uint32_t f, wire, v, l; char fields[64]; uint32_t fo = 0; int proto_type = -1;
    while (pb_next(&p, end, &f, &wire, &v, &d, &l)) {
        if (f == 1 && wire == PB_BYTES) { text_latin1(out, cap, d, l); text_utf8 = d; text_utf8_len = l; return 1; }
        if (f == 6 && wire == PB_BYTES) {
            const uint8_t *q = d, *qe = d + l; uint32_t f2, w2, v2, l2; const uint8_t *d2;
            while (pb_next(&q, qe, &f2, &w2, &v2, &d2, &l2)) if (f2 == 1 && w2 == PB_BYTES) { text_latin1(out, cap, d2, l2); text_utf8 = d2; text_utf8_len = l2; return 1; }
        }
        if (f == 31 && wire == PB_BYTES && depth < 2) {
            const uint8_t *q = d, *qe = d + l; uint32_t f2, w2, v2, l2; const uint8_t *d2;
            while (pb_next(&q, qe, &f2, &w2, &v2, &d2, &l2)) if (f2 == 2 && w2 == PB_BYTES && message_text(d2, l2, out, cap, depth + 1)) return 1;
        }
        if (f == 12 && wire == PB_BYTES) {
            const uint8_t *q = d, *qe = d + l; uint32_t f2, w2, v2, l2; const uint8_t *d2; proto_type = 0;
            while (pb_next(&q, qe, &f2, &w2, &v2, &d2, &l2)) if (f2 == 2 && w2 == PB_VARINT) proto_type = (int)v2;
        }
        if (fo + 6 < sizeof fields) fo += wa_fmt(fields + fo, sizeof fields - fo, "%s%u", fo ? "," : "", f);
    }
    if (proto_type >= 0) wa_fmt(out, cap, "[protocol message, type %d]", proto_type);
    else wa_fmt(out, cap, "[no text; message fields %s]", fields);
    return 0;
}

/* <receipt id to=from [recipient] [participant] [type=sender|inactive]/> (whatsmeow sendMessageReceipt: the ack of a decrypted message) */
static int send_receipt(const wab_node *n, const char *sender_user)
{
    static wab_node rc; static wab_attr a[5]; uint32_t k = 0;
    const wab_value *id = wab_get_attr(n, "id"), *from = wab_get_attr(n, "from"), *rcp = wab_get_attr(n, "recipient"), *part = wab_get_attr(n, "participant");
    if (!id || !from) return 1;
    wab_node_init(&rc, "receipt");
    a[k].key = wab_s("id"); a[k].val = *id; k++;
    a[k].key = wab_s("to"); a[k].val = *from; k++;
    if (rcp) { a[k].key = wab_s("recipient"); a[k].val = *rcp; k++; }
    if (part) { a[k].key = wab_s("participant"); a[k].val = *part; k++; }
    a[k].key = wab_s("type"); a[k].val = wab_text(user_is_ours(sender_user) ? "sender" : "inactive"); k++;   /* inactive: no presence sent */
    rc.attrs = a; rc.n_attrs = k;
    io->receipts_sent++;
    return send_node(&rc, "receipt");
}

static void jid_user(char *dst, uint32_t cap, const wab_jid *j) { uint32_t i; for (i = 0; i < j->user.len && i + 1 < cap; i++) dst[i] = (char)j->user.p[i]; dst[i] = 0; }

/* an incoming <message>: decrypt the <enc> child with the sender's session, print the text, answer with a receipt */
static int handle_message(const wab_node *n)
{
    const wab_value *from = wab_get_attr(n, "from"), *part = wab_get_attr(n, "participant"), *enc_type; const wab_node *enc = 0; uint32_t i, plen = 0, used = 0, elen;
    char user[32], idb[32], ty[16]; int lid, is_pk, r; sig_session *s; static heartbeat hb; uint32_t t0;
    if (!from || from->kind != WAB_JID) { logl("msg: <message> without a from JID, acknowledged"); return send_ack(n); }
    if (wab_str_eq(&from->jid.server, "g.us") || wab_str_eq(&from->jid.server, "broadcast") || wab_str_eq(&from->jid.server, "newsletter")) {
        wa_fmt(line, sizeof line, "msg: %s message id %s from %s (sender keys are out of scope): acknowledged, not decrypted", wab_str_eq(&from->jid.server, "g.us") ? "group" : "broadcast/newsletter",
               attr_cstr(n, "id", idb, sizeof idb), attr_cstr(n, part ? "participant" : "from", user, sizeof user)); logl(line);
        return send_ack(n);
    }
    jid_user(user, sizeof user, &from->jid); lid = wab_str_eq(&from->jid.server, "lid");
    if (n->val.kind == WAB_LIST) for (i = 0; i < n->n_children; i++) if (wab_str_eq(&n->children[i].tag, "enc")) { enc = &n->children[i]; break; }
    if (!enc) {
        wa_fmt(line, sizeof line, "msg: message %s from %s:%u without <enc>%s: acknowledged", attr_cstr(n, "id", idb, sizeof idb), user, (uint32_t)from->jid.device, wab_get_child(n, "unavailable") ? " (unavailable)" : ""); logl(line);
        return send_ack(n);
    }
    enc_type = wab_get_attr(enc, "type");
    if (!enc_type || enc_type->kind != WAB_STR || !(wab_str_eq(&enc_type->str, "pkmsg") || wab_str_eq(&enc_type->str, "msg"))) {
        wa_fmt(line, sizeof line, "msg: message %s from %s:%u with <enc type=%s>: not a pairwise message, acknowledged", attr_cstr(n, "id", idb, sizeof idb), user, (uint32_t)from->jid.device, attr_cstr(enc, "type", ty, sizeof ty)); logl(line);
        return send_ack(n);
    }
    is_pk = wab_str_eq(&enc_type->str, "pkmsg");
    if (enc->val.kind != WAB_BYTES && enc->val.kind != WAB_STR) { logl("msg: <enc> without content, acknowledged"); return send_ack(n); }
    elen = enc->val.str.len;
    /* the ciphertext as hex (200 bytes per line): an offline replay of exactly this message against the stored
       credentials and prekeys (host, vamos) is worth more than any guess when the 68000 stops here */
    for (i = 0; i < elen && i < (elen <= 1200 ? elen : 100); i += 100) { char pfx[40]; wa_fmt(pfx, sizeof pfx, "enc %s %u/%u: ", is_pk ? "pkmsg" : "msg", i, elen); log_hex(pfx, enc->val.str.p + i, elen - i < 100 ? elen - i : 100); }   /* 100 bytes: the A500 log line holds 300 chars and costs 0.4 s; whole dump only for short messages (the replay) */
    if (elen > SIG_BODY_MAX + 160) {
        /* longer than this build decrypts (SIG_BODY_MAX inner bytes; a prekey message adds ~140): the phone's inline
           history bootstrap is such a message (166 KB live). Acknowledged so the server stops re-sending it, lost. */
        wa_fmt(line, sizeof line, "msg: message %s from %s:%u (%s, %u bytes%s) is longer than this build decrypts (%u): acknowledged and receipted, lost",
               attr_cstr(n, "id", idb, sizeof idb), user, (uint32_t)from->jid.device, is_pk ? "pkmsg" : "msg", elen, wab_get_attr(n, "offline") ? ", offline" : "", (uint32_t)SIG_BODY_MAX); logl(line);
        io->msgs_deferred++;
        /* the <ack> alone did not stop the server from delivering the 166 KB history message again at the next login
           (live attempt 7b): like a decrypted message it gets a <receipt> (type=sender for our own account) */
        if (!send_ack(n)) return 0;
        return send_receipt(n, user);
    }
    s = sig_store_get(io->sessions, user, from->jid.device, lid, is_pk);
    if (!s) { wa_fmt(line, sizeof line, "msg: message %s from %s:%u is a plain msg but we have no session with that device: acknowledged, lost", attr_cstr(n, "id", idb, sizeof idb), user, (uint32_t)from->jid.device); logl(line); io->msgs_failed++; return send_ack(n); }
    wa_fmt(line, sizeof line, "msg: message %s from %s:%u@%s, <enc type=%s v=%s> %u bytes%s%s", attr_cstr(n, "id", idb, sizeof idb), user, (uint32_t)from->jid.device, lid ? "lid" : WA_SERVER_JID,
           is_pk ? "pkmsg" : "msg", attr_cstr(enc, "v", ty, sizeof ty), elen, wab_get_attr(n, "offline") ? " (waited on the server while we were offline)" : "", sig_session_has_state(s) ? "" : " (new session: X3DH as responder)"); logl(line);
    t0 = ms();
    heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0); hb.poll = drain_poll;
    heartbeat_arm(&hb);
    r = sig_decrypt(s, &me_local, is_pk, enc->val.str.p, elen, msg_plain, sizeof msg_plain, &plen, &used);
    heartbeat_disarm(); io->pongs += hb.sent;
    io->d_decrypt = ms() - t0;
    if (r != SIG_OK) {
        wa_fmt(line, sizeof line, "msg: DECRYPTION FAILED (%s) after %T s: acknowledged without a retry receipt (pacing rule), the message is lost", sig_errstr(r), io->d_decrypt); logl(line);
        io->msgs_failed++;
        return send_ack(n);
    }
    save_sessions();
    if (used) { wa_fmt(line, sizeof line, "msg: one-time prekey %u consumed, %u left in the record", used, io->prekeys ? io->prekeys->n : 0u); logl(line); if (io->save_prekeys) io->save_prekeys(io->ctx); }
    if (!wa_unpad(msg_plain, &plen)) { logl("msg: decrypted, but the WhatsApp padding is invalid: acknowledged"); io->msgs_failed++; return send_ack(n); }
    {
        char text[200], fromstr[48];
        int have = message_text(msg_plain, plen, text, sizeof text, 0);
        wa_fmt(fromstr, sizeof fromstr, "%s:%u", user, (uint32_t)from->jid.device);
        wa_fmt(line, sizeof line, "msg: %s in %T s (%u bytes plaintext): %s%s%s", have ? "TEXT" : "decrypted", io->d_decrypt, plen, have ? "\"" : "", text, have ? "\"" : ""); logl(line);
        if (have && io->chat_recv) io->chat_recv(io->ctx, fromstr, text);
        if (have && io->on_text) { char pn[48]; io->on_text(io->ctx, user, from->jid.device, lid, wab_get_attr(n, "notify") ? attr_cstr(n, "notify", pn, sizeof pn) : "", dec_value(wab_get_attr(n, "t")), (const char *)text_utf8, text_utf8_len); }
        io->msgs_received++; io->t_msg_received = ms();
    }
    return send_receipt(n, user);
}

/* a text to user:device: session from the store or a new one from the prekey bundle (X3DH), Message protobuf, WhatsApp
 * padding, Signal encryption, <message id type=text to><participants><to jid><enc v=2 type=pkmsg|msg/></to></participants>
 * [<device-identity/>]</message>; the server's <ack> and the peer's <receipt> are reported by handle_async */
static int send_text_inner(const char *user, uint32_t device, int lid, const char *text);
static int send_text(const char *user, uint32_t device, int lid, const char *text)
{
    int r = send_text_inner(user, device, lid, text);
    if (io->on_sent) io->on_sent(io->ctx, user, device, lid, text, r ? last_msg_id : "", r);
    return r;
}
static int send_text_inner(const char *user, uint32_t device, int lid, const char *text)
{
    static wab_node msg, parts, to, enc, devid; static wab_attr ma[3], ta[1], ea[2]; static wab_node children[2];
    static heartbeat hb; sig_session *s; uint32_t t0, plen, clen, dlen = 0; int is_pk, r;
    s = sig_store_get(io->sessions, user, device, lid, 0);
    if (!s || !sig_session_has_state(s)) {
        sig_bundle b;
        wa_fmt(line, sizeof line, "signal: no session with %s:%u yet: fetching the prekey bundle", user, device); logl(line);
        if (!fetch_bundle(user, device, lid, &b)) return 0;
        s = sig_store_get(io->sessions, user, device, lid, 1);
        t0 = ms();
        heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0); hb.poll = drain_poll;
        heartbeat_arm(&hb);
        r = sig_session_start(s, &me_local, &b);
        heartbeat_disarm(); io->pongs += hb.sent;
        io->d_session = ms() - t0;
        if (r != SIG_OK) { wa_fmt(line, sizeof line, "signal: session setup REJECTED: %s", sig_errstr(r)); logl(line); sig_session_init(s); return 0; }
        io->sessions_started++;
        wa_fmt(line, sizeof line, "signal: session with %s:%u established in %T s (XEdDSA of the signed prekey, X3DH with %u ladders, 2 key pairs, 1 ratchet ladder; %u pongs)", user, device, io->d_session, b.has_opk ? 4u : 3u, hb.sent); logl(line);
        save_sessions();
    }
    plen = build_message(msg_pt, sizeof msg_pt - 16, text, user, user_is_ours(user));
    if (!plen) { logl("msg: text too long"); return 0; }
    plen = wa_pad(msg_pt, plen, sizeof msg_pt);
    t0 = ms();
    heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0); hb.poll = drain_poll;
    heartbeat_arm(&hb);
    r = sig_encrypt(s, &me_local, msg_pt, plen, msg_ct, sizeof msg_ct, &clen, &is_pk);
    heartbeat_disarm(); io->pongs += hb.sent;
    io->d_encrypt = ms() - t0;
    if (r != SIG_OK) { wa_fmt(line, sizeof line, "msg: encryption failed: %s", sig_errstr(r)); logl(line); return 0; }
    save_sessions();
    new_message_id(last_msg_id);
    wab_node_init(&enc, "enc");
    ea[0].key = wab_s("v"); ea[0].val = wab_text("2");
    ea[1].key = wab_s("type"); ea[1].val = wab_text(is_pk ? "pkmsg" : "msg");
    enc.attrs = ea; enc.n_attrs = 2; enc.val = wab_bytes(msg_ct, clen);
    wab_node_init(&to, "to");
    ta[0].key = wab_s("jid"); ta[0].val = wab_jid_value(user, lid ? "lid" : WA_SERVER_JID, device);
    to.attrs = ta; to.n_attrs = 1; to.val.kind = WAB_LIST; to.children = &enc; to.n_children = 1;
    wab_node_init(&parts, "participants"); parts.val.kind = WAB_LIST; parts.children = &to; parts.n_children = 1;
    children[0] = parts;
    if (is_pk) {
        /* ADVSignedDeviceIdentity{details, accountSignatureKey, accountSignature, deviceSignature}: the phone verifies our device */
        pb_writer w2; const wa_adv_identity *adv = &io->creds->adv;
        pb_w_init(&w2, msg_devid, sizeof msg_devid);
        pb_w_bytes(&w2, 1, adv->details, adv->details_len); pb_w_bytes(&w2, 2, adv->account_sig_key, 32); pb_w_bytes(&w2, 3, adv->account_sig, 64); pb_w_bytes(&w2, 4, adv->device_sig, 64);
        dlen = w2.ok ? w2.len : 0;
        wab_node_init(&devid, "device-identity"); devid.val = wab_bytes(msg_devid, dlen);
        children[1] = devid;
    }
    wab_node_init(&msg, "message");
    ma[0].key = wab_s("id"); ma[0].val = wab_text(last_msg_id);
    ma[1].key = wab_s("type"); ma[1].val = wab_text("text");
    ma[2].key = wab_s("to"); ma[2].val = wab_jid_value(user, lid ? "lid" : WA_SERVER_JID, 0);
    msg.attrs = ma; msg.n_attrs = 3; msg.val.kind = WAB_LIST; msg.children = children; msg.n_children = is_pk ? 2 : 1;
    if (!send_node(&msg, "message")) return 0;
    io->msgs_sent++; io->t_msg_sent = ms(); io->t_msg_ack = 0; io->t_msg_receipt = 0;
    wa_fmt(line, sizeof line, "msg: sent message %s to %s:%u as %s (%u bytes Signal, %u bytes padded plaintext, encrypt %T s%s)", last_msg_id, user, device, is_pk ? "pkmsg + device-identity" : "msg", clen, plen, io->d_encrypt,
           user_is_ours(user) ? ", DeviceSentMessage for our own number" : ""); logl(line);
    return 1;
}

/* after <success>: whatsmeow handleConnectSuccess - prekey count, upload when the server runs low, <active/>, then
 * linger_ms online (receipts and notifications acknowledged, keepalive every 25 s), then close. 1 = done. */
/* one-time prekeys while online: 3.3 s per key on the 68000, the heartbeat keeps the WebSocket alive meanwhile */
static uint32_t make_prekeys(uint32_t count, const char *when)
{
    static heartbeat hb; uint32_t t0 = ms(), made;
    heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0); hb.poll = drain_poll;
    heartbeat_arm(&hb);
    made = wa_prekeys_generate(io->prekeys, count, &rng);
    heartbeat_disarm(); io->pongs += hb.sent;
    io->d_prekeys += ms() - t0;
    wa_fmt(line, sizeof line, "prekeys: %u new one-time prekeys (X25519, ids up to %u) in %T s %s (%u pongs); %u pending upload, %u in the record",
           made, io->prekeys->next_id - 1, ms() - t0, when, hb.sent, wa_prekeys_pending(io->prekeys), io->prekeys->n); logl(line);
    if (made && io->save_prekeys) io->save_prekeys(io->ctx);
    return hb.error ? 0 : 1;
}

static int post_login(void)
{
    char id[32]; const wab_node *r; uint32_t t_end, last_ka, cd; int gone, cl; const char *cu;
    /* 1. how many one-time prekeys of ours does the server hold */
    next_iq_id(id, sizeof id);
    if (!send_iq1(id, "encrypt", "get", "count", "prekey count query")) return fail("RESULT: logged in, but sending the prekey count query failed", 0, 0);
    r = wait_result(id, 30000);
    if (!r) return fail("RESULT: logged in, but no answer to the prekey count query", 0, 0);
    { const wab_node *c = wab_get_child(r, "count"); io->have_server_prekeys = c != 0; io->server_prekeys = c ? dec_value(wab_get_attr(c, "value")) : 0; }
    wa_fmt(line, sizeof line, "login: the server holds %u one-time prekeys of ours (whatsmeow uploads below %u)", io->server_prekeys, (uint32_t)WA_PREKEYS_MIN_SERVER); logl(line);
    /* 2. upload the pending batch when the server runs low (generating one first if nothing is pending) */
    if (io->prekeys && io->have_server_prekeys && io->server_prekeys < WA_PREKEYS_MIN_SERVER && !wa_prekeys_pending(io->prekeys)) {
        if (!make_prekeys(io->prekeys_wanted, "online, the server ran out")) return fail("RESULT: logged in, connection lost while generating prekeys", 0, 0);
    }
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
    /* 2b. the chat text goes out while we are still passive: prekey bundle, X3DH, <message>, the server's <ack>. The
          offline batch only comes after <active/>, and FS-UAE's A2065 emulation has died shortly after that burst in
          three live attempts - the user's text is on its way before the risky part begins. */
    if (io->sessions && io->chat_user && io->chat_send) {
        if (!send_text(io->chat_user, io->chat_device, io->chat_lid, io->chat_send)) logl("msg: the initial text was not sent");
        else {
            uint32_t t0 = ms();
            while (!io->t_msg_ack && ms() - t0 < 30000) {
                const wab_node *n = recv_node(1000, &gone);
                if (gone) return fail("RESULT: logged in and text sent, but the connection closed before the server's ack", 0, 0);
                if (n && !handle_async(n)) { close_ws(); return 1; }
            }
            if (!io->t_msg_ack) logl("msg: no <ack> from the server within 30 s (passive mode may withhold it); going active");
        }
    }
    /* 3. passive -> active */
    next_iq_id(id, sizeof id);
    if (!send_iq1(id, "passive", "set", "active", "passive/active")) return fail("RESULT: logged in, but sending <active/> failed", 0, 0);
    r = wait_result(id, 30000);
    if (!iq_is_result(r)) return fail("RESULT: logged in, but <active/> was not accepted (see recv: line)", 0, 0);
    io->active_set = 1; io->t_active = ms();
    state(WA_CONN_ONLINE, "active");
    wa_fmt(line, sizeof line, "login: <active/> accepted %T s after <success>; staying online for %T s", io->t_active - io->t_login_accepted, io->linger_ms); logl(line);
    /* 3b. the offline batch: right after <active/> the server delivers everything that waited for us (receipts,
          notifications, status updates, messages - 29 stanzas in one 170 KB WebSocket message in the first live chat
          attempt), ending with <ib><offline count/></ib>. Each stanza is handled as it arrives (acknowledged, messages
          decrypted when we have sessions); nothing else goes out until the batch is done or the line has been quiet. */
    {
        uint32_t t0 = ms(), last = ms(), before = io->frames_after_login, quiet, rx_seen = io->rx_bytes; offline_done = 0; offline_preview = 0;
        for (;;) {
            const wab_node *n;
            /* until the preview: 8 s of silence ends the wait; after a preview announcing stanzas: 45 s of silence, 15
             * minutes in all. Silence means no BYTES: the 166 KB history frame takes the 68000 ~50 s to receive (TLS
             * decryption at ~3 KB/s), and live attempts 4 and 5 ended because this loop gave up after 45 s without a
             * complete stanza, then computed keys while the frame was still streaming in. */
            quiet = io->drain_quiet_ms ? io->drain_quiet_ms : offline_preview ? 45000 : 8000;
            /* bytes count only while a long frame is coming in; our own keepalive's results every 20 s do not (live
             * attempt 8: the batch phase lasted the full 15 minutes on 45 pong results) */
            if (io->rx_bytes != rx_seen) { rx_seen = io->rx_bytes; if (long_total) last = ms(); }
            if (offline_done || ms() - last >= quiet || ms() - t0 > 900000) break;
            n = recv_node(1000, &gone);
            if (gone) { logl("login: connection closed by the server during the offline batch"); close_ws(); return 1; }
            if (n) { if (!is_ping_result(n)) last = ms(); if (!handle_async(n)) { close_ws(); return 1; } }
        }
        wa_fmt(line, sizeof line, "login: offline batch: %u stanzas in %T s%s", io->frames_after_login - before, ms() - t0, offline_done ? ", <offline> marker seen" : offline_preview ? ", NO <offline> marker (line quiet for 45 s)" : ", nothing announced (quiet for 8 s)"); logl(line);
    }
    /* 4. idle time: the key material for the next start (two key pairs, es with the server static just verified),
          pongs from the heartbeat keep the WebSocket alive meanwhile; the record goes to the caller right away */
    if (io->precompute_next && io->nextkeys) {
        static heartbeat hb; uint32_t t0 = ms();
        heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0); hb.poll = drain_poll;
        heartbeat_arm(&hb);
        wa_nextkeys_compute(io->nextkeys, &rng, have_cached_static ? cached_static : 0);
        heartbeat_disarm(); io->pongs += hb.sent;
        io->t_nextkeys = ms() - t0; io->nextkeys_ready = 1;
        wa_fmt(line, sizeof line, "keys: next connection's TLS + Noise ephemeral key pairs%s computed in %T s while online (%u pongs)",
               have_cached_static ? " and es" : "", io->t_nextkeys, hb.sent); logl(line);
        if (io->save_nextkeys) io->save_nextkeys(io->ctx);
        if (hb.error) { logl("login: connection lost during the precomputation"); close_ws(); return 1; }
    }
    if (io->prekeys && wa_prekeys_pending(io->prekeys) < io->prekeys_wanted && io->prekeys->n < WA_PREKEYS_MAX) {
        if (!make_prekeys(io->prekeys_wanted - wa_prekeys_pending(io->prekeys), "while online, for the next upload")) { close_ws(); return 1; }
    }
    /* 5. linger / chat: incoming stanzas (messages decrypted when a session store is set), typed lines sent to the peer */
    if (io->sessions && io->chat_user && io->chat_send && !io->msgs_sent) { if (!send_text(io->chat_user, io->chat_device, io->chat_lid, io->chat_send)) logl("msg: the initial text was not sent (second try, after <active/>)"); }
    t_end = ms() + io->linger_ms; last_ka = ms();
    while (ms() < t_end) {
        const wab_node *n; uint32_t now = ms(), left = t_end - now;
        if (!keepalive_due()) break; (void)last_ka;
        if (io->sessions && next_chat_line(&cu, &cd, &cl)) {
            if (chat_line[0] == '/' && chat_line[1] == 'q') { logl("chat: /quit"); break; }
            if (!cu) logl("chat: no peer configured (chat_user), line dropped");
            else if (chat_line[0] && !send_text(cu, cd, cl, chat_line)) logl("chat: the line was not sent");
            continue;
        }
        n = recv_node(left < 1000 ? left : 1000, &gone);
        if (gone) { logl("login: connection closed by the server"); break; }
        if (n && !handle_async(n)) break;
    }
    close_ws();
    return 1;
}

static const char *post_summary(void)
{
    static char s[256];
    wa_fmt(s, sizeof s, "; server prekeys %u + %u uploaded, %s, %u stanzas, %u acks, %u texts sent, %u received, %u undecryptable, %u too long, %u KB received%s", io->server_prekeys, io->prekeys_uploaded,
           io->active_set ? "active" : "not active", io->frames_after_login, io->acks_sent, io->msgs_sent, io->msgs_received, io->msgs_failed, io->msgs_deferred, io->rx_bytes / 1024, io->messages_seen && !io->sessions ? ", messages waiting" : "");
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
        server_time(n); state(WA_CONN_LOGIN, "logged in"); ka_last = ms();
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
        r = recv_frame(20000, &plain, &plen);
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
            r = recv_frame(slice, &plain, &plen);
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
    heartbeat_init(&hb, &w, io->now_ms, 4000, hb_send, 0); hb.poll = drain_poll;
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
        r = recv_frame(30000, &plain, &plen);
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
        if (!handshake(payload, pl, &plain, &plen)) return 0; }
    r = expect_success(plain, plen);
    if (r) r = post_login(); else close_ws();
    if (r) wa_fmt(io->result, sizeof io->result, "RESULT: PAIRED and LOGGED IN as %s:%u (scan -> sign %T s, login connection %T s)%s", io->creds->jid_user, io->creds->jid_device,
                  io->t_sign_sent - io->t_pair_success, io->t_login_accepted - io->t_login_connect, post_summary());
    return r;
}

int wa_probe_run(wa_probe_io *pio)
{
    static uint8_t payload[WA_CLIENTPAYLOAD_MAX]; uint8_t *plain = 0;
    const uint8_t *pp = wa_client_payload; uint32_t pl = sizeof wa_client_payload, plen = 0;

    if (!prepared || io != pio) { if (!wa_probe_prepare(pio)) return 0; }
    prepared = 0;                               /* key pairs are used once */
    io = pio; t_start = io->now_ms(); pend_len = 0; io->rx_bytes = 0;
    io->t_tls = io->t_ws = io->t_hello = io->t_finish = io->t_accepted = 0; io->pongs = io->ladders = 0; io->result[0] = 0;
    io->paired_now = io->logged_in = 0; io->t_qr_shown = io->t_pair_success = io->d_verify = io->d_sign = io->t_sign_sent = io->t_515 = io->t_login_connect = io->t_login_accepted = 0; io->qr_shown = 0;
    io->server_prekeys = io->prekeys_uploaded = io->t_active = io->frames_after_login = io->acks_sent = io->messages_seen = 0; io->have_server_prekeys = io->active_set = 0;
    iq_counter = 0; iq_prefix[0] = 0;
    io->msgs_sent = io->msgs_received = io->msgs_failed = io->msgs_deferred = io->receipts_sent = io->sessions_started = 0; io->d_session = io->d_encrypt = io->d_decrypt = 0;
    io->t_msg_sent = io->t_msg_ack = io->t_msg_receipt = io->t_msg_received = 0; last_msg_id[0] = 0;
    if (io->sessions && !io->sessions_loaded) { sig_store_init(io->sessions); io->sessions_loaded = 1; }
    if (io->mode == WA_MODE_PAIR && io->creds) local_init();

    if (io->mode == WA_MODE_PAIR) {
        if (io->creds->paired) pl = wa_clientpayload_login(payload, sizeof payload, io->creds->jid_user, io->creds->jid_device);
        else pl = wa_clientpayload_registration(payload, sizeof payload, &io->creds->id);
        if (!pl) return fail("RESULT: ClientPayload failed", 0, 0);
        pp = payload;
        wa_fmt(line, sizeof line, "payload: %s ClientPayload, %u bytes", io->creds->paired ? "login" : "registration", pl); logl(line);
    }
    if (!handshake(pp, pl, &plain, &plen)) return 0;
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
    io = pio; t_start = io->now_ms(); pend_len = 0; io->tunnel = 1; io->result[0] = 0; frames_reset(); big_buffers(pio);
    io->paired_now = io->logged_in = 0; io->pongs = 0; io->qr_shown = 0;
    io->t_qr_shown = io->t_pair_success = io->d_verify = io->d_sign = io->t_sign_sent = io->t_515 = io->t_login_connect = io->t_login_accepted = 0;
    io->server_prekeys = io->prekeys_uploaded = io->t_active = io->frames_after_login = io->acks_sent = io->messages_seen = 0; io->have_server_prekeys = io->active_set = 0;
    iq_counter = 0; iq_prefix[0] = 0;
    if (!rng.instantiated) drbg_instantiate(&rng, io->seed, io->seed_len);
    io->msgs_sent = io->msgs_received = io->msgs_failed = io->msgs_deferred = io->receipts_sent = io->sessions_started = 0; io->d_session = io->d_encrypt = io->d_decrypt = 0;
    io->t_msg_sent = io->t_msg_ack = io->t_msg_receipt = io->t_msg_received = 0; last_msg_id[0] = 0;
    if (io->sessions && !io->sessions_loaded) { sig_store_init(io->sessions); io->sessions_loaded = 1; }
    if (io->mode == WA_MODE_PAIR && io->creds) local_init();
    ws_client_start(&w, io->host, "/ws/chat", "https://web.whatsapp.com", msgbuf, WA_PROBE_MSGBUF, &rng, out, sizeof out);
    w.state = WS_OPEN; w.stream = 1; io->rx_bytes = 0;
    for (i = 0; i < sizeof tr; i++) ((uint8_t *)&tr)[i] = 0;
}
static uint8_t sim_first[WA_PROBE_MSG_MAX];
int wa_probe_sim_pair(wa_probe_io *pio, const uint8_t *first_frame, uint32_t len)
{
    uint8_t *plain = sim_first;
    sim_open(pio);
    cp(plain, first_frame, len);
    return pair_session(plain, len);
}
int wa_probe_sim_login(wa_probe_io *pio, const uint8_t *first_frame, uint32_t len)
{
    uint8_t *plain = sim_first;
    int r;
    sim_open(pio);
    if (!rng.instantiated) drbg_instantiate(&rng, io->seed, io->seed_len);
    cp(plain, first_frame, len);
    r = expect_success(plain, len);
    if (r) r = post_login(); else close_ws();
    if (r) wa_fmt(io->result, sizeof io->result, "RESULT: LOGGED IN (sim)%s", post_summary());
    return r;
}
#endif
