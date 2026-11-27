/*
 * Offline simulation of the pairing session in tests/wa_probe_core.c (make pair-sim): a fake WhatsApp server on a
 * fake WebSocket. The core is compiled with -DWA_PROBE_SIM and noise_transport_encrypt/decrypt renamed to the
 * pass-through stubs below (plaintext || 16 dummy tag bytes), so every frame the core sends can be decoded here and
 * every scripted server frame reaches the real pair_session() code: pair-device (the recorded IQ) -> ack expected ->
 * codes shown with short validity (rotation exercised: the "phone" scans the SECOND code) -> pair-success (synthetic,
 * signed for the fixed test identity by tools/pairvectors) -> pair-device-sign expected and checked -> stream:error 515
 * -> close -> the core wants to reconnect: the sim has no reconnect callback, so the session ends there with the
 * credentials complete. A second run feeds <success> to the login path. Also: wrong-secret pair-success -> error IQ
 * 401 and close; exhausted codes -> close without reconnect.
 *   wa_pair_sim <pair_device_iq.bin> <pair_success_iq.bin>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "wa_probe_core.h"
#include "creds.h"
#include "wabinary.h"
#include "noise.h"
#include "prekeys.h"
#include "inflate.h"

int wa_probe_sim_pair(wa_probe_io *pio, const uint8_t *first_frame, uint32_t len);
int wa_probe_sim_login(wa_probe_io *pio, const uint8_t *first_frame, uint32_t len);
void test_identity(wa_identity *id);

/* pass-through "encryption" (the core's calls are renamed to these) */
void sim_encrypt(noise_transport *t, const uint8_t *pt, uint32_t len, uint8_t *ct) { (void)t; memmove(ct, pt, len); memset(ct + len, 0xee, 16); }
int  sim_decrypt(noise_transport *t, const uint8_t *ct, uint32_t len, uint8_t *pt) { (void)t; if (len < 16) return 0; memmove(pt, ct, len - 16); return 1; }

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static struct timespec t0;
static uint32_t now_ms(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return (uint32_t)((ts.tv_sec - t0.tv_sec) * 1000 + (ts.tv_nsec - t0.tv_nsec) / 1000000); }
static void log_line(void *ctx, const char *s) { (void)ctx; printf("+%7.2fs  %s\n", now_ms() / 1000.0, s); fflush(stdout); }

/* ---- the fake server ------------------------------------------------------------------------- */
static uint8_t *pd_frame, *ps_frame; static uint32_t pd_len, ps_len;
static uint8_t queue[8][4096]; static uint32_t qlen[8], qhead, qtail;           /* server -> client frames (decrypted node frames) */
static int coalesce;                                                              /* deliver the next two queued frames in ONE WebSocket message */
static int closed_by_server, closed_after_queue, stage, codes_shown, ticks, pongs, keepalives, acks, signs, errors, closes;
static int counts, uploads, actives, stanza_acks, upload_keys, bad_upload; static char ack_class[2][16], ack_id[2][16], ack_to[2][40];
static wa_prekeys prekeys; static int prekeys_saved; static void save_prekeys(void *ctx) { (void)ctx; prekeys_saved++; }
static uint32_t scan_at_code;                                                     /* which code the "phone" scans (1-based); 0 = never */
static uint32_t exp_first_ms = 3000, exp_next_ms = 1500;
static uint8_t sign_frame[2048]; static uint32_t sign_len;
static char err_code[8], err_text[32];
static uint8_t arena_mem[16384];

static void enqueue(const uint8_t *frame, uint32_t len) { memcpy(queue[qtail & 7], frame, len); qlen[qtail & 7] = len; qtail++; }
static void enqueue_node(const wab_node *n) { uint8_t b[512]; uint32_t l; if (wab_encode_frame(n, b, sizeof b, &l) == WAB_OK) enqueue(b, l); }

/* <iq from=s.whatsapp.net type=result id=ID>[child]</iq> */
static void enqueue_result(const wab_value *id, const wab_node *child)
{
    wab_node n; wab_attr a[3];
    wab_node_init(&n, "iq");
    a[0].key = wab_s("from"); a[0].val = wab_jid_value("", "s.whatsapp.net", 0);
    a[1].key = wab_s("type"); a[1].val = wab_text("result");
    a[2].key = wab_s("id"); a[2].val = *id;
    n.attrs = a; n.n_attrs = 3;
    if (child) { n.val.kind = WAB_LIST; n.children = child; n.n_children = 1; }
    enqueue_node(&n);
}
/* a compressed frame: flags 02, then a zlib stream with one stored block (inflate's Huffman paths are covered by
 * make inflate-test; this exercises the frame path in the core) */
static void enqueue_compressed_node(const wab_node *n)
{
    uint8_t b[1024], f[1100]; uint32_t l, o = 0, ad;
    if (wab_encode_node(n, b, sizeof b, &l) != WAB_OK) { CHECK(!"encode"); return; }
    f[o++] = 0x02; f[o++] = 0x78; f[o++] = 0x01;                /* flags; CMF, FLG */
    f[o++] = 0x01; f[o++] = (uint8_t)l; f[o++] = (uint8_t)(l >> 8); f[o++] = (uint8_t)~l; f[o++] = (uint8_t)(~l >> 8);
    memcpy(f + o, b, l); o += l;
    ad = wa_adler32(b, l); f[o++] = (uint8_t)(ad >> 24); f[o++] = (uint8_t)(ad >> 16); f[o++] = (uint8_t)(ad >> 8); f[o++] = (uint8_t)ad;
    enqueue(f, o);
}
static void enqueue_stream_error(const char *code)
{
    wab_node n; wab_attr a[1];
    wab_node_init(&n, "stream:error"); a[0].key = wab_s("code"); a[0].val = wab_text(code); n.attrs = a; n.n_attrs = 1;
    enqueue_node(&n);
}

/* a WebSocket server frame (unmasked binary) with the 3-byte WA length and the "ciphertext" */
static int32_t io_recv(void *ctx, uint8_t *p, uint32_t cap, uint32_t timeout_ms)
{
    (void)ctx;
    if (closed_by_server) return -1;
    if (qhead == qtail && closed_after_queue) { closed_by_server = 1; return -1; }
    if (qhead == qtail) { usleep(timeout_ms * 1000 > 200000 ? 200000 : timeout_ms * 1000); return 0; }
    {
        uint32_t o = 0, total = 0, k, n = coalesce && qtail - qhead >= 2 ? 2 : 1;
        for (k = 0; k < n; k++) total += 3 + qlen[(qhead + k) & 7] + 16;
        if (coalesce) coalesce = 0;
        if (cap < total + 4) return -1;
        p[o++] = 0x82;
        if (total < 126) p[o++] = (uint8_t)total; else { p[o++] = 126; p[o++] = (uint8_t)(total >> 8); p[o++] = (uint8_t)total; }
        for (k = 0; k < n; k++) {
            uint32_t len = qlen[qhead & 7], flen = len + 16; const uint8_t *f = queue[qhead & 7];
            qhead++;
            p[o++] = (uint8_t)(flen >> 16); p[o++] = (uint8_t)(flen >> 8); p[o++] = (uint8_t)flen;
            memcpy(p + o, f, len); o += len; memset(p + o, 0xee, 16); o += 16;
        }
        return (int32_t)o;
    }
}

/* the client's masked frames: pongs (opcode 10), close (8), binary nodes (2) */
static int io_send(void *ctx, const uint8_t *p, uint32_t n)
{
    (void)ctx;
    while (n >= 2) {
        uint32_t op = p[0] & 15, len = p[1] & 127, o = 2, i; const uint8_t *mask; static uint8_t pl[4096];
        if (len == 126) { len = ((uint32_t)p[2] << 8) | p[3]; o = 4; }
        mask = p + o; o += 4;
        if (o + len > n || len > sizeof pl) return 0;
        for (i = 0; i < len; i++) pl[i] = p[o + i] ^ mask[i & 3];
        if (op == 10) pongs++;
        else if (op == 8) { closes++; }
        else if (op == 2) {
            const wab_node *nd; wab_arena a; int e; uint32_t flen = ((uint32_t)pl[0] << 16) | ((uint32_t)pl[1] << 8) | pl[2];
            CHECK(flen == len - 3 && flen >= 16);
            wab_arena_init(&a, arena_mem, sizeof arena_mem);
            e = wab_decode_frame(pl + 3, flen - 16, &a, &nd);
            CHECK(e == WAB_OK);
            if (e == WAB_OK) {
                const wab_value *type = wab_get_attr(nd, "type"), *id = wab_get_attr(nd, "id"), *xmlns = wab_get_attr(nd, "xmlns");
                CHECK(wab_str_eq(&nd->tag, "iq") || wab_str_eq(&nd->tag, "ack"));
                if (wab_str_eq(&nd->tag, "ack")) {
                    const wab_value *cl = wab_get_attr(nd, "class"), *to = wab_get_attr(nd, "to"); int k = stanza_acks < 2 ? stanza_acks : 1;
                    stanza_acks++;
                    if (cl && cl->kind == WAB_STR) snprintf(ack_class[k], sizeof ack_class[k], "%.*s", (int)cl->str.len, (const char *)cl->str.p);
                    if (id && id->kind == WAB_STR) snprintf(ack_id[k], sizeof ack_id[k], "%.*s", (int)id->str.len, (const char *)id->str.p);
                    if (to && to->kind == WAB_JID) snprintf(ack_to[k], sizeof ack_to[k], "%.*s@%.*s", (int)to->jid.user.len, (const char *)to->jid.user.p, (int)to->jid.server.len, (const char *)to->jid.server.p);
                    CHECK(wab_get_attr(nd, "type") != 0);              /* receipt type / notification type copied */
                }
                else if (xmlns && wab_str_eq(&xmlns->str, "w:p")) { keepalives++; CHECK(type && wab_str_eq(&type->str, "get")); CHECK(wab_get_child(nd, "ping") != 0); }
                else if (xmlns && wab_str_eq(&xmlns->str, "encrypt") && wab_get_child(nd, "count")) {
                    wab_node c; wab_attr ca[1];
                    counts++; CHECK(type && wab_str_eq(&type->str, "get"));
                    wab_node_init(&c, "count"); ca[0].key = wab_s("value"); ca[0].val = wab_text(counts == 1 ? "0" : "3"); c.attrs = ca; c.n_attrs = 1;
                    enqueue_result(id, &c);
                }
                else if (xmlns && wab_str_eq(&xmlns->str, "encrypt") && wab_get_child(nd, "list")) {
                    const wab_node *reg = wab_get_child(nd, "registration"), *ty = wab_get_child(nd, "type"), *idn = wab_get_child(nd, "identity"), *list = wab_get_child(nd, "list"), *skey = wab_get_child(nd, "skey");
                    uint32_t k;
                    uploads++; CHECK(type && wab_str_eq(&type->str, "set"));
                    CHECK(reg && reg->val.kind == WAB_BYTES && reg->val.str.len == 4 && reg->val.str.p[2] == 0x12 && reg->val.str.p[3] == 0x34);
                    CHECK(ty && ty->val.kind == WAB_BYTES && ty->val.str.len == 1 && ty->val.str.p[0] == 5);
                    CHECK(idn && idn->val.kind == WAB_BYTES && idn->val.str.len == 32);
                    CHECK(list && list->val.kind == WAB_LIST && list->n_children == 3);
                    for (k = 0; list && k < list->n_children; k++) {
                        const wab_node *key = &list->children[k], *kid = wab_get_child(key, "id"), *kv = wab_get_child(key, "value");
                        upload_keys++;
                        if (!(wab_str_eq(&key->tag, "key") && kid && kid->val.str.len == 3 && kid->val.str.p[2] == (uint8_t)(k + 1) && kv && kv->val.str.len == 32
                              && memcmp(kv->val.str.p, prekeys.k[k].pub, 32) == 0)) bad_upload++;
                    }
                    CHECK(skey && wab_get_child(skey, "id") && wab_get_child(skey, "value") && wab_get_child(skey, "signature") && wab_get_child(skey, "signature")->val.str.len == 64);
                    enqueue_result(id, 0);
                }
                else if (xmlns && wab_str_eq(&xmlns->str, "passive")) {
                    wab_node ntf, rcpt, cnt; wab_attr na[4], ra[4], ca[1];
                    actives++; CHECK(type && wab_str_eq(&type->str, "set")); CHECK(wab_get_child(nd, "active") != 0);
                    enqueue_result(id, 0);
                    /* what the server then sends: a compressed notification and a receipt (both to be acknowledged) */
                    wab_node_init(&ntf, "notification"); na[0].key = wab_s("from"); na[0].val = wab_jid_value("", "s.whatsapp.net", 0);
                    na[1].key = wab_s("id"); na[1].val = wab_text("1234567890"); na[2].key = wab_s("type"); na[2].val = wab_text("encrypt"); na[3].key = wab_s("t"); na[3].val = wab_text("1764300001");
                    ntf.attrs = na; ntf.n_attrs = 4; wab_node_init(&cnt, "count"); ca[0].key = wab_s("value"); ca[0].val = wab_text("3"); cnt.attrs = ca; cnt.n_attrs = 1;
                    ntf.val.kind = WAB_LIST; ntf.children = &cnt; ntf.n_children = 1;
                    enqueue_compressed_node(&ntf);
                    wab_node_init(&rcpt, "receipt"); ra[0].key = wab_s("from"); ra[0].val = wab_jid_value("4917612345678", "s.whatsapp.net", 0);
                    ra[1].key = wab_s("id"); ra[1].val = wab_text("ABCDEF1234"); ra[2].key = wab_s("type"); ra[2].val = wab_text("read"); ra[3].key = wab_s("t"); ra[3].val = wab_text("1764300002");
                    rcpt.attrs = ra; rcpt.n_attrs = 4;
                    enqueue_node(&rcpt);
                }
                else if (wab_get_child(nd, "pair-device-sign")) {
                    const wab_node *di = wab_get_child(wab_get_child(nd, "pair-device-sign"), "device-identity"); const wab_value *ki;
                    signs++;
                    CHECK(type && wab_str_eq(&type->str, "result"));
                    CHECK(id && wab_str_eq(&id->str, "3EB0ABCDEF"));
                    CHECK(di && di->val.kind == WAB_BYTES && di->val.str.len > 100);
                    ki = di ? wab_get_attr(di, "key-index") : 0; CHECK(ki && wab_str_eq(&ki->str, "3"));
                    memcpy(sign_frame, pl + 3, flen - 16); sign_len = flen - 16;
                    if (stage == 3) { wab_node end; stage = 4; enqueue_stream_error("515"); wab_node_init(&end, "xmlstreamend"); enqueue_node(&end); coalesce = 1; closed_after_queue = 1; }
                }
                else if (type && wab_str_eq(&type->str, "error")) {
                    const wab_node *er = wab_get_child(nd, "error"); const wab_value *c, *t;
                    errors++;
                    c = er ? wab_get_attr(er, "code") : 0; t = er ? wab_get_attr(er, "text") : 0;
                    if (c) snprintf(err_code, sizeof err_code, "%.*s", (int)c->str.len, (const char *)c->str.p);
                    if (t) snprintf(err_text, sizeof err_text, "%.*s", (int)t->str.len, (const char *)t->str.p);
                }
                else if (type && wab_str_eq(&type->str, "result") && nd->val.kind == WAB_NONE) {
                    /* the pair-device ack: id of the recorded IQ */
                    acks++;
                    CHECK(id && id->str.len > 0);
                    if (stage == 1) stage = 2;
                }
                else CHECK(!"unexpected client node");
            }
        }
        p += o + len; n -= o + len;
    }
    return 1;
}
static void show_qr(void *ctx, const char *text, const qr *code, uint32_t valid_ms, uint32_t index, uint32_t count)
{
    (void)ctx; codes_shown++;
    CHECK(strncmp(text, "https://wa.me/settings/linked_devices#2@", 40) == 0);
    CHECK(code->size == 61 && code->version == 11);     /* 277 chars, level L */
    CHECK(count == 6 && index == (uint32_t)codes_shown);
    CHECK(valid_ms == (index == 1 ? exp_first_ms : exp_next_ms));
    if (index == scan_at_code) { enqueue(ps_frame, ps_len); stage = 3; }   /* the phone scans this code "immediately" */
}
static void qr_tick(void *ctx, uint32_t remaining_ms) { (void)ctx; (void)remaining_ms; ticks++; }
static void qr_hide(void *ctx, const char *status) { (void)ctx; printf("           [display] %s\n", status); }
static int saved; static void save_creds(void *ctx) { (void)ctx; saved++; }

static void reset(wa_probe_io *io, wa_creds *creds)
{
    qhead = qtail = 0; closed_by_server = 0; closed_after_queue = 0; coalesce = 0; stage = 1; codes_shown = ticks = pongs = keepalives = acks = signs = errors = closes = 0; sign_len = 0; saved = 0;
    err_code[0] = err_text[0] = 0;
    memset(creds, 0, sizeof *creds); test_identity(&creds->id);
    io->creds = creds; io->creds_loaded = 1; io->paired_now = 0;
    counts = uploads = actives = stanza_acks = upload_keys = bad_upload = prekeys_saved = 0; memset(ack_class, 0, sizeof ack_class); memset(ack_id, 0, sizeof ack_id); memset(ack_to, 0, sizeof ack_to);
    wa_prekeys_init(&prekeys); io->prekeys = &prekeys; io->prekeys_loaded = 1; io->prekeys_wanted = 3; io->save_prekeys = save_prekeys; io->linger_ms = 1500;
}

int main(int argc, char **argv)
{
    static wa_probe_io io; static wa_creds creds; static uint8_t seed[64]; FILE *f; int r;
    if (argc != 3) { printf("usage: wa_pair_sim <pair_device_iq.bin> <pair_success_iq.bin>\n"); return 2; }
    clock_gettime(CLOCK_MONOTONIC, &t0);
    f = fopen(argv[1], "rb"); pd_frame = malloc(4096); pd_len = (uint32_t)fread(pd_frame, 1, 4096, f); fclose(f);
    f = fopen(argv[2], "rb"); ps_frame = malloc(4096); ps_len = (uint32_t)fread(ps_frame, 1, 4096, f); fclose(f);
    memset(seed, 7, sizeof seed);
    io.send = io_send; io.recv = io_recv; io.reconnect = 0; io.now_ms = now_ms; io.log = log_line;
    io.host = "web.whatsapp.com"; io.seed = seed; io.seed_len = 64; io.mode = WA_MODE_PAIR; io.debug = 0;
    io.show_qr = show_qr; io.qr_tick = qr_tick; io.qr_hide = qr_hide; io.save_creds = save_creds; io.qr_mask = QR_MASK_AUTO;
    io.qr_first_ms = 3000; io.qr_next_ms = 1500;

    /* ---- A: the phone scans the second code; full path up to the reconnect ---- */
    printf("--- A: pair-device, two codes, scan, pair-success, pair-device-sign, 515 ---\n");
    reset(&io, &creds); scan_at_code = 2;
    r = wa_probe_sim_pair(&io, pd_frame, pd_len);
    printf("%s\n", io.result);
    CHECK(r == 0 && strstr(io.result, "no reconnect callback") != 0);   /* the sim stops where the login connection would start */
    CHECK(acks == 1 && codes_shown == 2 && signs == 1 && errors == 0 && closes == 1);
    CHECK(ticks >= 2 && pongs == 0);                                      /* first code 3 s: no 4-s pong due yet */
    CHECK(io.paired_now && creds.paired && saved == 1);
    CHECK(strcmp(creds.jid_user, "4917612345678") == 0 && creds.jid_device == 7 && strcmp(creds.lid_user, "123456789012345") == 0);
    CHECK(strcmp(creds.platform, "android") == 0 && strcmp(creds.business, "Amiga Test") == 0);
    CHECK(creds.adv.key_index == 3 && creds.adv.signed_by_us && wa_pair_check_device_sig(&creds.adv, &creds.id));
    CHECK(io.t_515 && io.t_sign_sent && io.t_pair_success && io.t_qr_shown && io.d_verify && io.qr_shown == 2);   /* the 515 was the first of two frames in one message */
    { f = fopen("build/pair_sim_sign.bin", "wb"); if (f) { fwrite(sign_frame, 1, sign_len, f); fclose(f); } }

    /* ---- B: wrong ADV secret in the identity: error IQ 401 hmac-mismatch, close, no sign ---- */
    printf("--- B: pair-success under a foreign ADV secret ---\n");
    reset(&io, &creds); scan_at_code = 1; creds.id.adv_secret[5] ^= 1;
    r = wa_probe_sim_pair(&io, pd_frame, pd_len);
    printf("%s\n", io.result);
    CHECK(r == 0 && strstr(io.result, "REJECTED") != 0 && signs == 0 && errors == 1 && closes == 1 && !creds.paired && saved == 0);
    CHECK(strcmp(err_code, "401") == 0 && strcmp(err_text, "hmac-mismatch") == 0);

    /* ---- C: nobody scans: 6 codes, pongs and keepalives while waiting, close, no reconnect ---- */
    printf("--- C: codes exhausted (6 x short validity) ---\n");
    reset(&io, &creds); scan_at_code = 0; io.qr_first_ms = exp_first_ms = 4500; io.qr_next_ms = exp_next_ms = 1000;
    r = wa_probe_sim_pair(&io, pd_frame, pd_len);
    printf("%s\n", io.result);
    CHECK(r == 0 && strstr(io.result, "not scanned") != 0 && codes_shown == 6 && signs == 0 && closes == 1 && !creds.paired);
    CHECK(pongs >= 1);                                                    /* 4.5 s first code: one pong due */
    io.qr_first_ms = exp_first_ms = 3000; io.qr_next_ms = exp_next_ms = 1500;

    /* ---- D: the login connection's first frame ---- */
    printf("--- D: login: <success> / <failure> ---\n");
    {   wab_node n; wab_attr a[2]; uint8_t b[256]; uint32_t l;
        reset(&io, &creds); creds.paired = 1; strcpy(creds.jid_user, "4917612345678"); creds.jid_device = 7;
        wab_node_init(&n, "success"); a[0].key = wab_s("t"); a[0].val = wab_text("1764300000"); a[1].key = wab_s("lid"); a[1].val = wab_jid_value("123456789012345", "lid", 7);
        n.attrs = a; n.n_attrs = 2;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        { hmac_drbg prng; drbg_instantiate(&prng, seed, sizeof seed); wa_prekeys_generate(&prekeys, 3, &prng); }   /* the sim skips wa_probe_prepare */
        r = wa_probe_sim_login(&io, b, l);
        printf("%s\n", io.result);
        CHECK(r == 1 && io.logged_in);
        CHECK(counts == 1 && uploads == 1 && actives == 1 && upload_keys == 3 && bad_upload == 0);
        CHECK(io.server_prekeys == 0 && io.prekeys_uploaded == 3 && io.active_set && prekeys_saved == 1 && wa_prekeys_pending(&prekeys) == 0);
        CHECK(stanza_acks == 2 && io.acks_sent == 2 && io.frames_after_login == 5);   /* 3 results + notification + receipt */
        CHECK(strcmp(ack_class[0], "notification") == 0 && strcmp(ack_id[0], "1234567890") == 0 && strcmp(ack_to[0], "@s.whatsapp.net") == 0);
        CHECK(strcmp(ack_class[1], "receipt") == 0 && strcmp(ack_id[1], "ABCDEF1234") == 0 && strcmp(ack_to[1], "4917612345678@s.whatsapp.net") == 0);
        CHECK(closes == 1);
        /* a second login: the server now has 3 prekeys, nothing pending -> no upload */
        reset(&io, &creds); creds.paired = 1; strcpy(creds.jid_user, "4917612345678"); creds.jid_device = 7; counts = 1; /* so the fake answers "3" */
        wab_node_init(&n, "success"); a[0].key = wab_s("t"); a[0].val = wab_text("1764300000"); a[1].key = wab_s("lid"); a[1].val = wab_jid_value("123456789012345", "lid", 7); n.attrs = a; n.n_attrs = 2;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        r = wa_probe_sim_login(&io, b, l);
        CHECK(r == 1 && uploads == 0 && actives == 1 && io.server_prekeys == 3 && io.prekeys_uploaded == 0);
        wab_node_init(&n, "failure"); a[0].key = wab_s("reason"); a[0].val = wab_text("401"); n.attrs = a; n.n_attrs = 1;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        r = wa_probe_sim_login(&io, b, l);
        printf("%s\n", io.result);
        CHECK(r == 0 && !io.logged_in && strstr(io.result, "REJECTED") != 0);
    }
    printf("%s: %d checks, %d failures\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails ? 1 : 0;
}
