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
#include <ctype.h>
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
#include "../proto/signal.h"
#include "ed25519.h"

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
static uint8_t queue[16][4096]; static uint32_t qlen[16], qhead, qtail;           /* server -> client frames (decrypted node frames) */
static int coalesce;                                                              /* deliver the next N (2 by default) queued frames in ONE WebSocket message */
static int coalesce_n = 2;
static uint32_t fat_frame;                                                        /* F/G: a frame of this many bytes (longer than a TLS record) leads the message */
static int fat_batch; static uint32_t fat_first;                                 /* F/G: the "offline batch" after <active/>: fat frame + 6 fat notifications in one message */
static uint32_t fat_size; static int fat_real;                                    /* the fat frame: a real 40 KB stanza (F, decoded and acknowledged) or garbage longer than the core's buffer (G, skipped) */
static uint8_t fatbuf[65536]; static uint32_t fat_len;                            /* F: the encoded fat stanza */
static uint8_t big[262144]; static uint32_t big_len, big_off, rx_total;           /* the WebSocket message being served in chunks */
static int closed_by_server, closed_after_queue, stage, codes_shown, ticks, pongs, keepalives, acks, signs, errors, closes;
static int counts, uploads, actives, stanza_acks, upload_keys, bad_upload, fat_acked; static uint32_t rx_before_batch; static char ack_class[2][16], ack_id[2][16], ack_to[2][40];
static wa_prekeys prekeys; static int prekeys_saved; static void save_prekeys(void *ctx) { (void)ctx; prekeys_saved++; }
static uint32_t scan_at_code;                                                     /* which code the "phone" scans (1-based); 0 = never */
static uint32_t exp_first_ms = 3000, exp_next_ms = 1500;
static uint8_t sign_frame[2048]; static uint32_t sign_len;
static char err_code[8], err_text[32];
static uint8_t arena_mem[16384];

static void enqueue(const uint8_t *frame, uint32_t len) { memcpy(queue[qtail & 15], frame, len); qlen[qtail & 15] = len; qtail++; }
static void enqueue_node(const wab_node *n) { static uint8_t b[4096]; uint32_t l; if (wab_encode_frame(n, b, sizeof b, &l) == WAB_OK) enqueue(b, l); else CHECK(!"encode (queue frame)"); }

static void enqueue_result(const wab_value *id, const wab_node *child);
/* ---- E: the Signal vectors (tests/vectors/signal_vectors.txt, name=hex) and the fake phone ---- */
static char *vec_text; static uint32_t vec_len;
static uint32_t vec(const char *name, uint8_t *out, uint32_t cap)
{
    const char *p = vec_text, *e; uint32_t n = 0, k = strlen(name);
    while (p && p < vec_text + vec_len) {
        if (strncmp(p, name, k) == 0 && p[k] == '=') {
            p += k + 1;
            while (n < cap && isxdigit((unsigned char)p[0]) && isxdigit((unsigned char)p[1])) { unsigned v; sscanf(p, "%2x", &v); out[n++] = (uint8_t)v; p += 2; }
            return n;
        }
        e = strchr(p, '\n'); p = e ? e + 1 : 0;
    }
    return 0;
}
static int bundles, msgs, receipts, sessions_saved, phone_sent; static char msg_id[32]; static char rcpt_type[2][16], rcpt_id[2][16];
static char recv_text[2][200]; static int recv_n; static uint8_t enc_out[1400]; static uint32_t enc_out_len; static int enc_is_pk;
static sig_store sessions;
static void save_sessions(void *ctx) { (void)ctx; sessions_saved++; }
static void chat_recv(void *ctx, const char *from, const char *text)
{
    (void)ctx; CHECK(strcmp(from, "4917612345678:0") == 0);
    if (recv_n < 2) snprintf(recv_text[recv_n], sizeof recv_text[0], "%s", text);
    recv_n++;
}
/* Bob's (the phone's) prekey bundle as the server lists it: registration BE32, type 05, identity, skey{id BE24, value,
 * signature}, key{id, value} */
static void enqueue_bundle(const wab_value *iq_id)
{
    static wab_node list, usr, parts[5], sk[3], ok[2]; static wab_attr ua[1];
    static uint8_t ident[32], spk[32], sig[64], opk[32]; static const uint8_t reg[4] = { 0, 0, 0xBE, 0xEF }, ty[1] = { 5 }, skid[3] = { 0, 0, 7 }, okid[3] = { 0, 0, 42 };
    CHECK(vec("bob_ident_pub", ident, 32) == 32 && vec("bob_spk_pub", spk, 32) == 32 && vec("bob_spk_sig", sig, 64) == 64 && vec("bob_opk_pub", opk, 32) == 32);
    wab_node_init(&parts[0], "registration"); parts[0].val = wab_bytes(reg, 4);
    wab_node_init(&parts[1], "type"); parts[1].val = wab_bytes(ty, 1);
    wab_node_init(&parts[2], "identity"); parts[2].val = wab_bytes(ident, 32);
    wab_node_init(&sk[0], "id"); sk[0].val = wab_bytes(skid, 3); wab_node_init(&sk[1], "value"); sk[1].val = wab_bytes(spk, 32); wab_node_init(&sk[2], "signature"); sk[2].val = wab_bytes(sig, 64);
    wab_node_init(&parts[3], "skey"); parts[3].val.kind = WAB_LIST; parts[3].children = sk; parts[3].n_children = 3;
    wab_node_init(&ok[0], "id"); ok[0].val = wab_bytes(okid, 3); wab_node_init(&ok[1], "value"); ok[1].val = wab_bytes(opk, 32);
    wab_node_init(&parts[4], "key"); parts[4].val.kind = WAB_LIST; parts[4].children = ok; parts[4].n_children = 2;
    wab_node_init(&usr, "user"); ua[0].key = wab_s("jid"); ua[0].val = wab_jid_value("4917612345678", "s.whatsapp.net", 0); usr.attrs = ua; usr.n_attrs = 1;
    usr.val.kind = WAB_LIST; usr.children = parts; usr.n_children = 5;
    wab_node_init(&list, "list"); list.val.kind = WAB_LIST; list.children = &usr; list.n_children = 1;
    enqueue_result(iq_id, &list);
}
/* <message from=phone id type=text t><enc v=2 type=pkmsg|msg>vector</enc></message> */
static void enqueue_phone_message(const char *vector, const char *id, const char *type)
{
    static wab_node m, enc; static wab_attr ma[4], ea[2]; static uint8_t body[2][1024]; static int slot; uint32_t l;
    uint8_t *b = body[slot & 1]; slot++;
    l = vec(vector, b, 1024); CHECK(l > 50);
    wab_node_init(&enc, "enc"); ea[0].key = wab_s("v"); ea[0].val = wab_text("2"); ea[1].key = wab_s("type"); ea[1].val = wab_text(type); enc.attrs = ea; enc.n_attrs = 2; enc.val = wab_bytes(b, l);
    wab_node_init(&m, "message");
    ma[0].key = wab_s("from"); ma[0].val = wab_jid_value("4917612345678", "s.whatsapp.net", 0);
    ma[1].key = wab_s("id"); ma[1].val = wab_text(id); ma[2].key = wab_s("type"); ma[2].val = wab_text("text"); ma[3].key = wab_s("t"); ma[3].val = wab_text("1764300010");
    m.attrs = ma; m.n_attrs = 4; m.val.kind = WAB_LIST; m.children = &enc; m.n_children = 1;
    enqueue_node(&m);
}

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
    if (big_off >= big_len) {
        if (qhead == qtail) { usleep(timeout_ms * 1000 > 200000 ? 200000 : timeout_ms * 1000); return 0; }
        /* build the next WebSocket message (one or several WA frames, optionally led by an oversize one) into big */
        uint32_t o = 0, total = 0, k, n;
        if (fat_batch && qhead == fat_first) { fat_batch = 0; fat_frame = fat_real ? fat_len + 16 : fat_size; coalesce = 1; coalesce_n = 6; rx_before_batch = rx_total; }   /* F/G: the fat message */
        n = coalesce && qtail - qhead >= (uint32_t)coalesce_n ? (uint32_t)coalesce_n : 1;
        for (k = 0; k < n; k++) total += 3 + qlen[(qhead + k) & 15] + 16;
        if (fat_frame) total += 3 + fat_frame;
        if (coalesce) coalesce = 0;
        big[o++] = 0x82;
        if (total < 126) big[o++] = (uint8_t)total; else if (total < 65536) { big[o++] = 126; big[o++] = (uint8_t)(total >> 8); big[o++] = (uint8_t)total; }
        else { big[o++] = 127; memset(big + o, 0, 4); o += 4; big[o++] = (uint8_t)(total >> 24); big[o++] = (uint8_t)(total >> 16); big[o++] = (uint8_t)(total >> 8); big[o++] = (uint8_t)total; }
        if (fat_frame) {
            big[o++] = (uint8_t)(fat_frame >> 16); big[o++] = (uint8_t)(fat_frame >> 8); big[o++] = (uint8_t)fat_frame;
            if (fat_real) { memcpy(big + o, fatbuf, fat_len); memset(big + o + fat_len, 0xee, 16); } else memset(big + o, 0xfa, fat_frame);
            o += fat_frame; fat_frame = 0;
        }
        for (k = 0; k < n; k++) {
            uint32_t len = qlen[qhead & 15], flen = len + 16; const uint8_t *f = queue[qhead & 15];
            qhead++;
            big[o++] = (uint8_t)(flen >> 16); big[o++] = (uint8_t)(flen >> 8); big[o++] = (uint8_t)flen;
            memcpy(big + o, f, len); o += len; memset(big + o, 0xee, 16); o += 16;
        }
        big_len = o; big_off = 0;
        if (fat_frame == 0 && coalesce_n == 6) coalesce_n = 2;
    }
    {   /* served in chunks no larger than the caller's buffer (the TCP stack hands over what has arrived) */
        uint32_t c = big_len - big_off; if (c > cap) c = cap;
        memcpy(p, big + big_off, c); big_off += c; rx_total += c;
        return (int32_t)c;
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
                CHECK(wab_str_eq(&nd->tag, "iq") || wab_str_eq(&nd->tag, "ack") || wab_str_eq(&nd->tag, "message") || wab_str_eq(&nd->tag, "receipt"));
                if (wab_str_eq(&nd->tag, "message")) {
                    /* our text to the phone: <message id type=text to><participants><to jid><enc v=2 type/></to></participants>[<device-identity/>]</message> */
                    const wab_value *to = wab_get_attr(nd, "to"); const wab_node *parts = wab_get_child(nd, "participants"), *pto = parts ? wab_get_child(parts, "to") : 0, *enc = pto ? wab_get_child(pto, "enc") : 0, *di = wab_get_child(nd, "device-identity");
                    const wab_value *v = enc ? wab_get_attr(enc, "v") : 0, *et = enc ? wab_get_attr(enc, "type") : 0, *pj = pto ? wab_get_attr(pto, "jid") : 0;
                    wab_node ack; wab_attr aa[3];
                    msgs++;
                    CHECK(id && id->kind == WAB_STR && id->str.len == 22 && strncmp((const char *)id->str.p, "3EB0", 4) == 0);
                    CHECK(type && wab_str_eq(&type->str, "text"));
                    CHECK(to && to->kind == WAB_JID && wab_str_eq(&to->jid.user, "4917612345678") && wab_str_eq(&to->jid.server, "s.whatsapp.net") && to->jid.device == 0);
                    CHECK(pj && pj->kind == WAB_JID && wab_str_eq(&pj->jid.user, "4917612345678") && pj->jid.device == 0);
                    CHECK(v && wab_str_eq(&v->str, "2"));
                    CHECK(et && (wab_str_eq(&et->str, "pkmsg") || wab_str_eq(&et->str, "msg")));
                    enc_is_pk = et && wab_str_eq(&et->str, "pkmsg");
                    CHECK(enc_is_pk ? di && di->val.kind == WAB_BYTES && di->val.str.len > 100 : di == 0);   /* the device identity rides along with a prekey message */
                    if (enc && enc->val.kind == WAB_BYTES && enc->val.str.len <= sizeof enc_out) { memcpy(enc_out, enc->val.str.p, enc->val.str.len); enc_out_len = enc->val.str.len; }
                    if (id && id->kind == WAB_STR) snprintf(msg_id, sizeof msg_id, "%.*s", (int)id->str.len, (const char *)id->str.p);
                    /* the server's ack, then (first message only) the phone's two answers: a prekey message starting a new session, a plain one */
                    wab_node_init(&ack, "ack"); aa[0].key = wab_s("class"); aa[0].val = wab_text("message"); aa[1].key = wab_s("id"); aa[1].val = *id; aa[2].key = wab_s("from"); aa[2].val = *to;
                    ack.attrs = aa; ack.n_attrs = 3; enqueue_node(&ack);
                    /* both answers are prekey messages: libsignal keeps sending those until it has seen a message of ours on the new session */
                    if (!phone_sent) { phone_sent = 1; enqueue_phone_message("wa_pkmsg1", "PHONE0000000001", "pkmsg"); enqueue_phone_message("wa_msg2", "PHONE0000000002", "pkmsg"); }
                }
                else if (wab_str_eq(&nd->tag, "receipt")) {
                    const wab_value *to = wab_get_attr(nd, "to"); int k = receipts < 2 ? receipts : 1;
                    receipts++;
                    CHECK(to && to->kind == WAB_JID && wab_str_eq(&to->jid.user, "4917612345678") && to->jid.device == 0);
                    CHECK(wab_get_attr(nd, "participant") == 0 && wab_get_attr(nd, "recipient") == 0);
                    if (type && type->kind == WAB_STR) snprintf(rcpt_type[k], sizeof rcpt_type[k], "%.*s", (int)type->str.len, (const char *)type->str.p);
                    if (id && id->kind == WAB_STR) snprintf(rcpt_id[k], sizeof rcpt_id[k], "%.*s", (int)id->str.len, (const char *)id->str.p);
                }
                else if (wab_str_eq(&nd->tag, "ack")) {
                    const wab_value *cl = wab_get_attr(nd, "class"), *to = wab_get_attr(nd, "to"); int k = stanza_acks < 2 ? stanza_acks : 1;
                    stanza_acks++;
                    if (cl && cl->kind == WAB_STR) snprintf(ack_class[k], sizeof ack_class[k], "%.*s", (int)cl->str.len, (const char *)cl->str.p);
                    if (id && id->kind == WAB_STR) snprintf(ack_id[k], sizeof ack_id[k], "%.*s", (int)id->str.len, (const char *)id->str.p);
                    if (id && id->kind == WAB_STR && id->str.len == 10 && memcmp(id->str.p, "FATBIG0001", 10) == 0) fat_acked++;
                    if (to && to->kind == WAB_JID) snprintf(ack_to[k], sizeof ack_to[k], "%.*s@%.*s", (int)to->jid.user.len, (const char *)to->jid.user.p, (int)to->jid.server.len, (const char *)to->jid.server.p);
                    CHECK((wab_get_attr(nd, "type") != 0) == (strcmp(ack_class[k], "message") != 0));   /* receipt / notification type copied, none for a message (whatsmeow) */
                }
                else if (xmlns && wab_str_eq(&xmlns->str, "w:p")) { keepalives++; CHECK(type && wab_str_eq(&type->str, "get")); CHECK(wab_get_child(nd, "ping") != 0); }
                else if (xmlns && wab_str_eq(&xmlns->str, "encrypt") && wab_get_child(nd, "count")) {
                    wab_node c; wab_attr ca[1];
                    counts++; CHECK(type && wab_str_eq(&type->str, "get"));
                    wab_node_init(&c, "count"); ca[0].key = wab_s("value"); ca[0].val = wab_text(counts == 1 ? "0" : "3"); c.attrs = ca; c.n_attrs = 1;
                    enqueue_result(id, &c);
                }
                else if (xmlns && wab_str_eq(&xmlns->str, "encrypt") && wab_get_child(nd, "key")) {
                    const wab_node *u = wab_get_child(wab_get_child(nd, "key"), "user"); const wab_value *uj = u ? wab_get_attr(u, "jid") : 0, *rs = u ? wab_get_attr(u, "reason") : 0;
                    bundles++; CHECK(type && wab_str_eq(&type->str, "get"));
                    CHECK(uj && uj->kind == WAB_JID && wab_str_eq(&uj->jid.user, "4917612345678") && wab_str_eq(&uj->jid.server, "s.whatsapp.net") && uj->jid.device == 0);
                    CHECK(rs && wab_str_eq(&rs->str, "identity"));
                    enqueue_bundle(id);
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
                    if (fat_batch) {
                        /* F/G: the offline batch as one WebSocket message far longer than a TLS record: a fat frame
                           (F: a real 40 KB notification, decoded and acknowledged; G: 200 KB of garbage, longer than
                           the core's buffer, skipped) followed by six 3 KB notifications (acknowledged), then the marker */
                        static uint8_t blob[3000], bigblob[40000]; static wab_node fn[6], fc[6], fatn, fatc; static wab_attr fa[6][4], fta[4]; static char ids[6][12]; static wab_node ib, off; static wab_attr ia[1], oa[1]; int k;
                        memset(blob, 0x5b, sizeof blob); memset(bigblob, 0x5c, sizeof bigblob);
                        if (fat_real) {
                            wab_node_init(&fatn, "notification"); fta[0].key = wab_s("from"); fta[0].val = wab_jid_value("", "s.whatsapp.net", 0);
                            fta[1].key = wab_s("id"); fta[1].val = wab_text("FATBIG0001"); fta[2].key = wab_s("type"); fta[2].val = wab_text("server_sync"); fta[3].key = wab_s("t"); fta[3].val = wab_text("1764300003");
                            fatn.attrs = fta; fatn.n_attrs = 4;
                            wab_node_init(&fatc, "collection"); fatc.val = wab_bytes(bigblob, sizeof bigblob);
                            fatn.val.kind = WAB_LIST; fatn.children = &fatc; fatn.n_children = 1;
                            CHECK(wab_encode_frame(&fatn, fatbuf, sizeof fatbuf, &fat_len) == WAB_OK && fat_len > 40000);
                        }
                        for (k = 0; k < 6; k++) {
                            snprintf(ids[k], sizeof ids[k], "FAT%07d", k);
                            wab_node_init(&fn[k], "notification"); fa[k][0].key = wab_s("from"); fa[k][0].val = wab_jid_value("", "s.whatsapp.net", 0);
                            fa[k][1].key = wab_s("id"); fa[k][1].val = wab_text(ids[k]); fa[k][2].key = wab_s("type"); fa[k][2].val = wab_text("status"); fa[k][3].key = wab_s("t"); fa[k][3].val = wab_text("1764300003");
                            fn[k].attrs = fa[k]; fn[k].n_attrs = 4;
                            wab_node_init(&fc[k], "blob"); fc[k].val = wab_bytes(blob, sizeof blob);
                            fn[k].val.kind = WAB_LIST; fn[k].children = &fc[k]; fn[k].n_children = 1;
                        }
                        /* the frames already queued go out one by one; the message starting with the first fat
                           notification carries the oversize frame in front and all six notifications */
                        fat_first = qtail;
                        for (k = 0; k < 6; k++) enqueue_node(&fn[k]);
                        wab_node_init(&off, "offline"); oa[0].key = wab_s("count"); oa[0].val = wab_text("7"); off.attrs = oa; off.n_attrs = 1;
                        wab_node_init(&ib, "ib"); ia[0].key = wab_s("from"); ia[0].val = wab_jid_value("", "s.whatsapp.net", 0); ib.attrs = ia; ib.n_attrs = 1; ib.val.kind = WAB_LIST; ib.children = &off; ib.n_children = 1;
                        enqueue_node(&ib);
                    }
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
    qhead = qtail = 0; closed_by_server = 0; closed_after_queue = 0; coalesce = 0; coalesce_n = 2; fat_frame = 0; fat_batch = 0; fat_first = 0xffffffffu; fat_size = 0; fat_real = 0; fat_len = 0; fat_acked = 0; big_len = big_off = 0; rx_total = 0; rx_before_batch = 0; stage = 1; codes_shown = ticks = pongs = keepalives = acks = signs = errors = closes = 0; sign_len = 0; saved = 0;
    err_code[0] = err_text[0] = 0;
    memset(creds, 0, sizeof *creds); test_identity(&creds->id);
    io->creds = creds; io->creds_loaded = 1; io->paired_now = 0;
    counts = uploads = actives = stanza_acks = upload_keys = bad_upload = prekeys_saved = 0; memset(ack_class, 0, sizeof ack_class); memset(ack_id, 0, sizeof ack_id); memset(ack_to, 0, sizeof ack_to);
    wa_prekeys_init(&prekeys); io->prekeys = &prekeys; io->prekeys_loaded = 1; io->prekeys_wanted = 3; io->save_prekeys = save_prekeys; io->linger_ms = 1500;
}

int main(int argc, char **argv)
{
    static wa_probe_io io; static wa_creds creds; static uint8_t seed[64]; FILE *f; int r;
    if (argc != 3 && argc != 4) { printf("usage: wa_pair_sim <pair_device_iq.bin> <pair_success_iq.bin> [signal_vectors.txt]\n"); return 2; }
    if (argc == 4) { f = fopen(argv[3], "rb"); if (!f) { printf("cannot open %s\n", argv[3]); return 2; } vec_text = malloc(65536); vec_len = (uint32_t)fread(vec_text, 1, 65535, f); vec_text[vec_len] = 0; fclose(f); }
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
        CHECK(io.server_prekeys == 0 && io.prekeys_uploaded == 3 && io.active_set);
        /* after the upload the idle phase regenerates the batch: 3 pending again, record saved twice (upload, refill) */
        CHECK(prekeys_saved == 2 && wa_prekeys_pending(&prekeys) == 3 && prekeys.n == 6 && io.nextkeys_ready == 0);
        CHECK(stanza_acks == 2 && io.acks_sent == 2 && io.frames_after_login == 5);   /* 3 results + notification + receipt */
        CHECK(strcmp(ack_class[0], "notification") == 0 && strcmp(ack_id[0], "1234567890") == 0 && strcmp(ack_to[0], "@s.whatsapp.net") == 0);
        CHECK(strcmp(ack_class[1], "receipt") == 0 && strcmp(ack_id[1], "ABCDEF1234") == 0 && strcmp(ack_to[1], "4917612345678@s.whatsapp.net") == 0);
        CHECK(closes == 1);
        /* a second login: the server holds 3 (< 5) and nothing is pending -> a batch is generated online, then uploaded,
         * and the idle phase refills the pending batch */
        reset(&io, &creds); creds.paired = 1; strcpy(creds.jid_user, "4917612345678"); creds.jid_device = 7; counts = 1; /* so the fake answers "3" */
        wab_node_init(&n, "success"); a[0].key = wab_s("t"); a[0].val = wab_text("1764300000"); a[1].key = wab_s("lid"); a[1].val = wab_jid_value("123456789012345", "lid", 7); n.attrs = a; n.n_attrs = 2;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        r = wa_probe_sim_login(&io, b, l);
        CHECK(r == 1 && uploads == 1 && actives == 1 && io.server_prekeys == 3 && io.prekeys_uploaded == 3 && upload_keys == 3);
        CHECK(wa_prekeys_pending(&prekeys) == 3 && prekeys.n == 6 && prekeys_saved == 3);   /* saved: generated, uploaded, refilled */
        wab_node_init(&n, "failure"); a[0].key = wab_s("reason"); a[0].val = wab_text("401"); n.attrs = a; n.n_attrs = 1;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        r = wa_probe_sim_login(&io, b, l);
        printf("%s\n", io.result);
        CHECK(r == 0 && !io.logged_in && strstr(io.result, "REJECTED") != 0);
    }
    /* ---- E: the interim chat (docs/SIGNAL.md): our text to the phone (bundle, X3DH, pkmsg + device identity), the
     * phone's two answers (a prekey message that starts a session the other way round, then a plain message), receipts;
     * a second connection reuses the stored session (plain msg, no bundle) ---- */
    if (vec_text) {
        wab_node n; wab_attr a[2]; uint8_t b[256]; uint32_t l; int i;
        printf("--- E: chat: bundle, pkmsg out, two pkmsg in, receipts, session reuse ---\n");
        reset(&io, &creds); creds.paired = 1; strcpy(creds.jid_user, "4917612345678"); creds.jid_device = 7; strcpy(creds.lid_user, "123456789012345"); creds.lid_device = 7;
        creds.adv.details_len = 120; memset(creds.adv.details, 0x5a, 120); memset(creds.adv.account_sig_key, 1, 32); memset(creds.adv.account_sig, 2, 64); memset(creds.adv.device_sig, 3, 64);
        { hmac_drbg prng; drbg_instantiate(&prng, seed, sizeof seed); wa_prekeys_generate(&prekeys, 3, &prng); }
        /* the one-time prekey the phone used (tools/signalvectors: Alice's OPK 5), already uploaded */
        { wa_prekey *k = &prekeys.k[prekeys.n++]; k->id = 5; for (i = 0; i < 32; i++) k->priv[i] = (uint8_t)(i * 37 + 23); k->priv[0] &= 248; k->priv[31] &= 127; k->priv[31] |= 64; x25519_base_comb(k->pub, k->priv); k->uploaded = 1; if (prekeys.next_id <= 5) prekeys.next_id = 6; }
        io.sessions = &sessions; io.sessions_loaded = 0; io.save_sessions = save_sessions; io.chat_recv = chat_recv; io.chat_input = 0;
        io.chat_user = "4917612345678"; io.chat_device = 0; io.chat_lid = 0; io.chat_send = "Hallo vom Amiga"; io.linger_ms = 3000;
        bundles = msgs = receipts = sessions_saved = recv_n = 0; enc_out_len = 0; memset(rcpt_type, 0, sizeof rcpt_type); memset(rcpt_id, 0, sizeof rcpt_id); memset(recv_text, 0, sizeof recv_text);
        wab_node_init(&n, "success"); a[0].key = wab_s("t"); a[0].val = wab_text("1764300000"); a[1].key = wab_s("lid"); a[1].val = wab_jid_value("123456789012345", "lid", 7); n.attrs = a; n.n_attrs = 2;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        r = wa_probe_sim_login(&io, b, l);
        printf("%s\n", io.result);
        CHECK(r == 1 && io.logged_in && uploads == 1 && actives == 1);
        CHECK(bundles == 1 && msgs == 1 && enc_is_pk && enc_out_len > 100 && msg_id[0] == '3');
        CHECK(io.msgs_sent == 1 && io.sessions_started == 1 && io.t_msg_ack > 0 && io.t_msg_sent > 0 && io.d_session > 0);
        CHECK(io.msgs_received == 2 && io.msgs_failed == 0 && receipts == 2 && io.receipts_sent == 2);
        CHECK(strcmp(rcpt_type[0], "sender") == 0 && strcmp(rcpt_id[0], "PHONE0000000001") == 0 && strcmp(rcpt_type[1], "sender") == 0 && strcmp(rcpt_id[1], "PHONE0000000002") == 0);
        CHECK(recv_n == 2 && strcmp(recv_text[0], "Antwort vom Telefon: hallo Amiga!") == 0 && strcmp(recv_text[1], "zweite Nachricht, gleiche Sitzung \xe4\xf6\xfc") == 0);   /* UTF-8 -> Latin-1 for the console */
        CHECK(wa_prekeys_find(&prekeys, 5) == 0 && prekeys.n == 6);          /* the one-time prekey is gone; 3 uploaded + 3 refilled remain */
        CHECK(sessions.n == 1 && sessions_saved >= 3 && stanza_acks == 2);   /* no ack for decrypted messages: receipts only */
        { f = fopen("build/msg_pkmsg.bin", "wb"); if (f) { fwrite(enc_out, 1, enc_out_len, f); fclose(f); } }
        /* the store survives a write/read round trip and the next connection sends a plain message on the phone's session */
        {   static uint8_t rec[SIG_STORE_MAX_SIZE]; uint32_t rl = sig_store_write(rec, sizeof rec, &sessions);
            CHECK(rl > 0 && sig_store_read(&sessions, rec, rl) && sessions.n == 1);
        }
        reset(&io, &creds); creds.paired = 1; strcpy(creds.jid_user, "4917612345678"); creds.jid_device = 7; counts = 1;
        io.sessions = &sessions; io.sessions_loaded = 1; io.save_sessions = save_sessions; io.chat_recv = chat_recv; io.chat_input = 0;
        io.chat_user = "4917612345678"; io.chat_device = 0; io.chat_lid = 0; io.chat_send = "zweiter Text, bestehende Sitzung"; io.linger_ms = 1500;
        bundles = msgs = receipts = recv_n = 0; enc_is_pk = -1;
        wab_node_init(&n, "success"); a[0].key = wab_s("t"); a[0].val = wab_text("1764300000"); a[1].key = wab_s("lid"); a[1].val = wab_jid_value("123456789012345", "lid", 7); n.attrs = a; n.n_attrs = 2;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        r = wa_probe_sim_login(&io, b, l);
        printf("%s\n", io.result);
        CHECK(r == 1 && bundles == 0 && msgs == 1 && enc_is_pk == 0 && io.msgs_sent == 1 && io.sessions_started == 0 && io.msgs_received == 0 && receipts == 0);
    }
    /* ---- F: the offline batch as one long WebSocket message: a 40 KB stanza (longer than a TLS record, far shorter
     * than the 176 KiB message buffer) is collected, decrypted in place, decoded and acknowledged, the six 3 KB stanzas
     * behind it are acknowledged one by one as they stream in, the <offline> marker ends the drain before the chat ---- */
    printf("--- F: 58 KB WebSocket message in 8 KiB pieces: 40 KB stanza + 6 stanzas decoded and acknowledged ---\n");
    {   wab_node n; wab_attr a[2]; uint8_t b[256]; uint32_t l;
        reset(&io, &creds); creds.paired = 1; strcpy(creds.jid_user, "4917612345678"); creds.jid_device = 7; counts = 1; fat_batch = 1; fat_real = 1;
        io.sessions = 0; io.chat_user = 0; io.chat_send = 0; io.chat_input = 0; io.linger_ms = 1500;
        wab_node_init(&n, "success"); a[0].key = wab_s("t"); a[0].val = wab_text("1764300000"); a[1].key = wab_s("lid"); a[1].val = wab_jid_value("123456789012345", "lid", 7); n.attrs = a; n.n_attrs = 2;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        r = wa_probe_sim_login(&io, b, l);
        printf("%s\n", io.result);
        CHECK(r == 1 && io.logged_in && actives == 1);
        CHECK(stanza_acks == 9 && io.acks_sent == 9);                          /* notification + receipt + the 40 KB notification + 6 fat notifications */
        CHECK(fat_acked == 1);
        CHECK(strcmp(ack_id[1], "FAT0000005") == 0 && strcmp(ack_class[1], "notification") == 0);
        CHECK(io.frames_after_login == 3 + 2 + 7 + 1);                         /* 3 results, 2 small, 7 fat, the <ib offline> marker */
        CHECK(fat_frame == 0 && fat_batch == 0 && big_off == big_len);
        CHECK(io.rx_bytes == rx_total && rx_total > rx_before_batch + 58000);          /* every served byte was counted */
    }
    /* ---- G: the same batch led by a 200 KB frame, longer than the message buffer: skipped byte by byte with the Noise
     * counter advanced, the six stanzas behind it still decode and are acknowledged ---- */
    printf("--- G: 218 KB WebSocket message: 200 KB frame skipped, 6 stanzas acknowledged ---\n");
    {   wab_node n; wab_attr a[2]; uint8_t b[256]; uint32_t l;
        reset(&io, &creds); creds.paired = 1; strcpy(creds.jid_user, "4917612345678"); creds.jid_device = 7; counts = 1; fat_batch = 1; fat_real = 0; fat_size = 200000;
        io.sessions = 0; io.chat_user = 0; io.chat_send = 0; io.chat_input = 0; io.linger_ms = 1500;
        wab_node_init(&n, "success"); a[0].key = wab_s("t"); a[0].val = wab_text("1764300000"); a[1].key = wab_s("lid"); a[1].val = wab_jid_value("123456789012345", "lid", 7); n.attrs = a; n.n_attrs = 2;
        CHECK(wab_encode_frame(&n, b, sizeof b, &l) == WAB_OK);
        r = wa_probe_sim_login(&io, b, l);
        printf("%s\n", io.result);
        CHECK(r == 1 && io.logged_in && actives == 1);
        CHECK(stanza_acks == 8 && io.acks_sent == 8);                          /* notification + receipt + 6 fat notifications */
        CHECK(fat_acked == 0);
        CHECK(strcmp(ack_id[1], "FAT0000005") == 0 && strcmp(ack_class[1], "notification") == 0);
        CHECK(io.frames_after_login == 3 + 2 + 6 + 1);                         /* 3 results, 2 small, 6 fat, the <ib offline> marker (the skipped frame is not counted) */
        CHECK(fat_frame == 0 && fat_batch == 0 && big_off == big_len);
    }
    printf("%s: %d checks, %d failures\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails ? 1 : 0;
}
