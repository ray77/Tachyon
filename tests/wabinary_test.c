/*
 * Host test of proto/wabinary.c (make wabinary-test, built with ASan and UBSan):
 *   wabinary_test <pair_device_iq.bin> <wabinary_ref.bin>
 * 1. token tables, 2. the pair-device IQ captured from web.whatsapp.com (make wa-capture), 3. reference
 * vectors from whatsmeow's encoder/decoder (tools/wabvectors), 4. every encoding type built and checked
 * byte by byte, 5. malformed input and too small buffers, 6. mutated frames: whatever the decoder accepts
 * must encode back to the same bytes. All inputs are copied into exact-size heap blocks, so ASan sees any
 * read or write past the end.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wabinary.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

#define ARENA_SIZE (1u << 20)
static uint8_t arena_mem[ARENA_SIZE];

static uint8_t *dup_exact(const uint8_t *p, uint32_t n)
{
    uint8_t *r = malloc(n ? n : 1);
    if (!r) exit(2);
    if (n) memcpy(r, p, n);
    return r;
}

static uint8_t *read_file(const char *path, uint32_t *len)
{
    FILE *f = fopen(path, "rb"); long n; uint8_t *p;
    if (!f) { printf("cannot open %s\n", path); exit(2); }
    fseek(f, 0, SEEK_END); n = ftell(f); fseek(f, 0, SEEK_SET);
    p = malloc((size_t)n + 1);
    if (!p || fread(p, 1, (size_t)n, f) != (size_t)n) exit(2);
    fclose(f); *len = (uint32_t)n;
    return p;
}

/* decode a frame held in an exact-size copy; the copy and the arena stay valid until the next call */
static int decode(const uint8_t *frame, uint32_t len, const wab_node **n)
{
    static uint8_t *held; static wab_arena a;
    free(held); held = dup_exact(frame, len);
    wab_arena_init(&a, arena_mem, ARENA_SIZE);
    return wab_decode_frame(held, len, &a, n);
}

/* encode into an exact-size heap block (two passes: size query, then the real one) */
static uint8_t *encode(const wab_node *n, uint32_t *len, int *err)
{
    uint32_t need = 0, got = 0; uint8_t *out; int e;
    e = wab_encode_frame(n, 0, 0, &need);
    if (e != WAB_ERR_BUFFER) { *err = e; *len = 0; return 0; }
    out = malloc(need);
    *err = wab_encode_frame(n, out, need, &got);
    *len = got;
    CHECK(got == need);
    return out;
}

static int encodes_to(const wab_node *n, const uint8_t *want, uint32_t want_len)
{
    uint32_t len; int e, ok; uint8_t *o = encode(n, &len, &e);
    ok = e == WAB_OK && len == want_len && memcmp(o, want, len) == 0;
    if (!ok) {
        uint32_t i;
        printf("  encode: %s, %u bytes (want %u)\n  got ", wab_errstr(e), len, want_len);
        for (i = 0; i < len && i < 80; i++) printf("%02x", o[i]);
        printf("\n  want ");
        for (i = 0; i < want_len && i < 80; i++) printf("%02x", want[i]);
        printf("\n");
    }
    free(o);
    return ok;
}

/* ---- text dump in the format of tools/wabvectors ----------------------------------------------- */
typedef struct { char *p; size_t len, cap; } text;
static void put_s(text *t, const char *s)
{
    size_t n = strlen(s);
    if (t->len + n + 1 > t->cap) { t->cap = (t->cap + n) * 2 + 256; t->p = realloc(t->p, t->cap); if (!t->p) exit(2); }
    memcpy(t->p + t->len, s, n + 1); t->len += n;
}
static void put_hex(text *t, const uint8_t *p, uint32_t n)
{
    char b[3]; uint32_t i;
    for (i = 0; i < n; i++) { snprintf(b, sizeof b, "%02x", p[i]); put_s(t, b); }
}
static void dump_value(text *t, const wab_value *v)
{
    char b[32];
    if (v->kind == WAB_STR) { put_s(t, "s:"); put_hex(t, v->str.p, v->str.len); }
    else if (v->kind == WAB_BYTES) { put_s(t, "b:"); put_hex(t, v->str.p, v->str.len); }
    else if (v->kind == WAB_JID) {
        put_s(t, "j:"); put_hex(t, v->jid.user.p, v->jid.user.len); put_s(t, "/"); put_hex(t, v->jid.server.p, v->jid.server.len);
        snprintf(b, sizeof b, "/%u/%u", v->jid.device, v->jid.integrator); put_s(t, b);
    } else put_s(t, "?");
}
static int key_cmp(const void *a, const void *b)
{
    const wab_str *x = &(*(const wab_attr *const *)a)->key, *y = &(*(const wab_attr *const *)b)->key;
    uint32_t m = x->len < y->len ? x->len : y->len; int c = memcmp(x->p, y->p, m);
    return c ? c : (int)x->len - (int)y->len;
}
static void dump_node(text *t, const wab_node *n)
{
    const wab_attr **order = malloc((n->n_attrs + 1) * sizeof *order); uint32_t i;
    put_s(t, "(s:"); put_hex(t, n->tag.p, n->tag.len);
    for (i = 0; i < n->n_attrs; i++) order[i] = &n->attrs[i];
    qsort(order, n->n_attrs, sizeof *order, key_cmp);
    for (i = 0; i < n->n_attrs; i++) { put_s(t, " s:"); put_hex(t, order[i]->key.p, order[i]->key.len); put_s(t, "="); dump_value(t, &order[i]->val); }
    free(order);
    if (n->val.kind == WAB_LIST && n->children_form == WAB_L_EMPTY) ;   /* whatsmeow reads LIST_EMPTY as no content */
    else if (n->val.kind == WAB_LIST) { put_s(t, " ["); for (i = 0; i < n->n_children; i++) dump_node(t, &n->children[i]); put_s(t, "]"); }
    else if (n->val.kind != WAB_NONE) { put_s(t, " "); dump_value(t, &n->val); }
    put_s(t, ")");
}

/* human readable, for the captured IQ */
static void print_str(const wab_str *s)
{
    uint32_t i;
    for (i = 0; i < s->len && i < 48; i++) putchar(s->p[i] >= 32 && s->p[i] < 127 ? s->p[i] : '.');
    if (s->len > 48) printf("...(%u bytes)", s->len);
}
static void print_value(const wab_value *v)
{
    if (v->kind == WAB_JID) { print_str(&v->jid.user); if (v->jid.user.len) putchar('@'); print_str(&v->jid.server); if (v->jid.device) printf(" device %u", v->jid.device); }
    else print_str(&v->str);
}
static void print_node(const wab_node *n, int indent)
{
    uint32_t i;
    printf("%*s<", indent, ""); print_str(&n->tag);
    for (i = 0; i < n->n_attrs; i++) { putchar(' '); print_str(&n->attrs[i].key); printf("=\""); print_value(&n->attrs[i].val); putchar('"'); }
    if (n->val.kind == WAB_NONE) { printf("/>\n"); return; }
    putchar('>');
    if (n->val.kind == WAB_LIST) { putchar('\n'); for (i = 0; i < n->n_children; i++) print_node(&n->children[i], indent + 2); printf("%*s", indent, ""); }
    else print_value(&n->val);
    printf("</"); print_str(&n->tag); printf(">\n");
}

/* deep copy with every wire form reset to AUTO: what the encoder chooses on its own */
static void auto_str(wab_str *s) { s->form = WAB_F_AUTO; }
static void auto_value(wab_value *v) { auto_str(&v->str); auto_str(&v->jid.user); auto_str(&v->jid.server); v->jid.type = WAB_JID_AUTO; }
static void *pool[4096]; static int pooled;
static void *pool_alloc(size_t n) { void *p = malloc(n ? n : 1); if (!p || pooled == 4096) exit(2); return pool[pooled++] = p; }
static void pool_free(void) { while (pooled) free(pool[--pooled]); }
static void auto_node(wab_node *d, const wab_node *s)
{
    uint32_t i;
    *d = *s;
    auto_str(&d->tag); auto_value(&d->val); d->list_form = d->children_form = WAB_L_AUTO;
    if (s->n_attrs) {
        wab_attr *a = pool_alloc(s->n_attrs * sizeof *a);
        for (i = 0; i < s->n_attrs; i++) { a[i] = s->attrs[i]; auto_str(&a[i].key); auto_value(&a[i].val); }
        d->attrs = a;
    }
    if (s->n_children) {
        wab_node *c = pool_alloc(s->n_children * sizeof *c);
        for (i = 0; i < s->n_children; i++) auto_node(&c[i], &s->children[i]);
        d->children = c;
    }
}

/* ---- 1. tokens --------------------------------------------------------------------------------- */
static void test_tokens(void)
{
    /* every token: decode the token form, re-encode from plain text, expect the token form again */
    uint32_t i, n_ok = 0, lens = 0;
    for (i = 1; i < 236 + 1024; i++) {
        uint8_t f[6]; uint32_t k = 0, flen; const wab_node *n; wab_node b; char name[64];
        f[k++] = 0; f[k++] = 0xf8; f[k++] = 1;
        if (i < 236) f[k++] = (uint8_t)i; else { f[k++] = (uint8_t)(236 + ((i - 236) >> 8)); f[k++] = (uint8_t)((i - 236) & 255); }
        flen = k;
        if (decode(f, flen, &n) != WAB_OK || !n->tag.len || n->tag.len >= sizeof name) { printf("token %u does not decode\n", i); continue; }
        memcpy(name, n->tag.p, n->tag.len); name[n->tag.len] = 0; lens += n->tag.len;
        wab_node_init(&b, name);
        if (encodes_to(&b, f, flen)) n_ok++; else printf("  token %u '%s'\n", i, name);
    }
    CHECK(n_ok == 1259);
    CHECK(lens == 10663);
    {   /* spot checks against both upstream tables */
        static const struct { uint8_t b0, b1; const char *s; } spot[] = {
            { 1, 0, "xmlstreamstart" }, { 3, 0, "s.whatsapp.net" }, { 6, 0, "from" }, { 25, 0, "iq" }, { 235, 0, "screen_height" },
            { 236, 0, "read-self" }, { 237, 0x50, "ref" }, { 237, 0xee, "pair-device" } };
        for (i = 0; i < sizeof spot / sizeof spot[0]; i++) {
            uint8_t f[5] = { 0, 0xf8, 1, spot[i].b0, spot[i].b1 }; const wab_node *n;
            CHECK(decode(f, spot[i].b0 >= 236 ? 5 : 4, &n) == WAB_OK && wab_str_eq(&n->tag, spot[i].s));
        }
    }
    printf("tokens: %u of 1259 round trip\n", n_ok);
}

/* ---- 2. captured pair-device IQ ---------------------------------------------------------------- */
static void test_captured(const uint8_t *frame, uint32_t len)
{
    const wab_node *n, *pd; const wab_value *from, *type, *id, *xmlns; wab_arena a; uint32_t i, used; uint8_t *copy;
    CHECK(len == 679);
    CHECK(decode(frame, len, &n) == WAB_OK);
    if (!n) return;
    print_node(n, 0);
    CHECK(wab_str_eq(&n->tag, "iq"));
    CHECK(n->n_attrs == 4);
    from = wab_get_attr(n, "from"); type = wab_get_attr(n, "type"); id = wab_get_attr(n, "id"); xmlns = wab_get_attr(n, "xmlns");
    CHECK(from && from->kind == WAB_JID && from->jid.type == WAB_JID_PAIR && from->jid.user.len == 0 && wab_str_eq(&from->jid.server, "s.whatsapp.net"));
    CHECK(type && type->kind == WAB_STR && wab_str_eq(&type->str, "set"));
    CHECK(xmlns && xmlns->kind == WAB_STR && wab_str_eq(&xmlns->str, "md"));
    CHECK(id && id->kind == WAB_STR && id->str.len > 0);
    if (id) for (i = 0; i < id->str.len; i++) CHECK((id->str.p[i] >= '0' && id->str.p[i] <= '9') || id->str.p[i] == '.' || id->str.p[i] == '-');
    CHECK(wab_get_attr(n, "to") == 0);
    CHECK(n->val.kind == WAB_LIST && n->n_children == 1);
    pd = wab_get_child(n, "pair-device");
    CHECK(pd != 0);
    if (!pd) return;
    CHECK(pd->n_attrs == 0 && pd->val.kind == WAB_LIST && pd->n_children == 6);
    for (i = 0; i < pd->n_children; i++) {
        const wab_node *r = &pd->children[i];
        CHECK(wab_str_eq(&r->tag, "ref") && r->n_attrs == 0 && r->val.kind == WAB_BYTES);
        CHECK(r->val.str.len > 32 && memcmp(r->val.str.p, "2@", 2) == 0);
    }
    CHECK(wab_get_child(n, "ref") == 0 && wab_get_child(pd, "nothing") == 0);
    CHECK(encodes_to(n, frame, len));                           /* byte for byte */

    {   /* the encoder's own choice differs only where the server did not take the shortest form; same tree */
        wab_node c; uint32_t clen; int e; uint8_t *o; text t1 = { 0, 0, 0 }, t2 = { 0, 0, 0 };
        auto_node(&c, n);
        dump_node(&t1, n);
        o = encode(&c, &clen, &e);
        CHECK(e == WAB_OK);
        pool_free();
        CHECK(decode(o, clen, &n) == WAB_OK);
        if (n) { dump_node(&t2, n); CHECK(strcmp(t1.p, t2.p) == 0); }
        printf("captured IQ: %u bytes, re-encoded identically; with AUTO forms %u bytes\n", len, clen);
        free(o); free(t1.p); free(t2.p);
    }
    /* arena: find the size needed; every smaller one must fail cleanly */
    copy = dup_exact(frame, len);
    wab_arena_init(&a, arena_mem, ARENA_SIZE);
    CHECK(wab_decode_frame(copy, len, &a, &n) == WAB_OK);
    used = a.used;
    for (i = 0; i <= used; i++) {
        uint8_t *m = malloc(i ? i : 1); wab_arena s; int e;
        wab_arena_init(&s, m, i);
        e = wab_decode_frame(copy, len, &s, &n);
        CHECK(e == (i < used ? WAB_ERR_ARENA : WAB_OK));
        free(m);
    }
    /* a misaligned arena base is aligned by wab_arena_init */
    for (i = 1; i < 8; i++) {
        wab_arena s; wab_arena_init(&s, arena_mem + i, used + 8);
        CHECK(wab_decode_frame(copy, len, &s, &n) == WAB_OK && ((uintptr_t)n % sizeof(void *)) == 0);
    }
    free(copy);
    printf("captured IQ: arena %u bytes on this host\n", used);
    /* every truncation fails */
    for (i = 0; i < len; i++) { int e = decode(frame, i, &n); CHECK(e == WAB_ERR_TRUNCATED && n == 0); }
    {   uint8_t *longer = calloc(1, len + 1); memcpy(longer, frame, len);
        CHECK(decode(longer, len + 1, &n) == WAB_ERR_TRAILING); free(longer); }
    /* every output buffer that is too small */
    CHECK(decode(frame, len, &n) == WAB_OK);
    for (i = 0; i < len; i++) {
        uint8_t *o = malloc(i ? i : 1); uint32_t need = 0;
        CHECK(wab_encode_frame(n, o, i, &need) == WAB_ERR_BUFFER && need == len);
        free(o);
    }
}

/* ---- 3. whatsmeow reference vectors ------------------------------------------------------------ */
static uint32_t be32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }

static void test_reference(const uint8_t *p, uint32_t len)
{
    uint32_t pos = 0; int count = 0;
    while (pos + 4 <= len) {
        uint32_t flen, dlen; const uint8_t *frame, *want; const wab_node *n; wab_node c; text t = { 0, 0, 0 };
        flen = be32(p + pos); pos += 4; frame = p + pos; pos += flen;
        dlen = be32(p + pos); pos += 4; want = p + pos; pos += dlen;
        count++;
        if (decode(frame, flen, &n) != WAB_OK) { printf("vector %d: decode failed\n", count); CHECK(0); continue; }
        dump_node(&t, n);
        if (t.len != dlen || memcmp(t.p, want, dlen) != 0) { printf("vector %d: tree differs\n  got  %.200s\n  want %.200s\n", count, t.p, (const char *)want); CHECK(0); }
        else CHECK(1);
        CHECK(encodes_to(n, frame, flen));                      /* recorded forms */
        auto_node(&c, n);
        CHECK(encodes_to(&c, frame, flen));                     /* our preferred forms == whatsmeow's */
        pool_free();
        free(t.p);
        if (flen < 600) { uint32_t i; for (i = 0; i < flen; i++) CHECK(decode(frame, i, &n) == WAB_ERR_TRUNCATED); }
    }
    CHECK(pos == len && count >= 60);
    printf("whatsmeow vectors: %d (tree, round trip, preferred encoding)\n", count);
}

/* ---- 4. every encoding type, byte by byte ------------------------------------------------------ */
/* encode n -> want, decode want -> encode again -> want */
static void both_ways(const wab_node *n, const uint8_t *want, uint32_t len, int line)
{
    const wab_node *d; int ok = encodes_to(n, want, len) && decode(want, len, &d) == WAB_OK && encodes_to(d, want, len);
    checks++;
    if (!ok) { fails++; printf("FAIL %s:%d: both_ways\n", __FILE__, line); }
}
#define B(n, ...) do { static const uint8_t w_[] = { __VA_ARGS__ }; both_ways(n, w_, sizeof w_, __LINE__); } while (0)

/* a frame the decoder accepts although it is not the preferred form: must come back unchanged */
static void keeps(const uint8_t *f, uint32_t len, int line)
{
    const wab_node *n; int ok = decode(f, len, &n) == WAB_OK && encodes_to(n, f, len);
    checks++;
    if (!ok) { fails++; printf("FAIL %s:%d: keeps\n", __FILE__, line); }
}
#define KEEP(...) do { static const uint8_t f_[] = { __VA_ARGS__ }; keeps(f_, sizeof f_, __LINE__); } while (0)

static void test_encodings(void)
{
    wab_node n, kid[2]; wab_attr a[2]; static uint8_t blob[(1u << 20) + 16];
    uint32_t i;

    wab_node_init(&n, "iq");                       B(&n, 0, 0xf8, 1, 25);
    n.val.kind = WAB_LIST;                         B(&n, 0, 0xf8, 2, 25, 0);                          /* LIST_EMPTY */
    wab_node_init(&kid[0], "ref"); wab_node_init(&kid[1], "iq");
    n.children = kid; n.n_children = 2;            B(&n, 0, 0xf8, 2, 25, 0xf8, 2, 0xf8, 1, 237, 0x50, 0xf8, 1, 25);
    n.list_form = WAB_L_16; n.children_form = WAB_L_16;
    B(&n, 0, 0xf9, 0, 2, 25, 0xf9, 0, 2, 0xf8, 1, 237, 0x50, 0xf8, 1, 25);

    wab_node_init(&n, "iq"); n.attrs = a; n.n_attrs = 1;
    a[0].key = wab_s("id");
    a[0].val = wab_text("491");                    B(&n, 0, 0xf8, 3, 25, 8, 0xff, 0x82, 0x49, 0x1f);  /* nibble, odd */
    a[0].val = wab_text("1.5-");                   B(&n, 0, 0xf8, 3, 25, 8, 0xff, 2, 0x1b, 0x5a);     /* nibble, even */
    a[0].val = wab_text("0AF");                    B(&n, 0, 0xf8, 3, 25, 8, 0xfb, 0x82, 0x0a, 0xff);  /* hex, odd */
    a[0].val = wab_text("BEEF");                   B(&n, 0, 0xf8, 3, 25, 8, 0xfb, 2, 0xbe, 0xef);     /* hex, even */
    a[0].val = wab_text("md");                     B(&n, 0, 0xf8, 3, 25, 8, 0xfc, 2, 'm', 'd');       /* BINARY_8 */
    a[0].val = wab_text("ab");                     B(&n, 0, 0xf8, 3, 25, 8, 0xfc, 2, 'a', 'b');       /* lower case: not hex */
    a[0].val = wab_text("");                       B(&n, 0, 0xf8, 3, 25, 8, 0xfc, 0);
    a[0].val = wab_text("set");                    B(&n, 0, 0xf8, 3, 25, 8, 90);                      /* single token */
    a[0].val = wab_text("pair-device");            B(&n, 0, 0xf8, 3, 25, 8, 237, 0xee);               /* DICTIONARY_1 */
    a[0].val = wab_text("read-self");              B(&n, 0, 0xf8, 3, 25, 8, 236, 0);                  /* DICTIONARY_0 */
    for (i = 2; i <= 3; i++) {                     /* DICTIONARY_2 / 3: decode, then encode the text */
        uint8_t f[7] = { 0, 0xf8, 3, 25, 8, 0, 7 }; char s[64]; const wab_node *d; const wab_value *v;
        f[5] = (uint8_t)(236 + i);
        CHECK(decode(f, 7, &d) == WAB_OK);
        v = wab_get_attr(d, "id"); CHECK(v && v->str.len < sizeof s);
        memcpy(s, v->str.p, v->str.len); s[v->str.len] = 0;
        a[0].val = wab_text(s); CHECK(encodes_to(&n, f, 7));
    }

    /* JIDs */
    a[0].key = wab_s("to");
    a[0].val = wab_jid_value("", "s.whatsapp.net", 0);       B(&n, 0, 0xf8, 3, 25, 17, 0xfa, 0, 3);
    a[0].val = wab_jid_value("123", "g.us", 0);              B(&n, 0, 0xf8, 3, 25, 17, 0xfa, 0xff, 0x82, 0x12, 0x3f, 28);
    a[0].val = wab_jid_value("4917", "s.whatsapp.net", 7);     B(&n, 0, 0xf8, 3, 25, 17, 0xf7, 0, 7, 0xff, 2, 0x49, 0x17);
    a[0].val = wab_jid_value("4917", "lid", 7);                B(&n, 0, 0xf8, 3, 25, 17, 0xf7, 1, 7, 0xff, 2, 0x49, 0x17);
    a[0].val = wab_jid_value("4917", "hosted", 0);             B(&n, 0, 0xf8, 3, 25, 17, 0xf7, 128, 0, 0xff, 2, 0x49, 0x17);
    a[0].val = wab_jid_value("4917", "hosted.lid", 2);         B(&n, 0, 0xf8, 3, 25, 17, 0xf7, 129, 2, 0xff, 2, 0x49, 0x17);
    {   /* a recorded AD form is kept for device 0 and unknown domains, dropped when the server changed */
        static const uint8_t f[] = { 0, 0xf8, 3, 25, 17, 0xf7, 5, 0, 0xff, 1, 0x12 };
        const wab_node *d; wab_node m; wab_attr b;
        keeps(f, sizeof f, __LINE__);
        CHECK(decode(f, sizeof f, &d) == WAB_OK && d->attrs[0].val.jid.agent == 5 && wab_str_eq(&d->attrs[0].val.jid.server, "s.whatsapp.net"));
        m = *d; b = d->attrs[0]; b.val.jid.server = wab_s("g.us"); m.attrs = &b;
        {   static const uint8_t w[] = { 0, 0xf8, 3, 25, 17, 0xfa, 0xff, 1, 0x12, 28 }; CHECK(encodes_to(&m, w, sizeof w)); }
        b.val.jid.server = wab_s("lid");
        {   static const uint8_t w[] = { 0, 0xf8, 3, 25, 17, 0xf7, 1, 0, 0xff, 1, 0x12 }; CHECK(encodes_to(&m, w, sizeof w)); }
    }
    KEEP(0, 0xf8, 3, 25, 17, 0xf6, 0xff, 1, 0x12, 0x12, 0x34, 0xfc, 4, 'm', 's', 'g', 'r');            /* FB_JID */
    KEEP(0, 0xf8, 3, 25, 17, 0xf5, 0xff, 1, 0x12, 0, 3, 0x12, 0x34, 0xfc, 7, 'i', 'n', 't', 'e', 'r', 'o', 'p');
    KEEP(0, 0xf8, 2, 25, 0xfa, 0, 3);                                                                  /* JID content */

    /* byte content: BINARY_8 / 20 / 32 */
    wab_node_init(&n, "enc");
    for (i = 0; i < sizeof blob; i++) blob[i] = (uint8_t)(i * 31);
    n.val = wab_bytes(blob, 3);                    B(&n, 0, 0xf8, 2, 29, 0xfc, 3, 0, 31, 62);
    n.val = wab_bytes(blob, 0);                    B(&n, 0, 0xf8, 2, 29, 0xfc, 0);
    {
        static const struct { uint32_t len; uint32_t hdr; uint8_t h[5]; } t[] = {
            { 255, 2, { 0xfc, 0xff } }, { 256, 4, { 0xfd, 0, 1, 0 } }, { 70000, 4, { 0xfd, 1, 0x11, 0x70 } },
            { (1u << 20) - 1, 4, { 0xfd, 0x0f, 0xff, 0xff } }, { 1u << 20, 5, { 0xfe, 0, 0x10, 0, 0 } } };
        for (i = 0; i < sizeof t / sizeof t[0]; i++) {
            uint32_t l; int e; uint8_t *o; const wab_node *d;
            n.val = wab_bytes(blob, t[i].len);
            o = encode(&n, &l, &e);
            CHECK(e == WAB_OK && l == 4 + t[i].hdr + t[i].len);
            CHECK(memcmp(o + 4, t[i].h, t[i].hdr) == 0 && memcmp(o + 4 + t[i].hdr, blob, t[i].len) == 0);
            CHECK(decode(o, l, &d) == WAB_OK && d->val.kind == WAB_BYTES && d->val.str.len == t[i].len && encodes_to(d, o, l));
            CHECK(decode(o, l - 1, &d) == WAB_ERR_TRUNCATED);
            free(o);
        }
    }
    /* forms the preferred encoder would not choose */
    KEEP(0, 0xf8, 2, 25, 0xfd, 0, 0, 1, 'x');                       /* BINARY_20 for one byte */
    KEEP(0, 0xf8, 2, 25, 0xfe, 0, 0, 0, 1, 'x');                    /* BINARY_32 for one byte */
    KEEP(0, 0xf8, 3, 25, 8, 0xfb, 5, 0x16, 0x13, 0x39, 0x89, 0x79); /* digits as HEX_8, as in the captured IQ */
    KEEP(0, 0xf8, 3, 25, 8, 0xfc, 3, 's', 'e', 't');                /* token as raw string */
    KEEP(0, 0xf8, 3, 25, 8, 0);                                     /* LIST_EMPTY as attribute value */
    KEEP(0, 0xf8, 3, 25, 8, 0xff, 0);                               /* empty packed string */
    KEEP(0, 0xf8, 2, 0xfc, 2, 'i', 'q', 0xf8, 0);                   /* raw tag, LIST_8 with no children */
    KEEP(0, 0xf8, 2, 25, 0xf9, 0, 0);                               /* LIST_16 with no children */
    KEEP(0, 0xf8, 2, 25, 90);                                       /* token content */
    KEEP(0, 0xf8, 2, 25, 0xff, 1, 0x12);                            /* packed content */
    {   /* the longest packed string the wire allows: 254 characters */
        uint8_t f[133]; uint32_t k = 0; const wab_node *d;
        f[k++] = 0; f[k++] = 0xf8; f[k++] = 2; f[k++] = 25; f[k++] = 0xff; f[k++] = 127;
        while (k < 6 + 127) f[k++] = 0x42;
        CHECK(decode(f, k, &d) == WAB_OK && d->val.str.len == 254); keeps(f, k, __LINE__);
    }

    /* encoder errors */
    {
        uint32_t l; uint8_t o[64];
        wab_node_init(&n, "");                     CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        wab_node_init(&n, "iq"); n.attrs = a; n.n_attrs = 1;
        a[0].key = wab_s(""); a[0].val = wab_text("x");   CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        a[0].key = wab_s("id"); a[0].val = wab_bytes(blob, 1); CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        a[0].val.kind = WAB_NONE;                  CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        a[0].val = wab_jid_value("1", "", 0);      CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        a[0].val = wab_jid_value("1", "g.us", 3);  CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        a[0].val = wab_jid_value("1", "lid", 256); CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        n.n_attrs = 32768;                         CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        wab_node_init(&n, "iq"); n.val.kind = 99;  CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        n.val.kind = WAB_LIST; n.n_children = 65536;      CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_VALUE);
        n.n_children = 1; n.children = &n;         CHECK(wab_encode_frame(&n, o, sizeof o, &l) == WAB_ERR_DEPTH);   /* cycle */
    }
    printf("hand built nodes: all encodings\n");
}

/* ---- 5. malformed input ------------------------------------------------------------------------ */
static void bad(const uint8_t *f, uint32_t len, int want, int line)
{
    const wab_node *n; int e = decode(f, len, &n);
    checks++;
    if (e != want || n) { fails++; printf("FAIL %s:%d: %s, expected %s\n", __FILE__, line, wab_errstr(e), wab_errstr(want)); }
}
#define BAD(want, ...) do { static const uint8_t f_[] = { __VA_ARGS__ }; bad(f_, sizeof f_, want, __LINE__); } while (0)

static void test_malformed(void)
{
    uint32_t i;
    const wab_node *n;
    CHECK(decode((const uint8_t *)"", 0, &n) == WAB_ERR_TRUNCATED);
    BAD(WAB_ERR_TRUNCATED, 0);
    BAD(WAB_ERR_COMPRESSED, 2, 0x78, 0x9c, 3, 0, 0, 0, 0, 1);
    BAD(WAB_ERR_FORMAT, 0, 0);                                      /* node with an empty list */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 0);
    BAD(WAB_ERR_FORMAT, 0, 25);                                     /* no list header */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 1, 0);                             /* empty tag */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 1, 0xfc, 0);
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 1, 0xf8, 1, 25);                   /* list as tag */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 1, 0xfa, 0, 3);                    /* JID as tag */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 3, 25, 0, 90);                     /* empty key */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 3, 25, 0xfa, 0, 3, 90);            /* JID as key */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 3, 25, 8, 0xf8, 0);                /* list as value */
    for (i = 240; i <= 244; i++) { uint8_t f[4] = { 0, 0xf8, 1, 0 }; f[3] = (uint8_t)i; bad(f, 4, WAB_ERR_FORMAT, __LINE__); }
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 2, 25, 240);
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 3, 25, 17, 0xfa, 0xff, 1, 0x12, 0);           /* JID without server */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 3, 25, 17, 0xfa, 0xfa, 0, 3, 3);              /* JID inside a JID */
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 3, 25, 17, 0xf7, 0, 1, 0xf8, 0);
    BAD(WAB_ERR_PACKED, 0, 0xf8, 2, 25, 0xff, 1, 0x1c);             /* nibble 12 */
    BAD(WAB_ERR_PACKED, 0, 0xf8, 2, 25, 0xff, 1, 0xf1);             /* 15 inside the string */
    BAD(WAB_ERR_PACKED, 0, 0xf8, 2, 25, 0xff, 0x81, 0x12);          /* odd length, padding not 15 */
    BAD(WAB_ERR_PACKED, 0, 0xf8, 2, 25, 0xfb, 0x81, 0x12);
    BAD(WAB_ERR_PACKED, 0, 0xf8, 2, 25, 0xff, 0x80);                /* odd length of zero bytes */
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 2, 25, 0xff, 127, 0x12);
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 2, 25, 0xfc, 255, 'x');         /* oversize lengths */
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 2, 25, 0xfd, 0x0f, 0xff, 0xff, 'x');
    BAD(WAB_ERR_FORMAT, 0, 0xf8, 2, 25, 0xfd, 0x10, 0, 1, 'x');     /* more than 20 bits */
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 2, 25, 0xfe, 0xff, 0xff, 0xff, 0xff, 'x');
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 2, 25, 0xfe, 0x80, 0, 0, 0, 'x');
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 255, 25);                       /* oversize counts */
    BAD(WAB_ERR_TRUNCATED, 0, 0xf9, 0xff, 0xff, 25);
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 2, 25, 0xf8, 255);
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 2, 25, 0xf9, 0xff, 0xff, 0xf8, 1, 25);
    BAD(WAB_ERR_TRUNCATED, 0, 0xf8, 2, 25, 0xf8, 2, 0xf8, 1, 25);   /* list one node short */
    BAD(WAB_ERR_TRAILING, 0, 0xf8, 1, 25, 0);
    for (i = WAB_MAX_DEPTH - 1; i <= WAB_MAX_DEPTH + 1; i++) {      /* i + 1 nodes below each other */
        uint8_t f[1024]; uint32_t k = 0, j; int e;
        f[k++] = 0;
        for (j = 0; j < i; j++) { f[k++] = 0xf8; f[k++] = 2; f[k++] = 25; f[k++] = 0xf8; f[k++] = 1; }
        f[k++] = 0xf8; f[k++] = 1; f[k++] = 25;
        e = decode(f, k, &n);
        CHECK(e == (i + 1 <= WAB_MAX_DEPTH ? WAB_OK : WAB_ERR_DEPTH));
        if (e == WAB_OK) CHECK(encodes_to(n, f, k));
    }
    {   /* a megabyte of nesting stops at the depth limit */
        uint32_t len = 1 + 5 * 200000; uint8_t *f = calloc(1, len);
        for (i = 0; i < 200000; i++) memcpy(f + 1 + 5 * i, "\xf8\x02\x19\xf8\x01", 5);
        CHECK(decode(f, len, &n) == WAB_ERR_DEPTH);
        free(f);
    }
    CHECK(strcmp(wab_errstr(WAB_ERR_COMPRESSED), "compressed: unsupported") == 0);
    printf("malformed input: rejected\n");
}

/* ---- 6. mutations ------------------------------------------------------------------------------ */
static uint32_t rnd_state = 0x2026a500u;
static uint32_t rnd(void) { rnd_state ^= rnd_state << 13; rnd_state ^= rnd_state >> 17; rnd_state ^= rnd_state << 5; return rnd_state; }

static void test_mutations(const uint8_t *iq, uint32_t iq_len, const uint8_t *ref, uint32_t ref_len)
{
    const uint8_t *seed[128]; uint32_t seed_len[128], n_seed = 0, pos = 0, it, accepted = 0, diverged = 0;
    seed[n_seed] = iq; seed_len[n_seed++] = iq_len;
    while (pos + 4 <= ref_len && n_seed < 128) {
        uint32_t flen = be32(ref + pos); pos += 4;
        if (flen < 1000) { seed[n_seed] = ref + pos; seed_len[n_seed++] = flen; }
        pos += flen; pos += 4 + be32(ref + pos);
    }
    for (it = 0; it < 300000; it++) {
        uint8_t m[1100]; uint32_t s = rnd() % n_seed, len = seed_len[s], k, edits = 1 + rnd() % 6; const wab_node *n;
        memcpy(m, seed[s], len);
        while (edits--) {
            uint32_t at = 1 + rnd() % (len > 1 ? len - 1 : 1);
            switch (rnd() % 5) {
            case 0: m[at] = (uint8_t)rnd(); break;
            case 1: m[at] = (uint8_t)(236 + rnd() % 20); break;            /* the special tags */
            case 2: m[at] ^= (uint8_t)(1u << (rnd() % 8)); break;
            case 3: if (len < sizeof m) { for (k = len; k > at; k--) m[k] = m[k - 1]; len++; m[at] = (uint8_t)rnd(); } break;
            default: if (len > 2 && at < len) { for (k = at; k + 1 < len; k++) m[k] = m[k + 1]; len--; } break;
            }
        }
        m[0] = 0;
        if (decode(m, len, &n) == WAB_OK) {
            uint32_t l; int e; uint8_t *o = encode(n, &l, &e);
            accepted++;
            if (e != WAB_OK || l != len || memcmp(o, m, len) != 0) {
                if (!diverged++) { uint32_t i; printf("mutation %u (%s):", it, wab_errstr(e)); for (i = 0; i < len; i++) printf("%02x", m[i]); printf("\n"); }
            }
            free(o);
        }
    }
    CHECK(diverged == 0);
    CHECK(accepted > 1000);
    printf("mutations: 300000, %u accepted, all re-encoded identically: %s\n", accepted, diverged ? "NO" : "yes");
}

int main(int argc, char **argv)
{
    uint8_t *iq, *ref; uint32_t iq_len, ref_len;
    if (argc != 3) { printf("usage: wabinary_test <pair_device_iq.bin> <wabinary_ref.bin>\n"); return 2; }
    iq = read_file(argv[1], &iq_len); ref = read_file(argv[2], &ref_len);
    test_tokens();
    test_captured(iq, iq_len);
    test_reference(ref, ref_len);
    test_encodings();
    test_malformed();
    test_mutations(iq, iq_len, ref, ref_len);
    { const wab_node *n; decode(iq, 0, &n); }
    free(iq); free(ref);
    printf("%s: %d checks, %d failures\n", fails ? "FAIL" : "PASS", checks, fails);
    return fails != 0;
}
