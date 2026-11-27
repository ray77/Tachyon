#include "x509.h"
#include "sha256.h"

/* ---- DER reader ------------------------------------------------------------- */
typedef struct { const uint8_t *p; uint32_t len; } der;

static int der_tlv(der *d, uint8_t *tag, der *val)      /* reads one TLV, advances d */
{
    uint32_t l, n, i;
    if (d->len < 2) return 0;
    *tag = d->p[0];
    if ((*tag & 0x1f) == 0x1f) return 0;                /* multi-byte tags not used */
    l = d->p[1]; n = 2;
    if (l & 0x80) {
        uint32_t k = l & 0x7f;
        if (k == 0 || k > 3 || d->len < 2 + k) return 0;
        l = 0;
        for (i = 0; i < k; i++) l = (l << 8) | d->p[2 + i];
        n = 2 + k;
        if (l < 0x80) return 0;                         /* not minimal */
    }
    if (d->len - n < l) return 0;
    val->p = d->p + n; val->len = l;
    d->p += n + l; d->len -= n + l;
    return 1;
}

static int der_expect(der *d, uint8_t tag, der *val)
{
    uint8_t t;
    const uint8_t *save = d->p; uint32_t slen = d->len;
    if (!der_tlv(d, &t, val) || t != tag) { d->p = save; d->len = slen; return 0; }
    return 1;
}

static int der_uint(der *v, uint32_t *out)               /* small positive INTEGER */
{
    uint32_t i, r = 0;
    if (v->len == 0 || v->len > 5 || (v->p[0] & 0x80)) return 0;
    for (i = 0; i < v->len; i++) { if (i == 0 && v->p[0] == 0 && v->len > 1) continue; r = (r << 8) | v->p[i]; }
    if (v->len == 5 && v->p[0] != 0) return 0;
    *out = r;
    return 1;
}

static int mem_eq(const uint8_t *a, const uint8_t *b, uint32_t n)
{
    uint32_t i, d = 0;
    for (i = 0; i < n; i++) d |= a[i] ^ b[i];
    return d == 0;
}

static const uint8_t OID_SHA256_RSA[9] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
static const uint8_t OID_RSA_ENC[9]    = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01 };
static const uint8_t OID_SAN[3]        = { 0x55,0x1d,0x11 };
static const uint8_t OID_BASIC[3]      = { 0x55,0x1d,0x13 };

static int alg_is(der *alg, const uint8_t *oid, uint32_t oidlen)   /* AlgorithmIdentifier with NULL/absent params */
{
    der a = *alg, o;
    if (!der_expect(&a, 0x06, &o)) return 0;
    return o.len == oidlen && mem_eq(o.p, oid, oidlen);
}

static int read_time(der *t, uint8_t tag, char out[16])
{
    uint32_t i;
    if (tag == 0x17) {                                  /* UTCTime YYMMDDHHMMSSZ */
        if (t->len != 13 || t->p[12] != 'Z') return 0;
        out[0] = (t->p[0] >= '5') ? '1' : '2'; out[1] = (t->p[0] >= '5') ? '9' : '0';
        for (i = 0; i < 13; i++) out[2 + i] = (char)t->p[i];
        out[15] = 0;
        return 1;
    }
    if (tag == 0x18) {                                  /* GeneralizedTime YYYYMMDDHHMMSSZ */
        if (t->len != 15 || t->p[14] != 'Z') return 0;
        for (i = 0; i < 15; i++) out[i] = (char)t->p[i];
        out[15] = 0;
        return 1;
    }
    return 0;
}

static int parse_extensions(x509_cert *c, der *exts)
{
    der seq;
    if (!der_expect(exts, 0x30, &seq)) return 0;
    while (seq.len) {
        der ext, oid, val; uint8_t t;
        if (!der_expect(&seq, 0x30, &ext)) return 0;
        if (!der_expect(&ext, 0x06, &oid)) return 0;
        if (ext.len && ext.p[0] == 0x01) { der b; if (!der_expect(&ext, 0x01, &b) || b.len != 1) return 0; }   /* critical flag: tolerated, see below */
        if (!der_expect(&ext, 0x04, &val)) return 0;
        if (oid.len == 3 && mem_eq(oid.p, OID_SAN, 3)) {
            der names;
            if (!der_expect(&val, 0x30, &names)) return 0;
            c->san = names.p; c->san_len = names.len;
        } else if (oid.len == 3 && mem_eq(oid.p, OID_BASIC, 3)) {
            der bc, flag;
            if (!der_expect(&val, 0x30, &bc)) return 0;
            if (bc.len && bc.p[0] == 0x01) { if (!der_tlv(&bc, &t, &flag) || flag.len != 1) return 0; c->is_ca = flag.p[0] != 0; }
        }
        /* unknown critical extensions are tolerated: the chain is only used for RSA key transport */
    }
    return 1;
}

int x509_parse(x509_cert *c, const uint8_t *der_in, uint32_t len)
{
    der d, cert, tbs, alg, sigbits, v, spki, keyalg, keybits, rsakey, nn, ee, validity, t;
    uint8_t tag;
    uint32_t i;
    for (i = 0; i < sizeof(*c); i++) ((uint8_t *)c)[i] = 0;
    c->der = der_in; c->len = len;
    d.p = der_in; d.len = len;
    if (!der_expect(&d, 0x30, &cert) || d.len) return 0;
    c->tbs = cert.p;
    if (!der_expect(&cert, 0x30, &tbs)) return 0;
    c->tbs_len = (uint32_t)(cert.p - c->tbs);
    if (!der_expect(&cert, 0x30, &alg)) return 0;
    c->sig_sha256_rsa = alg_is(&alg, OID_SHA256_RSA, 9);
    if (!der_expect(&cert, 0x03, &sigbits) || cert.len || sigbits.len < 2 || sigbits.p[0] != 0) return 0;
    c->sig = sigbits.p + 1; c->sig_len = sigbits.len - 1;
    /* tbsCertificate */
    if (tbs.len && tbs.p[0] == 0xa0) { if (!der_tlv(&tbs, &tag, &v)) return 0; }   /* version */
    if (!der_expect(&tbs, 0x02, &v)) return 0;                                      /* serial */
    if (!der_expect(&tbs, 0x30, &v)) return 0;                                      /* signature alg (inner) */
    if (!alg_is(&v, OID_SHA256_RSA, 9)) c->sig_sha256_rsa = 0;
    c->issuer = tbs.p; if (!der_expect(&tbs, 0x30, &v)) return 0; c->issuer_len = (uint32_t)(tbs.p - c->issuer);
    if (!der_expect(&tbs, 0x30, &validity)) return 0;
    if (!der_tlv(&validity, &tag, &t) || !read_time(&t, tag, c->not_before)) return 0;
    if (!der_tlv(&validity, &tag, &t) || !read_time(&t, tag, c->not_after)) return 0;
    c->subject = tbs.p; if (!der_expect(&tbs, 0x30, &v)) return 0; c->subject_len = (uint32_t)(tbs.p - c->subject);
    if (!der_expect(&tbs, 0x30, &spki)) return 0;
    if (!der_expect(&spki, 0x30, &keyalg) || !alg_is(&keyalg, OID_RSA_ENC, 9)) return 0;
    if (!der_expect(&spki, 0x03, &keybits) || keybits.len < 2 || keybits.p[0] != 0) return 0;
    keybits.p++; keybits.len--;
    if (!der_expect(&keybits, 0x30, &rsakey)) return 0;
    if (!der_expect(&rsakey, 0x02, &nn) || !der_expect(&rsakey, 0x02, &ee)) return 0;
    if (nn.len && nn.p[0] == 0) { nn.p++; nn.len--; }
    if (nn.len < 128 || nn.len > 512 || !(nn.p[0] & 0x80)) return 0;
    c->n = nn.p; c->n_len = nn.len;
    if (!der_uint(&ee, &c->e)) return 0;
    /* optional issuerUniqueID [1], subjectUniqueID [2], extensions [3] */
    while (tbs.len) {
        if (!der_tlv(&tbs, &tag, &v)) return 0;
        if (tag == 0xa3 && !parse_extensions(c, &v)) return 0;
    }
    return 1;
}

int x509_verify_signature(const x509_cert *c, const uint8_t *n_be, uint32_t n_len, uint32_t e)
{
    static rsa_pub k;       /* 2.5 KiB; static keeps it off the 68000 stack */
    if (!c->sig_sha256_rsa) return 0;
    if (!rsa_pub_set(&k, n_be, n_len, e)) return 0;
    return rsa_verify_pkcs1_sha256(&k, c->tbs, c->tbs_len, c->sig, c->sig_len);
}

static int lower(int ch) { return (ch >= 'A' && ch <= 'Z') ? ch + 32 : ch; }

static int name_match(const uint8_t *pat, uint32_t plen, const char *host)
{
    uint32_t hlen = 0, i;
    while (host[hlen]) hlen++;
    if (plen >= 2 && pat[0] == '*' && pat[1] == '.') {   /* one wildcard label, must match at least one label */
        const char *dot = host;
        while (*dot && *dot != '.') dot++;
        if (!*dot || dot == host) return 0;
        dot++;
        hlen -= (uint32_t)(dot - host);
        if (hlen != plen - 2) return 0;
        for (i = 0; i < hlen; i++) if (lower(dot[i]) != lower(pat[2 + i])) return 0;
        return 1;
    }
    if (plen != hlen) return 0;
    for (i = 0; i < hlen; i++) if (lower(host[i]) != lower(pat[i])) return 0;
    return 1;
}

int x509_match_host(const x509_cert *c, const char *host)
{
    der names; uint8_t tag; der v;
    if (!c->san) return 0;
    names.p = c->san; names.len = c->san_len;
    while (names.len) {
        if (!der_tlv(&names, &tag, &v)) return 0;
        if (tag == 0x82 && name_match(v.p, v.len, host)) return 1;   /* [2] dNSName */
    }
    return 0;
}

static int str_le(const char *a, const char *b) { int i; for (i = 0; i < 15; i++) { if (a[i] < b[i]) return 1; if (a[i] > b[i]) return 0; } return 1; }
int x509_valid_at(const x509_cert *c, const char *now) { return !now || (str_le(c->not_before, now) && str_le(now, c->not_after)); }

static int pin_index(const x509_pin *pins, int npins, const uint8_t *n, uint32_t n_len, uint32_t e)
{
    int j;
    for (j = 0; j < npins; j++) if (pins[j].n_len == n_len && pins[j].e == e && mem_eq(pins[j].n, n, n_len)) return j;
    return -1;
}

int x509_verify_chain_pins(const x509_cert *certs, int count, const x509_pin *pins, int npins,
                           const char *host, const char *now, int *pin_used)
{
    int i, j, used = -1;
    if (count < 1 || count > 4 || npins < 1 || npins > X509_MAX_PINS) return 0;
    for (i = 0; i < count && used < 0; i++) {
        const x509_cert *c = &certs[i];
        if (i > 0 && !c->is_ca) return 0;
        /* trust anchor reached by key: a certificate carrying a pinned key itself (e.g. the cross-signed DigiCert
         * Global Root G2 that web.whatsapp.com sends as third certificate, signed by a root we do not know) ends the
         * chain without its own signature being checked; the leaf is never the anchor */
        if (i > 0 && (j = pin_index(pins, npins, c->n, c->n_len, c->e)) >= 0) { used = j; break; }
        if (!c->sig_sha256_rsa) return 0;
        if (!x509_valid_at(c, now)) return 0;
        /* One RSA verification per certificate (each costs ~9.6 s on the 68000): a certificate whose issuer is the
         * next one in the chain is checked under that issuer's key; if that issuer carries a pinned key, or the
         * certificate is the last one, it is checked under the pinned key, which completes the chain. Anything the
         * server sent beyond the completing certificate is ignored. */
        if (i + 1 < count) {
            const x509_cert *issuer = &certs[i + 1];
            if (c->issuer_len != issuer->subject_len || !mem_eq(c->issuer, issuer->subject, c->issuer_len)) return 0;
            j = pin_index(pins, npins, issuer->n, issuer->n_len, issuer->e);
            if (j >= 0) {
                if (!x509_verify_signature(c, pins[j].n, pins[j].n_len, pins[j].e)) return 0;
                used = j; break;
            }
            if (!x509_verify_signature(c, issuer->n, issuer->n_len, issuer->e)) return 0;
        } else {
            for (j = 0; j < npins && used < 0; j++)          /* last certificate: signed by one of the pins? */
                if (x509_verify_signature(c, pins[j].n, pins[j].n_len, pins[j].e)) used = j;
            if (used < 0) return 0;
        }
    }
    if (used < 0) return 0;
    if (pin_used) *pin_used = used;
    return x509_match_host(&certs[0], host);
}

int x509_verify_chain(const x509_cert *certs, int count, const uint8_t *root_n, uint32_t root_n_len, uint32_t root_e,
                      const char *host, const char *now)
{
    x509_pin p; p.n = root_n; p.n_len = root_n_len; p.e = root_e;
    return x509_verify_chain_pins(certs, count, &p, 1, host, now, 0);
}

/* ---- certificate cache ------------------------------------------------------------- */
static void u32_be(uint8_t b[4], uint32_t v) { b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16); b[2] = (uint8_t)(v >> 8); b[3] = (uint8_t)v; }

void x509_cache_fingerprint(uint8_t fp[32], const x509_pin *pins, int npins,
                            const char *host, const uint8_t *leaf_der, uint32_t leaf_len)
{
    sha256_ctx h; uint8_t b[4]; uint32_t hl = 0; int j;
    while (host[hl]) hl++;
    sha256_init(&h);
    sha256_update(&h, (const uint8_t *)"WhatsA500 x509 cache v2", 23);  /* every field is length-prefixed: no boundary ambiguity */
    u32_be(b, (uint32_t)npins); sha256_update(&h, b, 4);
    for (j = 0; j < npins; j++) {
        u32_be(b, pins[j].n_len); sha256_update(&h, b, 4); sha256_update(&h, pins[j].n, pins[j].n_len);
        u32_be(b, pins[j].e); sha256_update(&h, b, 4);
    }
    u32_be(b, hl); sha256_update(&h, b, 4); sha256_update(&h, (const uint8_t *)host, hl);
    u32_be(b, leaf_len); sha256_update(&h, b, 4); sha256_update(&h, leaf_der, leaf_len);
    sha256_final(&h, fp);
}

int x509_cache_match(const x509_cache *c, const x509_pin *pins, int npins,
                     const char *host, const uint8_t *leaf_der, uint32_t leaf_len)
{
    uint8_t fp[32]; uint32_t i, diff = 0;
    if (!c || !c->valid) return 0;
    x509_cache_fingerprint(fp, pins, npins, host, leaf_der, leaf_len);
    for (i = 0; i < 32; i++) diff |= fp[i] ^ c->fp[i];
    return diff == 0;
}

void x509_cache_store(x509_cache *c, const x509_pin *pins, int npins,
                      const char *host, const uint8_t *leaf_der, uint32_t leaf_len)
{
    x509_cache_fingerprint(c->fp, pins, npins, host, leaf_der, leaf_len);
    c->valid = 1;
}

/* ---- cache file ---------------------------------------------------------------------------------------------- */
static void xc_be16(uint8_t *d, uint32_t v) { d[0] = (uint8_t)(v >> 8); d[1] = (uint8_t)v; }
static uint32_t xc_rd16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }

uint32_t x509_cache_write(uint8_t *out, uint32_t cap, const x509_cache *c)
{
    uint32_t o = 0, i, limbs = (uint32_t)c->key.limbs, size;
    if (!c->valid || limbs == 0 || limbs > RSA_MAX_LIMBS) return 0;
    size = 1 + 32 + 2 + 4 + 2 + 4 * limbs + 32;
    if (cap < size) return 0;
    out[o++] = 1;
    for (i = 0; i < 32; i++) out[o++] = c->fp[i];
    xc_be16(out + o, limbs); o += 2;
    out[o++] = (uint8_t)(c->key.e >> 24); out[o++] = (uint8_t)(c->key.e >> 16); out[o++] = (uint8_t)(c->key.e >> 8); out[o++] = (uint8_t)c->key.e;
    xc_be16(out + o, c->key.n0inv); o += 2;
    for (i = 0; i < limbs; i++) { xc_be16(out + o, c->key.n[i]); o += 2; }
    for (i = 0; i < limbs; i++) { xc_be16(out + o, c->key.rr[i]); o += 2; }
    sha256(out + o, out, o);
    return size;
}

int x509_cache_read(x509_cache *c, const uint8_t *in, uint32_t len)
{
    uint8_t h[32]; uint32_t o = 0, i, limbs, d = 0;
    c->valid = 0;
    if (len < 1 + 32 + 2 + 4 + 2 + 32 || in[0] != 1) return 0;
    limbs = xc_rd16(in + 33);
    if (limbs == 0 || limbs > RSA_MAX_LIMBS || len != 1 + 32 + 2 + 4 + 2 + 4 * limbs + 32) return 0;
    sha256(h, in, len - 32);
    for (i = 0; i < 32; i++) d |= h[i] ^ in[len - 32 + i];
    if (d) return 0;
    o = 1;
    for (i = 0; i < 32; i++) c->fp[i] = in[o++];
    o += 2;
    c->key.e = ((uint32_t)in[o] << 24) | ((uint32_t)in[o + 1] << 16) | ((uint32_t)in[o + 2] << 8) | in[o + 3]; o += 4;
    c->key.n0inv = (uint16_t)xc_rd16(in + o); o += 2;
    c->key.limbs = (int)limbs;
    for (i = 0; i < RSA_MAX_LIMBS; i++) { c->key.n[i] = 0; c->key.rr[i] = 0; }
    for (i = 0; i < limbs; i++) { c->key.n[i] = (uint16_t)xc_rd16(in + o); o += 2; }
    for (i = 0; i < limbs; i++) { c->key.rr[i] = (uint16_t)xc_rd16(in + o); o += 2; }
    c->valid = 1;
    return 1;
}
