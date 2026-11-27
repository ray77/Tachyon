/* X.509 parsing and chain verification against the live RSA chain of web.whatsapp.com
 * (tests/certs/, fetched 2026-11-26) with the DigiCert Global Root G2 key pinned. */
#include <stdio.h>
#include <string.h>
#include "x509.h"
#include "rsa.h"
#include "../tests/certs/wa_rsa_chain.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }

int main(void)
{
    static x509_cert c[3];
    static uint8_t rootn[256];
    uint32_t i;
    result(x509_parse(&c[0], wa_cert0, sizeof wa_cert0), "parse leaf");
    result(x509_parse(&c[1], wa_cert1, sizeof wa_cert1), "parse intermediate");
    result(x509_parse(&c[2], wa_cert2, sizeof wa_cert2), "parse root (cross-signed G2)");
    printf("  leaf  n=%u bytes e=%u ca=%d sha256rsa=%d %s..%s\n", c[0].n_len, c[0].e, c[0].is_ca, c[0].sig_sha256_rsa, c[0].not_before, c[0].not_after);
    printf("  inter n=%u bytes e=%u ca=%d\n", c[1].n_len, c[1].e, c[1].is_ca);
    printf("  root  n=%u bytes e=%u ca=%d\n", c[2].n_len, c[2].e, c[2].is_ca);
    result(c[0].n_len == 256 && c[0].e == 65537 && !c[0].is_ca, "leaf: RSA-2048, e=65537, not a CA");
    result(c[1].is_ca && c[2].is_ca, "intermediate and root flagged cA");
    result(x509_match_host(&c[0], "web.whatsapp.com"), "SAN matches web.whatsapp.com via *.whatsapp.com");
    {   /* cache file: fingerprint + prepared RSA key survive the round trip; corruption, truncation and a foreign version are rejected */
        static x509_cache a, b; static uint8_t buf[X509_CACHE_FILE_MAX]; uint32_t n, i; int bad = 0;
        x509_pin pin; pin.n = c[2].n; pin.n_len = c[2].n_len; pin.e = c[2].e;
        result(rsa_pub_set(&a.key, c[0].n, c[0].n_len, c[0].e), "prepared leaf key");
        x509_cache_store(&a, &pin, 1, "web.whatsapp.com", wa_cert0, sizeof wa_cert0);
        n = x509_cache_write(buf, sizeof buf, &a);
        result(n == 1 + 32 + 2 + 4 + 2 + 4 * 128 + 32, "cache file written (RSA-2048: 615 bytes)");
        result(x509_cache_read(&b, buf, n) && b.valid && memcmp(a.fp, b.fp, 32) == 0 && b.key.limbs == a.key.limbs && b.key.e == a.key.e
               && b.key.n0inv == a.key.n0inv && memcmp(a.key.n, b.key.n, sizeof a.key.n) == 0 && memcmp(a.key.rr, b.key.rr, sizeof a.key.rr) == 0, "cache file read back identical");
        result(rsa_pub_check(&b.key, c[0].n, c[0].n_len, c[0].e), "read-back key passes rsa_pub_check against the leaf");
        result(x509_cache_match(&b, &pin, 1, "web.whatsapp.com", wa_cert0, sizeof wa_cert0), "read-back entry hits for the same pin set / host / leaf");
        for (i = 0; i < n; i += 37) { buf[i] ^= 1; if (x509_cache_read(&b, buf, n)) bad++; buf[i] ^= 1; }
        result(bad == 0, "every corrupted byte rejected (SHA-256)");
        result(!x509_cache_read(&b, buf, n - 1) && !x509_cache_read(&b, buf + 1, n - 1), "truncated / shifted record rejected");
        buf[0] = 2; result(!x509_cache_read(&b, buf, n), "unknown version rejected"); buf[0] = 1;
        result(x509_cache_write(buf, n - 1, &a) == 0, "no room: nothing written");
    }
    result(x509_match_host(&c[0], "WHATSAPP.COM"), "SAN exact match, case-insensitive");
    result(!x509_match_host(&c[0], "a.b.whatsapp.com"), "wildcard does not span two labels");
    result(!x509_match_host(&c[0], "whatsapp.org"), "unrelated host rejected");
    result(x509_verify_signature(&c[0], c[1].n, c[1].n_len, c[1].e), "leaf signature by intermediate (RSA-2048 PKCS#1 SHA-256)");
    result(x509_verify_signature(&c[1], c[2].n, c[2].n_len, c[2].e), "intermediate signature by Global Root G2");
    result(!x509_verify_signature(&c[0], c[2].n, c[2].n_len, c[2].e), "leaf not signed by the root directly");
    for (i = 0; i < c[2].n_len; i++) rootn[i] = c[2].n[i];     /* the pinned trust anchor is the G2 key itself */
    result(x509_verify_chain(c, 2, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", "20261126000000Z"), "chain leaf -> intermediate -> pinned G2 key, valid now");
    result(!x509_verify_chain(c, 2, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", "20270101000000Z"), "chain rejected after notAfter");
    result(x509_verify_chain(c, 3, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", "20261126000000Z"), "chain of 3 with the cross-signed G2 appended (as the live server sends it) accepted");
    result(x509_verify_chain(c, 3, c[1].n, c[1].n_len, c[1].e, "web.whatsapp.com", "20261126000000Z"), "chain of 3 accepted with the intermediate key pinned (leaf signed by it; rest ignored)");
    result(x509_verify_chain(c, 1, c[1].n, c[1].n_len, c[1].e, "web.whatsapp.com", 0), "leaf alone accepted with the intermediate key pinned");
    result(!x509_verify_chain(c, 1, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", 0), "leaf alone rejected with the root key pinned");
    result(!x509_verify_chain(c, 2, rootn, c[2].n_len, c[2].e, "example.com", 0), "chain rejected for wrong host");
    rootn[100] ^= 1;
    result(!x509_verify_chain(c, 2, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", 0), "chain rejected under a wrong root key");
    result(!x509_verify_chain(c, 3, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", 0), "chain of 3 rejected under a wrong root key (appended root is not the anchor)");
    rootn[100] ^= 1;                                            /* the G2 key again */
    {   /* pin set: root G2 and the CA1 intermediate; the chain completes at the intermediate (one RSA verification) */
        x509_pin pins[2]; int used = -1;
        pins[0].n = c[1].n; pins[0].n_len = c[1].n_len; pins[0].e = c[1].e;      /* intermediate */
        pins[1].n = rootn;  pins[1].n_len = c[2].n_len; pins[1].e = c[2].e;      /* root */
        result(x509_verify_chain_pins(c, 3, pins, 2, "web.whatsapp.com", "20261126000000Z", &used) && used == 0, "pin set {intermediate, root}: chain of 3 completes at the intermediate");
        used = -1;
        result(x509_verify_chain_pins(c, 2, pins, 2, "web.whatsapp.com", 0, &used) && used == 0, "pin set: chain of 2 completes at the intermediate");
        pins[0].n = rootn; pins[0].n_len = c[2].n_len; pins[0].e = c[2].e; pins[1].n = c[1].n; pins[1].n_len = c[1].n_len; pins[1].e = c[1].e;
        used = -1;
        result(x509_verify_chain_pins(c, 2, pins, 2, "web.whatsapp.com", 0, &used) && used == 1, "pin set {root, intermediate}: order does not matter, intermediate used");
        pins[1].n = c[0].n; pins[1].n_len = c[0].n_len; pins[1].e = c[0].e;      /* an unrelated second pin (the leaf's own key) */
        used = -1;
        result(x509_verify_chain_pins(c, 2, pins, 2, "web.whatsapp.com", 0, &used) && used == 0, "pin set {root, other}: falls back to the root (two verifications)");
        rootn[10] ^= 0x55; pins[0].n = rootn;
        result(!x509_verify_chain_pins(c, 2, pins, 2, "web.whatsapp.com", 0, 0), "pin set with neither key matching rejected");
        result(!x509_verify_chain_pins(c, 1, pins, 1, "web.whatsapp.com", 0, 0), "leaf alone under a wrong single pin rejected");
        rootn[10] ^= 0x55;
    }
    {   /* truncated / corrupted DER must not parse or verify */
        x509_cert t;
        static uint8_t bad[2048];
        memcpy(bad, wa_cert0, sizeof wa_cert0);
        result(!x509_parse(&t, wa_cert0, sizeof wa_cert0 - 1), "truncated DER rejected");
        bad[sizeof wa_cert0 - 1] ^= 1;
        result(x509_parse(&t, bad, sizeof wa_cert0) && !x509_verify_signature(&t, c[1].n, c[1].n_len, c[1].e), "flipped signature bit rejected");
        memcpy(bad, wa_cert0, sizeof wa_cert0);
        bad[200] ^= 1;      /* inside tbs */
        result(x509_parse(&t, bad, sizeof wa_cert0) == 0 || !x509_verify_signature(&t, c[1].n, c[1].n_len, c[1].e), "flipped tbs bit rejected");
    }
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
