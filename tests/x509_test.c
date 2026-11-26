/* X.509 parsing and chain verification against the live RSA chain of web.whatsapp.com
 * (tests/certs/, fetched 2026-11-26) with the DigiCert Global Root G2 key pinned. */
#include <stdio.h>
#include <string.h>
#include "x509.h"
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
    result(x509_match_host(&c[0], "WHATSAPP.COM"), "SAN exact match, case-insensitive");
    result(!x509_match_host(&c[0], "a.b.whatsapp.com"), "wildcard does not span two labels");
    result(!x509_match_host(&c[0], "whatsapp.org"), "unrelated host rejected");
    result(x509_verify_signature(&c[0], c[1].n, c[1].n_len, c[1].e), "leaf signature by intermediate (RSA-2048 PKCS#1 SHA-256)");
    result(x509_verify_signature(&c[1], c[2].n, c[2].n_len, c[2].e), "intermediate signature by Global Root G2");
    result(!x509_verify_signature(&c[0], c[2].n, c[2].n_len, c[2].e), "leaf not signed by the root directly");
    for (i = 0; i < c[2].n_len; i++) rootn[i] = c[2].n[i];     /* the pinned trust anchor is the G2 key itself */
    result(x509_verify_chain(c, 2, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", "20261126000000Z"), "chain leaf -> intermediate -> pinned G2 key, valid now");
    result(!x509_verify_chain(c, 2, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", "20270101000000Z"), "chain rejected after notAfter");
    result(!x509_verify_chain(c, 2, rootn, c[2].n_len, c[2].e, "example.com", 0), "chain rejected for wrong host");
    rootn[100] ^= 1;
    result(!x509_verify_chain(c, 2, rootn, c[2].n_len, c[2].e, "web.whatsapp.com", 0), "chain rejected under a wrong root key");
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
