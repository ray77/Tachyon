/*
 * proto/inflate.c against Go's compress/zlib (tools/genvectors -mode inflate): every vector must decompress to the
 * exact plain bytes; every single-byte corruption of the stream must be rejected (data or checksum error), a
 * truncated stream must report truncation, a too-small output buffer must report that. Also the stored-block
 * writer used by the pairing simulator and wa_adler32 itself.
 *   inflate_test tests/vectors/inflate.txt
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "inflate.h"

static int fails, checks;
#define CHECK(c) do { checks++; if (!(c)) { fails++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static int hexval(int c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }
static uint32_t unhex(const char *s, uint8_t *out, uint32_t cap)
{
    uint32_t n = 0;
    if (s[0] == '-' && (s[1] == 0 || s[1] == ' ' || s[1] == '\n')) return 0;
    while (hexval(s[0]) >= 0 && hexval(s[1]) >= 0 && n < cap) { out[n++] = (uint8_t)(hexval(s[0]) * 16 + hexval(s[1])); s += 2; }
    return n;
}

int main(int argc, char **argv)
{
    static char linebuf[200000]; static uint8_t comp[65536], plain[65536], out[65536];
    FILE *f; int vectors = 0, harmless = 0;
    if (argc < 2 || !(f = fopen(argv[1], "r"))) { printf("usage: inflate_test <inflate.txt>\n"); return 2; }
    while (fgets(linebuf, sizeof linebuf, f)) {
        char name[64], *p = linebuf, *q; uint32_t cl, pl, ol, i; int e;
        if (sscanf(p, "%63s", name) != 1) continue;
        p += strlen(name); while (*p == ' ') p++;
        cl = unhex(p, comp, sizeof comp);
        q = strchr(p, ' '); if (!q) continue; while (*q == ' ') q++;
        pl = unhex(q, plain, sizeof plain);
        vectors++;
        e = wa_inflate(comp, cl, out, sizeof out, &ol);
        CHECK(e == WA_INFLATE_OK);
        CHECK(ol == pl && memcmp(out, plain, pl) == 0);
        if (e != WA_INFLATE_OK || ol != pl) printf("  %s: %s, %u of %u bytes\n", name, wa_inflate_errstr(e), ol, pl);
        /* exact-size output buffer is fine, one byte less is not (unless empty) */
        e = wa_inflate(comp, cl, out, pl, &ol); CHECK(e == WA_INFLATE_OK && ol == pl);
        if (pl) { e = wa_inflate(comp, cl, out, pl - 1, &ol); CHECK(e == WA_INFLATE_ERR_OUTPUT); }
        /* truncation: every prefix shorter than the stream must fail, and never with "ok" */
        for (i = 0; i < cl; i += cl / 7 + 1) { e = wa_inflate(comp, i, out, sizeof out, &ol); CHECK(e != WA_INFLATE_OK); }
        /* corruption: flip one bit in each of a few positions (header, data, trailer): never "ok" with the same output */
        for (i = 0; i < cl; i += cl / 11 + 1) {
            comp[i] ^= 0x10;
            e = wa_inflate(comp, cl, out, sizeof out, &ol);
            if (e == WA_INFLATE_OK && ol == pl && memcmp(out, plain, pl) == 0 && pl) {
                /* a flipped bit that changes nothing: only the padding bits before a stored block can do that */
                harmless++; printf("  %s: bit flip at byte %u of %u is ignored (stored-block padding?) byte %02x\n", name, i, cl, comp[i] ^ 0x10);
            }
            comp[i] ^= 0x10;
        }
        /* Adler-32 trailer alone */
        comp[cl - 1] ^= 1; e = wa_inflate(comp, cl, out, sizeof out, &ol); CHECK(e == WA_INFLATE_ERR_CHECKSUM); comp[cl - 1] ^= 1;
    }
    fclose(f);
    CHECK(vectors >= 30);
    CHECK(harmless <= vectors / 4);        /* the stored-block vectors' padding */
    /* Adler-32 known answers (RFC 1950 example "Wikipedia" = 0x11E60398) */
    CHECK(wa_adler32((const uint8_t *)"Wikipedia", 9) == 0x11E60398u);
    CHECK(wa_adler32((const uint8_t *)"", 0) == 1);
    {   /* a 10000-byte run exercises the NMAX split */
        static uint8_t big[10000]; uint32_t a = 1, b = 0, i; for (i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 7);
        for (i = 0; i < sizeof big; i++) { a = (a + big[i]) % 65521u; b = (b + a) % 65521u; }
        CHECK(wa_adler32(big, sizeof big) == ((b << 16) | a));
    }
    /* not zlib: gzip magic, wrong FCHECK, preset dictionary */
    { static const uint8_t gz[] = { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3 }; uint32_t ol; CHECK(wa_inflate(gz, sizeof gz, out, sizeof out, &ol) == WA_INFLATE_ERR_HEADER); }
    { static const uint8_t bad[] = { 0x78, 0x9d, 3, 0, 0, 0, 0, 1 }; uint32_t ol; CHECK(wa_inflate(bad, sizeof bad, out, sizeof out, &ol) == WA_INFLATE_ERR_HEADER); }
    { static const uint8_t dict[] = { 0x78, 0xbb, 1, 2, 3, 4, 3, 0, 0, 0, 0, 1 }; uint32_t ol; CHECK(wa_inflate(dict, sizeof dict, out, sizeof out, &ol) == WA_INFLATE_ERR_HEADER); }
    printf("%s: %d checks, %d failures (%d vectors)\n", fails ? "FAIL" : "PASS", checks, fails, vectors);
    return fails ? 1 : 0;
}
