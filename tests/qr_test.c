/* Host test for ui/qr.c (make qr-test): every code is rendered to PBM and decoded with zbarimg, and
 * compared module by module with the reference encoder python-qrcode. Usage: qr_test <python> <outdir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "../ui/qr.h"

static const char *py, *dir;
static int fails, cases, same_mask, decoded;

#define CHECK(c, ...) do { if (!(c)) { printf("FAIL "); printf(__VA_ARGS__); printf("\n"); fails++; } } while (0)

/* ref.py <hex data> <L|M> <version, 0 = smallest> <mask, -1 = automatic> -> "version mask" and the rows.
 * Reference is python-qrcode. segno is not usable for this: it inserts a spare 0x00 codeword before the
 * pad codewords when the bit stream already ends on a byte boundary, i.e. in every non-full byte mode code. */
static const char *ref_py =
    "import sys, qrcode\n"
    "from qrcode.util import QRData, MODE_8BIT_BYTE\n"
    "d = bytes.fromhex(sys.argv[1])\n"
    "v, m = int(sys.argv[3]), int(sys.argv[4])\n"
    "level = {'L': qrcode.constants.ERROR_CORRECT_L, 'M': qrcode.constants.ERROR_CORRECT_M}[sys.argv[2]]\n"
    "q = qrcode.QRCode(version=v or None, error_correction=level, border=0)\n"
    "q.add_data(QRData(d, mode=MODE_8BIT_BYTE), optimize=0)\n"
    "if not v: q.best_fit()\n"
    "q.mask_pattern = q.best_mask_pattern() if m < 0 else m\n"
    "q.make(fit=False)\n"
    "print(q.version, q.mask_pattern)\n"
    "for r in q.get_matrix(): print(''.join('1' if c else '0' for c in r))\n";

typedef struct { unsigned version, mask, size; unsigned char m[QR_MAX_SIZE][QR_MAX_SIZE]; } ref_code;

static int reference(ref_code *r, const uint8_t *data, uint32_t len, uint32_t ecc, uint32_t ver, int mask)
{
    char cmd[1200], line[200];
    uint32_t i, x, y;
    int n = snprintf(cmd, sizeof cmd, "'%s' -I '%s/ref.py' ", py, dir);
    FILE *f;
    for (i = 0; i < len; i++) n += snprintf(cmd + n, sizeof cmd - n, "%02x", data[i]);
    snprintf(cmd + n, sizeof cmd - n, " %c %u %d", ecc == QR_ECC_L ? 'L' : 'M', ver, mask);
    if (!(f = popen(cmd, "r"))) return -1;
    if (!fgets(line, sizeof line, f) || sscanf(line, "%u %u", &r->version, &r->mask) != 2 || r->version > QR_MAX_VERSION) {
        pclose(f);
        return -1;
    }
    r->size = 17 + 4 * r->version;
    for (y = 0; y < r->size; y++) {
        if (!fgets(line, sizeof line, f) || strlen(line) < r->size) { pclose(f); return -1; }
        for (x = 0; x < r->size; x++) r->m[y][x] = line[x] == '1';
    }
    return pclose(f) == 0 ? 0 : -1;
}

static uint32_t diff_modules(const qr *q, const ref_code *r)
{
    uint32_t x, y, d = 0;
    for (y = 0; y < q->size; y++)
        for (x = 0; x < q->size; x++) d += qr_module(q, x, y) != r->m[y][x];
    return d;
}

/* both copies of the 15 format bits, bit 0 first */
static void format_bits(uint32_t out[2], uint32_t n, uint32_t (*mod)(const void *, uint32_t, uint32_t), const void *c)
{
    uint32_t i;
    out[0] = out[1] = 0;
    for (i = 0; i < 15; i++) {
        uint32_t x = i < 8 ? 8 : (i == 8 ? 7 : 14 - i), y = i < 6 ? i : (i < 8 ? i + 1 : 8);
        out[0] |= mod(c, x, y) << i;
        out[1] |= mod(c, i < 8 ? n - 1 - i : 8, i < 8 ? 8 : n - 15 + i) << i;
    }
}
static uint32_t mod_qr(const void *c, uint32_t x, uint32_t y) { return qr_module(c, x, y); }
static uint32_t mod_ref(const void *c, uint32_t x, uint32_t y) { return ((const ref_code *)c)->m[y][x]; }

/* the four penalty rules, written independently of ui/qr.c and as plainly as possible */
static long plain_penalty(const qr *q)
{
    int n = q->size, x, y, o, k, dark = 0;
    long s = 0;
    for (o = 0; o < 2; o++) {
        for (y = 0; y < n; y++) {
            char line[QR_MAX_SIZE + 1], *p;
            for (x = 0; x < n; x++) line[x] = '0' + (o ? qr_module(q, y, x) : qr_module(q, x, y));
            line[n] = 0;
            for (x = 0; x < n; x += k) {
                for (k = 1; x + k < n && line[x + k] == line[x]; k++) ;
                if (k >= 5) s += k - 2;
            }
            for (p = line; (p = strstr(p, "10111010000")); p++) s += 40;
            for (p = line; (p = strstr(p, "00001011101")); p++) s += 40;
        }
    }
    for (y = 0; y < n; y++) {
        for (x = 0; x < n; x++) {
            uint32_t c = qr_module(q, x, y);
            dark += c;
            if (x + 1 < n && y + 1 < n && qr_module(q, x + 1, y) == c && qr_module(q, x, y + 1) == c &&
                qr_module(q, x + 1, y + 1) == c) s += 3;
        }
    }
    return s + 10 * (labs(20L * dark - 10L * n * n) / ((long)n * n));
}

static void zbar_check(const char *name, const qr *q, const uint8_t *data, uint32_t len)
{
    static char pbm[64 * 1024];
    char path[512], cmd[700];
    uint8_t out[1024];
    size_t n;
    FILE *f;
    uint32_t size = qr_render_pbm(q, pbm, sizeof pbm, 4);
    CHECK(size, "%s: PBM render", name);
    snprintf(path, sizeof path, "%s/%s.pbm", dir, name);
    if (!(f = fopen(path, "wb")) || fwrite(pbm, 1, size, f) != size) { CHECK(0, "%s: write %s", name, path); return; }
    fclose(f);
    /* binary mode: the payload bytes as they are, without charset guessing */
    snprintf(cmd, sizeof cmd, "zbarimg -q --raw -Sbinary '%s'", path);
    if (!(f = popen(cmd, "r"))) { CHECK(0, "%s: zbarimg", name); return; }
    n = fread(out, 1, sizeof out, f);
    CHECK(pclose(f) == 0, "%s: zbarimg found no code", name);
    CHECK(n == len && !memcmp(out, data, len), "%s: zbar decoded %zu bytes, expected %u equal bytes", name, n, len);
    if (n == len && !memcmp(out, data, len)) decoded++;
}

/* min_version 1: the version is chosen by both encoders and must agree */
static void run_case(const char *name, const uint8_t *data, uint32_t len, uint32_t ecc, uint32_t min_version,
                     uint32_t want_version, qr *result)
{
    static qr q, forced;
    static qr_work w;
    static ref_code ref;
    uint32_t m, x, y, best_mask = 0, fa[2], fb[2];
    long best = -1;

    cases++;
    if (qr_encode_ex(&q, &w, data, len, ecc, min_version, QR_MASK_AUTO)) { CHECK(0, "%s: encode", name); return; }
    if (result) *result = q;
    CHECK(q.version == want_version, "%s: version %u, expected %u", name, q.version, want_version);
    CHECK(q.size == 17 + 4 * q.version && q.ecc == ecc && q.mask < 8, "%s: header fields", name);
    for (y = 0; y < QR_MAX_SIZE; y++)
        for (x = 0; x < QR_STRIDE * 8; x++)
            if ((x >= q.size || y >= q.size) && qr_module(&q, x, y)) { CHECK(0, "%s: bit outside at %u,%u", name, x, y); y = QR_MAX_SIZE; break; }
    zbar_check(name, &q, data, len);

    if (reference(&ref, data, len, ecc, min_version > 1 ? min_version : 0, -1)) { CHECK(0, "%s: reference encoder", name); return; }
    CHECK(ref.version == q.version, "%s: version %u, reference %u", name, q.version, ref.version);
    forced = q;
    if (ref.mask == q.mask) same_mask++;
    else qr_encode_ex(&forced, &w, data, len, ecc, min_version, ref.mask);
    CHECK(forced.size == ref.size && !diff_modules(&forced, &ref), "%s: %u modules differ from the reference (mask %u)",
          name, diff_modules(&forced, &ref), ref.mask);
    format_bits(fa, forced.size, mod_qr, &forced);
    format_bits(fb, ref.size, mod_ref, &ref);
    CHECK(fa[0] == fb[0] && fa[1] == fb[1] && fa[0] == fa[1], "%s: format bits %04x/%04x, reference %04x/%04x", name, fa[0], fa[1], fb[0], fb[1]);

    for (m = 0; m < 8; m++) {
        long s;
        qr_encode_ex(&forced, &w, data, len, ecc, min_version, m);
        CHECK(forced.mask == m, "%s: forced mask %u", name, m);
        s = plain_penalty(&forced);
        if (best < 0 || s < best) { best = s; best_mask = m; }
    }
    CHECK(q.mask == best_mask, "%s: chose mask %u, lowest penalty has %u", name, q.mask, best_mask);
}

static uint32_t rnd_state = 0x2463534bu;
static uint8_t rnd(void)
{
    rnd_state ^= rnd_state << 13; rnd_state ^= rnd_state >> 17; rnd_state ^= rnd_state << 5;
    return (uint8_t)(rnd_state >> 11);
}

static void b64_blob(char *out, uint32_t chars)   /* base64 of random bytes: chars - 1 symbols and one '=' */
{
    static const char abc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    uint32_t i;
    for (i = 0; i + 1 < chars; i++) out[i] = abc[rnd() & 63];
    out[i++] = '=';
    out[i] = 0;
}

int main(int argc, char **argv)
{
    /* byte mode capacities of ISO/IEC 18004 table 7, versions 1..15 */
    static const uint32_t capacity[2][15] = {
        { 17, 32, 53, 78, 106, 134, 154, 192, 230, 271, 321, 367, 425, 458, 520 },
        { 14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 251, 287, 331, 362, 412 },
    };
    static const char *shorts[] = { "A", "Tachyon", "https://web.whatsapp.com/", "0123456789012345678901234567890",
                                    ("Gr\xc3\xbc\xc3\x9f" "e vom Amiga 500") };
    static qr q;
    static qr_work w;
    static uint8_t buf[QR_MAX_INPUT + 1];
    static char pbm[64 * 1024];
    char path[512], name[64], pair[256], ref64[32], k1[48], k2[48], k3[48];
    uint32_t i, v, e, m, len, n;
    FILE *f;

    if (argc != 3) { fprintf(stderr, "usage: %s <python with qrcode> <output dir>\n", argv[0]); return 2; }
    py = argv[1]; dir = argv[2];
    mkdir(dir, 0755);
    snprintf(path, sizeof path, "%s/ref.py", dir);
    if (!(f = fopen(path, "w"))) { perror(path); return 2; }
    fputs(ref_py, f);
    fclose(f);

    /* the pairing string: "ref,noisePub,identityPub,advSecret" */
    b64_blob(ref64, 24); b64_blob(k1, 44); b64_blob(k2, 44); b64_blob(k3, 44);
    n = (uint32_t)snprintf(pair, sizeof pair, "2@%s,%s,%s,%s", ref64, k1, k2, k3);
    for (e = QR_ECC_L; e <= QR_ECC_M; e++) {
        static ref_code ref;
        snprintf(name, sizeof name, "pairing_%c", e ? 'M' : 'L');
        run_case(name, (const uint8_t *)pair, n, e, 1, e ? 9 : 8, &q);
        printf("pairing string: %u bytes, level %c -> version %u, %u x %u modules, mask %u\n",
               n, e ? 'M' : 'L', q.version, q.size, q.size, q.mask);
        for (m = 0; m < 8; m++) {       /* every mask against the reference */
            qr_encode_ex(&q, &w, (const uint8_t *)pair, n, e, 1, m);
            CHECK(!reference(&ref, (const uint8_t *)pair, n, e, 0, (int)m) && ref.size == q.size && !diff_modules(&q, &ref),
                  "%s mask %u differs from the reference", name, m);
        }
    }

    for (i = 0; i < sizeof shorts / sizeof *shorts; i++) {
        for (e = QR_ECC_L; e <= QR_ECC_M; e++) {
            len = (uint32_t)strlen(shorts[i]);
            for (v = 1; capacity[e][v - 1] < len; v++) ;
            snprintf(name, sizeof name, "short%u_%c", i, e ? 'M' : 'L');
            run_case(name, (const uint8_t *)shorts[i], len, e, 1, v, 0);
        }
    }

    /* every version: filled to capacity and one byte more; beyond QR_MAX_INPUT through min_version */
    for (e = QR_ECC_L; e <= QR_ECC_M; e++) {
        for (v = 1; v <= QR_MAX_VERSION; v++) {
            uint32_t cap = capacity[e][v - 1];
            len = cap < QR_MAX_INPUT ? cap : QR_MAX_INPUT;
            for (i = 0; i < len; i++) buf[i] = rnd();
            snprintf(name, sizeof name, "v%u_%c_full", v, e ? 'M' : 'L');
            run_case(name, buf, len, e, cap <= QR_MAX_INPUT ? 1 : v, v, 0);
            if (cap < QR_MAX_INPUT) {
                buf[len] = rnd();
                snprintf(name, sizeof name, "v%u_%c_over", v, e ? 'M' : 'L');
                run_case(name, buf, len + 1, e, 1, v + 1, 0);
            }
        }
    }
    /* longest input, as a run of equal bytes (stresses the penalty rules) */
    for (i = 0; i < QR_MAX_INPUT; i++) buf[i] = 0xff;
    run_case("ones300_L", buf, QR_MAX_INPUT, QR_ECC_L, 1, 11, 0);
    run_case("ones300_M", buf, QR_MAX_INPUT, QR_ECC_M, 1, 13, 0);
    /* all zeros gives all-zero blocks (zero feedback in Reed-Solomon); python-qrcode crashes on those
     * (glog(0)), so zbar alone checks them */
    for (i = 0; i < QR_MAX_INPUT; i++) buf[i] = 0;
    for (e = QR_ECC_L; e <= QR_ECC_M; e++) {
        CHECK(qr_encode(&q, &w, buf, QR_MAX_INPUT, e) == 0, "zeros: encode");
        cases++;
        zbar_check(e ? "zeros300_M" : "zeros300_L", &q, buf, QR_MAX_INPUT);
    }

    /* arguments and limits */
    CHECK(qr_encode(&q, &w, buf, 0, QR_ECC_L) == 0 && q.version == 1, "empty input");
    CHECK(qr_encode(&q, &w, buf, QR_MAX_INPUT + 1, QR_ECC_L) == -1, "301 bytes accepted");
    CHECK(qr_encode(&q, &w, buf, 1, 2) == -1, "unknown ECC level accepted");
    CHECK(qr_encode_ex(&q, &w, buf, 1, QR_ECC_L, 0, QR_MASK_AUTO) == -1, "version 0 accepted");
    CHECK(qr_encode_ex(&q, &w, buf, 1, QR_ECC_L, 16, QR_MASK_AUTO) == -1, "version 16 accepted");
    CHECK(qr_encode_ex(&q, &w, buf, 1, QR_ECC_L, 1, 9) == -1, "mask 9 accepted");

    /* PBM: exact size, refusal when the buffer is one byte short, odd width */
    CHECK(qr_encode(&q, &w, buf, 1, QR_ECC_L) == 0, "encode");
    n = qr_render_pbm(&q, pbm, sizeof pbm, 1);          /* 29 x 29: "P4\n29 29\n" + 29 * 4 */
    CHECK(n == 9 + 29 * 4 && !memcmp(pbm, "P4\n29 29\n", 9), "PBM header or size (%u)", n);
    CHECK(qr_render_pbm(&q, pbm, n, 1) == n && qr_render_pbm(&q, pbm, n - 1, 1) == 0, "PBM capacity check");
    CHECK(qr_render_pbm(&q, pbm, sizeof pbm, 0) == 0 && qr_render_pbm(&q, pbm, sizeof pbm, 65) == 0, "PBM scale check");

    printf("%d cases, %d decoded by zbar, mask choice equals the reference in %d\n", cases, decoded, same_mask);
    printf("sizeof(qr) = %zu, sizeof(qr_work) = %zu\n", sizeof(qr), sizeof(qr_work));
    printf(fails ? "qr_test: %d FAILED\n" : "qr_test: PASS\n", fails);
    return fails != 0;
}
