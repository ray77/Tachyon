/* TLS 1.3 client against the loopback Go server (tools/tls13server): full handshake with a precomputed
 * X25519 key pair, echo round trip across the 16 KiB record limit, a forged record must be rejected,
 * a chain under a wrong pinned key must be rejected before anything is sent after the ClientHello,
 * and a handshake fed in 1-byte reads must still complete. Host only (POSIX sockets).
 * Optional 4th argument: record the first session (deterministic DRBG seed) for the Amiga replay. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "tls13.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }

static int send_all(int fd, const uint8_t *p, uint32_t n) { while (n) { ssize_t w = write(fd, p, n); if (w <= 0) return 0; p += w; n -= (uint32_t)w; } return 1; }

/* recording for the Amiga replay (bench/tls13_vector.h): everything the server sent before CONNECTED, the DRBG
 * seed and the pinned certificate, so the deterministic client reproduces the same session offline */
static uint8_t rec_seed[64];
static uint8_t rec_srv[65536]; static uint32_t rec_srv_len; static int recording;
static size_t chunk = 4096;

static int pump(int fd, tls13 *t, int (*done)(tls13 *))
{
    uint8_t buf[4096];
    for (;;) {
        if (t->out_len) { if (!send_all(fd, t->out, t->out_len)) return 0; t->out_len = 0; }
        if (done(t)) return 1;
        { ssize_t r = read(fd, buf, chunk); if (r <= 0) return 0;
          if (recording && t->state != TLS13_ST_CONNECTED && rec_srv_len + (uint32_t)r <= sizeof rec_srv) { memcpy(rec_srv + rec_srv_len, buf, (size_t)r); rec_srv_len += (uint32_t)r; }
          if (!tls13_input(t, buf, (uint32_t)r)) return 0; }
    }
}
static int connected(tls13 *t) { return t->state == TLS13_ST_CONNECTED; }
static int have_app(tls13 *t) { return t->app_len > 0; }
static uint32_t app_seen;
static int have_app_more(tls13 *t) { if (t->app_len > app_seen) { app_seen = t->app_len; return 1; } return 0; }

static int dial(int port)
{
    struct sockaddr_in sa;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port); sa.sin_addr.s_addr = htonl(0x7f000001);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { printf("FAIL connect\n"); exit(1); }
    return fd;
}

int main(int argc, char **argv)
{
    const char *certpath = argc > 1 ? argv[1] : "build/tls13_test_cert.der";
    int port = argc > 2 ? atoi(argv[2]) : 4436;
    static uint8_t der[4096], seed[64];
    static tls13 t;
    static x509_cert sc;
    static tls13_keypair kp;
    static x509_cache cache;
    hmac_drbg rng;
    uint32_t derlen;
    int fd, ok;
    FILE *f = fopen(certpath, "rb");
    if (!f) { printf("FAIL cannot read %s\n", certpath); return 1; }
    derlen = (uint32_t)fread(der, 1, sizeof der, f); fclose(f);
    result(x509_parse(&sc, der, derlen), "parse test server certificate");
    f = fopen("/dev/urandom", "rb"); if (!f || fread(seed, 1, 64, f) != 64) { printf("FAIL urandom\n"); return 1; } fclose(f);
    recording = argc > 3;
    if (recording) { memset(seed, 0x42, 64); seed[0] = 13; }    /* record mode: fixed seed, replayable */
    memcpy(rec_seed, seed, 64);
    rng.instantiated = 0; drbg_instantiate(&rng, seed, 64);

    /* ---- connection 1: the real thing, key pair precomputed (as the A500 would do it) ---- */
    fd = dial(port);
    result(tls13_keypair_generate(&kp, &rng), "X25519 key pair precomputed");
    ok = tls13_client_start_kp(&t, "tls-test.localhost", sc.n, sc.n_len, sc.e, 0, &rng, &kp);
    tls13_set_cert_cache(&t, &cache);                       /* empty: full verification, then the leaf is stored */
    result(ok && t.out_len > 0, "ClientHello built");
    ok = pump(fd, &t, connected);
    printf("  state=%d error=%s chain=%d cached=%d\n", t.state, tls13_errstr(t.error), t.chain_len, t.cert_cached);
    result(ok, "handshake completes (X25519, chain + RSA-PSS CertificateVerify verified, server Finished verified)");
    result(ok && !t.cert_cached && cache.valid, "empty certificate cache: chain verified, leaf fingerprint stored");
    recording = 0;
    if (ok) {
        static const uint8_t msg[] = "hello from the amiga side";
        ok = tls13_send(&t, msg, sizeof msg - 1) == (int)(sizeof msg - 1) && pump(fd, &t, have_app);
        result(ok && t.app_len == 5 + sizeof msg - 1 && memcmp(t.app, "echo:", 5) == 0 && memcmp(t.app + 5, msg, sizeof msg - 1) == 0, "application data round trip");
        t.app_len = 0;
        {   /* a 20 KiB message crosses the 16 KiB record limit; the server echoes per record ("echo:" + up to 16384 bytes) */
            static uint8_t big[20000], got[32768]; uint32_t i, gl = 0;
            for (i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 7);
            {   uint32_t sent = 0; ok = 1;
                while (ok && sent < sizeof big) {
                    int c = tls13_send(&t, big + sent, sizeof big - sent);
                    if (c < 0) ok = 0;
                    else if (c == 0) { ok = send_all(fd, t.out, t.out_len); t.out_len = 0; }
                    else sent += (uint32_t)c;
                }
            }
            while (ok && gl < sizeof big + 10) {
                t.app_len = 0; app_seen = 0;
                ok = pump(fd, &t, have_app_more);
                if (ok && gl + t.app_len <= sizeof got) { memcpy(got + gl, t.app, t.app_len); gl += t.app_len; }
            }
            t.app_len = 0;
            result(ok && gl == sizeof big + 10 && memcmp(got, "echo:", 5) == 0 && memcmp(got + 5, big, 16384) == 0
                   && memcmp(got + 5 + 16384, "echo:", 5) == 0 && memcmp(got + 10 + 16384, big + 16384, sizeof big - 16384) == 0,
                   "20 KiB message in two records round trips");
        }
        {   /* tamper: a forged protected record -> GCM failure, state ERROR */
            uint8_t fake[5 + 1 + 16 + 4] = { 23, 3, 3, 0, 21 };
            result(!tls13_input(&t, fake, sizeof fake) && t.state == TLS13_ST_ERROR, "forged record rejected (GCM tag)");
        }
    }
    close(fd);

    /* ---- connection 2: the same server under a wrong pinned root key must be rejected at the Certificate ---- */
    {
        static uint8_t wrong_n[256]; uint32_t i;
        for (i = 0; i < sc.n_len && i < sizeof wrong_n; i++) wrong_n[i] = sc.n[i];
        wrong_n[sc.n_len / 2] ^= 0x5a;
        fd = dial(port);
        ok = tls13_client_start(&t, "tls-test.localhost", wrong_n, sc.n_len, sc.e, 0, &rng);
        ok = ok && !pump(fd, &t, connected);
        printf("  state=%d error=%s\n", t.state, tls13_errstr(t.error));
        result(ok && t.state == TLS13_ST_ERROR && strcmp(tls13_errstr(t.error), "certificate chain does not verify") == 0,
               "chain under a wrong pinned key rejected");
        result(t.out_len == 0 && !t.wr_encrypted, "nothing sent after the ClientHello (no Finished, no client keys)");
        close(fd);
    }

    /* ---- connection 3: 1-byte reads exercise record and handshake reassembly; the certificate cache hits ---- */
    {
        chunk = 1;
        fd = dial(port);
        ok = tls13_client_start(&t, "tls-test.localhost", sc.n, sc.n_len, sc.e, 0, &rng);
        tls13_set_cert_cache(&t, &cache);
        ok = ok && pump(fd, &t, connected);
        result(ok, "handshake completes with 1-byte reads");
        result(ok && t.cert_cached == 1, "certificate cache hit: chain verification skipped, CertificateVerify still checked");
        if (ok) {
            static const uint8_t msg[] = "bytewise";
            ok = tls13_send(&t, msg, 8) == 8 && pump(fd, &t, have_app);
            result(ok && t.app_len == 13 && memcmp(t.app, "echo:bytewise", 13) == 0, "round trip with 1-byte reads");
        }
        close(fd);
        chunk = 4096;
    }

    /* ---- connection 4: same leaf, different host name (also in the SAN): the fingerprint binds the host -> miss ---- */
    {
        x509_cache before = cache;
        fd = dial(port);
        ok = tls13_client_start(&t, "a.test.localhost", sc.n, sc.n_len, sc.e, 0, &rng);
        tls13_set_cert_cache(&t, &cache);
        ok = ok && pump(fd, &t, connected);
        result(ok && t.cert_cached == 0, "cache miss for another host: full chain verification instead");
        result(cache.valid && memcmp(before.fp, cache.fp, 32) != 0, "cache now holds the new (root, host, leaf) entry");
        close(fd);
    }

    /* ---- connection 5: cache hit, but the clock says the leaf has expired: rejected before any key is derived ---- */
    {
        fd = dial(port);
        ok = tls13_client_start(&t, "a.test.localhost", sc.n, sc.n_len, sc.e, "20991231235959Z", &rng);
        tls13_set_cert_cache(&t, &cache);
        ok = ok && !pump(fd, &t, connected);
        printf("  state=%d error=%s cached=%d\n", t.state, tls13_errstr(t.error), t.cert_cached);
        result(ok && t.state == TLS13_ST_ERROR && strcmp(tls13_errstr(t.error), "certificate chain does not verify") == 0 && !t.wr_encrypted,
               "cached leaf outside its validity period rejected, nothing sent");
        close(fd);
    }

    if (argc > 3) {
        FILE *rec = fopen(argv[3], "wb");
        if (rec) {
            uint8_t l[4];
            l[0] = (uint8_t)(derlen >> 24); l[1] = (uint8_t)(derlen >> 16); l[2] = (uint8_t)(derlen >> 8); l[3] = (uint8_t)derlen;
            fwrite(l, 1, 4, rec); fwrite(der, 1, derlen, rec);
            l[0] = (uint8_t)(rec_srv_len >> 24); l[1] = (uint8_t)(rec_srv_len >> 16); l[2] = (uint8_t)(rec_srv_len >> 8); l[3] = (uint8_t)rec_srv_len;
            fwrite(l, 1, 4, rec); fwrite(rec_srv, 1, rec_srv_len, rec); fwrite(rec_seed, 1, 64, rec); fclose(rec);
            printf("recorded %u server bytes to %s\n", rec_srv_len, argv[3]);
        }
    }
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
