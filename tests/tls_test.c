/* TLS 1.2 RSA client against the loopback Go server (tools/tlsserver): full handshake,
 * echo round trip, then a corrupted record must be rejected. Host only (POSIX sockets). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include "tls12.h"

static int failures;
static void result(int ok, const char *what) { printf("%s %s\n", ok ? "PASS" : "FAIL", what); if (!ok) failures++; }

static int send_all(int fd, const uint8_t *p, uint32_t n) { while (n) { ssize_t w = write(fd, p, n); if (w <= 0) return 0; p += w; n -= (uint32_t)w; } return 1; }

/* recording for the Amiga replay (bench/tls_vector.h): everything the server sent, plus the DRBG seed
 * and the pinned certificate, so the deterministic client reproduces the same session offline */
static FILE *rec;
static uint8_t rec_seed[64];
static uint8_t rec_srv[65536]; static uint32_t rec_srv_len;

/* pump: send t->out, read until predicate(t) or error */
static int pump(int fd, tls12 *t, int (*done)(tls12 *))
{
    uint8_t buf[4096];
    for (;;) {
        if (t->out_len) { if (!send_all(fd, t->out, t->out_len)) return 0; t->out_len = 0; }
        if (done(t)) return 1;
        { ssize_t r = read(fd, buf, sizeof buf); if (r <= 0) return 0;
          if (t->state != TLS_ST_CONNECTED && rec_srv_len + (uint32_t)r <= sizeof rec_srv) { memcpy(rec_srv + rec_srv_len, buf, (size_t)r); rec_srv_len += (uint32_t)r; }
          if (!tls12_input(t, buf, (uint32_t)r)) return 0; }
    }
}
static int connected(tls12 *t) { return t->state == TLS_ST_CONNECTED; }
static int have_app(tls12 *t) { return t->app_len > 0; }
static uint32_t app_seen;
static int have_app_more(tls12 *t) { if (t->app_len > app_seen) { app_seen = t->app_len; return 1; } return 0; }


int main(int argc, char **argv)
{
    const char *certpath = argc > 1 ? argv[1] : "build/tls_test_cert.der";
    int port = argc > 2 ? atoi(argv[2]) : 4433;
    static uint8_t der[4096], seed[64];
    static tls12 t;
    static x509_cert sc;
    hmac_drbg rng;
    uint32_t derlen;
    int fd, ok;
    struct sockaddr_in sa;
    FILE *f = fopen(certpath, "rb");
    if (!f) { printf("FAIL cannot read %s\n", certpath); return 1; }
    derlen = (uint32_t)fread(der, 1, sizeof der, f); fclose(f);
    result(x509_parse(&sc, der, derlen), "parse test server certificate");
    f = fopen("/dev/urandom", "rb"); if (!f || fread(seed, 1, 64, f) != 64) { printf("FAIL urandom\n"); return 1; } fclose(f);
    if (argc > 3) { memset(seed, 0x42, 64); seed[0] = 7; }       /* record mode: fixed seed, replayable */
    memcpy(rec_seed, seed, 64);
    rng.instantiated = 0; drbg_instantiate(&rng, seed, 64);

    fd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_port = htons((uint16_t)port); sa.sin_addr.s_addr = htonl(0x7f000001);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) { printf("FAIL connect\n"); return 1; }

    /* trust anchor: the self-signed test certificate's own key */
    ok = tls12_client_start(&t, "tls-test.localhost", sc.n, sc.n_len, sc.e, 0, &rng);
    result(ok && t.out_len > 0, "ClientHello built");
    ok = pump(fd, &t, connected);
    printf("  state=%d error=%s chain=%d\n", t.state, tls12_errstr(t.error), t.chain_len);
    result(ok, "handshake completes (RSA key transport, AES-128-GCM, server Finished verified)");
    if (ok) {
        static const uint8_t msg[] = "hello from the amiga side";
        ok = tls12_send(&t, msg, sizeof msg - 1) == (int)(sizeof msg - 1) && pump(fd, &t, have_app);
        result(ok && t.app_len == 5 + sizeof msg - 1 && memcmp(t.app, "echo:", 5) == 0 && memcmp(t.app + 5, msg, sizeof msg - 1) == 0, "application data round trip");
        t.app_len = 0;
        {   /* a 20 KiB message crosses the 16 KiB record limit; the server echoes per record ("echo:" + up to 16384 bytes);
             * the client's app buffer is drained after every pump since it holds one record's worth */
            static uint8_t big[20000], got[32768]; uint32_t i, gl = 0;
            for (i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i * 7);
            {   uint32_t sent = 0; ok = 1;
                while (ok && sent < sizeof big) {
                    int c = tls12_send(&t, big + sent, sizeof big - sent);
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
        {   /* tamper: flip a bit in an incoming record -> decrypt failure, state ERROR */
            uint8_t fake[5 + 8 + 1 + 16] = { 23, 3, 3, 0, 25 };
            result(!tls12_input(&t, fake, sizeof fake) && t.state == TLS_ST_ERROR, "forged record rejected (GCM tag)");
        }
    }
    close(fd);
    if (argc > 3 && (rec = fopen(argv[3], "wb")) != 0) {
        uint8_t l[4];
        l[0] = (uint8_t)(derlen >> 24); l[1] = (uint8_t)(derlen >> 16); l[2] = (uint8_t)(derlen >> 8); l[3] = (uint8_t)derlen;
        fwrite(l, 1, 4, rec); fwrite(der, 1, derlen, rec);
        l[0] = (uint8_t)(rec_srv_len >> 24); l[1] = (uint8_t)(rec_srv_len >> 16); l[2] = (uint8_t)(rec_srv_len >> 8); l[3] = (uint8_t)rec_srv_len;
        fwrite(l, 1, 4, rec); fwrite(rec_srv, 1, rec_srv_len, rec); fwrite(rec_seed, 1, 64, rec); fclose(rec);
        printf("recorded %u server bytes to %s\n", rec_srv_len, argv[3]);
    }
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
