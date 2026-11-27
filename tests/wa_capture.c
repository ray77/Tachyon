/*
 * Test vector capture for tests/wabinary_test.c: writes the plaintext of the first decrypted server frame
 * (the pair-device IQ) of a live probe run to the file named by WA_CAPTURE.
 * The probe itself stays untouched: for this build only, tests/wa_probe_core.c is compiled with
 * -Dnoise_transport_decrypt=wa_capture_decrypt, so its one transport decryption goes through the wrapper
 * below (make wa-capture; network required).
 */
#include <stdio.h>
#include <stdlib.h>
#include "noise.h"

int wa_capture_decrypt(noise_transport *t, const uint8_t *ct, uint32_t len, uint8_t *pt);

int wa_capture_decrypt(noise_transport *t, const uint8_t *ct, uint32_t len, uint8_t *pt)
{
    static int done;
    const char *path = getenv("WA_CAPTURE");
    int ok = noise_transport_decrypt(t, ct, len, pt);
    if (ok && !done && path && *path) {
        FILE *f = fopen(path, "wb");
        if (f) {
            if (fwrite(pt, 1, len - 16, f) == len - 16) printf("capture: %u plaintext bytes -> %s\n", (unsigned)(len - 16), path);
            fclose(f);
            done = 1;
        }
    }
    return ok;
}
