/* Unity build for the Blitter AES-GCM benchmark binary (see unity.c for why). */
#define BLITGCM_HW
#include "../../crypto/ref/aes.c"
#include "../../crypto/blit/blitaes.c"
#include "../../crypto/blit/blitgcm.c"
#include "../blitgcm_bench.c"
