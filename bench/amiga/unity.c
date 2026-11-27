/*
 * Unity build for the Amiga benchmark: without a linker (see docs/TOOLCHAIN.md)
 * every C module is compiled as one translation unit so vbcc emits a single
 * assembler file with unique local labels.
 */
#include "../../crypto/ref/x25519_ref.c"
#include "../../crypto/ref/sha512.c"
#include "../../crypto/ref/ed25519.c"
#include "../../crypto/ref/sha256.c"
#include "../../crypto/ref/aes.c"
#include "../../crypto/ref/drbg.c"
#include "../../crypto/ref/noise.c"
#include "../../crypto/ref/rsa.c"
#include "../../crypto/ref/x509.c"
#include "../../crypto/ref/tls12.c"
#include "../../crypto/ref/sha1.c"
#include "../../crypto/ref/ws.c"
#include "../../crypto/ref/heartbeat.c"
#include "../../crypto/ref/yield.c"
#include "../x25519_bench.c"
