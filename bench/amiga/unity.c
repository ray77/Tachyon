/*
 * Unity build for the Amiga benchmark: without a linker (see docs/TOOLCHAIN.md)
 * every C module is compiled as one translation unit so vbcc emits a single
 * assembler file with unique local labels.
 */
#include "../../crypto/ref/x25519_ref.c"
#include "../x25519_bench.c"
