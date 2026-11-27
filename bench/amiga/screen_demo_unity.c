/*
 * Unity build for the screen demo (ui/screen.c + bench/amiga/screen_demo.c): without a linker (see
 * docs/TOOLCHAIN.md) both modules are compiled as one translation unit so vbcc emits a single assembler file;
 * bench/amiga/startup_screen.s includes it.
 */
#include "../../ui/screen.c"
#include "screen_demo.c"
