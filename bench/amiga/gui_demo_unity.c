/*
 * Unity build for the GUI demo (ui/screen.c + ui/font8.c + ui/ftext.c + ui/gui.c + bench/amiga/gui_demo.c):
 * without a linker (docs/TOOLCHAIN.md) all modules are one translation unit; bench/amiga/startup_gui.s includes
 * the assembler output.
 */
#include "../../ui/screen.c"
#include "../../ui/font8.c"
#include "../../ui/ftext.c"
#include "../../ui/gui.c"
#include "gui_demo.c"
