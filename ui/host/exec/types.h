/*
 * Tachyon - host stand-in for <exec/types.h> (ui/host/, only on the -Iui/host include path of the host builds):
 * the Amiga scalar types the ui/ modules use, so ui/screen.h, ui/gui.c, ui/ftext.c compile unchanged with the host
 * compiler (ui/screen_host.c renders into a host framebuffer). 32-bit LONG/ULONG as on the 68000.
 */
#ifndef EXEC_TYPES_H
#define EXEC_TYPES_H
typedef void            VOID;
typedef void           *APTR;
typedef int             LONG;        /* 32-bit like on the 68000 (long would be 64-bit on macOS) */
typedef unsigned int    ULONG;
typedef short           WORD;
typedef unsigned short  UWORD;
typedef signed char     BYTE;
typedef unsigned char   UBYTE;
typedef unsigned char  *STRPTR;
typedef short           BOOL;
#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif
#endif
