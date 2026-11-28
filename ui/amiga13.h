/*
 * Tachyon - intuition.library / graphics.library / console.device bindings for Kickstart 1.3 (vbcc, no SDK).
 *
 * Same style as net/bsdsocket13.h: the library base is passed explicitly in a6, the vector offsets come from
 * the NDK 3.2 FD files (FD/intuition_lib.fd, FD/graphics_lib.fd, FD/console_lib.fd) - every function used here
 * is V33 (Kickstart 1.2/1.3); no tag-list functions (OpenScreenTagList, OpenWindowTagList are V36+), no
 * keymap.library (its functions are V36+, see the FD file; on 1.3 raw key translation is console.device's
 * RawKeyConvert, opened as a library with unit CONU_LIBRARY = -1).
 *
 * The structures are copied from NDK 3.2 R4 Include_H (intuition/intuition.h, intuition/screens.h,
 * graphics/rastport.h, graphics/view.h, graphics/text.h, graphics/gfx.h, devices/inputevent.h), restricted
 * to the fields that existed in V33/V34 and that this client reads. The 1.3 layouts are identical for these
 * prefixes (vbcc, 68000: WORD 2, LONG/pointer 4, 2-byte alignment); checked offsets: Screen.Font 40,
 * Screen.ViewPort 44, Screen.RastPort 84, Screen.BitMap 184, Window.WScreen 46, Window.RPort 50,
 * Window.IDCMPFlags 82, Window.UserPort 86, RastPort 100 bytes (Font 52, TxHeight 58, TxWidth 60,
 * TxBaseline 62), ViewPort 40 bytes (Modes 32), NewScreen 32 bytes, NewWindow 48 bytes, IntuiMessage 52 bytes
 * (Class 20, Code 24, Qualifier 26, IAddress 28), InputEvent 22 bytes (ie_Code 6, ie_Qualifier 8, ie_addr 10),
 * TextFont tf_YSize 20, tf_XSize 24, tf_Baseline 26.
 */
#ifndef TACHYON_AMIGA13_H
#define TACHYON_AMIGA13_H

#include <exec/types.h>
#include <exec/ports.h>      /* struct Message, struct MsgPort, struct Node */

/* ---- graphics.library structures ------------------------------------------------------------------ */
struct TextAttr { STRPTR ta_Name; UWORD ta_YSize; UBYTE ta_Style; UBYTE ta_Flags; };
#define FS_NORMAL    0
#define FPF_ROMFONT  0x01
#define FPF_DISKFONT 0x02
#define FPF_DESIGNED 0x40

struct TextFont {
    struct Message tf_Message;                        /* 20 bytes, ln_Name = font name */
    UWORD tf_YSize; UBYTE tf_Style; UBYTE tf_Flags; UWORD tf_XSize; UWORD tf_Baseline; UWORD tf_BoldSmear;
    UWORD tf_Accessors; UBYTE tf_LoChar; UBYTE tf_HiChar; APTR tf_CharData; UWORD tf_Modulo;
    APTR tf_CharLoc; APTR tf_CharSpace; APTR tf_CharKern;
};

struct BitMap { UWORD BytesPerRow; UWORD Rows; UBYTE Flags; UBYTE Depth; UWORD pad; UBYTE *Planes[8]; };   /* 40 bytes */

struct RastPort {                                     /* 100 bytes (the 1.2+ layout, GFX_RASTPORT_1_2 undefined) */
    void *Layer; struct BitMap *BitMap; UWORD *AreaPtrn; void *TmpRas; void *AreaInfo; void *GelsInfo;
    UBYTE Mask; BYTE FgPen; BYTE BgPen; BYTE AOlPen; BYTE DrawMode; BYTE AreaPtSz; BYTE linpatcnt; BYTE dummy;
    UWORD Flags; UWORD LinePtrn; WORD cp_x, cp_y; UBYTE minterms[8]; WORD PenWidth; WORD PenHeight;
    struct TextFont *Font; UBYTE AlgoStyle; UBYTE TxFlags; UWORD TxHeight; UWORD TxWidth; UWORD TxBaseline;
    WORD TxSpacing; APTR *RP_User; ULONG longreserved[2]; UWORD wordreserved[7]; UBYTE reserved[8];
};
#define JAM1       0
#define JAM2       1
#define COMPLEMENT 2

struct RasInfo { struct RasInfo *Next; struct BitMap *BitMap; WORD RxOffset, RyOffset; };
struct ViewPort {                                     /* 40 bytes */
    struct ViewPort *Next; void *ColorMap; void *DspIns; void *SprIns; void *ClrIns; void *UCopIns;
    WORD DWidth, DHeight; WORD DxOffset, DyOffset; UWORD Modes; UBYTE SpritePriorities; UBYTE ExtendedModes;
    struct RasInfo *RasInfo;
};
#define HIRES 0x8000
#define LACE  0x0004

/* ---- intuition.library structures ----------------------------------------------------------------- */
struct NewScreen {                                    /* 32 bytes */
    WORD LeftEdge, TopEdge, Width, Height, Depth; UBYTE DetailPen, BlockPen; UWORD ViewModes; UWORD Type;
    struct TextAttr *Font; STRPTR DefaultTitle; void *Gadgets; struct BitMap *CustomBitMap;
};
#define CUSTOMSCREEN 0x000F
#define CUSTOMBITMAP 0x0040
#define SCREENQUIET  0x0100

/* prefix of struct Screen up to and including the RastPort (the rest - BitMap, LayerInfo, gadgets - is not used) */
struct Screen {
    struct Screen *NextScreen; struct Window *FirstWindow; WORD LeftEdge, TopEdge; WORD Width, Height;
    WORD MouseY, MouseX; UWORD Flags; STRPTR Title; STRPTR DefaultTitle;
    BYTE BarHeight, BarVBorder, BarHBorder, MenuVBorder, MenuHBorder; BYTE WBorTop, WBorLeft, WBorRight, WBorBottom;
    struct TextAttr *Font;                            /* offset 40 */
    struct ViewPort ViewPort;                         /* offset 44 */
    struct RastPort RastPort;                         /* offset 84 */
    struct BitMap BitMap;                             /* offset 184 */
};

struct NewWindow {                                    /* 48 bytes */
    WORD LeftEdge, TopEdge; WORD Width, Height; UBYTE DetailPen, BlockPen; ULONG IDCMPFlags; ULONG Flags;
    void *FirstGadget; void *CheckMark; STRPTR Title; struct Screen *Screen; struct BitMap *BitMap;
    WORD MinWidth, MinHeight; UWORD MaxWidth, MaxHeight; UWORD Type;
};
#define WFLG_SIMPLE_REFRESH 0x00000040UL
#define WFLG_BACKDROP       0x00000100UL
#define WFLG_BORDERLESS     0x00000800UL
#define WFLG_ACTIVATE       0x00001000UL
#define WFLG_RMBTRAP        0x00010000UL
#define WFLG_NOCAREREFRESH  0x00020000UL
#define IDCMP_MOUSEBUTTONS  0x00000008UL
#define IECODE_LBUTTON      0x68                  /* IntuiMessage Code: left button down (SELECTDOWN) */
#define IDCMP_RAWKEY        0x00000400UL
#define IDCMP_VANILLAKEY    0x00200000UL

/* prefix of struct Window up to the IDCMP ports */
struct Window {
    struct Window *NextWindow; WORD LeftEdge, TopEdge; WORD Width, Height; WORD MouseY, MouseX;
    WORD MinWidth, MinHeight; UWORD MaxWidth, MaxHeight; ULONG Flags; void *MenuStrip; STRPTR Title;
    void *FirstRequest; void *DMRequest; WORD ReqCount; struct Screen *WScreen;
    struct RastPort *RPort;                           /* offset 50 */
    BYTE BorderLeft, BorderTop, BorderRight, BorderBottom; struct RastPort *BorderRPort; void *FirstGadget;
    struct Window *Parent, *Descendant; UWORD *Pointer; BYTE PtrHeight; BYTE PtrWidth; BYTE XOffset, YOffset;
    ULONG IDCMPFlags;                                 /* offset 82 */
    struct MsgPort *UserPort, *WindowPort;            /* offset 86, 90 */
    struct IntuiMessage *MessageKey;
};

struct IntuiMessage {                                 /* 52 bytes */
    struct Message ExecMessage; ULONG Class; UWORD Code; UWORD Qualifier; APTR IAddress;
    WORD MouseX, MouseY; ULONG Seconds, Micros; struct Window *IDCMPWindow; struct IntuiMessage *SpecialLink;
};

/* ---- input events (devices/inputevent.h) for console.device RawKeyConvert ---------------------------- */
struct InputEvent {                                   /* 22 bytes; ie_addr stands for the ie_position union */
    struct InputEvent *ie_NextEvent; UBYTE ie_Class; UBYTE ie_SubClass; UWORD ie_Code; UWORD ie_Qualifier;
    ULONG ie_addr; ULONG ie_TimeStamp[2];
};
#define IECLASS_RAWKEY       0x01
#define IECODE_UP_PREFIX     0x80
#define IEQUALIFIER_LSHIFT   0x0001
#define IEQUALIFIER_RSHIFT   0x0002
#define IEQUALIFIER_CAPSLOCK 0x0004
#define IEQUALIFIER_CONTROL  0x0008
#define IEQUALIFIER_LALT     0x0010
#define IEQUALIFIER_RALT     0x0020
#define IEQUALIFIER_REPEAT   0x0200
#define CONU_LIBRARY         (-1)

/* ---- intuition.library vectors (intuition_lib.fd, V33) --------------------------------------------- */
BOOL  __int_CloseScreen(__reg("a6") void *, __reg("a0") struct Screen *screen) = "\tjsr\t-66(a6)";
VOID  __int_CloseWindow(__reg("a6") void *, __reg("a0") struct Window *window) = "\tjsr\t-72(a6)";
VOID  __int_ModifyIDCMP(__reg("a6") void *, __reg("a0") struct Window *window, __reg("d0") ULONG flags) = "\tjsr\t-150(a6)";
struct Screen *__int_OpenScreen(__reg("a6") void *, __reg("a0") const struct NewScreen *ns) = "\tjsr\t-198(a6)";
struct Window *__int_OpenWindow(__reg("a6") void *, __reg("a0") const struct NewWindow *nw) = "\tjsr\t-204(a6)";
VOID  __int_ScreenToFront(__reg("a6") void *, __reg("a0") struct Screen *screen) = "\tjsr\t-252(a6)";
VOID  __int_ShowTitle(__reg("a6") void *, __reg("a0") struct Screen *screen, __reg("d0") LONG showIt) = "\tjsr\t-282(a6)";
VOID  __int_ActivateWindow(__reg("a6") void *, __reg("a0") struct Window *window) = "\tjsr\t-450(a6)";

/* ---- graphics.library vectors (graphics_lib.fd, V33) ----------------------------------------------- */
LONG  __gfx_BltBitMap(__reg("a6") void *, __reg("a0") struct BitMap *src, __reg("d0") LONG xSrc, __reg("d1") LONG ySrc,
                      __reg("a1") struct BitMap *dst, __reg("d2") LONG xDest, __reg("d3") LONG yDest, __reg("d4") LONG xSize,
                      __reg("d5") LONG ySize, __reg("d6") ULONG minterm, __reg("d7") ULONG mask, __reg("a2") void *tempA) = "\tjsr\t-30(a6)";
VOID  __gfx_BltTemplate(__reg("a6") void *, __reg("a0") const void *source, __reg("d0") LONG xSrc, __reg("d1") LONG srcMod,
                        __reg("a1") struct RastPort *rp, __reg("d2") LONG xDest, __reg("d3") LONG yDest,
                        __reg("d4") LONG xSize, __reg("d5") LONG ySize) = "\tjsr\t-36(a6)";
LONG  __gfx_TextLength(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("a0") const char *s, __reg("d0") ULONG count) = "\tjsr\t-54(a6)";
LONG  __gfx_Text(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("a0") const char *s, __reg("d0") ULONG count) = "\tjsr\t-60(a6)";
LONG  __gfx_SetFont(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("a0") struct TextFont *font) = "\tjsr\t-66(a6)";
struct TextFont *__gfx_OpenFont(__reg("a6") void *, __reg("a0") struct TextAttr *ta) = "\tjsr\t-72(a6)";
VOID  __gfx_CloseFont(__reg("a6") void *, __reg("a1") struct TextFont *font) = "\tjsr\t-78(a6)";
VOID  __gfx_LoadRGB4(__reg("a6") void *, __reg("a0") struct ViewPort *vp, __reg("a1") const UWORD *colors, __reg("d0") LONG count) = "\tjsr\t-192(a6)";
VOID  __gfx_WaitBlit(__reg("a6") void *) = "\tjsr\t-228(a6)";
VOID  __gfx_ScrollRaster(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("d0") LONG dx, __reg("d1") LONG dy,
                         __reg("d2") LONG xMin, __reg("d3") LONG yMin, __reg("d4") LONG xMax, __reg("d5") LONG yMax) = "\tjsr\t-396(a6)";
VOID  __gfx_SetRast(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("d0") ULONG pen) = "\tjsr\t-234(a6)";
VOID  __gfx_Move(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("d0") LONG x, __reg("d1") LONG y) = "\tjsr\t-240(a6)";
VOID  __gfx_Draw(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("d0") LONG x, __reg("d1") LONG y) = "\tjsr\t-246(a6)";
VOID  __gfx_WaitTOF(__reg("a6") void *) = "\tjsr\t-270(a6)";
VOID  __gfx_SetRGB4(__reg("a6") void *, __reg("a0") struct ViewPort *vp, __reg("d0") LONG index, __reg("d1") ULONG r, __reg("d2") ULONG g, __reg("d3") ULONG b) = "\tjsr\t-288(a6)";
VOID  __gfx_RectFill(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("d0") LONG xMin, __reg("d1") LONG yMin, __reg("d2") LONG xMax, __reg("d3") LONG yMax) = "\tjsr\t-306(a6)";
VOID  __gfx_SetAPen(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("d0") ULONG pen) = "\tjsr\t-342(a6)";
VOID  __gfx_SetBPen(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("d0") ULONG pen) = "\tjsr\t-348(a6)";
VOID  __gfx_SetDrMd(__reg("a6") void *, __reg("a1") struct RastPort *rp, __reg("d0") ULONG mode) = "\tjsr\t-354(a6)";

/* ---- console.device as a library (console_lib.fd, V33): a6 = the device base from io_Device ---------- */
LONG  __con_RawKeyConvert(__reg("a6") void *, __reg("a0") struct InputEvent *events, __reg("a1") char *buffer,
                          __reg("d1") LONG length, __reg("a2") void *keyMap) = "\tjsr\t-48(a6)";

#endif
