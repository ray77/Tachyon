; Tachyon - utility.library V37 for Kickstart 1.3 (vasm -Fhunkexe, loaded by OpenLibrary from LIBS:).
; Library skeleton (RTF_AUTOINIT romtag, Open/Close/Expunge), the register-exact routines that C cannot
; express (CallHookPkt, SDivMod32/UDivMod32 with two results, 64-bit multiplies) and the function table
; in the order of utility_lib.fd; everything else comes from tools/amiga/utility13.c (vbcc, included below).
; Why: 2.0-era SANA-II drivers (Aminet a2065.device) open utility.library at init time; on 1.3 that
; fails and OpenDevice returns -1 (docs/NETWORK.md).

	section	text,code

; --- exec offsets --------------------------------------------------------------------------------
LN_SUCC		equ	0
LN_TYPE		equ	8
LN_NAME		equ	10
LIB_FLAGS	equ	14
LIB_NEGSIZE	equ	16
LIB_POSSIZE	equ	18
LIB_VERSION	equ	20
LIB_REVISION	equ	22
LIB_IDSTRING	equ	24
LIB_OPENCNT	equ	32
LIB_SIZE	equ	34
NT_LIBRARY	equ	9
LIBF_SUMUSED	equ	4
LIBF_CHANGED	equ	2
LIBF_DELEXP	equ	8
RTC_MATCHWORD	equ	$4afc
RTF_AUTOINIT	equ	$80
_LVORemove	equ	-252
_LVOFreeMem	equ	-210

; our base: struct Library + seglist + SysBase
ub_SegList	equ	LIB_SIZE
ub_SysBase	equ	LIB_SIZE+4
UB_SIZE		equ	LIB_SIZE+8

start:	moveq	#-1,d0		; not a program
	rts
romtag:	dc.w	RTC_MATCHWORD
	dc.l	romtag
	dc.l	endskip
	dc.b	RTF_AUTOINIT
	dc.b	37		; version
	dc.b	NT_LIBRARY
	dc.b	0		; priority
	dc.l	libname
	dc.l	idstring
	dc.l	inittable

libname:	dc.b	"utility.library",0
idstring:	dc.b	"utility 37.0 (27.11.2026) Tachyon utility.library for Kickstart 1.3",13,10,0
	even

inittable:
	dc.l	UB_SIZE
	dc.l	functable
	dc.l	datatable
	dc.l	libinit

; InitStruct: INITBYTE = $a0,off,val,0  INITWORD = $90,off,word  INITLONG = $80,off,long
datatable:
	dc.b	$a0,LN_TYPE,NT_LIBRARY,0
	dc.b	$80,LN_NAME
	dc.l	libname
	dc.b	$a0,LIB_FLAGS,LIBF_SUMUSED|LIBF_CHANGED,0
	dc.b	$90,LIB_VERSION
	dc.w	37
	dc.b	$90,LIB_REVISION
	dc.w	0
	dc.b	$80,LIB_IDSTRING
	dc.l	idstring
	dc.l	0

; d0 = library base, a0 = seglist, a6 = SysBase; returns the base
libinit:
	move.l	d0,a1
	move.l	a0,ub_SegList(a1)
	move.l	a6,ub_SysBase(a1)
	rts

libopen:				; a6 = base; returns base in d0, clears delayed expunge
	addq.w	#1,LIB_OPENCNT(a6)
	bclr	#3,LIB_FLAGS(a6)	; LIBF_DELEXP
	move.l	a6,d0
	rts

libclose:				; returns 0 (or the seglist when a delayed expunge is pending)
	subq.w	#1,LIB_OPENCNT(a6)
	bne.s	.keep
	btst	#3,LIB_FLAGS(a6)
	bne.s	libexpunge
.keep	moveq	#0,d0
	rts

libexpunge:
	tst.w	LIB_OPENCNT(a6)
	beq.s	.go
	bset	#3,LIB_FLAGS(a6)
	moveq	#0,d0
	rts
.go	movem.l	d2/a5/a6,-(sp)
	move.l	a6,a5
	move.l	ub_SegList(a5),d2
	move.l	ub_SysBase(a5),a6
	move.l	a5,a1
	jsr	_LVORemove(a6)
	move.l	a5,a1
	moveq	#0,d0
	move.w	LIB_NEGSIZE(a5),d0
	sub.l	d0,a1
	add.w	LIB_POSSIZE(a5),d0
	jsr	_LVOFreeMem(a6)
	move.l	d2,d0
	movem.l	(sp)+,d2/a5/a6
	rts

libnull:
	moveq	#0,d0
	rts

; --- CallHookPkt(hook a0, object a2, paramPacket a1): calls h_Entry(hook) with the same registers ----
callhookpkt:
	move.l	8(a0),-(sp)		; h_Entry
	rts				; tail call: the hook returns to our caller

; --- UDivMod32(dividend d0, divisor d1): quotient d0, remainder d1 (also vbcc's __divu) --------------
	xdef	__divu
__divu:
udivmod32:
	movem.l	d2-d3,-(sp)
	moveq	#0,d2			; remainder
	moveq	#31,d3
.loop	add.l	d0,d0			; next dividend bit -> X
	addx.l	d2,d2			; remainder = remainder*2 + bit
	bcs.s	.sub			; remainder overflowed 32 bits: certainly >= divisor
	cmp.l	d1,d2
	bcs.s	.skip
.sub	sub.l	d1,d2
	addq.l	#1,d0			; quotient bit (bit 0 is free after the shift)
.skip	dbf	d3,.loop
	move.l	d2,d1
	movem.l	(sp)+,d2-d3
	rts

; --- SDivMod32: quotient d0, remainder d1 (remainder takes the dividend's sign, as the ROM does) ------
sdivmod32:
	movem.l	d2-d3,-(sp)
	move.l	d0,d2			; sign of the dividend -> remainder sign
	move.l	d0,d3
	eor.l	d1,d3			; sign of the quotient
	tst.l	d0
	bpl.s	.a
	neg.l	d0
.a	tst.l	d1
	bpl.s	.b
	neg.l	d1
.b	bsr.s	udivmod32
	tst.l	d3
	bpl.s	.c
	neg.l	d0
.c	tst.l	d2
	bpl.s	.d
	neg.l	d1
.d	movem.l	(sp)+,d2-d3
	rts

; --- UMult32 / SMult32: low 32 bits of d0*d1 (identical for signed and unsigned) ------------------------
umult32:
smult32:
	movem.l	d2-d3,-(sp)
	move.l	d0,d2
	move.l	d1,d3
	swap	d2			; d2 = a_hi:a_lo swapped
	swap	d3
	mulu.w	d1,d2			; a_hi*b_lo
	mulu.w	d0,d3			; a_lo*b_hi
	mulu.w	d1,d0			; a_lo*b_lo
	add.w	d3,d2
	swap	d2
	clr.w	d2
	add.l	d2,d0
	movem.l	(sp)+,d2-d3
	rts

; --- UMult64(d0, d1): 64-bit product, high longword in d0, low in d1 -----------------------------------
umult64:
	movem.l	d2-d5,-(sp)
	move.l	d0,d2			; a
	move.l	d1,d3			; b
	move.l	d2,d4
	swap	d4			; d4.w = a_hi
	move.l	d3,d5
	swap	d5			; d5.w = b_hi
	mulu.w	d3,d0			; d0 = a_lo*b_lo
	mulu.w	d5,d2			; d2 = a_lo*b_hi  (d2.w was a_lo)
	mulu.w	d4,d3			; d3 = a_hi*b_lo  (d3.w was b_lo)
	mulu.w	d5,d4			; d4 = a_hi*b_hi
	moveq	#0,d1
	add.l	d3,d2			; middle sum (may carry)
	addx.l	d1,d1			; d1 = carry of the middle sum
	swap	d1			; carry belongs to bit 32 of the middle -> bit 16 of the high word... keep as d1<<16 below
	move.l	d2,d3
	clr.w	d3
	swap	d3			; d3 = middle_hi (upper 16 bits of the middle sum)
	or.l	d1,d3			; plus the middle carry at bit 16
	swap	d2
	clr.w	d2			; d2 = middle_lo << 16
	add.l	d2,d0			; low longword
	moveq	#0,d1
	addx.l	d1,d4			; carry into high
	add.l	d3,d4
	move.l	d0,d1			; low -> d1
	move.l	d4,d0			; high -> d0
	movem.l	(sp)+,d2-d5
	rts

; --- SMult64: sign-magnitude around UMult64 --------------------------------------------------------------
smult64:
	movem.l	d2,-(sp)
	move.l	d0,d2
	eor.l	d1,d2			; sign of the result
	tst.l	d0
	bpl.s	.a
	neg.l	d0
.a	tst.l	d1
	bpl.s	.b
	neg.l	d1
.b	bsr.s	umult64
	tst.l	d2
	bpl.s	.c
	neg.l	d1			; negate the 64-bit value d0:d1
	negx.l	d0
.c	movem.l	(sp)+,d2
	rts

; --- function table in utility_lib.fd order (bias 30 .. 294) ---------------------------------------------
functable:
	dc.l	libopen			; -6
	dc.l	libclose		; -12
	dc.l	libexpunge		; -18
	dc.l	libnull			; -24
	dc.l	_u_FindTagItem		; -30
	dc.l	_u_GetTagData		; -36
	dc.l	_u_PackBoolTags		; -42
	dc.l	_u_NextTagItem		; -48
	dc.l	_u_FilterTagChanges	; -54
	dc.l	_u_MapTags		; -60
	dc.l	_u_AllocateTagItems	; -66
	dc.l	_u_CloneTagItems	; -72
	dc.l	_u_FreeTagItems		; -78
	dc.l	_u_RefreshTagItemClones	; -84
	dc.l	_u_TagInArray		; -90
	dc.l	_u_FilterTagItems	; -96
	dc.l	callhookpkt		; -102
	dc.l	libnull			; -108 reserved
	dc.l	libnull			; -114 reserved
	dc.l	_u_Amiga2Date		; -120
	dc.l	_u_Date2Amiga		; -126
	dc.l	_u_CheckDate		; -132
	dc.l	smult32			; -138
	dc.l	umult32			; -144
	dc.l	sdivmod32		; -150
	dc.l	udivmod32		; -156
	dc.l	_u_Stricmp		; -162
	dc.l	_u_Strnicmp		; -168
	dc.l	_u_ToUpper		; -174
	dc.l	_u_ToLower		; -180
	dc.l	_u_ApplyTagChanges	; -186
	dc.l	libnull			; -192 reserved
	dc.l	smult64			; -198
	dc.l	umult64			; -204
	dc.l	_u_Zero			; -210 PackStructureTags
	dc.l	_u_Zero			; -216 UnpackStructureTags
	dc.l	_u_Zero			; -222 AddNamedObject
	dc.l	_u_Zero			; -228 AllocNamedObjectA
	dc.l	_u_Zero			; -234 AttemptRemNamedObject
	dc.l	_u_Zero			; -240 FindNamedObject
	dc.l	libnull			; -246 FreeNamedObject
	dc.l	_u_Zero			; -252 NamedObjectName
	dc.l	libnull			; -258 ReleaseNamedObject
	dc.l	libnull			; -264 RemNamedObject
	dc.l	_u_GetUniqueID		; -270
	dc.l	libnull			; -276 reserved
	dc.l	libnull			; -282 reserved
	dc.l	libnull			; -288 reserved
	dc.l	libnull			; -294 reserved
	dc.l	-1

	xref	_u_FindTagItem,_u_GetTagData,_u_PackBoolTags,_u_NextTagItem,_u_FilterTagChanges,_u_MapTags
	xref	_u_AllocateTagItems,_u_CloneTagItems,_u_FreeTagItems,_u_RefreshTagItemClones,_u_TagInArray
	xref	_u_FilterTagItems,_u_Amiga2Date,_u_Date2Amiga,_u_CheckDate,_u_Stricmp,_u_Strnicmp,_u_ToUpper
	xref	_u_ToLower,_u_ApplyTagChanges,_u_GetUniqueID,_u_Zero

; --- generated C part --------------------------------------------------------------------------------------
	include	"build/amiga/utility13_c.s"

endskip:
