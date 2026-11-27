; Tachyon - a2065fix.device: SANA-II wrapper around a2065.device (vasm -Fhunkexe, loaded by OpenDevice
; from DEVS:Networks). Device skeleton (RTF_AUTOINIT romtag, Open/Close/Expunge/BeginIO/AbortIO vectors);
; the logic is in tools/amiga/sanafix.c (vbcc, included below). See docs/NETWORK.md section 4.

	section	text,code

LN_TYPE		equ	8
LN_NAME		equ	10
LIB_FLAGS	equ	14
LIB_VERSION	equ	20
LIB_REVISION	equ	22
LIB_IDSTRING	equ	24
LIB_OPENCNT	equ	32
LIB_SIZE	equ	34
NT_DEVICE	equ	3
LIBF_SUMUSED	equ	4
LIBF_CHANGED	equ	2
RTC_MATCHWORD	equ	$4afc
RTF_AUTOINIT	equ	$80

db_SegList	equ	LIB_SIZE
DB_SIZE		equ	LIB_SIZE+4

start:	moveq	#-1,d0
	rts
romtag:	dc.w	RTC_MATCHWORD
	dc.l	romtag
	dc.l	endskip
	dc.b	RTF_AUTOINIT
	dc.b	1		; version
	dc.b	NT_DEVICE
	dc.b	0
	dc.l	devname
	dc.l	idstring
	dc.l	inittable

devname:	dc.b	"a2065fix.device",0
idstring:	dc.b	"a2065fix 1.0 (27.11.2026) Tachyon SANA-II wrapper around a2065.device",13,10,0
	even

inittable:
	dc.l	DB_SIZE
	dc.l	functable
	dc.l	datatable
	dc.l	devinit

datatable:
	dc.b	$a0,LN_TYPE,NT_DEVICE,0
	dc.b	$80,LN_NAME
	dc.l	devname
	dc.b	$a0,LIB_FLAGS,LIBF_SUMUSED|LIBF_CHANGED,0
	dc.b	$90,LIB_VERSION
	dc.w	1
	dc.b	$90,LIB_REVISION
	dc.w	0
	dc.b	$80,LIB_IDSTRING
	dc.l	idstring
	dc.l	0

devinit:				; d0 = base, a0 = seglist
	move.l	d0,a1
	move.l	a0,db_SegList(a1)
	rts

devexpunge:				; stays resident (opened by the stack for the whole session)
	moveq	#0,d0
	rts

devnull:
	moveq	#0,d0
	rts

functable:
	dc.l	_fix_open		; -6  (a1 = ioreq, d0 = unit, d1 = flags)
	dc.l	_fix_close		; -12 (a1 = ioreq)
	dc.l	devexpunge		; -18
	dc.l	devnull			; -24
	dc.l	_fix_beginio		; -30 (a1 = ioreq)
	dc.l	_fix_abortio		; -36 (a1 = ioreq)
	dc.l	-1

	xref	_fix_open,_fix_close,_fix_beginio,_fix_abortio

	include	"build/amiga/sanafix_c.s"

endskip:
