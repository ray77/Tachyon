; WhatsA500 smoke test: pure 68000 assembly, Kickstart 1.3 compatible.
; Opens dos.library, prints a line to the console and writes result.txt to SYS:.
; Entry: called by the CLI with A0 = command line, D0 = length.

	section	text,code

_LVOOpenLibrary	equ	-552
_LVOCloseLibrary	equ	-414
_LVOOutput	equ	-60
_LVOWrite	equ	-48
_LVOOpen	equ	-30
_LVOClose	equ	-36
MODE_NEWFILE	equ	1006

start:
	movem.l	d2-d7/a2-a6,-(sp)
	move.l	4.w,a6			; ExecBase
	lea	dosname(pc),a1
	moveq	#0,d0			; any version (KS 1.3 = V34)
	jsr	_LVOOpenLibrary(a6)
	move.l	d0,d7			; d7 = DOSBase
	beq	.fail
	move.l	d7,a6

	jsr	_LVOOutput(a6)		; d0 = console handle
	move.l	d0,d1
	beq	.nofile
	move.l	#msg,d2
	moveq	#msgend-msg,d3
	jsr	_LVOWrite(a6)

.nofile
	move.l	#fname,d1
	move.l	#MODE_NEWFILE,d2
	jsr	_LVOOpen(a6)
	move.l	d0,d6			; d6 = file handle
	beq	.close
	move.l	d6,d1
	move.l	#msg,d2
	moveq	#msgend-msg,d3
	jsr	_LVOWrite(a6)
	move.l	d6,d1
	jsr	_LVOClose(a6)

.close
	move.l	4.w,a6
	move.l	d7,a1
	jsr	_LVOCloseLibrary(a6)
	moveq	#0,d0
	bra	.exit
.fail
	moveq	#20,d0
.exit
	movem.l	(sp)+,d2-d7/a2-a6
	rts

; strings live in the code section so pc-relative addressing works across the whole hunk
dosname:	dc.b	"dos.library",0
fname:		dc.b	"SYS:result.txt",0
msg:		dc.b	"WhatsA500 smoke test: 68000 alive, dos.library OK",10
msgend:
	even
