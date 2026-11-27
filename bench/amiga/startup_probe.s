; Tachyon WhatsApp-probe startup for Kickstart 1.3 (vasm, -Fhunkexe): bench/amiga/startup.s with the probe unity build.
; Freestanding: no C library, no vlink. The C modules compiled by vbcc are
; pulled in with INCLUDE so one vasm run produces the whole executable.
; Entry from the CLI: A0 = command line, D0 = length. Returns D0 from main().

	section	text,code

	xref	_main
_start:
	movem.l	d2-d7/a2-a6,-(sp)
	move.l	sp,oldsp		; the CLI stack is only 4000 bytes under Kickstart 1.3
	lea	stack_top,sp		; so run main() on our own 64 KiB stack (BSS, Fast RAM)
	jsr	_main
	move.l	oldsp,sp
	movem.l	(sp)+,d2-d7/a2-a6
	rts

	section	bss,bss
oldsp:		ds.l	1
stack_bottom:	ds.b	65536
stack_top:
	section	text,code

; --- vbcc runtime helpers normally supplied by vc.lib ------------------------
; __divu: unsigned 32/32 division. In: d0 = dividend, d1 = divisor.
; Out: d0 = quotient, d1 = remainder. All other registers preserved.
; Shift-subtract, 32 iterations; division by zero returns garbage.
	xdef	__divu
__divu:
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

; --- assembler backends ----------------------------------------------------
	include	"crypto/m68k/fe16.s"
	include	"crypto/m68k/sha256.s"
	include	"crypto/m68k/aes.s"
	include	"crypto/m68k/mont.s"

; --- generated C modules -------------------------------------------------
	include	"build/amiga/wa_probe.s"
