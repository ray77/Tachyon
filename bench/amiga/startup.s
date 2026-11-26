; WhatsA500 benchmark startup for Kickstart 1.3 (vasm, -Fhunkexe).
; Freestanding: no C library, no vlink. The C modules compiled by vbcc are
; pulled in with INCLUDE so one vasm run produces the whole executable.
; Entry from the CLI: A0 = command line, D0 = length. Returns D0 from main().

	section	text,code

	xref	_main
_start:
	movem.l	d2-d7/a2-a6,-(sp)
	jsr	_main
	movem.l	(sp)+,d2-d7/a2-a6
	rts

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

; --- generated C modules -------------------------------------------------
	include	"build/amiga/x25519bench.s"
