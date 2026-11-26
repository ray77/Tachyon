; WhatsA500 - Blitter program executor
; void ba_exec_asm(a0 = arena, a1 = ba_blit program, d0 = count, d1 = key offset bytes)
; Entry layout (32 bytes): con0.w con1.w a.l b.l c.l d.l amod.w bmod.w cmod.w dmod.w size.w flags.w
; Waits for the Blitter (DMACONR bit 14, read twice as WaitBlit does), loads all registers,
; starts the blit. ~250 cycles per entry instead of ~900 through graphics.library + C.
	xdef	_ba_exec_asm
_ba_exec_asm:
	movem.l	d2-d3/a2/a6,-(sp)
	lea	$dff000,a6
	move.w	d0,d2
	subq.w	#1,d2
	bmi.s	.done
.loop:
	tst.w	$02(a6)			; dmaconr, first read (A1000 quirk compatible)
.wait:
	btst	#6,$02(a6)		; BBUSY is bit 14 = bit 6 of the high byte at $dff002
	bne.s	.wait
	move.w	(a1)+,$40(a6)		; bltcon0
	move.w	(a1)+,$42(a6)		; bltcon1
	move.l	#$ffffffff,$44(a6)	; bltafwm/bltalwm
	move.l	(a1)+,d0
	add.l	a0,d0
	move.l	d0,$50(a6)		; bltapt
	move.l	(a1)+,d0
	add.l	a0,d0
	move.l	d0,$4c(a6)		; bltbpt
	move.l	(a1)+,d0
	add.l	a0,d0
	move.l	d0,a2			; bltcpt candidate (key offset added below if flagged)
	move.l	(a1)+,d0
	add.l	a0,d0
	move.l	d0,$54(a6)		; bltdpt
	move.w	(a1)+,$64(a6)		; bltamod
	move.w	(a1)+,$62(a6)		; bltbmod
	move.w	(a1)+,$60(a6)		; bltcmod
	move.w	(a1)+,$66(a6)		; bltdmod
	move.w	(a1)+,d3		; size
	move.w	(a1)+,d0		; flags
	btst	#0,d0
	beq.s	.nokey
	add.l	d1,a2
.nokey:
	move.l	a2,$48(a6)		; bltcpt
	move.w	d3,$58(a6)		; bltsize starts the blit
	dbf	d2,.loop
.wait2:
	btst	#6,$02(a6)
	bne.s	.wait2
.done:
	movem.l	(sp)+,d2-d3/a2/a6
	rts
