; WhatsA500 - CPU side of the Blitter AES-GCM pipeline (crypto/blit/blitgcm.c)
;
; bg_ctr_fill_asm: writes the 128 lanes of 1024 counter blocks straight into the transposed
; state (same layout as blitgcm_ctr_fill_c): 96 constant nonce lanes (8 rows per byte, 64 words
; each, stride 16 bytes) and 32 counter lanes per word w (bits 0..5 from ctr + w, bits 6..31
; from one of two precomputed 26-word tables). 8192 word writes, ~22 ms instead of 180 ms in C.
;
; bg_ctr_params layout: cst[12][8] at 0 (192 bytes), tab[2][26] at 192 (2 x 52), klo[6] at 296, ctr at 308

; void bg_ctr_fill_asm(a0 = arena, a1 = const bg_ctr_params *p)
	xdef	_bg_ctr_fill_asm
_bg_ctr_fill_asm:
	movem.l	d2-d7/a2-a6,-(sp)
	move.l	a0,a2			; a2 = STATE base (BA_STATE = 0)
	move.l	a1,a3			; a3 -> cst[y][r], consumed 8 words per byte
	move.l	a0,a6			; a6 = column base of the byte pair (y>>1)*2
	move.w	#6,a5			; 6 byte pairs
.pair:
	move.l	a6,a4			; even byte y: rows 0..7
	bsr.s	.fillbyte
	lea	8192(a6),a4		; odd byte y+1: rows 8..15
	bsr.s	.fillbyte
	addq.l	#2,a6
	subq.l	#1,a5
	move.l	a5,d0
	bne.s	.pair
	bra	.counter

; a4 = row 0 of the byte's lanes; 8 lane values from (a3)+; 64 words per lane at stride 16
.fillbyte:
	movem.w	(a3)+,d0-d7
	lea	1024(a4),a0
.fw:
	move.w	d0,(a4)
	move.w	d1,1024(a4)
	move.w	d2,2048(a4)
	move.w	d3,3072(a4)
	move.w	d4,4096(a4)
	move.w	d5,5120(a4)
	move.w	d6,6144(a4)
	move.w	d7,7168(a4)
	move.w	d0,16(a4)
	move.w	d1,1040(a4)
	move.w	d2,2064(a4)
	move.w	d3,3088(a4)
	move.w	d4,4112(a4)
	move.w	d5,5136(a4)
	move.w	d6,6160(a4)
	move.w	d7,7184(a4)
	lea	32(a4),a4
	cmpa.l	a0,a4
	bne.s	.fw
	rts

; counter lanes: bit n of the counter -> row 15-n (n < 16, column 14) / row 31-n (n >= 16, column 12)
.counter:
	move.l	308(a1),d2		; ctr of block 0
	move.l	d2,d4
	lsr.l	#6,d4			; u0 = ctr >> 6 selects tab[0]
	lea	296(a1),a3		; klo[0..5]
	move.l	a2,a4			; word w: STATE + 16*w
	lea	1024(a2),a0		; end after 64 words
.cw:
	move.l	d2,d1
	lsr.l	#6,d1
	lea	192(a1),a5		; tab[0]
	cmp.l	d4,d1
	beq.s	.sel
	lea	244(a1),a5		; tab[1]: (ctr + w) >> 6 == u0 + 1
.sel:
	btst	#0,d2
	sne	d0
	ext.w	d0
	move.w	(a3),d1
	eor.w	d1,d0
	move.w	d0,15*1024+14(a4)
	btst	#1,d2
	sne	d0
	ext.w	d0
	move.w	2(a3),d1
	eor.w	d1,d0
	move.w	d0,14*1024+14(a4)
	btst	#2,d2
	sne	d0
	ext.w	d0
	move.w	4(a3),d1
	eor.w	d1,d0
	move.w	d0,13*1024+14(a4)
	btst	#3,d2
	sne	d0
	ext.w	d0
	move.w	6(a3),d1
	eor.w	d1,d0
	move.w	d0,12*1024+14(a4)
	btst	#4,d2
	sne	d0
	ext.w	d0
	move.w	8(a3),d1
	eor.w	d1,d0
	move.w	d0,11*1024+14(a4)
	btst	#5,d2
	sne	d0
	ext.w	d0
	move.w	10(a3),d1
	eor.w	d1,d0
	move.w	d0,10*1024+14(a4)
	move.w	(a5)+,9*1024+14(a4)	; bits 6..15
	move.w	(a5)+,8*1024+14(a4)
	move.w	(a5)+,7*1024+14(a4)
	move.w	(a5)+,6*1024+14(a4)
	move.w	(a5)+,5*1024+14(a4)
	move.w	(a5)+,4*1024+14(a4)
	move.w	(a5)+,3*1024+14(a4)
	move.w	(a5)+,2*1024+14(a4)
	move.w	(a5)+,1*1024+14(a4)
	move.w	(a5)+,0*1024+14(a4)
	move.w	(a5)+,15*1024+12(a4)	; bits 16..31
	move.w	(a5)+,14*1024+12(a4)
	move.w	(a5)+,13*1024+12(a4)
	move.w	(a5)+,12*1024+12(a4)
	move.w	(a5)+,11*1024+12(a4)
	move.w	(a5)+,10*1024+12(a4)
	move.w	(a5)+,9*1024+12(a4)
	move.w	(a5)+,8*1024+12(a4)
	move.w	(a5)+,7*1024+12(a4)
	move.w	(a5)+,6*1024+12(a4)
	move.w	(a5)+,5*1024+12(a4)
	move.w	(a5)+,4*1024+12(a4)
	move.w	(a5)+,3*1024+12(a4)
	move.w	(a5)+,2*1024+12(a4)
	move.w	(a5)+,1*1024+12(a4)
	move.w	(a5)+,0*1024+12(a4)
	addq.l	#1,d2
	lea	16(a4),a4
	cmpa.l	a0,a4
	bne	.cw
	movem.l	(sp)+,d2-d7/a2-a6
	rts

; void bg_xor_asm(a0 = dst, a1 = keystream, a2 = src, d0 = number of longwords)
; dst = keystream ^ src; dst may alias src. ~45 cycles per longword (keystream in Chip RAM).
	xdef	_bg_xor_asm
_bg_xor_asm:
	movem.l	d2-d6,-(sp)
	move.l	d0,d1
	lsr.l	#2,d0
	beq.s	.rem
	subq.l	#1,d0
.x4:
	movem.l	(a1)+,d2-d5
	move.l	(a2)+,d6
	eor.l	d6,d2
	move.l	(a2)+,d6
	eor.l	d6,d3
	move.l	(a2)+,d6
	eor.l	d6,d4
	move.l	(a2)+,d6
	eor.l	d6,d5
	movem.l	d2-d5,(a0)
	lea	16(a0),a0
	dbf	d0,.x4
.rem:
	and.w	#3,d1
	beq.s	.xdone
	subq.w	#1,d1
.x1:
	move.l	(a1)+,d2
	move.l	(a2)+,d6
	eor.l	d6,d2
	move.l	d2,(a0)+
	dbf	d1,.x1
.xdone:
	movem.l	(sp)+,d2-d6
	rts
