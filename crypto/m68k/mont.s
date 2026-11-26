; WhatsA500 / AmigaCrypto - Montgomery product for RSA on a plain 68000
;
; int rsa_mont_mul_asm(a0 = a, a1 = b, a2 = n, a3 = r, d0 = limbs, d1 = n0inv)
;   r = a*b*R^-1 (mod n) before the final conditional subtraction, little-endian
;   16-bit limbs. Returns the top limb (0 or 1) in d0; the caller subtracts n if
;   top != 0 or r >= n. r may alias a or b (column i only writes limbs below the
;   ones still to be read).
;
; Product scanning (Comba) form of Montgomery multiplication: column sums in a
; 48-bit accumulator d6 (low 32) / d7 (carry count), m[i] computed as soon as
; column i is complete, so no partial sums are written back to memory. 2n^2
; MULU.W, ~90 cycles each including the loop.
	xdef	_rsa_mont_mul_asm
_rsa_mont_mul_asm:
	movem.l	d2-d7/a2-a6,-(sp)
	lea	-512(sp),sp		; m[256]
	move.l	sp,a6
	move.w	d0,d2			; n (limbs)
	move.w	d1,d3			; n0inv
	moveq	#0,d5			; constant 0 for addx
	moveq	#0,d6
	moveq	#0,d7
	moveq	#0,d0			; i
; ---- phase 1: columns 0 .. n-1, produce m[i] -------------------------------
.p1:
	move.l	a0,a4			; pa = a
	move.w	d0,d1
	add.w	d1,d1
	lea	2(a1,d1.w),a5		; pb = b + 2i + 2, predecrement reads b[i] first
	move.w	d0,d1			; count = i+1 -> dbf i
.p1a:
	move.w	(a4)+,d4
	mulu.w	-(a5),d4
	add.l	d4,d6
	addx.w	d5,d7
	dbf	d1,.p1a
	move.l	a6,a4			; pm = m
	tst.w	d0
	beq.s	.p1m_done
	move.w	d0,d1
	add.w	d1,d1
	lea	2(a2,d1.w),a5		; pn = n + 2i + 2, reads n[i] .. n[1]
	move.w	d0,d1
	subq.w	#1,d1			; count = i -> dbf i-1
.p1m:
	move.w	(a4)+,d4
	mulu.w	-(a5),d4
	add.l	d4,d6
	addx.w	d5,d7
	dbf	d1,.p1m
.p1m_done:
	move.w	d6,d4
	mulu.w	d3,d4			; m[i] = acc.low * n0inv mod 2^16
	move.w	d4,(a4)			; a4 = m + 2i
	mulu.w	(a2),d4			; m[i] * n[0]
	add.l	d4,d6
	addx.w	d5,d7
	clr.w	d6			; acc >>= 16 (low word is zero now)
	swap	d6
	swap	d7
	or.l	d7,d6
	moveq	#0,d7
	addq.w	#1,d0
	cmp.w	d2,d0
	blt	.p1
; ---- phase 2: columns n .. 2n-2, produce r[i-n] ------------------------------
	move.w	d2,d1
	add.w	d1,d1			; 2n (byte offset of the element past the end)
	lea	(a1,d1.w),a5		; b + 2n
	move.l	a5,-(sp)		; save b end
	lea	(a2,d1.w),a5
	move.l	a5,-(sp)		; save n end
.p2:
	move.w	d0,d1
	sub.w	d2,d1
	addq.w	#1,d1			; jstart = i-n+1
	add.w	d1,d1			; byte offset
	lea	(a0,d1.w),a4		; pa = a + 2*jstart
	move.l	4(sp),a5		; pb = b + 2n
	move.w	d2,d1
	add.w	d2,d1
	sub.w	d0,d1
	subq.w	#2,d1			; count-1 = 2n-2-i
	move.w	d1,-(sp)		; keep count-1 for the m loop
.p2a:
	move.w	(a4)+,d4
	mulu.w	-(a5),d4
	add.l	d4,d6
	addx.w	d5,d7
	dbf	d1,.p2a
	move.w	d0,d1
	sub.w	d2,d1
	addq.w	#1,d1
	add.w	d1,d1
	lea	(a6,d1.w),a4		; pm = m + 2*jstart
	move.l	2(sp),a5		; pn = n + 2n
	move.w	(sp)+,d1
.p2m:
	move.w	(a4)+,d4
	mulu.w	-(a5),d4
	add.l	d4,d6
	addx.w	d5,d7
	dbf	d1,.p2m
	move.w	d0,d1
	sub.w	d2,d1
	add.w	d1,d1
	move.w	d6,(a3,d1.w)		; r[i-n] = acc.low
	clr.w	d6
	swap	d6
	swap	d7
	or.l	d7,d6
	moveq	#0,d7
	addq.w	#1,d0
	move.w	d2,d1
	add.w	d2,d1
	subq.w	#1,d1			; 2n-1
	cmp.w	d1,d0
	blt	.p2
	addq.w	#8,sp			; drop saved end pointers
	move.w	d2,d1
	subq.w	#1,d1
	add.w	d1,d1
	move.w	d6,(a3,d1.w)		; r[n-1]
	clr.w	d6
	swap	d6			; top limb
	move.l	d6,d0
	lea	512(sp),sp
	movem.l	(sp)+,d2-d7/a2-a6
	rts
