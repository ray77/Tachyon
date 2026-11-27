#!/usr/bin/env python3
"""Generate crypto/m68k/fe16.s: field arithmetic for GF(2^255-19) in radix 2^16
on the plain 68000 (vasm Motorola syntax), fully unrolled.

    python3 tools/gen_fe16_asm.py > crypto/m68k/fe16.s

Routines (vbcc __reg calling convention, arrays of 16 little-endian 16-bit limbs;
d0/d1/a0/a1 scratch, all other registers preserved):

  _fe16_mul        a0 = h, a1 = f, a2 = g   h = f*g mod p   (alias of the default variant)
  _fe16_mul_comba  schoolbook Comba, 256 products
  _fe16_mul_kara   one level Karatsuba, 192 products + ~2.5k cycles of bookkeeping
  _fe16_sqr        a0 = h, a1 = f           h = f*f mod p
  _fe16_add        a0 = h, a1 = f, a2 = g   h = f+g        (ADDX chain)
  _fe16_sub        a0 = h, a1 = f, a2 = g   h = f-g+4p     (ADDX / SUBX chains)
  _fe16_mul121665  a0 = h, a1 = f           h = 121665*f   (16 MULU by 56129, 2^16 part shifts a limb)

All routines mirror the C functions in crypto/ref/x25519_ref.c step by step
(same carry handling, same two fold passes), so results are bit-for-bit comparable.
The second fold pass only touches limb 0 (fold_last): when pass 1 carried out of
2^256, the value left is < 1482 (< 2^23 for mul121665), so adding 38 cannot carry
further - the C version's full chain adds zeros there. 24 instead of 376 cycles.

Both compute the exact 512-bit product with a 48-bit column accumulator
(d0 = low 32 bits, d1 = carries, d3 = constant zero for addx), then reduce
h = r_lo + 38*r_hi (2^256 = 38 mod p) and fold the carry twice, exactly like
fe16_mul_c in crypto/ref/x25519_ref.c, so results are bit-for-bit comparable.

Squaring only forms the 120 cross products f[i]*f[j] (i < j) once per column,
doubles that sum, then adds the carry from the previous column (parked in d4,
it must not be doubled) and the square term f[k/2]^2 for even columns:
136 instead of 256 MULU.W.
"""
import sys

out = []
emit = out.append


def product():
    """one 16x16 product from (a0)+ and -(a1), added to the 48-bit accumulator"""
    emit("\tmove.w\t(a0)+,d2")
    emit("\tmulu.w\t-(a1),d2")
    emit("\tadd.l\td2,d0")
    emit("\taddx.w\td3,d1")


def column_end(k):
    """store limb k and shift the accumulator right by 16"""
    emit("\tmove.w\td0,(a2)+")
    if k < 30:
        emit("\tclr.w\td0")
        emit("\tswap\td0")
        emit("\tswap\td1")
        emit("\tadd.l\td1,d0")
        emit("\tmoveq\t#0,d1")
    else:
        emit("\tswap\td0")
        emit("\tmove.w\td0,(a2)+\t\t; r[31]")


def reduce_and_fold():
    """h = r_lo + 38*r_hi, then two full fold passes. r at (sp), h at a5."""
    emit("; reduction: h[i] = r[i] + 38*r[i+16] with carry chain (d1 = accumulator)")
    emit("\tmove.l\tsp,a0\t\t\t; a0 -> r[0]")
    emit("\tlea\t32(sp),a1\t\t; a1 -> r[16]")
    emit("\tmove.l\ta5,a2\t\t\t; a2 -> h")
    emit("\tmoveq\t#0,d1")
    for _ in range(16):
        emit("\tmove.w\t(a1)+,d2")
        emit("\tmulu.w\t#38,d2")
        emit("\tadd.l\td2,d1")
        emit("\tmoveq\t#0,d2")
        emit("\tmove.w\t(a0)+,d2")
        emit("\tadd.l\td2,d1")
        emit("\tmove.w\td1,(a2)+")
        emit("\tclr.w\td1")
        emit("\tswap\td1")
    emit("; d1 = carry (< 39): 38*carry < 1482 fits a word, so fold pass 1 is an X-flag chain")
    emit("; fold pass 1")
    fold_cheap()
    emit("; fold pass 2: if pass 1 carried out, h < 1482 now, so only limb 0 changes")
    fold_last(1)


def prologue(name, has_g):
    emit(f"\txdef\t{name}")
    emit(f"{name}:")
    emit("\tmovem.l\td2-d4/a2-a5,-(sp)")
    emit("\tlea\t-64(sp),sp\t\t; r[32]: 512-bit product")
    emit("\tmove.l\ta0,a5\t\t\t; a5 = h")
    emit("\tmove.l\ta1,a3\t\t\t; a3 = f")
    emit("\tmove.l\ta2,a4\t\t\t; a4 = g" if has_g else "\tmove.l\ta1,a4\t\t\t; a4 = f (squaring)")
    emit("\tmove.l\tsp,a2\t\t\t; a2 = r write pointer")
    emit("\tmoveq\t#0,d0\t\t\t; accumulator low 32 bits")
    emit("\tmoveq\t#0,d1\t\t\t; accumulator carries (bits 32..47)")
    emit("\tmoveq\t#0,d3\t\t\t; permanent zero for addx")


def epilogue():
    emit("\tlea\t64(sp),sp")
    emit("\tmovem.l\t(sp)+,d2-d4/a2-a5")
    emit("\trts")
    emit("")


def set_pointers(first, k):
    """a0 -> f[first] (walks up), a1 -> g[k-first+1] (walks down with -(a1))"""
    if first == 0:
        emit("\tmove.l\ta3,a0")
    else:
        emit(f"\tlea\t{2*first}(a3),a0")
    emit(f"\tlea\t{2*(k-first+1)}(a4),a1")


def comba(n, store_last=True):
    """n x n limb Comba product of (a3) and (a4) into (a2)+, 2n limbs.
    Accumulator d0/d1 must be zero on entry; d3 = 0."""
    for k in range(2 * n - 1):
        first = 0 if k < n else k - (n - 1)
        last = k if k < n else n - 1
        emit(f"; column {k}: f[{first}..{last}] * g[{k-first}..{k-last}]")
        set_pointers(first, k)
        for _ in range(first, last + 1):
            product()
        emit("\tmove.w\td0,(a2)+")
        if k < 2 * n - 2:
            emit("\tclr.w\td0")
            emit("\tswap\td0")
            emit("\tswap\td1")
            emit("\tadd.l\td1,d0")
            emit("\tmoveq\t#0,d1")
        else:
            emit("\tswap\td0")
            emit(f"\tmove.w\td0,(a2)+\t\t; limb {2*n-1}")
            emit("\tmoveq\t#0,d0")


def gen_mul():
    """schoolbook Comba, 256 products"""
    prologue("_fe16_mul_comba", True)
    comba(16)
    reduce_and_fold()
    epilogue()


def gen_mul_kara():
    """one level of Karatsuba: f = f0 + 2^128 f1, g = g0 + 2^128 g1 (8 limbs each).
    z0 = f0*g0 -> r[0..15], z2 = f1*g1 -> r[16..31],
    m  = (f0+f1)*(g0+g1) with the 9th-limb carries handled as masked corrections,
    z1 = m - z0 - z2 (17 limbs, non-negative), r[8..] += z1.  192 products.
    Stack frame: 0..63 r[32], 64..79 sf[8], 80..95 sg[8], 96..131 t[18]."""
    emit("\txdef\t_fe16_mul_kara")
    emit("_fe16_mul_kara:")
    emit("\tmovem.l\td2-d7/a2-a5,-(sp)")
    emit("\tlea\t-132(sp),sp")
    emit("\tmove.l\ta0,a5\t\t\t; a5 = h")
    emit("\tmove.l\ta1,a3\t\t\t; a3 = f")
    emit("\tmove.l\ta2,a4\t\t\t; a4 = g")
    emit("\tmoveq\t#0,d3\t\t\t; permanent zero")
    # sf = f0 + f1, carry -> d6 (as 0/-1 mask), sg = g0 + g1, carry -> d7 (mask)
    for (src, dst_off, maskreg) in (("a3", 64, "d6"), ("a4", 80, "d7")):
        emit(f"; s = lo + hi of ({src}), carry mask -> {maskreg}")
        emit(f"\tmove.l\t{src},a0")
        emit(f"\tlea\t16({src}),a1")
        emit(f"\tlea\t{dst_off}(sp),a2")
        emit("\tmove.w\t(a0)+,d0")
        emit("\tadd.w\t(a1)+,d0")
        emit("\tmove.w\td0,(a2)+")
        for _ in range(7):
            emit("\tmove.w\t(a0)+,d0")
            emit("\tmove.w\t(a1)+,d2")
            emit("\taddx.w\td2,d0")
            emit("\tmove.w\td0,(a2)+")
        emit(f"\tmoveq\t#0,{maskreg}")
        emit(f"\taddx.w\t{maskreg},{maskreg}")
        emit(f"\tneg.w\t{maskreg}\t\t\t; 0 or $FFFF")
    # z0 = f0*g0 -> r[0..15]
    emit("; z0 = f0 * g0")
    emit("\tmove.l\tsp,a2")
    emit("\tmoveq\t#0,d0")
    emit("\tmoveq\t#0,d1")
    comba(8)
    # z2 = f1*g1 -> r[16..31]  (a3/a4 advanced by 16 bytes, a2 continues)
    emit("; z2 = f1 * g1")
    emit("\tlea\t16(a3),a3")
    emit("\tlea\t16(a4),a4")
    emit("\tmoveq\t#0,d1")
    comba(8)
    # m = sf*sg -> t[0..15]
    emit("; m = (f0+f1)(g0+g1) low parts -> t[0..15]")
    emit("\tlea\t64(sp),a3")
    emit("\tlea\t80(sp),a4")
    emit("\tlea\t96(sp),a2")
    emit("\tmoveq\t#0,d1")
    comba(8)
    emit("\tclr.w\t(a2)+\t\t\t; t[16]")
    emit("\tclr.w\t(a2)\t\t\t; t[17] (never used, keeps the frame even)")
    # corrections: t[8..16] += mask_g & sf ; t[8..16] += mask_f & sg ; t[16] += cf & cg
    for (maskreg, src_off, label) in (("d7", 64, "cg * sf"), ("d6", 80, "cf * sg")):
        emit(f"; t[8..16] += {label}")
        emit(f"\tlea\t{src_off}(sp),a0")
        emit("\tlea\t112(sp),a1\t\t; t[8]")
        emit("\tmove.w\t(a0)+,d0")
        emit(f"\tand.w\t{maskreg},d0")
        emit("\tadd.w\td0,(a1)+")
        for _ in range(7):
            emit("\tmove.w\t(a0)+,d0")
            emit(f"\tand.w\t{maskreg},d0")
            emit("\tmove.w\t(a1),d2")
            emit("\taddx.w\td0,d2")
            emit("\tmove.w\td2,(a1)+")
        emit("\tmove.w\t(a1),d2")
        emit("\taddx.w\td3,d2")
        emit("\tmove.w\td2,(a1)\t\t\t; t[16]")
    emit("\tmove.w\td6,d0")
    emit("\tand.w\td7,d0")
    emit("\tneg.w\td0\t\t\t; cf & cg as 0/1")
    emit("\tadd.w\td0,128(sp)\t\t; t[16] += cf*cg")
    # z1 = t - r[0..15] - r[16..31]  (17 limbs, in place in t)
    for (off, label) in ((0, "z0"), (32, "z2")):
        emit(f"; t -= {label}")
        emit("\tlea\t96(sp),a0\t\t; t")
        emit(f"\tlea\t{off}(sp),a1")
        emit("\tmove.w\t(a1)+,d0")
        emit("\tsub.w\td0,(a0)+")
        for _ in range(15):
            emit("\tmove.w\t(a0),d2")
            emit("\tmove.w\t(a1)+,d0")
            emit("\tsubx.w\td0,d2")
            emit("\tmove.w\td2,(a0)+")
        emit("\tmove.w\t(a0),d2")
        emit("\tsubx.w\td3,d2")
        emit("\tmove.w\td2,(a0)\t\t\t; t[16]")
    # r[8..24] += t[0..16], propagate carry through r[25..31]
    emit("; r[8..] += z1")
    emit("\tlea\t96(sp),a0\t\t; t")
    emit("\tlea\t16(sp),a1\t\t; r[8]")
    emit("\tmove.w\t(a0)+,d0")
    emit("\tadd.w\td0,(a1)+")
    for _ in range(16):
        emit("\tmove.w\t(a1),d2")
        emit("\tmove.w\t(a0)+,d0")
        emit("\taddx.w\td0,d2")
        emit("\tmove.w\td2,(a1)+")
    for _ in range(7):
        emit("\tmove.w\t(a1),d2")
        emit("\taddx.w\td3,d2")
        emit("\tmove.w\td2,(a1)+")
    reduce_and_fold()
    emit("\tlea\t132(sp),sp")
    emit("\tmovem.l\t(sp)+,d2-d7/a2-a5")
    emit("\trts")
    emit("")


def sqr_column_end(k):
    """store limb k; park the shifted-out carry in d4 and clear the accumulator"""
    emit("\tmove.w\td0,(a2)+")
    if k < 30:
        emit("\tclr.w\td0")
        emit("\tswap\td0")
        emit("\tswap\td1")
        emit("\tadd.l\td1,d0")
        emit("\tmove.l\td0,d4\t\t\t; carry into the next column")
        emit("\tmoveq\t#0,d0")
        emit("\tmoveq\t#0,d1")
    else:
        emit("\tswap\td0")
        emit("\tmove.w\td0,(a2)+\t\t; r[31]")


def gen_sqr():
    prologue("_fe16_sqr", False)
    emit("\tmoveq\t#0,d4\t\t\t; carry from the previous column")
    for k in range(31):
        first = 0 if k < 16 else k - 15
        # cross products: i from first while i < k - i
        cross = [i for i in range(first, 16) if i < k - i <= 15]
        emit(f"; column {k}: 2 * sum f[i]*f[{k}-i] for i in {cross[0] if cross else '-'}..{cross[-1] if cross else '-'}"
             + (f" + f[{k//2}]^2" if k % 2 == 0 else ""))
        if cross:
            set_pointers(cross[0], k)
            for _ in cross:
                product()
            emit("\tadd.l\td0,d0\t\t\t; double the cross-product sum")
            emit("\taddx.w\td1,d1")
        emit("\tadd.l\td4,d0\t\t\t; + carry from the previous column")
        emit("\taddx.w\td3,d1")
        if k % 2 == 0:
            m = k // 2
            emit(f"\tmove.w\t{2*m}(a3),d2")
            emit("\tmulu.w\td2,d2")
            emit("\tadd.l\td2,d0")
            emit("\taddx.w\td3,d1")
        sqr_column_end(k)
    reduce_and_fold()
    epilogue()


def fold_cheap():
    """h += 38*d1 where d1 <= 2 (so 38*d1 <= 76 fits a word and every carry is 0/1):
    one add.w to limb 0, then an addx.w chain. Needs d3 = 0 and a5 = h. Leaves the
    carry out (0/1) in d1."""
    emit("\tmulu.w\t#38,d1")
    emit("\tmove.l\ta5,a0")
    emit("\tadd.w\td1,(a0)+")
    for _ in range(15):
        emit("\tmove.w\t(a0),d2")
        emit("\taddx.w\td3,d2")
        emit("\tmove.w\td2,(a0)+")
    emit("\tmoveq\t#0,d1")
    emit("\taddx.w\td1,d1\t\t\t; d1 = carry out")


def fold_last(limbs=1):
    """second fold pass: h += 38*d1 with d1 in {0,1}. Needs the bound proven at the call
    site: whenever d1 == 1 the limbs above `limbs`-1 are zero and the chain cannot carry
    out of limb `limbs`-1, so only `limbs` limbs are touched (constant time, no branch).
    Needs d3 = 0 (limbs > 1) and a5 = h."""
    emit("\tneg.w\td1\t\t\t; 0 or $FFFF")
    emit("\tand.w\t#38,d1\t\t\t; 0 or 38")
    if limbs == 1:
        emit("\tadd.w\td1,(a5)\t\t\t; limb 0 (h < 1482 whenever d1 was 1: no carry)")
    else:
        emit("\tmove.l\ta5,a0")
        emit("\tadd.w\td1,(a0)+")
        for _ in range(limbs - 1):
            emit("\tmove.w\t(a0),d2")
            emit("\taddx.w\td3,d2")
            emit("\tmove.w\td2,(a0)+")


def gen_add():
    emit("\txdef\t_fe16_add")
    emit("_fe16_add:")
    emit("\tmovem.l\td2-d3/a2/a5,-(sp)\t; a2 is callee-saved and walks over g")
    emit("\tmove.l\ta0,a5\t\t\t; a5 = h")
    emit("\tmove.w\t(a1)+,d0")
    emit("\tadd.w\t(a2)+,d0\t\t; limb 0 sets X")
    emit("\tmove.w\td0,(a0)+")
    for _ in range(15):
        emit("\tmove.w\t(a1)+,d0")
        emit("\tmove.w\t(a2)+,d2")
        emit("\taddx.w\td2,d0")
        emit("\tmove.w\td0,(a0)+")
    emit("\tmoveq\t#0,d1")
    emit("\taddx.w\td1,d1\t\t\t; d1 = carry (0/1)")
    emit("\tmoveq\t#0,d3")
    emit("; fold pass 1 (carry 0/1 -> + 38, X-flag chain)")
    fold_cheap()
    emit("; fold pass 2: if pass 1 carried out, h < 38 now, so only limb 0 changes")
    fold_last(1)
    emit("\tmovem.l\t(sp)+,d2-d3/a2/a5")
    emit("\trts")
    emit("")


def gen_sub():
    emit("\txdef\t_fe16_sub")
    emit("_fe16_sub:")
    emit("\tmovem.l\td2-d4/a2/a5,-(sp)\t; a2 is callee-saved and walks over g")
    emit("\tmove.l\ta0,a5\t\t\t; a5 = h")
    emit("\tmove.w\t#$FFFF,d4")
    emit("; h = f - g with borrow chain (first, so h may alias f or g)")
    emit("\tmove.w\t(a1)+,d0")
    emit("\tmove.w\t(a2)+,d2")
    emit("\tsub.w\td2,d0\t\t\t; limb 0 sets X = borrow")
    emit("\tmove.w\td0,(a0)+")
    for _ in range(15):
        emit("\tmove.w\t(a1)+,d0")
        emit("\tmove.w\t(a2)+,d2")
        emit("\tsubx.w\td2,d0")
        emit("\tmove.w\td0,(a0)+")
    emit("\tmoveq\t#0,d1")
    emit("\taddx.w\td1,d1\t\t\t; d1 = b (0/1)")
    emit("; h = h + (2^256 - 76): limb 0 + $FFB4, limbs 1..15 + $FFFF")
    emit("\tmove.l\ta5,a0")
    emit("\tadd.w\t#$FFB4,(a0)+\t\t; sets X")
    for _ in range(15):
        emit("\tmove.w\t(a0),d0")
        emit("\taddx.w\td4,d0")
        emit("\tmove.w\td0,(a0)+")
    emit("\tmoveq\t#0,d2")
    emit("\taddx.w\td2,d2\t\t\t; d2 = c (0/1)")
    emit("\taddq.w\t#1,d2")
    emit("\tsub.w\td1,d2")
    emit("\tmove.w\td2,d1\t\t\t; d1 = c + 1 - b  (0, 1 or 2 multiples of 2^256)")
    emit("\tmoveq\t#0,d3")
    emit("; fold pass 1 (d1 <= 2 -> + 38*d1 <= 76, X-flag chain)")
    fold_cheap()
    emit("; fold pass 2: if pass 1 carried out, h < 76 now, so only limb 0 changes")
    fold_last(1)
    emit("\tmovem.l\t(sp)+,d2-d4/a2/a5")
    emit("\trts")
    emit("")


def gen_mul121665():
    emit("\txdef\t_fe16_mul121665")
    emit("_fe16_mul121665:")
    emit("\tmovem.l\td2-d5/a5,-(sp)")
    emit("\tmove.l\ta0,a5\t\t\t; a5 = h")
    emit("\tmove.w\t#56129,d5\t\t; 121665 - 65536")
    emit("\tmoveq\t#0,d1\t\t\t; carry c")
    for _ in range(16):
        emit("\tmoveq\t#0,d4")
        emit("\tmove.w\t(a1)+,d4\t\t; f[i]")
        emit("\tmove.l\td4,d2")
        emit("\tmulu.w\td5,d2\t\t\t; t = f[i]*56129")
        emit("\tadd.l\td1,d2\t\t\t; + c")
        emit("\tmove.w\td2,(a0)+")
        emit("\tclr.w\td2")
        emit("\tswap\td2")
        emit("\tmove.l\td2,d1")
        emit("\tadd.l\td4,d1\t\t\t; c = (t >> 16) + f[i]")
    emit("; fold pass 1: c < 2^17, so 38*c needs a long accumulator")
    emit("\tadd.l\td1,d1\t\t\t; 2c")
    emit("\tmove.l\td1,d2")
    emit("\tlsl.l\t#4,d2\t\t\t; 32c")
    emit("\tadd.l\td1,d2\t\t\t; 34c")
    emit("\tadd.l\td1,d1\t\t\t; 4c")
    emit("\tadd.l\td1,d2\t\t\t; 38c")
    emit("\tmove.l\td2,d1")
    emit("\tmove.l\ta5,a0")
    emit("\tmove.l\ta5,a1")
    for _ in range(16):
        emit("\tmoveq\t#0,d2")
        emit("\tmove.w\t(a0)+,d2")
        emit("\tadd.l\td2,d1")
        emit("\tmove.w\td1,(a1)+")
        emit("\tclr.w\td1")
        emit("\tswap\td1")
    emit("; d1 = carry (0/1)")
    emit("\tmoveq\t#0,d3")
    emit("; fold pass 2: if pass 1 carried out, h < 38*2^17 < 2^23 now (limbs 2..15 zero,")
    emit("; limb 1 < 77), so + 38 reaches limb 1 at most")
    fold_last(2)
    emit("\tmovem.l\t(sp)+,d2-d5/a5")
    emit("\trts")
    emit("")


emit("; GENERATED by tools/gen_fe16_asm.py - do not edit by hand.")
emit("; GF(2^255-19) field arithmetic for the 68000: radix 2^16, fully unrolled Comba.")
emit("")
emit("\tsection\ttext,code")
emit("")
gen_mul()
gen_mul_kara()
emit("; fe16_mul = the variant currently selected as default")
emit("\txdef\t_fe16_mul")
emit("_fe16_mul\tequ\t_fe16_mul_kara")
emit("")
gen_sqr()
gen_add()
gen_sub()
gen_mul121665()
sys.stdout.write("\n".join(out) + "\n")
