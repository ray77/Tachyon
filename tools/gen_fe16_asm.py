#!/usr/bin/env python3
"""Generate crypto/m68k/fe16.s: field arithmetic for GF(2^255-19) in radix 2^16
on the plain 68000 (vasm Motorola syntax), fully unrolled.

    python3 tools/gen_fe16_asm.py > crypto/m68k/fe16.s

Routines (vbcc __reg calling convention, arrays of 16 little-endian 16-bit limbs;
d0/d1/a0/a1 scratch, all other registers preserved):

  _fe16_mul        a0 = h, a1 = f, a2 = g   h = f*g mod p
  _fe16_sqr        a0 = h, a1 = f           h = f*f mod p
  _fe16_add        a0 = h, a1 = f, a2 = g   h = f+g        (ADDX chain)
  _fe16_sub        a0 = h, a1 = f, a2 = g   h = f-g+4p     (ADDX / SUBX chains)
  _fe16_mul121665  a0 = h, a1 = f           h = 121665*f   (16 MULU by 56129, 2^16 part shifts a limb)

All routines mirror the C functions in crypto/ref/x25519_ref.c step by step
(same carry handling, same two fold passes), so results are bit-for-bit comparable.

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
    emit("; d1 = carry (< 39). Two fold passes: h += 38*carry, full propagation (constant time)")
    for p in range(2):
        emit(f"; fold pass {p+1}")
        emit("\tmulu.w\t#38,d1")
        emit("\tmove.l\ta5,a0")
        emit("\tmove.l\ta5,a1")
        for _ in range(16):
            emit("\tmoveq\t#0,d2")
            emit("\tmove.w\t(a0)+,d2")
            emit("\tadd.l\td2,d1")
            emit("\tmove.w\td1,(a1)+")
            emit("\tclr.w\td1")
            emit("\tswap\td1")


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


def gen_mul():
    prologue("_fe16_mul", True)
    for k in range(31):
        first = 0 if k < 16 else k - 15
        last = k if k < 16 else 15
        emit(f"; column {k}: f[{first}..{last}] * g[{k-first}..{k-last}]")
        set_pointers(first, k)
        for _ in range(first, last + 1):
            product()
        column_end(k)
    reduce_and_fold()
    epilogue()


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
    emit("; fold pass 1")
    fold_cheap()
    emit("; fold pass 2")
    fold_cheap()
    emit("\tmovem.l\t(sp)+,d2-d3/a2/a5")
    emit("\trts")
    emit("")


def gen_sub():
    emit("\txdef\t_fe16_sub")
    emit("_fe16_sub:")
    emit("\tmovem.l\td2-d4/a2/a5,-(sp)\t; a2 is callee-saved and walks over g")
    emit("\tmove.l\ta0,a5\t\t\t; a5 = h")
    emit("\tmove.w\t#$FFFF,d4")
    emit("; h = f + (2^256 - 76): limb 0 + $FFB4, limbs 1..15 + $FFFF")
    emit("\tmove.w\t(a1)+,d0")
    emit("\tadd.w\t#$FFB4,d0")
    emit("\tmove.w\td0,(a0)+")
    for _ in range(15):
        emit("\tmove.w\t(a1)+,d0")
        emit("\taddx.w\td4,d0")
        emit("\tmove.w\td0,(a0)+")
    emit("\tmoveq\t#0,d1")
    emit("\taddx.w\td1,d1\t\t\t; d1 = c1 (0/1)")
    emit("; h = h - g with borrow chain")
    emit("\tmove.l\ta5,a0")
    emit("\tmove.w\t(a0),d0")
    emit("\tmove.w\t(a2)+,d2")
    emit("\tsub.w\td2,d0\t\t\t; limb 0 sets X = borrow")
    emit("\tmove.w\td0,(a0)+")
    for _ in range(15):
        emit("\tmove.w\t(a0),d0")
        emit("\tmove.w\t(a2)+,d2")
        emit("\tsubx.w\td2,d0")
        emit("\tmove.w\td0,(a0)+")
    emit("\tmoveq\t#0,d2")
    emit("\taddx.w\td2,d2\t\t\t; d2 = b (0/1)")
    emit("\taddq.w\t#1,d1")
    emit("\tsub.w\td2,d1\t\t\t; d1 = c1 + 1 - b  (0, 1 or 2 multiples of 2^256)")
    emit("\tmoveq\t#0,d3")
    emit("; fold pass 1")
    fold_cheap()
    emit("; fold pass 2")
    fold_cheap()
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
    emit("; fold pass 2")
    fold_cheap()
    emit("\tmovem.l\t(sp)+,d2-d5/a5")
    emit("\trts")
    emit("")


emit("; GENERATED by tools/gen_fe16_asm.py - do not edit by hand.")
emit("; GF(2^255-19) field arithmetic for the 68000: radix 2^16, fully unrolled Comba.")
emit("")
emit("\tsection\ttext,code")
emit("")
gen_mul()
gen_sqr()
gen_add()
gen_sub()
gen_mul121665()
sys.stdout.write("\n".join(out) + "\n")
