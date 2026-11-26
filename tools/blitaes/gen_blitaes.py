#!/usr/bin/env python3
"""Blitter program for bit-sliced AES-256 (v2: Blitter-side transposition, docs/CUSTOM-CHIPS.md).

Data: 1024 blocks = 16 KiB in STATE, viewed as 16 "rows" k of 1 KiB (row k = blocks 64k .. 64k+63).
Transposition (4 stages, Blitter barrel shifter + masks) turns every 16x16 bit matrix
{block w+64k, 16-bit chunk q} into lane words: after it, word at STATE + 1024k + 16w + 2q
holds bit position (15 - k) of chunk q (i.e. byte 2q + (k >> 3), bit 7 - (k & 7)) of blocks w, w+64, ..., w+15*64 (bit j of the word <-> block w+64j,
j numbered as the model/pack function define). So the AES lane for (bit b, row r, col c),
byte index y = 4c+r: k = (y & 1)*8 + (7 - b), q = y >> 1, lane = 64 words at stride 16 bytes.

Sections: WHITE (STATE ^= key pattern), TIN (transpose in), SBOX (113 gates x 2 blits of 512
contiguous words), MIX (per lane, 1-word lines with modulo 14; round key through C with modulo -2),
FINAL (ShiftRows + key), TOUT (transpose out). Entry: con0, con1, a, b, c, d, amod, bmod, cmod, dmod,
size, flags (1: c is a key lane -> add round*256). For DESC blits the pointers address the last word.
"""
import sys
L = 64
LANE = L * 2
ROW = 1024                                   # bytes per k-row
STATE = 0
SOUT = STATE + 16 * ROW
TMP = SOUT + 16 * ROW
gates = [l.split() for l in open(__file__.rsplit('/', 1)[0] + '/sbox113.txt') if l.strip()]
last = {}
for i, (op, o, a, b) in enumerate(gates):
    for x in (a, b): last[x] = i
slot_of, free, nslots = {}, [], 0
def alloc(w):
    global nslots
    s = free.pop() if free else nslots
    if s == nslots: nslots += 1
    slot_of[w] = s
    return s
plan = []
for i, (op, o, a, b) in enumerate(gates):
    srcs = []
    for x in (a, b):
        if x[0] == 'U': srcs.append(('state', 7 - int(x[1:])))
        elif x[0] == 'S': srcs.append(('sout', 7 - int(x[1:])))
        else: srcs.append(('tmp', slot_of[x]))
    dst = ('sout', 7 - int(o[1:])) if o[0] == 'S' else ('tmp', alloc(o))
    plan.append((op, dst, srcs[0], srcs[1]))
    for x in (a, b):
        if x[0] == 't' and last[x] == i: free.append(slot_of[x])
MIX = TMP + nslots * 2 * ROW                 # 2 scratch lanes, each 64 words at stride 16 -> reserve 2 KiB
KEYS = MIX + 2 * ROW
KEYPAT = KEYS + 15 * 256                     # 128 bytes: key repeated 8 times
MASKS = KEYPAT + 128                         # 4 x 1 KiB mask rows
ARENA = MASKS + 4 * ROW

def half_addr(ref, h):
    kind, v = ref
    if kind == 'state': return STATE + ((7 - v) + 8 * h) * ROW      # bit v lives in transposed row 7-v (+8 for odd bytes)
    if kind == 'sout': return SOUT + ((7 - v) + 8 * h) * ROW
    return TMP + v * 2 * ROW + h * ROW
def lane(base, b, r, c):
    y = 4 * c + r
    return base + ((y & 1) * 8 + (7 - b)) * ROW + (y >> 1) * 2     # transposed row t holds bit 15-t of the chunk

USEA, USEB, USEC, USED = 0x800, 0x400, 0x200, 0x100
LF = {'XOR': 0x3c, 'AND': 0xc0, 'XNOR': 0xc3, 'XOR3': 0x96, 'AXC': 0x5a, 'SEL_B_WHERE_C': 0xd8, 'SEL_A_WHERE_C': 0xe4}
prog = []
def blit(lf, a, b, c, d, hw, amod=0, bmod=0, cmod=0, dmod=0, ash=0, desc=0, flags=0):
    con0 = USEA | USED | lf | (ash << 12)
    if b is not None: con0 |= USEB
    if c is not None: con0 |= USEC
    prog.append((con0, 2 if desc else 0, a, b or 0, c or 0, d, amod & 0xffff, bmod & 0xffff, cmod & 0xffff, dmod & 0xffff, hw, flags))
def size_lines(words_per_line, lines): return ((lines & 1023) << 6) | (words_per_line & 63)
S512 = size_lines(64, 8)                     # 512 contiguous words
S_LANE = size_lines(1, 64)                   # 64 one-word lines

def section_white():
    # STATE ^= keypat: 128 lines of 64 words, B re-reads the 128-byte key pattern
    blit(LF['XOR'], STATE, KEYPAT, None, STATE, size_lines(64, 128), bmod=-128)

def section_transpose(buf_a, buf_b):
    """4 stages, ping-pong buf_a -> buf_b -> buf_a -> buf_b -> buf_a"""
    src, dst = buf_a, buf_b
    for si, (d, s, mhi) in enumerate(((8, 8, 0xff00), (4, 4, 0xf0f0), (2, 2, 0xcccc), (1, 1, 0xaaaa))):
        mask = MASKS + si * ROW
        for k in range(16):
            if k & d: continue
            # new[k]   = (X[k] & Mhi) | ((X[k+d] >> s) & ~Mhi)   : A = X[k+d] shifted right, B = X[k], C = Mhi
            blit(LF['SEL_B_WHERE_C'], src + (k + d) * ROW, src + k * ROW, mask, dst + k * ROW, S512, ash=s)
            # new[k+d] = ((X[k] << s) & Mhi) | (X[k+d] & ~Mhi)   : descending, A = X[k] shifted left
            lastw = ROW - 2
            blit(LF['SEL_A_WHERE_C'], src + k * ROW + lastw, src + (k + d) * ROW + lastw, mask + lastw, dst + (k + d) * ROW + lastw, S512, ash=s, desc=1)
        src, dst = dst, src
    assert src == buf_a

def section_sbox():
    for op, dst, s0, s1 in plan:
        for h in range(2):
            blit(LF[op], half_addr(s0, h), half_addr(s1, h), None, half_addr(dst, h), S512)

def mix_terms(b, r):
    t = []
    bm1 = (b - 1) % 8
    for k, mult in ((0, 2), (1, 3), (2, 1), (3, 1)):
        rr = (r + k) % 4
        if mult in (2, 3):
            if b != 0: t.append((bm1, rr, rr))
            if b in (0, 1, 3, 4): t.append((7, rr, rr))
        if mult in (1, 3): t.append((b, rr, rr))
    return t

def lane_blit(lf, a, b, c, d, cmod=0, flags=0):
    blit(lf, a, b, c, d, S_LANE, amod=14, bmod=14 if b is not None else 0, cmod=(cmod if c is not None else 0), dmod=14, flags=flags)

def section_mix():
    scratch = [MIX, MIX + 2]                 # two scratch lanes interleaved in the MIX row (stride 16)
    for b in range(8):
        for r in range(4):
            terms = mix_terms(b, r)
            for c in range(4):
                srcs = [lane(SOUT, tb, tr, (c + rot) % 4) for (tb, tr, rot) in terms]
                dst = lane(STATE, b, r, c)
                key = KEYS + ((b * 4 + r) * 4 + c) * 2
                acc, si = None, 0
                while len(srcs) > 2 or (acc is not None and len(srcs) > 1):
                    if acc is None:
                        lane_blit(LF['XOR3'], srcs[0], srcs[1], srcs[2], scratch[si], cmod=14); srcs = srcs[3:]
                    else:
                        lane_blit(LF['XOR3'], acc, srcs[0], srcs[1], scratch[si], cmod=14); srcs = srcs[2:]
                    acc = scratch[si]; si ^= 1
                if acc is None:
                    lane_blit(LF['XOR3'], srcs[0], srcs[1], key, dst, cmod=-2, flags=1)
                elif len(srcs) == 1:
                    lane_blit(LF['XOR3'], acc, srcs[0], key, dst, cmod=-2, flags=1)
                else:
                    lane_blit(LF['AXC'], acc, None, key, dst, cmod=-2, flags=1)

def section_final():
    for b in range(8):
        for r in range(4):
            for c in range(4):
                lane_blit(LF['AXC'], lane(SOUT, b, r, (c + r) % 4), None, KEYS + ((b * 4 + r) * 4 + c) * 2, lane(STATE, b, r, c), cmod=-2, flags=1)

marks = {}
def mark(name): marks[name] = len(prog)
mark('white'); section_white()
mark('tin'); section_transpose(STATE, SOUT)
mark('sbox'); section_sbox()
mark('mix'); section_mix()
mark('final'); section_final()
mark('tout'); section_transpose(STATE, SOUT)
mark('end')
names = ['white', 'tin', 'sbox', 'mix', 'final', 'tout']
out = ['/* GENERATED by tools/blitaes/gen_blitaes.py (v2) - do not edit */', '#define BA_L %d' % L,
       '#define BA_STATE %d\n#define BA_SOUT %d\n#define BA_TMP %d\n#define BA_MIX %d\n#define BA_KEYS %d\n#define BA_KEYPAT %d\n#define BA_MASKS %d\n#define BA_ARENA %d' % (STATE, SOUT, TMP, MIX, KEYS, KEYPAT, MASKS, ARENA)]
for i, n in enumerate(names):
    out.append('#define BA_SEC_%s %d\n#define BA_N%s %d' % (n.upper(), marks[n], n.upper(), marks[names[i + 1]] - marks[n] if i + 1 < len(names) else marks['end'] - marks[n]))
out.append('typedef struct { uint16_t con0, con1; uint32_t a, b, c, d; uint16_t amod, bmod, cmod, dmod, size, flags; } ba_blit;')
out.append('static const ba_blit ba_prog[%d] = {' % len(prog))
for e in prog: out.append('  { 0x%04x, %d, %d, %d, %d, %d, 0x%04x, 0x%04x, 0x%04x, 0x%04x, 0x%04x, %d },' % e)
out.append('};')
sys.stdout.write('\n'.join(out) + '\n')
sys.stderr.write('blits: ' + ' '.join('%s=%d' % (n, marks[names[i + 1]] - marks[n] if i + 1 < len(names) else marks['end'] - marks[n]) for i, n in enumerate(names)) + '; temps %d; arena %d\n' % (nslots, ARENA))
