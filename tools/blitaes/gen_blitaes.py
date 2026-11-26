#!/usr/bin/env python3
"""Generate the Blitter program for bit-sliced AES-256 encryption (docs/CUSTOM-CHIPS.md).

Layout (all in one Chip RAM arena, 16-bit words):
  STATE : 128 lanes [bit b][row r][col c], each L words (word k holds the bit of 16 blocks 16k..16k+15)
  SOUT  : S-box output, same layout
  TMP   : pool of temporaries, 16L words each (one per live S-box wire)
  MIX   : 2 scratch lanes of L words for MixColumns chains
  KEYS  : 15 round keys x 128 lanes x 1 word (0x0000 / 0xFFFF): read through the C channel with modulo -2
Program entry: con0, a_off, b_off, c_off, d_off (bytes from arena), cmod, size, flags (1 = c_off is a key lane,
add round*256 bytes).
Bit convention: bit 0 = LSB of the byte; the S-box circuit uses U0 = MSB, so U_i = lane bit (7-i), S_i -> bit (7-i).
"""
import sys
L = int(sys.argv[1]) if len(sys.argv) > 1 else 64
assert L % 4 == 0 and 16 * L % 64 == 0
LANE = L * 2                       # bytes per lane
STATE = 0
SOUT = STATE + 128 * LANE
gates = [l.split() for l in open(__file__.rsplit('/', 1)[0] + '/sbox113.txt') if l.strip()]

# liveness of S-box wires -> temp slots
last = {}
for i, (op, o, a, b) in enumerate(gates):
    for x in (a, b):
        last[x] = i
slot_of, free, nslots = {}, [], 0
def alloc(w):
    global nslots
    if free: s = free.pop()
    else: s = nslots; nslots += 1
    slot_of[w] = s
    return s
sbox_plan = []     # (op, dst, srcA, srcB) with symbolic refs
for i, (op, o, a, b) in enumerate(gates):
    srcs = []
    for x in (a, b):
        if x.startswith('U'): srcs.append(('state', 7 - int(x[1:])))
        elif x.startswith('S'): srcs.append(('sout', 7 - int(x[1:])))
        else: srcs.append(('tmp', slot_of[x]))
    if o.startswith('S'): dst = ('sout', 7 - int(o[1:]))
    else: dst = ('tmp', alloc(o))
    sbox_plan.append((op, dst, srcs[0], srcs[1]))
    for x in (a, b):
        if x.startswith('t') and last[x] == i: free.append(slot_of[x])
TMP = SOUT + 128 * LANE
MIX = TMP + nslots * 16 * LANE
KEYS = MIX + 2 * LANE
ARENA = KEYS + 15 * 128 * 2

def lane(base, b, r, c): return base + ((b * 4 + r) * 4 + c) * LANE
def bitblock(base, b): return base + b * 16 * LANE
def addr(ref):
    kind, v = ref
    if kind == 'state': return bitblock(STATE, v)
    if kind == 'sout': return bitblock(SOUT, v)
    if kind == 'tmp': return TMP + v * 16 * LANE
    raise ValueError(ref)

USEA, USEB, USEC, USED = 0x800, 0x400, 0x200, 0x100
LF = {'XOR': 0x3c, 'AND': 0xc0, 'XNOR': 0xc3, 'XOR3': 0x96, 'COPY': 0xf0}
def size(words):
    if words <= 64: return (1 << 6) | (words & 63)
    assert words % 64 == 0 and words // 64 <= 1024
    h = words // 64
    return ((h & 1023) << 6) | 0
prog = []
def blit(lf, a, b, c, d, words, cmod=0, flags=0, hw=None):
    con0 = USEA | USED | lf
    if b is not None: con0 |= USEB
    if c is not None: con0 |= USEC
    prog.append((con0, a, b or 0, c or 0, d, cmod & 0xffff, hw if hw else size(words), flags))

def sbox_round():
    for op, dst, s0, s1 in sbox_plan:
        blit(LF[op], addr(s0), addr(s1), None, addr(dst), 16 * L)

def mix_terms(b, r):
    """input lanes (bit, row, rotation) for output bit b, row r (ShiftRows folded into the column rotation)"""
    t = []
    bm1 = (b - 1) % 8
    for k, mult in ((0, 2), (1, 3), (2, 1), (3, 1)):
        rr = (r + k) % 4
        if mult in (2, 3):
            if b != 0: t.append((bm1, rr, rr))        # bit b-1 of 2a (bit 0 of 2a has no b-1 source)
            if b in (0, 1, 3, 4): t.append((7, rr, rr))   # overflow a_7 * 0x1b
        if mult in (1, 3):
            t.append((b, rr, rr))
    return t

# per-column key blit: 1-word lines, height L, C modulo -2 keeps the key pointer on one word
def key_blit(lf, a, b, keylane, d):
    blit(lf, a, b, keylane, d, L, cmod=-2, flags=1, hw=((L & 1023) << 6) | 1)

def mix_round():
    for b in range(8):
        for r in range(4):
            terms = mix_terms(b, r)
            for c in range(4):
                srcs = [lane(SOUT, tb, tr, (c + rot) % 4) for (tb, tr, rot) in terms]
                dst = lane(STATE, b, r, c)
                key = KEYS + ((b * 4 + r) * 4 + c) * 2
                acc = None
                # consume sources three at a time into MIX scratch, last blit folds the key via the C channel
                while len(srcs) > 2:
                    a_, b_, c_ = srcs[0], srcs[1], srcs[2]
                    if acc is None:
                        blit(LF['XOR3'], a_, b_, c_, MIX, L)
                        acc = MIX
                        srcs = srcs[3:]
                    else:
                        blit(LF['XOR3'], acc, a_, b_, MIX + LANE if acc == MIX else MIX, L)
                        acc = MIX + LANE if acc == MIX else MIX
                        srcs = srcs[2:]
                if acc is None:
                    # <= 2 sources: A ^ B ^ key
                    key_blit(LF['XOR3'], srcs[0], srcs[1] if len(srcs) > 1 else srcs[0], key, dst) if len(srcs) == 2 else key_blit(LF['XOR3'] , srcs[0], None, key, dst)
                elif len(srcs) == 0:
                    key_blit(LF['XOR3'], acc, None, key, dst)       # acc ^ key: A ^ C with B unused -> use LF A^C
                elif len(srcs) == 1:
                    key_blit(LF['XOR3'], acc, srcs[0], key, dst)
                else:
                    blit(LF['XOR3'], acc, srcs[0], srcs[1], MIX + LANE if acc == MIX else MIX, L)
                    key_blit(LF['XOR3'], MIX + LANE if acc == MIX else MIX, None, key, dst)

def final_round():
    for b in range(8):
        for r in range(4):
            for c in range(4):
                key_blit(LF['XOR3'], lane(SOUT, b, r, (c + r) % 4), None, KEYS + ((b * 4 + r) * 4 + c) * 2, lane(STATE, b, r, c))

# fix the minterms for blits without B: A ^ C with B disabled -> 0x5A (independent of B)
def fix_b_unused():
    for i, e in enumerate(prog):
        con0, a, b, c, d, cmod, sz, fl = e
        if not (con0 & USEB) and (con0 & 0xff) == 0x96:
            prog[i] = ((con0 & ~0xff) | 0x5a, a, b, c, d, cmod, sz, fl)

sbox_round(); n_sbox = len(prog)
mix_round(); n_mix = len(prog) - n_sbox
final_round(); n_final = len(prog) - n_sbox - n_mix
fix_b_unused()

out = []
out.append('/* GENERATED by tools/blitaes/gen_blitaes.py %d - do not edit */' % L)
out.append('#define BA_L %d' % L)
out.append('#define BA_STATE %d\n#define BA_SOUT %d\n#define BA_TMP %d\n#define BA_MIX %d\n#define BA_KEYS %d\n#define BA_ARENA %d' % (STATE, SOUT, TMP, MIX, KEYS, ARENA))
out.append('#define BA_NSBOX %d\n#define BA_NMIX %d\n#define BA_NFINAL %d' % (n_sbox, n_mix, n_final))
out.append('typedef struct { uint16_t con0; uint32_t a, b, c, d; uint16_t cmod, size; uint16_t flags; } ba_blit;')
out.append('static const ba_blit ba_prog[%d] = {' % len(prog))
for e in prog:
    out.append('  { 0x%04x, %d, %d, %d, %d, 0x%04x, 0x%04x, %d },' % e)
out.append('};')
sys.stdout.write('\n'.join(out) + '\n')
sys.stderr.write('L=%d sbox %d mix %d final %d blits; temps %d; arena %d bytes\n' % (L, n_sbox, n_mix, n_final, nslots, ARENA))
