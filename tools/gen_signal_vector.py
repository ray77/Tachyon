#!/usr/bin/env python3
"""Turn the libsignal vectors (tools/signalvectors -> tests/vectors/signal_vectors.txt, name=hex) into a C header
for the Amiga vector runner in bench/x25519_bench.c (Signal section: X3DH both roles, Double Ratchet on the 68000).

    tools/gen_signal_vector.py tests/vectors/signal_vectors.txt > bench/signal_vector.h
"""
import sys
path = sys.argv[1]
want = ["alice_ident_priv", "alice_ident_pub", "alice_spk_priv", "alice_spk_pub", "alice_opk_priv", "alice_opk_pub",
        "bob_ident_pub", "bob_spk_pub", "bob_spk_sig", "bob_opk_pub",
        "s1_alice_base_priv", "s1_alice_ratchet1_priv", "s1_pkmsg1_pt", "s1_pkmsg1",
        "s2_pkmsg1", "s2_pkmsg1_pt", "s2_alice1_ratchet_priv", "s2_msg1", "s2_msg1_pt", "s2_msg2", "s2_msg2_pt",
        "wa_pkmsg1", "wa_pkmsg1_pt", "wa_msg2", "wa_msg2_pt"]
vals = {}
for line in open(path):
    line = line.strip()
    if "=" not in line or line.startswith("#"):
        continue
    k, v = line.split("=", 1)
    if k in want:
        vals[k] = bytes.fromhex(v)
missing = [k for k in want if k not in vals]
if missing:
    sys.exit("missing vectors: " + " ".join(missing))
def arr(name, b):
    out = f"#define SV_{name.upper()}_LEN {len(b)}\nstatic const uint8_t sv_{name}[{len(b)}] = {{\n"
    for i in range(0, len(b), 16):
        out += "  " + ",".join(f"0x{x:02x}" for x in b[i:i + 16]) + ",\n"
    return out + "};\n"
print(f"/* GENERATED from {path} (libsignal oracle tools/signalvectors, tools/gen_signal_vector.py) - do not edit */")
for k in want:
    print(arr(k, vals[k]), end="")
