#!/usr/bin/env python3
"""Turn a recorded loopback TLS session (tests/tls_test.c / tests/tls13_test.c 4th argument:
4-byte cert length, cert DER, 4-byte server length, server bytes, 64-byte DRBG seed) into a C header
for the Amiga replay in bench/x25519_bench.c.

    tools/gen_tls_vector.py tests/vectors/tls13_session.bin tv13 > bench/tls13_vector.h
"""
import struct, sys
path, prefix = sys.argv[1], sys.argv[2]
d = open(path, 'rb').read()
cl = struct.unpack('>I', d[:4])[0]; cert = d[4:4 + cl]; o = 4 + cl
sl = struct.unpack('>I', d[o:o + 4])[0]; srv = d[o + 4:o + 4 + sl]; seed = d[o + 4 + sl:o + 4 + sl + 64]
assert len(seed) == 64
def arr(name, b):
    out = f"static const uint8_t {name}[{len(b)}] = {{\n"
    for i in range(0, len(b), 16):
        out += "  " + ",".join(f"0x{x:02x}" for x in b[i:i + 16]) + ",\n"
    return out + "};\n"
print(f"/* GENERATED from {path} (loopback Go TLS server session, tools/gen_tls_vector.py) - do not edit */")
print(arr(prefix + "_cert", cert) + arr(prefix + "_server", srv) + arr(prefix + "_seed", seed), end="")
