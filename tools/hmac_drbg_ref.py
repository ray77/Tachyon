#!/usr/bin/env python3
"""Independent HMAC_DRBG (SP 800-90A 10.1.2, SHA-256) written from the spec, used only
to produce cross-check vectors for crypto/ref/drbg.c. Output: tests/vectors/hmac_drbg.txt
with lines: seed_hex reseed_hex out1_hex out2_hex out3_hex (out3 after reseed), 64 bytes each."""
import hmac, hashlib, random

def H(k, data): return hmac.new(k, data, hashlib.sha256).digest()

class Drbg:
    def __init__(self, seed):
        self.K = b"\x00" * 32; self.V = b"\x01" * 32
        self.update(seed)
    def update(self, data):
        self.K = H(self.K, self.V + b"\x00" + data); self.V = H(self.K, self.V)
        if data:
            self.K = H(self.K, self.V + b"\x01" + data); self.V = H(self.K, self.V)
    def generate(self, n):
        out = b""
        while len(out) < n:
            self.V = H(self.K, self.V); out += self.V
        self.update(b"")
        return out[:n]

rng = random.Random(20261126)
lines = []
for t in range(40):
    seedlen = rng.choice([32, 36, 48, 64, 100])
    seed = bytes(rng.getrandbits(8) for _ in range(seedlen))
    reseed = bytes(rng.getrandbits(8) for _ in range(rng.choice([32, 36, 7])))
    d = Drbg(seed)
    o1 = d.generate(64); o2 = d.generate(64)
    d.update(reseed)         # reseed = update with seed material
    o3 = d.generate(64)
    lines.append(" ".join(x.hex() for x in (seed, reseed, o1, o2, o3)))
open("tests/vectors/hmac_drbg.txt", "w").write("\n".join(lines) + "\n")
print(len(lines), "vectors")
