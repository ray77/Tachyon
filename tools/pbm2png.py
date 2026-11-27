#!/usr/bin/env python3
"""Converts the binary PBM (P4) that tests/wa_probe.c writes for each QR code (build/wa_qr.pbm) into a PNG, scaled up,
so the code can be viewed or sent as an image. Pure Python (zlib only): pbm2png.py in.pbm out.png [scale]"""
import struct
import sys
import zlib


def read_pbm(path):
    data = open(path, "rb").read()
    tokens, pos = [], 0
    while len(tokens) < 3:
        while data[pos:pos + 1].isspace():
            pos += 1
        if data[pos:pos + 1] == b"#":
            while data[pos:pos + 1] not in (b"\n", b""):
                pos += 1
            continue
        start = pos
        while not data[pos:pos + 1].isspace():
            pos += 1
        tokens.append(data[start:pos])
    pos += 1
    if tokens[0] != b"P4":
        raise SystemExit("not a P4 PBM")
    w, h = int(tokens[1]), int(tokens[2])
    stride = (w + 7) // 8
    rows = [data[pos + y * stride: pos + (y + 1) * stride] for y in range(h)]
    return w, h, rows


def write_png(path, w, h, rows, scale):
    raw = bytearray()
    for row in rows:
        line = bytearray()
        for x in range(w):
            dark = (row[x >> 3] >> (7 - (x & 7))) & 1
            line += bytes([0 if dark else 255]) * scale
        for _ in range(scale):
            raw += b"\x00" + line
    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xffffffff)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w * scale, h * scale, 8, 0, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
    open(path, "wb").write(png)


if __name__ == "__main__":
    w, h, rows = read_pbm(sys.argv[1])
    write_png(sys.argv[2], w, h, rows, int(sys.argv[3]) if len(sys.argv) > 3 else 8)
