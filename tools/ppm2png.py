#!/usr/bin/env python3
"""Converts a binary PPM (P6) that ui/screen_host.c wrote into a PNG, optionally scaling: ppm2png.py in.ppm out.png
[xscale yscale]. Default 1 2: a PAL hires pixel is about half as wide as high, so doubling the rows gives the picture
the monitor shows (640x512). Pure Python (zlib only)."""
import struct
import sys
import zlib


def read_ppm(path):
    data = open(path, "rb").read()
    tokens, pos = [], 0
    while len(tokens) < 4:
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
    if tokens[0] != b"P6":
        raise SystemExit("not a P6 PPM")
    w, h = int(tokens[1]), int(tokens[2])
    return w, h, data[pos:pos + w * h * 3]


def write_png(path, w, h, rgb, sx, sy):
    raw = bytearray()
    for y in range(h):
        row = rgb[y * w * 3:(y + 1) * w * 3]
        if sx > 1:
            row = b"".join(row[i:i + 3] * sx for i in range(0, len(row), 3))
        for _ in range(sy):
            raw += b"\x00" + row

    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xffffffff)
    png = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w * sx, h * sy, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b"")
    open(path, "wb").write(png)


if __name__ == "__main__":
    w, h, rgb = read_ppm(sys.argv[1])
    sx = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    sy = int(sys.argv[4]) if len(sys.argv) > 4 else 2
    write_png(sys.argv[2], w, h, rgb, sx, sy)
