"""Hostile and benign image fixtures, built from bytes without an image library.

Used by `brandsentinel sandbox selftest media` and by tests. Building them needs
no decoder, so the host process never has to import Pillow to produce them.
"""

import struct
import zlib
from importlib import resources


def _chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def png_gray(width: int, height: int, pixel=lambda x, y: (x * 7 + y * 13) % 256) -> bytes:
    """An 8-bit grayscale PNG with a deterministic pattern."""
    rows = b"".join(
        b"\x00" + bytes(pixel(x, y) & 0xFF for x in range(width)) for y in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(rows, 9))
        + _chunk(b"IEND", b"")
    )


def bomb_png(side: int = 30000) -> bytes:
    """A decompression bomb: a side x side grayscale PNG of zeros. A 30000-pixel
    side decodes to about 900 MB and compresses to under 1 MB."""
    row = b"\x00" * (side + 1)
    z = zlib.compressobj(9)
    body = b"".join(z.compress(row) for _ in range(side)) + z.flush()
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", side, side, 8, 0, 0, 0, 0))
        + _chunk(b"IDAT", body)
        + _chunk(b"IEND", b"")
    )


def lying_header_png(width: int = 60000, height: int = 60000) -> bytes:
    """A tiny file whose header declares an enormous image."""
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 0, 0, 0, 0))
        + _chunk(b"IDAT", zlib.compress(b"\x00" * 64))
        + _chunk(b"IEND", b"")
    )


def html_named_png() -> bytes:
    """What a server returns for /logo.png when it is really a page."""
    return b"<!doctype html><html><body><script>alert(1)</script>logo</body></html>"


def gif_frames(frames: int, width: int = 4, height: int = 4) -> bytes:
    """An animated GIF with `frames` tiny frames."""
    out = bytearray(b"GIF89a" + struct.pack("<HHBBB", width, height, 0x80, 0, 0))
    out += b"\x00\x00\x00\xff\xff\xff"  # two-colour global table
    out += b"\x21\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00"  # loop forever
    pixels = width * height
    # LZW, code size 2: clear, `pixels` literal zeros, end. Codes are 3 bits.
    codes = [4] + [0] * pixels + [5]
    bits, nbits = 0, 0
    data = bytearray()
    for i, c in enumerate(codes):
        size = 3 if i < 4 else 4 if i < 12 else 5
        bits |= c << nbits
        nbits += size
        while nbits >= 8:
            data.append(bits & 0xFF)
            bits >>= 8
            nbits -= 8
    if nbits:
        data.append(bits & 0xFF)
    frame = (
        b"\x21\xf9\x04\x04\x02\x00\x00\x00"  # graphic control: 20 ms delay
        + b"\x2c"
        + struct.pack("<HHHHB", 0, 0, width, height, 0)
        + b"\x02"
        + bytes([len(data)])
        + bytes(data)
        + b"\x00"
    )
    out += frame * frames
    out += b"\x3b"
    return bytes(out)


def ico_entries(count: int) -> bytes:
    """An ICO header listing `count` 16x16 entries that share one PNG payload."""
    payload = png_gray(16, 16)
    offset = 6 + 16 * count
    head = struct.pack("<HHH", 0, 1, count)
    entries = b"".join(
        struct.pack("<BBBBHHII", 16, 16, 0, 0, 1, 32, len(payload), offset) for _ in range(count)
    )
    return head + entries + payload


def truncated(data: bytes, keep: float = 0.5) -> bytes:
    return data[: max(16, int(len(data) * keep))]


def packaged(name: str) -> bytes:
    """A fixture image shipped with the package (synthetic; see selftest/README)."""
    return (resources.files("brandsentinel.sandbox") / "selftest" / name).read_bytes()
