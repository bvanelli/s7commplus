"""SeedTransform — generates the encrypted seed blob.

Uses Transform7 with random PRNG buffers, then chains
Monolith1.Loop -> Monolith2 (zero check) -> Monolith8 ->
Transform13 -> Monolith11 to produce the final 60-byte output.

Manual port of ``HarpoS7.Family0.Transforms.SeedTransform``. Transform7 and
Monolith11 run through the byte-equivalent ``transform7_compact`` and
``monolith11_compact`` modules, and Monolith8 -> Transform13 through
``transform13_compact``; see their docstrings.
"""

from __future__ import annotations

import os
import struct

from ._generated import monolith1, monolith2
from . import monolith11_compact, transform7_compact, transform13_compact
from ._generated.data import TRANSFORM7_DATA
from .pre_seed_transform import DESTINATION_SIZE as TRANSFORM1_SIZE

DESTINATION_SIZE = 0x3C
PUBLIC_KEY_LENGTH = 0x28


def _monolith1_loop(buf: bytearray) -> None:
    """Monolith1.Loop: execute until result is non-zero."""
    src = bytearray(buf[:0x48])
    result = monolith1.execute(buf, bytes(src))
    while result == 0:
        src[:0x48] = buf[:0x48]
        result = monolith1.execute(buf, bytes(src))


def execute(destination: bytearray | memoryview, public_key: bytes, transform1: bytes) -> None:
    if len(destination) < DESTINATION_SIZE:
        raise ValueError(f"destination too small ({len(destination)}, need {DESTINATION_SIZE})")
    if len(public_key) < PUBLIC_KEY_LENGTH:
        raise ValueError(f"publicKey too small ({len(public_key)}, need {PUBLIC_KEY_LENGTH})")
    if len(transform1) < TRANSFORM1_SIZE:
        raise ValueError(f"transform1 too small ({len(transform1)}, need {TRANSFORM1_SIZE})")

    prng1 = bytearray(os.urandom(0x14))
    prng2 = bytearray(0x14)
    t7_dst = bytearray(transform7_compact.DESTINATION_SIZE)
    work = bytearray(5 * 4)

    t7_loop = 0
    while t7_loop == 0:
        prng2 = bytearray(os.urandom(0x14))
        transform7_compact.execute(t7_dst, prng1, prng2, TRANSFORM7_DATA[0xD8:])

        _monolith1_loop(t7_dst)
        monolith2.execute(work, bytes(t7_dst))

        t7_loop = 0
        for d in struct.unpack("<5I", work):
            t7_loop |= d

    destination[0x14:0x28] = work[:0x14]
    destination[0x28:0x3C] = prng1[:0x14]

    transform7_compact.execute(t7_dst, prng1, prng2, public_key)
    _monolith1_loop(t7_dst)

    # Monolith8 -> Transform13 -> Monolith11: Monolith11 XORs its decode of
    # transform1 with Transform13's PRESENT-80 output under the span's value.
    mask = transform13_compact.mask(transform13_compact.span_value(t7_dst))
    decoded = monolith11_compact.execute_words(struct.unpack("<15I", transform1[:0x3C]) + (0,) * 15)
    destination[:0x14] = struct.pack("<5I", *(word ^ ((mask >> (32 * index)) & 0xFFFFFFFF) for index, word in enumerate(decoded)))
