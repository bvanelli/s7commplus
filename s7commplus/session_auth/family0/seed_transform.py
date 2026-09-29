"""SeedTransform — generates the encrypted seed blob.

Uses Transform7 with random PRNG buffers, then chains
Monolith1.Loop -> Monolith2 (zero check) -> Monolith8 ->
Transform13 -> Monolith11 to produce the final 60-byte output.

Manual port of ``HarpoS7.Family0.Transforms.SeedTransform``. Transform7 runs
through the byte-equivalent ``transform7_compact`` module, and Monolith8 ->
Transform13 -> Monolith11 on decoded values through ``transform13_compact`` and
``monolith9_compact``; see their docstrings.
"""

from __future__ import annotations

import os
import struct

from ._generated import monolith1, monolith2
from . import monolith9_compact, transform7_compact, transform13_compact
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


def _check_sizes(destination: bytearray | memoryview, public_key: bytes) -> None:
    if len(destination) < DESTINATION_SIZE:
        raise ValueError(f"destination too small ({len(destination)}, need {DESTINATION_SIZE})")
    if len(public_key) < PUBLIC_KEY_LENGTH:
        raise ValueError(f"publicKey too small ({len(public_key)}, need {PUBLIC_KEY_LENGTH})")


def execute(destination: bytearray | memoryview, public_key: bytes, transform1: bytes) -> None:
    """SeedTransform over PreSeedTransform's encoded 60-byte output."""
    _check_sizes(destination, public_key)
    if len(transform1) < TRANSFORM1_SIZE:
        raise ValueError(f"transform1 too small ({len(transform1)}, need {TRANSFORM1_SIZE})")
    execute_value(destination, public_key, monolith9_compact.decode(transform1))


def execute_value(destination: bytearray | memoryview, public_key: bytes, pre_seed: int) -> None:
    """SeedTransform for PreSeedTransform's decoded 160-bit value."""
    _check_sizes(destination, public_key)

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

    # Monolith8 -> Transform13 -> Monolith11: Monolith11 decodes both encoded
    # inputs (their encoding offsets cancel) and XORs the values.
    seed = pre_seed ^ transform13_compact.execute_value(transform13_compact.span_value(t7_dst))
    destination[:0x14] = seed.to_bytes(0x14, "little")
