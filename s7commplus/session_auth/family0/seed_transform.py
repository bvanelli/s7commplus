"""SeedTransform — generates the encrypted seed blob.

SeedTransform is an ECDH on the curve in ``curve.py``: a random scalar ``k``
gives the ephemeral ``x(k*G)`` that goes into the blob, and the shared
``x(k*public_key)`` keys Transform13, whose output masks the pre-seed.

Manual port of ``HarpoS7.Family0.Transforms.SeedTransform``. The original
chain (Transform7 -> Monolith1.Loop -> Monolith2 zero check, then Monolith8 ->
Transform13 -> Monolith11) is kept as ``reference_execute_value``: Monolith2
serializes the span's decoded value, Monolith1 only re-randomizes its
encoding, and Monolith8/Transform13/Monolith11 consume the decoded value, so
the runtime needs only the value that Transform7 decodes to. The two differ
only where Transform7's compatibility arithmetic is not modular, which
requires a field value below 47 at a subtraction and is not expected for
random scalars; see ``curve.py``.
"""

from __future__ import annotations

import os
import struct

from ._generated import monolith1, monolith2
from . import curve, monolith9_compact, transform7_compact, transform13_compact
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

    prng1 = os.urandom(0x14)  # Only blinds Transform7's encoding; still sent in the blob.
    ephemeral = 0
    while ephemeral == 0:
        scalar = curve.ladder_scalar(os.urandom(0x14))
        ephemeral = curve.x_multiply(scalar, curve.GENERATOR_X)
    shared = curve.x_multiply(scalar, int.from_bytes(public_key[:0x14], "little"))

    seed = pre_seed ^ transform13_compact.execute_value(shared)
    destination[:0x14] = seed.to_bytes(0x14, "little")
    destination[0x14:0x28] = ephemeral.to_bytes(0x14, "little")
    destination[0x28:0x3C] = prng1


def reference_execute_value(destination: bytearray | memoryview, public_key: bytes, pre_seed: int) -> None:
    """``execute_value`` through the original Transform7/Monolith1/Monolith2 chain; kept for analysis."""
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
