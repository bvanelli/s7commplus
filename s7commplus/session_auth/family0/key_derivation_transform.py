"""KeyDerivationTransform — derives three 128-bit keys from the pre-seed.

Calls Monolith10 to build a work buffer, then iterates Monolith9 six
times with SharedData entries to produce 12 uint32s (3 × 16-byte keys:
challenge encryption key, checksum encryption key, LUT seed).

Manual port of ``HarpoS7.Family0.Transforms.KeyDerivationTransform``,
retained as the reference. The runtime uses ``execute_value``: Monolith10 keys
the first three Monolith9 calls with the low 80 bits of the decoded source and
the last three with the high 80 bits. The postfix words are each block's tag,
so Monolith9 emits the plain ciphertext (see ``monolith9_compact``).
"""

from __future__ import annotations

import struct

from . import monolith9_compact
from ._generated import monolith9, monolith10
from ._generated.data import SHARED_DATA

SOURCE_SIZE = 0x3C
DESTINATION_SIZE = 0x30

# SHARED_DATA words 0..11 as six little-endian 64-bit plaintext blocks.
_SHARED = struct.unpack_from("<12I", SHARED_DATA)
PLAINTEXTS = tuple(_SHARED[2 * block] | _SHARED[2 * block + 1] << 32 for block in range(6))


def execute(destination: bytearray, source: bytes) -> None:
    if len(destination) < DESTINATION_SIZE:
        raise ValueError(f"destination too small ({len(destination)}, need {DESTINATION_SIZE})")
    if len(source) < SOURCE_SIZE:
        raise ValueError(f"source too small ({len(source)}, need {SOURCE_SIZE})")

    shared = struct.unpack("<36I", SHARED_DATA)

    buf1 = bytearray(0x18 * 4)
    buf1_dwords = list(struct.unpack(f"<{len(buf1) // 4}I", buf1))
    buf1_dwords[0] = 0xFFFFFFFF
    buf1_dwords[1] = 0xFFFFFFFF
    buf1_dwords[2] = 0x0000FFFF
    struct.pack_into(f"<{len(buf1_dwords)}I", buf1, 0, *buf1_dwords)

    buf1[3 * 4 : 3 * 4 + SOURCE_SIZE] = source[:SOURCE_SIZE]

    buf2 = bytearray(0xC5 * 4)
    monolith10.execute(buf2, bytes(buf1))

    m9_dst = bytearray(24)
    dst_dwords_out = [0] * (DESTINATION_SIZE // 4)

    for i in range(6):
        struct.pack_into("<II", buf2, 0xC0 * 4, shared[i * 2], shared[i * 2 + 1])
        struct.pack_into("<III", buf2, 0xC2 * 4, shared[0x12 + i * 3], shared[0x12 + i * 3 + 1], shared[0x12 + i * 3 + 2])

        monolith9.execute(m9_dst, bytes(buf2))

        m9_dwords = struct.unpack("<6I", m9_dst)
        dst_dwords_out[i * 2] = m9_dwords[0]
        dst_dwords_out[i * 2 + 1] = m9_dwords[1]

        if i == 2:
            buf1_dwords = list(struct.unpack(f"<{len(buf1) // 4}I", buf1))
            buf1_dwords[0] = 0
            buf1_dwords[1] = 0
            buf1_dwords[2] = 0
            struct.pack_into(f"<{len(buf1_dwords)}I", buf1, 0, *buf1_dwords)
            monolith10.execute(buf2, bytes(buf1))

    struct.pack_into(f"<{len(dst_dwords_out)}I", destination, 0, *dst_dwords_out)


def execute_value(pre_seed: int) -> bytes:
    """The 48 bytes ``execute`` derives from PreSeedTransform's decoded 160-bit value."""
    low, high = monolith9_compact.key_halves(pre_seed)
    return struct.pack(
        "<6Q", *(monolith9_compact.encrypt(block, low if index < 3 else high) for index, block in enumerate(PLAINTEXTS))
    )
