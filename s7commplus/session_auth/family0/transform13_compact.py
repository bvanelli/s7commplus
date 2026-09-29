"""Monolith8 -> Transform13 -> Monolith11 (second half) as plain arithmetic.

``seed_transform`` used to decode the Transform7 span with Monolith8, feed the
result through Transform13 (Monolith10 key schedule + Monolith9 block cipher,
three times) and XOR Monolith11's decode of that into its output. Recovery for
issue #55 showed that the whole chain computes:

* ``X = span_value(span)``: the span's 169 bits are local three-input gates
  over its eighteen words, read as ``2*payload + boundary`` modulo 2^160 - 47
  (the same decoder as ``tools/recover_monolith4_span_identity.py``);
* three PRESENT-80 encryptions of fixed ``SHARED_DATA`` blocks, under the low
  and high 80 bits of ``X``, with a slightly non-standard key schedule
  (``round_keys``);
* each ciphertext XOR ``OUTPUT_OFFSET``, concatenated and truncated to 160 bits.

The generated ``monolith8``/``monolith9``/``monolith10`` and ``transform13``
modules are kept as references and pinned against this model by tests.
"""

from __future__ import annotations

import struct

from ._generated.data import SHARED_DATA

MODULUS = (1 << 160) - 47
OUTPUT_OFFSET = 0x1D9AEB51CF334EA5
KEY_OFFSET = 0x87CA995217BA31853DCE
FIRST_ROUND_KEY_OFFSET = 0x0000081000000000
_KEY_MASK = (1 << 80) - 1
_BLOCK_MASK = (1 << 64) - 1

SBOX = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)

# Plaintext blocks: SHARED_DATA words 12..17 as three little-endian 64-bit values.
_SHARED = struct.unpack_from("<18I", SHARED_DATA)
PLAINTEXTS = tuple(_SHARED[2 * block] | _SHARED[2 * block + 1] << 32 for block in (6, 7, 8))


def _p_layer_bit(bit: int) -> int:
    return 63 if bit == 63 else 16 * bit % 63


# S-box layer followed by the P-layer, one table per state byte.
_SP_TABLES = tuple(
    tuple(
        sum((((SBOX[value >> 4] << 4 | SBOX[value & 15]) >> bit) & 1) << _p_layer_bit(8 * byte + bit) for bit in range(8))
        for value in range(256)
    )
    for byte in range(8)
)


def _update(register: int, counter: int) -> int:
    """The PRESENT-80 key-register update: rotate left 61, S-box the top nibble, add the round counter."""
    register = ((register << 61) | (register >> 19)) & _KEY_MASK
    return ((SBOX[register >> 76] << 76) | (register & ((1 << 76) - 1))) ^ (counter << 15)


def round_keys(key: int) -> list[int]:
    """The 32 round keys Monolith10 lays out for an 80-bit key register.

    Unlike standard PRESENT, round key 0 is taken from ``key`` itself, the
    rest of the schedule runs on ``key ^ KEY_OFFSET``, and bit 6 is flipped
    after the second update.
    """
    keys = [(key >> 16) ^ FIRST_ROUND_KEY_OFFSET]
    register = _update(key ^ KEY_OFFSET, 1)
    for counter in range(1, 32):
        keys.append(register >> 16)
        register = _update(register, counter + 1) ^ (0x40 if counter == 1 else 0)
    return keys


def _byte_reverse(value: int) -> int:
    return int.from_bytes(value.to_bytes(8, "little"), "big")


def present_rounds(state: int, keys: list[int]) -> int:
    """PRESENT's 31 S-box/P-layer rounds and final key addition, in the specification's bit order."""
    for round_key in keys[:-1]:
        state ^= round_key
        state = (
            _SP_TABLES[0][state & 0xFF]
            | _SP_TABLES[1][(state >> 8) & 0xFF]
            | _SP_TABLES[2][(state >> 16) & 0xFF]
            | _SP_TABLES[3][(state >> 24) & 0xFF]
            | _SP_TABLES[4][(state >> 32) & 0xFF]
            | _SP_TABLES[5][(state >> 40) & 0xFF]
            | _SP_TABLES[6][(state >> 48) & 0xFF]
            | _SP_TABLES[7][state >> 56]
        )
    return state ^ keys[-1]


def encrypt(block: int, key: int) -> int:
    """Monolith9: PRESENT rounds on the byte-reversed little-endian block, under ``round_keys(key)``."""
    return _byte_reverse(present_rounds(_byte_reverse(block), round_keys(key)))


def key_register(half: int) -> int:
    """Read an 80-bit half of ``X`` (little-endian bytes) as the big-endian key register."""
    return int.from_bytes(half.to_bytes(10, "little"), "big")


def mask(value: int) -> int:
    """Transform13's contribution to Monolith11's output for decoded span value ``X``."""
    low, high = key_register(value & _KEY_MASK), key_register(value >> 80)
    blocks = (encrypt(PLAINTEXTS[0], low), encrypt(PLAINTEXTS[1], low), encrypt(PLAINTEXTS[2], high))
    return sum((block ^ OUTPUT_OFFSET) << (64 * index) for index, block in enumerate(blocks)) & ((1 << 160) - 1)


def _lanes(*chunks: int) -> int:
    return sum(chunk << (32 * index) for index, chunk in enumerate(chunks))


# Span decoder masks, one 32-bit chunk per span word triple. Bit 0 is the
# boundary bit; bit i > 0 is payload bit i - 1. Each bit XORs its three inputs
# with _INVERT, applies majority or a choose(if_set, if_clear, selector) gate,
# then XORs _COMPLEMENT.
_INVERT = (
    _lanes(0x12808400, 0x10001E81, 0x88E40900, 0x8402CA04, 0xD0801200, 0x000000A0),
    _lanes(0x80002008, 0x84A20104, 0x00029002, 0x40050001, 0x000000C4, 0x00000002),
    _lanes(0x204040E2, 0x001CC02A, 0x501802D0, 0x00000050, 0x0409A912, 0x00000044),
)
_COMPLEMENT = _lanes(0x7132053E, 0xE45F9611, 0x67E35E21, 0xE216DB50, 0x951F183E, 0x00000017)
_MAJORITY = _lanes(0xD8C44282, 0x80B71907, 0x33188111, 0xE80580CB, 0x9C0A189B, 0x00000062)
# (if_set, if_clear, selector) word within the triple -> bits using that choose gate.
_CHOOSE = (
    ((0, 1, 2), _lanes(0x02208001, 0x00000000, 0x00A50800, 0x04125000, 0x41600600, 0x00000010)),
    ((0, 2, 1), _lanes(0x00010500, 0x18000680, 0x88404020, 0x00602E04, 0x00900000, 0x00000081)),
    ((1, 0, 2), _lanes(0x00003008, 0x24400000, 0x04021002, 0x01000000, 0x00004044, 0x00000100)),
    ((1, 2, 0), _lanes(0x04020000, 0x42002040, 0x00000004, 0x00800000, 0x20000000, 0x00000008)),
    ((2, 0, 1), _lanes(0x21100050, 0x0000C038, 0x00002408, 0x10000100, 0x00010020, 0x00000004)),
    ((2, 1, 0), _lanes(0x00080824, 0x01080000, 0x400002C0, 0x02080030, 0x0204A100, 0x00000000)),
)


def span_value(span: bytes | bytearray | memoryview) -> int:
    """Decode the 72-byte Transform7/Monolith1 span to ``X``, the value Monolith8 re-encodes."""
    if len(span) < 72:
        raise ValueError(f"span too small ({len(span)}, need 72)")
    words = struct.unpack("<18I", bytes(span[:72]))
    inputs = [_lanes(*words[member::3]) ^ _INVERT[member] for member in range(3)]
    a, b, c = inputs
    bits = ((a & b) | (a & c) | (b & c)) & _MAJORITY
    for (if_set, if_clear, selector), selected in _CHOOSE:
        choice = inputs[if_clear] ^ ((inputs[if_set] ^ inputs[if_clear]) & inputs[selector])
        bits |= choice & selected
    return (bits ^ _COMPLEMENT) % MODULUS
