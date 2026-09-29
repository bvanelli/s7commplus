"""Transform13 and the Monolith8 span decoding it consumes, on plain integers.

SeedTransform used to re-encode the Transform7 span with Monolith8 and pass it
through Transform13 (Monolith10 plus three Monolith9 calls). Recovery for issue
#55 showed that the chain computes:

* ``X = span_value(span)``: the span's 169 bits are local three-input gates
  over its eighteen words, read as ``2*payload + boundary`` modulo 2^160 - 47
  (the same decoder as ``tools/recover_monolith4_span_identity.py``);
* ``execute_value(X)``: three encryptions (``monolith9_compact``) of fixed
  ``SHARED_DATA`` blocks, under the low 80 bits of ``X`` for the first two and
  the high 80 bits for the third, concatenated and truncated to 160 bits.

The generated ``monolith8`` and the handwritten ``transform13`` port are kept as
references and pinned against this model by tests.
"""

from __future__ import annotations

import struct

from . import monolith9_compact
from ._generated.data import SHARED_DATA

MODULUS = (1 << 160) - 47

# Plaintext blocks: SHARED_DATA words 12..17 as three little-endian 64-bit values.
_SHARED = struct.unpack_from("<18I", SHARED_DATA)
PLAINTEXTS = tuple(_SHARED[2 * block] | _SHARED[2 * block + 1] << 32 for block in (6, 7, 8))


def execute_value(value: int) -> int:
    """The 160-bit value Transform13 encodes for decoded input ``value``."""
    low, high = monolith9_compact.key_halves(value)
    return monolith9_compact.encrypt_blocks(PLAINTEXTS, (low, low, high))


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
