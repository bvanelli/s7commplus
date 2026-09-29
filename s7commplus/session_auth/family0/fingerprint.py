"""HarpoFingerprint — challenge fingerprinting for session key derivation.

Produces an 8-byte fingerprint from a PLC challenge. Used by
DeriveSessionKey to build the HMAC-SHA256 input that yields the
24-byte session key.

Derived from ``HarpoS7.Fingerprint.HarpoFingerprint`` and
``HarpoS7.Fingerprint.ContextMutator``. The fingerprint is a fixed network of
496 nibble gates over a 544-nibble state:

- nibbles 0..31 hold ``challenge[2:18]``, high nibble first; the rest start
  at zero;
- each gate overwrites one nibble ``dst`` with ``table[state[a] << 4 | state[b]]``;
- the fingerprint is 16 nibbles of the final state.

HarpoS7 computes each gate's output from a FP_DATA2 nibble XOR a nibble of a
47-word context that ContextMutator changes between the 20 rounds. That
context never depends on the challenge, so ``_gates`` evaluates the same
formulas once for all 256 inputs of every gate. Every gate reads all bits of
both inputs and is balanced; no XOR- or addition-separable table was found,
so the network looks like white-box encodings of an unidentified primitive.
"""

from __future__ import annotations

import functools
import struct

from ._generated.data import FP_DATA1, FP_DATA2
from ._generated.data._constants import (
    FP_BIG_CONTEXT_INIT_INTS,
    FP_MUTATIONS,
    FP_XOR_MAGIC_INTS,
)

FINGERPRINT_LENGTH = 8
_STATE_NIBBLES = 544
_STEP_BYTES = 0x80  # FP_DATA2 bytes each gate reads its table from
_U32 = 0xFFFFFFFF

# Final-state nibbles that form the fingerprint, most significant first.
_OUTPUT = (187, 448, 378, 107, 239, 173, 166, 66, 458, 117, 138, 331, 126, 178, 344, 495)

_OP = {"+": int.__add__, "*": int.__mul__, "^": int.__xor__}

Gate = tuple[int, int, int, bytes]


def _load_collection(data: bytes) -> list[bytes]:
    lengths = struct.unpack("<20I", data[:80])
    offset = 80
    result = []
    for length in lengths:
        result.append(data[offset : offset + length * 2])
        offset += length * 2
    return result


def _gate_table(data: bytes, context: list[int], xor_magic: int, step: int) -> bytes:
    """The 256-entry table of one gate, indexed by ``a << 4 | b``."""
    block = data[step * _STEP_BYTES : (step + 1) * _STEP_BYTES]
    table = bytearray(256)
    for ab in range(256):
        b = ab & 0xF
        data_byte = block[ab >> 1]
        data_nibble = data_byte >> 4 if b & 1 == 0 else data_byte & 0xF
        word = context[((ab >> 3) + step * (_STEP_BYTES >> 2)) % len(context)] ^ xor_magic
        table[ab] = data_nibble ^ ((word >> (4 * (7 - (b & 7)))) & 0xF)
    return bytes(table)


@functools.cache
def _gates() -> tuple[Gate, ...]:
    """Every gate as ``(a, b, dst, table)`` in execution order."""
    context = list(FP_BIG_CONTEXT_INIT_INTS)
    gates = []
    for round_index, (wiring, data) in enumerate(zip(_load_collection(FP_DATA1), _load_collection(FP_DATA2))):
        wires = struct.unpack(f"<{len(wiring) // 2}H", wiring)
        for step in range(len(wires) // 3):
            a, b, dst = wires[3 * step : 3 * step + 3]
            gates.append((a, b, dst, _gate_table(data, context, FP_XOR_MAGIC_INTS[round_index], step)))
        for index, op, value in FP_MUTATIONS[round_index]:
            context[index] = _OP[op](context[index], value) & _U32
    return tuple(gates)


def fingerprint_challenge(destination: bytearray, challenge: bytes) -> None:
    if len(destination) < FINGERPRINT_LENGTH:
        raise ValueError("destination must be at least 8 bytes")
    if len(challenge) < 18:
        raise ValueError("challenge must be at least 18 bytes")

    state = [0] * _STATE_NIBBLES
    for index, byte in enumerate(challenge[2:18]):
        state[2 * index], state[2 * index + 1] = byte >> 4, byte & 0xF
    for a, b, dst, table in _gates():
        state[dst] = table[state[a] << 4 | state[b]]
    for index in range(FINGERPRINT_LENGTH):
        destination[index] = state[_OUTPUT[2 * index]] << 4 | state[_OUTPUT[2 * index + 1]]
