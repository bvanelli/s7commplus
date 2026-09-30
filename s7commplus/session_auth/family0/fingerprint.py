"""HarpoFingerprint — challenge fingerprinting for session key derivation.

Produces an 8-byte fingerprint from a PLC challenge. Used by
DeriveSessionKey to build the HMAC-SHA256 input that yields the
24-byte session key.

The fingerprint is a fixed network of 496 nibble gates over a 544-nibble
state:

- nibbles 0..31 hold ``challenge[2:18]``, high nibble first; the rest start
  at zero;
- each gate overwrites one nibble ``dst`` with ``table[state[a] << 4 | state[b]]``;
- the fingerprint is 16 nibbles of the final state.

``fingerprint_gates.bin`` holds the network: per gate, ``a``, ``b`` and
``dst`` as little-endian uint16, then the 256 table nibbles packed two per
byte, high nibble first. It is derived from HarpoS7's
``HarpoS7.Fingerprint.HarpoFingerprint`` and ``ContextMutator`` tables by
``tools/build_fingerprint_gates.py``; the port and the tables are kept in
``old/family0`` in the repository. Every gate reads all bits of both inputs
and is balanced, and no XOR- or addition-separable table was found, so the
network looks like white-box encodings of an unidentified primitive.
"""

from __future__ import annotations

import functools
import struct
from importlib.resources import files

FINGERPRINT_LENGTH = 8
_STATE_NIBBLES = 544
_GATE = struct.Struct("<3H128s")

# Final-state nibbles that form the fingerprint, most significant first.
_OUTPUT = (187, 448, 378, 107, 239, 173, 166, 66, 458, 117, 138, 331, 126, 178, 344, 495)

Gate = tuple[int, int, int, bytes]


def _parse_gates(data: bytes) -> tuple[Gate, ...]:
    """Every gate in ``fingerprint_gates.bin`` as ``(a, b, dst, table)``, in execution order."""
    if not data or len(data) % _GATE.size:
        raise ValueError("fingerprint gate data is empty or truncated")
    gates = []
    for a, b, dst, packed in _GATE.iter_unpack(data):
        if max(a, b, dst) >= _STATE_NIBBLES:
            raise ValueError("fingerprint gate index out of range")
        gates.append((a, b, dst, bytes(nibble for byte in packed for nibble in (byte >> 4, byte & 0xF))))
    return tuple(gates)


@functools.cache
def _gates() -> tuple[Gate, ...]:
    return _parse_gates(files("s7commplus.session_auth.family0").joinpath("fingerprint_gates.bin").read_bytes())


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
