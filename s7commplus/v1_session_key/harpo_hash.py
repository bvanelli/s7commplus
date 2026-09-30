"""HarpoHash — GCM's GHASH multiplication, as used by HarpoAesCtr.

This is the GF(2^128) multiplication of AES-GCM (NIST SP 800-38D). Blocks are
16 bytes read big endian in GCM's reflected bit order: the most significant
bit of the first byte is the coefficient of x^0, so multiplying by x is a
right shift, reduced by ``0xE1 << 120`` when a bit falls off the end.

HarpoS7 computes the product with Shoup's 8-bit tables:

- ``lut1`` multiplies a block by x.
- ``generate_lookup_table`` builds the 4 KB table whose entry ``i`` is the
  byte ``i`` (as the first byte of a block) times the key ``H``.
- ``hash_block`` multiplies a block by ``H`` one byte at a time, from the
  last byte to the first: ``z = z * x^8 ^ table[byte]``, where ``z * x^8``
  shifts the byte that falls off back in through ``LUT_SEED``.

``LUT_SEED`` is that reduction table: entry ``i`` is the 16-bit reduction of
the byte ``i`` shifted out of the block, stored big endian. Tests pin all
three against a textbook GHASH multiply and HarpoS7's vectors.

Ported from HarpoS7 (MIT) — ``HarpoS7.Aes.HarpoHash`` and
``HarpoS7.Aes.AesConsts``.
"""

from __future__ import annotations

BLOCK_SIZE = 16
LOOKUP_TABLE_SIZE = 256 * BLOCK_SIZE

#: GCM's reduction constant: x^128 = 1 + x + x^2 + x^7 in reflected order.
_R = 0xE1 << 120


def _reduction(byte: int) -> int:
    """The 16 bits that reduce ``byte`` after it is shifted out of the low end of a block."""
    reduction = 0
    for bit in range(8):
        if byte >> bit & 1:
            reduction ^= 0xE100 >> (7 - bit)
    return reduction


_REDUCTION = tuple(_reduction(byte) for byte in range(256))

#: The 256 reductions as big-endian 16-bit values (HarpoS7's ``LutSeed``).
LUT_SEED = b"".join(value.to_bytes(2, "big") for value in _REDUCTION)


def _times_x(value: int) -> int:
    return value >> 1 ^ (_R if value & 1 else 0)


def _multiply(a: int, b: int) -> int:
    """``a * b`` in GCM's field, bit by bit from ``a``'s x^0 coefficient."""
    product = 0
    for bit in range(127, -1, -1):
        if a >> bit & 1:
            product ^= b
        b = _times_x(b)
    return product


def _check_length(name: str, value: bytes, length: int) -> None:
    if len(value) != length:
        raise ValueError(f"{name} must be {length} bytes, got {len(value)}")


def lut1(state: bytes) -> bytes:
    """``state * x`` for a 16-byte block (HarpoS7's ``Lut1``)."""
    _check_length("state", state, BLOCK_SIZE)
    return _times_x(int.from_bytes(state, "big")).to_bytes(BLOCK_SIZE, "big")


def generate_lookup_table(key: bytes) -> bytes:
    """The 4096-byte Shoup table for ``key``: entry ``i`` is ``(i << 120) * key``."""
    _check_length("key", key, BLOCK_SIZE)
    h = int.from_bytes(key, "big")
    return b"".join(_multiply(byte << 120, h).to_bytes(BLOCK_SIZE, "big") for byte in range(256))


def hash_block(data: bytes, lut: bytes) -> bytes:
    """``data * H`` for the ``H`` whose table is ``lut`` (HarpoS7's ``HarpoHash.Hash``)."""
    _check_length("data", data, BLOCK_SIZE)
    _check_length("lut", lut, LOOKUP_TABLE_SIZE)
    z = 0
    for byte in reversed(data):
        z = (z >> 8) ^ (_REDUCTION[z & 0xFF] << 112) ^ int.from_bytes(lut[byte * BLOCK_SIZE : (byte + 1) * BLOCK_SIZE], "big")
    return z.to_bytes(BLOCK_SIZE, "big")
