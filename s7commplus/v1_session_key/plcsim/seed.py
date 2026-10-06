"""The encrypted seed of the PLCSIM blob: ECIES over NIST P-256.

The 96-byte seed is the client's ephemeral public point ``k*G`` (big-endian
``x || y``, 64 bytes) followed by the 16-byte challenge key encrypted with
AES-GCM (24-bit counter) under a key and IV derived from the ECDH shared
secret ``x(k*PK)``, and that encryption's 16-byte tag.

Ported from ``HarpoS7.Seed.HarpoSeedUtilities.GenerateEncryptedSeed`` (MIT),
which implements the same arithmetic with its own big-integer code.
"""

from __future__ import annotations

import secrets

from cryptography.hazmat.primitives.asymmetric import ec

from ..aes_gcm import AesGcm24
from ..key_derivation import derive_seed_encryption_key_and_iv

PUBLIC_KEY_LENGTH = 64
CHALLENGE_KEY_LENGTH = 16
SEED_LENGTH = 96

_CURVE = ec.SECP256R1()
#: Order of P-256's base point; a valid ephemeral scalar is in ``1..ORDER-1``.
ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def encrypt_seed(public_key: bytes, challenge_key: bytes, scalar: int | None = None) -> bytes:
    """Build the 96-byte seed for ``challenge_key`` under the PLC's family-03 ``public_key``.

    Args:
        public_key: 64-byte P-256 point, big-endian ``x || y``.
        challenge_key: 16-byte AES key that later encrypts the challenge.
        scalar: Ephemeral private scalar. Random unless given (for tests).

    Raises:
        ValueError: For a wrong-sized key, a point that is not on the curve, or a
            scalar outside ``1..ORDER-1``.
    """
    if len(public_key) != PUBLIC_KEY_LENGTH:
        raise ValueError(f"public_key must be {PUBLIC_KEY_LENGTH} bytes, got {len(public_key)}")
    if len(challenge_key) != CHALLENGE_KEY_LENGTH:
        raise ValueError(f"challenge_key must be {CHALLENGE_KEY_LENGTH} bytes, got {len(challenge_key)}")
    if scalar is None:
        scalar = secrets.randbelow(ORDER - 1) + 1
    elif not 0 < scalar < ORDER:
        raise ValueError("scalar must be in 1..ORDER-1")

    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(public_key[:32], "big"), int.from_bytes(public_key[32:], "big"), _CURVE
    )
    peer = numbers.public_key()  # raises ValueError if the point is not on the curve

    ephemeral = ec.derive_private_key(scalar, _CURVE)
    point = ephemeral.public_key().public_numbers()
    ephemeral_xy = point.x.to_bytes(32, "big") + point.y.to_bytes(32, "big")
    shared_x = ephemeral.exchange(ec.ECDH(), peer)

    # HarpoS7 hands the shared x to the KDF little-endian; the KDF reverses it back.
    key_iv = derive_seed_encryption_key_and_iv(shared_x[::-1], ephemeral_xy)
    gcm = AesGcm24(key_iv[:16])
    gcm.start(key_iv[32:48])
    return ephemeral_xy + gcm.encrypt(challenge_key) + gcm.tag()
