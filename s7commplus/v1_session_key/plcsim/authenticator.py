"""Builds the 216-byte SecurityKeyEncryptedKey blob for PLCSIM (key family 03).

Layout: 48 metadata, 96 encrypted seed, 16 IV, 16 encrypted challenge
(``challenge[2:18]``), 24 encrypted ``key1`` and a 16-byte tag. The challenge and
``key1`` are encrypted with AES-GCM (24-bit counter) under the key derived from
``key2``, and the session key is derived from ``key1``.

Ported from ``HarpoS7.Auth.LegacyAuthenticationScheme.AuthenticatePlcSim`` (MIT).
"""

from __future__ import annotations

import os

from ..aes_gcm import AesGcm24
from ..blob_metadata import ENCRYPTED_BLOB_LENGTH_PLCSIM, write_metadata
from ..key_derivation import derive_challenge_encryption_key, derive_session_key
from ..keys import KeyFamily
from .seed import SEED_LENGTH, encrypt_seed


def authenticate(
    challenge: bytes,
    public_key: bytes,
    *,
    key1: bytes | None = None,
    key2: bytes | None = None,
    iv: bytes | None = None,
    scalar: int | None = None,
) -> tuple[bytes, bytes]:
    """Build the blob and derive the session key.

    The keyword arguments replace the random values, in the order HarpoS7
    draws them (``key1``, ``key2``, ``iv``, then the seed scalar), so tests
    can be deterministic.

    Args:
        challenge: At least 18 bytes of the PLC challenge from CreateObject.
        public_key: 64-byte family-03 public key.

    Returns:
        ``(blob, session_key)``: the 216-byte blob and the 24-byte key.
    """
    if len(challenge) < 18:
        raise ValueError(f"challenge must be at least 18 bytes, got {len(challenge)}")
    key1 = os.urandom(24) if key1 is None else key1
    key2 = os.urandom(24) if key2 is None else key2
    iv = os.urandom(16) if iv is None else iv
    if len(key1) != 24 or len(key2) != 24 or len(iv) != 16:
        raise ValueError("key1 and key2 must be 24 bytes and iv 16 bytes")

    challenge_key = derive_challenge_encryption_key(key2)

    blob = bytearray(ENCRYPTED_BLOB_LENGTH_PLCSIM)
    offset = write_metadata(blob, public_key, key1, KeyFamily.PLCSIM)
    blob[offset : offset + SEED_LENGTH] = encrypt_seed(public_key, challenge_key, scalar)
    offset += SEED_LENGTH

    blob[offset : offset + 16] = iv
    offset += 16
    gcm = AesGcm24(challenge_key)
    gcm.start(iv)
    encrypted = gcm.encrypt(challenge[2:18]) + gcm.encrypt(key1)
    blob[offset : offset + len(encrypted)] = encrypted
    offset += len(encrypted)
    blob[offset : offset + 16] = gcm.tag()

    return bytes(blob), derive_session_key(key1, challenge)
