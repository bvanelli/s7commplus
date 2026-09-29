"""The PRESENT-80 model of Monolith8 -> Transform13 -> Monolith11 matches the generated chain."""

from __future__ import annotations

import os
import random
import struct
from unittest import mock

import pytest

from s7commplus.session_auth.family0 import (
    monolith11_compact,
    seed_transform,
    transform7_compact,
    transform13,
    transform13_compact,
)
from s7commplus.session_auth.family0._generated import monolith2, monolith8
from s7commplus.session_auth.family0._generated.data import TRANSFORM7_DATA
from tools.recover_monolith4_span_identity import normalized_terms
from tools.recover_monolith5_span_decoder import local_gate


def _standard_round_keys(key: int) -> list[int]:
    keys = []
    for counter in range(1, 33):
        keys.append(key >> 16)
        key = ((key << 61) | (key >> 19)) & ((1 << 80) - 1)
        key = (transform13_compact.SBOX[key >> 76] << 76) | (key & ((1 << 76) - 1))
        key ^= counter << 15
    return keys


@pytest.mark.parametrize(
    ("plaintext", "key", "ciphertext"),
    [
        (0, 0, 0x5579C1387B228445),
        (0, (1 << 80) - 1, 0xE72C46C0F5945049),
        ((1 << 64) - 1, 0, 0xA112FFC72F68417B),
        ((1 << 64) - 1, (1 << 80) - 1, 0x3333DCD3213210D2),
    ],
)
def test_rounds_reproduce_the_published_present80_vectors(plaintext: int, key: int, ciphertext: int) -> None:
    assert transform13_compact.present_rounds(plaintext, _standard_round_keys(key)) == ciphertext


def _span(rng: random.Random) -> bytes:
    """A Transform7/Monolith1 span as seed_transform produces one."""
    span = bytearray(transform7_compact.DESTINATION_SIZE)
    transform7_compact.execute(span, bytearray(rng.randbytes(20)), bytearray(rng.randbytes(20)), rng.randbytes(40))
    seed_transform._monolith1_loop(span)
    return bytes(span)


def test_span_value_matches_the_recovered_gate_decoder() -> None:
    boundary, terms = normalized_terms()
    rng = random.Random(1301)
    for _ in range(20):
        span = _span(rng)
        words = struct.unpack("<18I", span)
        payload = sum((local_gate(term, words) ^ int(term.weight < 0)) << bit for bit, term in enumerate(terms))
        assert transform13_compact.span_value(span) == (2 * payload + local_gate(boundary, words)) % transform13_compact.MODULUS


def test_span_value_rejects_short_spans() -> None:
    with pytest.raises(ValueError, match="span too small"):
        transform13_compact.span_value(bytes(71))


def test_transform13_decodes_to_the_present80_mask() -> None:
    rng = random.Random(1302)
    for _ in range(8):
        span = _span(rng)
        encoded = bytearray(60)
        monolith8.execute(encoded, span)
        output = bytearray(transform13.DESTINATION_SIZE)
        transform13.execute(output, bytes(encoded))
        decoded = monolith11_compact.execute_words((0,) * 15 + struct.unpack("<15I", output))
        mask = transform13_compact.mask(transform13_compact.span_value(span))
        assert decoded == tuple((mask >> (32 * index)) & 0xFFFFFFFF for index in range(5))


def _generated_seed_transform(destination: bytearray, public_key: bytes, transform1: bytes) -> None:
    """``seed_transform.execute`` as it ran through the generated Monolith8/Transform13 chain."""
    prng1 = bytearray(os.urandom(0x14))
    span = bytearray(transform7_compact.DESTINATION_SIZE)
    work = bytearray(20)
    while True:
        prng2 = bytearray(os.urandom(0x14))
        transform7_compact.execute(span, prng1, prng2, TRANSFORM7_DATA[0xD8:])
        seed_transform._monolith1_loop(span)
        monolith2.execute(work, bytes(span))
        if any(work):
            break
    destination[0x14:0x28] = work
    destination[0x28:0x3C] = prng1
    transform7_compact.execute(span, prng1, prng2, public_key)
    seed_transform._monolith1_loop(span)
    m8_buf = bytearray(20 + 72)
    monolith8.execute(memoryview(m8_buf)[20:], bytes(span))  # type: ignore[arg-type]
    m11_src = bytearray(120)
    transform13.execute(memoryview(m11_src)[0x3C:], bytes(m8_buf[20:]))  # type: ignore[arg-type]
    m11_src[:0x3C] = transform1[:0x3C]
    monolith11_compact.execute(m8_buf, bytes(m11_src))
    destination[:0x14] = m8_buf[:0x14]


def test_seed_transform_matches_the_generated_chain() -> None:
    for trial in range(6):
        rng = random.Random(1303 + trial)
        public_key, transform1 = rng.randbytes(40), rng.randbytes(60)
        outputs = []
        for implementation in (seed_transform.execute, _generated_seed_transform):
            entropy = random.Random(2303 + trial)
            destination = bytearray(seed_transform.DESTINATION_SIZE)
            with mock.patch("os.urandom", entropy.randbytes):
                implementation(destination, public_key, transform1)
            outputs.append(bytes(destination))
        assert outputs[0] == outputs[1]
