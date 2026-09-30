"""The fingerprint gate network matches the direct HarpoS7 port it replaced."""

from __future__ import annotations

import collections
import random

import pytest

from s7commplus.session_auth.family0 import fingerprint
from old.family0 import fingerprint as harpo
from tools import build_fingerprint_gates


def _fingerprint(challenge: bytes) -> bytes:
    output = bytearray(8)
    fingerprint.fingerprint_challenge(output, challenge)
    return bytes(output)


def _reference(challenge: bytes, destination: bytes = bytes(8)) -> bytes:
    output = bytearray(destination)
    harpo.harpo_fingerprint(output, challenge)
    return bytes(output)


def test_packaged_gates_are_built_from_the_harpo_tables() -> None:
    assert build_fingerprint_gates.TARGET.read_bytes() == build_fingerprint_gates.build()
    assert list(fingerprint._gates()) == harpo.gates()


def test_matches_the_harpo_port_on_random_challenges() -> None:
    rng = random.Random(4600)
    for _ in range(300):
        challenge = rng.randbytes(20)
        # The port's output ignores the destination's previous contents too.
        assert _fingerprint(challenge) == _reference(challenge, rng.randbytes(8))


@pytest.mark.parametrize("fill", [0x00, 0x0F, 0xF0, 0xFF])
def test_matches_the_harpo_port_on_constant_challenges(fill: int) -> None:
    assert _fingerprint(bytes([fill]) * 18) == _reference(bytes([fill]) * 18)


def test_matches_the_harpo_port_on_single_nibble_changes() -> None:
    base = bytes(18)
    for nibble in range(32):
        for value in (1, 8, 15):
            challenge = bytearray(base)
            challenge[2 + nibble // 2] = value << 4 if nibble % 2 == 0 else value
            assert _fingerprint(bytes(challenge)) == _reference(bytes(challenge))


def test_only_challenge_bytes_2_to_18_are_used() -> None:
    rng = random.Random(4601)
    challenge = rng.randbytes(20)
    variant = rng.randbytes(2) + challenge[2:18] + rng.randbytes(4)
    assert _fingerprint(challenge) == _fingerprint(variant)


def test_gate_network_shape() -> None:
    gates = fingerprint._gates()
    assert len(gates) == 496
    written = collections.Counter(dst for _, _, dst, _ in gates)
    assert min(written) >= 32 and max(written) < fingerprint._STATE_NIBBLES  # Challenge nibbles are never overwritten.
    available = set(range(32))
    for a, b, dst, table in gates:
        assert {a, b} <= available  # No gate reads a nibble before it is written.
        assert sorted(collections.Counter(table).values()) == [16] * 16  # Balanced.
        available.add(dst)
    assert set(fingerprint._OUTPUT) <= available


def test_every_output_nibble_depends_on_the_whole_challenge() -> None:
    dependencies: dict[int, frozenset[int]] = {nibble: frozenset({nibble}) for nibble in range(32)}
    for a, b, dst, _ in fingerprint._gates():
        dependencies[dst] = dependencies[a] | dependencies[b]
    assert all(dependencies[nibble] == frozenset(range(32)) for nibble in fingerprint._OUTPUT)


def test_rejects_short_buffers() -> None:
    with pytest.raises(ValueError, match="destination"):
        fingerprint.fingerprint_challenge(bytearray(7), bytes(18))
    with pytest.raises(ValueError, match="challenge"):
        fingerprint.fingerprint_challenge(bytearray(8), bytes(17))


@pytest.mark.parametrize("data", [b"", bytes(133), bytes(135)])
def test_rejects_empty_or_truncated_gate_data(data: bytes) -> None:
    with pytest.raises(ValueError, match="empty or truncated"):
        fingerprint._parse_gates(data)


def test_rejects_out_of_range_gate_indices() -> None:
    record = bytearray(build_fingerprint_gates.TARGET.read_bytes()[:134])
    record[4:6] = (544).to_bytes(2, "little")
    with pytest.raises(ValueError, match="out of range"):
        fingerprint._parse_gates(bytes(record))
