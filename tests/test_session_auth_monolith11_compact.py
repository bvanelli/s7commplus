"""Runtime-migration checks for Monolith11.

`family0/monolith11_compact.execute` replaced `_generated/monolith11.execute`
as the function ``seed_transform.py`` actually calls. These tests prove the
byte-level entry point (not just the word-level formula already covered in
``test_session_auth_bitwise_analysis.py``) is equivalent, and guard against a
regression back to importing the generated module at runtime.
"""

from __future__ import annotations

import random
from pathlib import Path

from s7commplus.session_auth.family0 import monolith11_compact, seed_transform
from s7commplus.session_auth.family0._generated import monolith11 as generated_monolith11

_FIXTURES = Path(__file__).parent / "fixtures/family0/monoliths"


def test_compact_execute_matches_upstream_fixture() -> None:
    source = (_FIXTURES / "monolith11-src.bin").read_bytes()
    expected = (_FIXTURES / "monolith11-dst.bin").read_bytes()

    destination = bytearray(len(expected))
    monolith11_compact.execute(destination, source)

    assert bytes(destination) == expected


def test_compact_execute_matches_generated_on_random_vectors_and_preserves_tail() -> None:
    rng = random.Random(0xC0FFEE11)
    for _ in range(100):
        source = bytes(rng.getrandbits(8) for _ in range(120))
        # A destination longer than 20 bytes exercises that both
        # implementations leave the tail untouched.
        tail = bytes(rng.getrandbits(8) for _ in range(72))

        generated_destination = bytearray(20) + bytearray(tail)
        generated_monolith11.execute(generated_destination, source)

        compact_destination = bytearray(20) + bytearray(tail)
        monolith11_compact.execute(compact_destination, source)

        assert bytes(compact_destination) == bytes(generated_destination)
        assert bytes(compact_destination[20:]) == tail


def test_seed_transform_no_longer_imports_generated_monolith11() -> None:
    assert not hasattr(seed_transform, "monolith11")
    assert seed_transform.monolith11_compact is monolith11_compact
