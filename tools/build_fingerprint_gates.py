"""Build ``family0/fingerprint_gates.bin`` from HarpoS7's fingerprint tables.

The runtime fingerprint evaluates a fixed network of 496 nibble gates. This
tool derives it from ``fp_data1.bin``, ``fp_data2.bin`` and the context
constants in ``old/family0/_generated/data`` (see ``old/family0/fingerprint.py``).
Without ``--write`` it only checks that the checked-in file is up to date.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from old.family0 import fingerprint

TARGET = Path(__file__).resolve().parents[1] / "s7commplus/session_auth/family0/fingerprint_gates.bin"


def build() -> bytes:
    return fingerprint.encode_gates(fingerprint.gates())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write the file instead of checking it")
    args = parser.parse_args()
    data = build()
    if args.write:
        TARGET.write_bytes(data)
        return 0
    if not TARGET.is_file() or TARGET.read_bytes() != data:
        print(f"{TARGET} is out of date; run python -m tools.build_fingerprint_gates --write", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
