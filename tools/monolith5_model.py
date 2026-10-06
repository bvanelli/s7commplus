"""Compact, analysis-only equivalent of generated Family-0 Monolith5.

The 32 nine-input truth tables and 168 position records in the adjacent JSON
are recovered from the generated source by ``tools.recover_monolith5``. This
module is deliberately outside the runtime package and has no wire effects.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import TypeAlias, cast

Component: TypeAlias = tuple[int, int, int]  # Source triplet, bit position, LUT index.
Entry: TypeAlias = tuple[int, list[Component], int, Component | None]

_DATA = json.loads(Path(__file__).with_name("monolith5_model.json").read_text(encoding="utf-8"))
if _DATA["version"] != 1:
    raise ValueError("unsupported Monolith5 model version")
_LUTS = tuple(int(value, 16) for value in cast(list[str], _DATA["luts"]))
_ENTRIES = cast(list[Entry], _DATA["entries"])


def execute_words(source: Sequence[int]) -> tuple[int, ...]:
    """Map 54 little-endian source words to twelve destination words.

    The two six-word outputs each contain 168 payload bits, packed in bits
    2..29 of every destination word. The second output stream starts with a
    zero bit; its later bits are quadratic combinations of the first stream's
    nine-input lane functions, with one boundary correction.
    """
    if len(source) < 54:
        raise ValueError("Monolith5 requires at least 54 source words")
    if len(_ENTRIES) != 168 or len(_LUTS) != 32:
        raise ValueError("invalid Monolith5 model size")

    first = 0
    second = 0

    def lane(component: Component) -> int:
        chunk, bit, function_id = component
        index = 0
        for span in range(3):
            for value in range(3):
                source_word = source[span * 18 + chunk * 3 + value]
                index |= ((source_word >> bit) & 1) << (span * 3 + value)
        return (_LUTS[function_id] >> index) & 1

    for position, (constant, components, second_mask, residual) in enumerate(_ENTRIES):
        values = [lane(component) for component in components]
        first_bit = constant
        for value in values:
            first_bit ^= value
        first |= first_bit << position

        if position < 167:
            second_bit = lane(residual) if residual is not None else 0
            for subset in range(1 << len(values)):
                if second_mask & (1 << subset) and all(values[index] for index in range(len(values)) if subset & (1 << index)):
                    second_bit ^= 1
            second |= second_bit << (position + 1)

    packed_first = tuple(((first >> (28 * word)) & 0x0FFFFFFF) << 2 for word in range(6))
    packed_second = tuple(((second >> (28 * word)) & 0x0FFFFFFF) << 2 for word in range(6))
    return packed_first + packed_second
