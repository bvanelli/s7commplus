"""Readable, independently checked model of generated Monolith11.

This is an analysis reference, not runtime code. The generated implementation
remains authoritative until a separate migration is justified and validated.
"""

from __future__ import annotations

from collections.abc import Sequence

# Coefficients are 32-bit lane masks, not secret material. For each triple
# (a, b, c), the six terms are a, b, a&b, c, a&c, b&c.
EVEN_COEFFICIENTS = (0x5DA724BA, 0x6250A363, 0xF6BDFCF6, 0x86F79499, 0xAFFF4FDF, 0x5FFBFBAF)
ODD_COEFFICIENTS = (0xECB2D69E, 0xC6D87455, 0xDFDFDF77, 0x104A21AB, 0xA7773DFB, 0x7DEFFE9F)


def _kernel(a: int, b: int, c: int, coefficients: tuple[int, ...]) -> int:
    return (
        (a & coefficients[0])
        ^ (b & coefficients[1])
        ^ (a & b & coefficients[2])
        ^ (c & coefficients[3])
        ^ (a & c & coefficients[4])
        ^ (b & c & coefficients[5])
    )


def execute_words(source: Sequence[int]) -> tuple[int, ...]:
    """Map 30 source words to five destination words.

    Output word ``i`` XORs the same kernel over source triples starting at
    ``3*i`` and ``15+3*i``. Even and odd output words use different masks.
    """
    if len(source) < 30:
        raise ValueError("Monolith11 requires at least 30 source words")
    output = []
    for index in range(5):
        coefficients = EVEN_COEFFICIENTS if index % 2 == 0 else ODD_COEFFICIENTS
        left_start = 3 * index
        right_start = 15 + left_start
        left = _kernel(source[left_start], source[left_start + 1], source[left_start + 2], coefficients)
        right = _kernel(source[right_start], source[right_start + 1], source[right_start + 2], coefficients)
        output.append((left ^ right) & 0xFFFFFFFF)
    return tuple(output)
