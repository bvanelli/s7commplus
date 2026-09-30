"""Readable model of Monolith11.

The equivalence proof in ``tests/test_session_auth_bitwise_analysis.py`` and
``s7commplus/session_auth/MONOLITH11_ANALYSIS.md`` covers the implementation
in ``old.family0.monolith11_compact``; this module re-exports it so existing
tools and tests that import ``tools.monolith11_model`` keep working unchanged.
"""

from __future__ import annotations

from old.family0.monolith11_compact import (
    EVEN_COEFFICIENTS,
    ODD_COEFFICIENTS,
    execute_words,
)

__all__ = ["EVEN_COEFFICIENTS", "ODD_COEFFICIENTS", "execute_words"]
