"""Readable model of Monolith11, now the runtime implementation.

This used to be an analysis-only reference; the equivalence proof in
``tests/test_session_auth_bitwise_analysis.py`` and
``s7commplus/session_auth/MONOLITH11_ANALYSIS.md`` justified promoting it to
runtime code. The canonical implementation now lives in
``s7commplus.session_auth.family0.monolith11_compact`` (used by
``seed_transform.py``); this module re-exports it so existing tools and tests
that import ``tools.monolith11_model`` keep working unchanged.
"""

from __future__ import annotations

from s7commplus.session_auth.family0.monolith11_compact import (
    EVEN_COEFFICIENTS,
    ODD_COEFFICIENTS,
    execute_words,
)

__all__ = ["EVEN_COEFFICIENTS", "ODD_COEFFICIENTS", "execute_words"]
