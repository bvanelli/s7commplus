"""Attribute access flags."""

from __future__ import annotations

import pytest

from s7commplus.protocol import AttributeFlags, attribute_flags_description


class TestAttributeFlags:
    def test_flag_values(self) -> None:
        expected = {
            "APPLICATION_READABLE": 0x1,
            "APPLICATION_WRITABLE": 0x2,
            "IS_IN": 0x4,
            "IS_OUT": 0x8,
            "CORE": 0x10,
            "PERSISTENT": 0x20,
            "BL": 0x40,
            "CLIENT_READONLY": 0x400,
            "SERVER_ONLY": 0x800,
            "CHANGEABLE_IN_RUN": 0x2000,
            "NEEDS_LEGITIMATION": 0x4000,
            "NORMAL_ACCESS": 0x8000,
            "STREAMING": 0x10000,
            "IS_QUALIFIER": 0x40000,
            "HMI_ACCESSIBLE": 0x100000,
            "HMI_VISIBLE": 0x800000,
            "PLAIN_MEMBER_CLASSIC": 0x1000000,
            "IS_HOST_RELEVANT": 0x8000000,
        }
        for name, value in expected.items():
            assert AttributeFlags[name] == value, name

    def test_combinable(self) -> None:
        flags = AttributeFlags.APPLICATION_WRITABLE | AttributeFlags.CHANGEABLE_IN_RUN
        assert AttributeFlags.APPLICATION_WRITABLE in flags
        assert AttributeFlags.APPLICATION_READABLE not in flags


class TestDescription:
    def test_single_flag(self) -> None:
        assert attribute_flags_description(0x4000) == "needs_legitimation"

    def test_multiple_flags_are_ordered_by_bit(self) -> None:
        # Bits are reported in enum order (lowest value first).
        assert attribute_flags_description(0x03) == "application_readable, application_writable"

    def test_zero_flags(self) -> None:
        assert attribute_flags_description(0) == "none"

    def test_unknown_bits_are_reported(self) -> None:
        # 0x20000 appears in real attribute tables but has no name; it must
        # render as a bit marker rather than being silently dropped.
        description = attribute_flags_description(0x20000)
        assert description == "bit 0x20000"

    def test_mixed_known_and_unknown(self) -> None:
        description = attribute_flags_description(AttributeFlags.CORE | 0x40000000)
        assert "core" in description
        assert "bit 0x40000000" in description

    @pytest.mark.parametrize(
        ("flags", "must_contain"),
        [
            (0x4006140, "needs_legitimation"),  # OperatingStateREQ-style value
            (0x2C130, "normal_access"),  # the most common table value
            (0x2C131, "application_readable"),
        ],
    )
    def test_real_attribute_values_decode(self, flags: int, must_contain: str) -> None:
        assert must_contain in attribute_flags_description(flags)
