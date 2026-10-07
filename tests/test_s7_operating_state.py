"""Operating-state attribute ids and request values (groundwork for #8)."""

from __future__ import annotations

import pytest

from s7commplus.protocol import (
    OPERATING_STATE_RUN_OBSERVED,
    OPERATING_STATE_STOP_OBSERVED,
    Ids,
    OperatingStateRequest,
)


class TestOperatingStateAttributes:
    def test_attribute_ids(self) -> None:
        # The writable request attribute and the read-only state attribute are
        # distinct attributes of the CPUexecUnit object (RID 52).
        assert Ids.CPU_EXEC_UNIT_OPERATING_STATE_REQ == 0x877
        assert Ids.CPU_EXEC_UNIT_OPERATING_STATE == 0xD9E
        assert Ids.CPU_EXEC_UNIT_OPERATING_STATE != Ids.CPU_EXEC_UNIT_OPERATING_STATE_REQ

    def test_executing_mode_attributes_unchanged(self) -> None:
        # The corroborating attributes get_cpu_state() already reads stay put.
        assert Ids.CPU_EXEC_UNIT_EXECUTING == 8064
        assert Ids.CPU_EXEC_UNIT_OPERATING_MODE == 8065


class TestOperatingStateRequestValues:
    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("STOP", 1),
            ("RESET_RETENTIVE", 2),
            ("RUN", 3),
            ("RUN_REDUNDANT", 4),
        ],
    )
    def test_request_values(self, name: str, value: int) -> None:
        assert OperatingStateRequest[name] == value

    def test_values_are_distinct(self) -> None:
        values = [int(member) for member in OperatingStateRequest]
        assert len(set(values)) == 4

    def test_observed_state_values(self) -> None:
        # Read-side values observed on real controllers; kept as documented
        # constants, not an enum, because the intermediate states vary by
        # firmware and are not pinned.
        assert OPERATING_STATE_STOP_OBSERVED == 4
        assert OPERATING_STATE_RUN_OBSERVED == 8
