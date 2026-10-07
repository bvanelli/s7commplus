"""INVOKE method identifiers and their readable names."""

from __future__ import annotations

import pytest

from s7commplus.protocol import (
    HMI_METHODS,
    REMOTE_FILE_ACCESS_MANAGER_METHODS,
    RESOLVE_ADDRESS_REMOTE_METHOD,
    RESOLVE_ADDRESS_REMOTE_RID,
    invoke_method_name,
)


class TestMethodTables:
    def test_remote_file_access_manager_methods(self) -> None:
        assert REMOTE_FILE_ACCESS_MANAGER_METHODS[1] == "Init"
        assert REMOTE_FILE_ACCESS_MANAGER_METHODS[2] == "OpenFile"
        assert REMOTE_FILE_ACCESS_MANAGER_METHODS[3] == "ReadFile"
        assert REMOTE_FILE_ACCESS_MANAGER_METHODS[4] == "WriteFile"
        assert REMOTE_FILE_ACCESS_MANAGER_METHODS[5] == "CloseFile"
        assert REMOTE_FILE_ACCESS_MANAGER_METHODS[13] == "RenameFile"
        # Method 14 is absent in the reference table.
        assert 14 not in REMOTE_FILE_ACCESS_MANAGER_METHODS

    def test_hmi_methods(self) -> None:
        assert HMI_METHODS[18667] == "AddonObject.CheckCompat"
        assert HMI_METHODS[18827] == "RuntimeUpdateService.BeginRuntimeUpdate"
        assert HMI_METHODS[15000009] == "DownloadService.PreFullDownload"
        assert HMI_METHODS[15000016] == "DownloadService.ActivateDownload"
        assert HMI_METHODS[15000019] == "DownloadService.AbortFullDownload"
        assert HMI_METHODS[15000039] == "ProjectManager.GetScsProject"

    def test_tables_are_injective(self) -> None:
        assert len(set(REMOTE_FILE_ACCESS_MANAGER_METHODS)) == len(REMOTE_FILE_ACCESS_MANAGER_METHODS)
        assert len(set(HMI_METHODS)) == len(HMI_METHODS)


class TestInvokeMethodName:
    def test_resolve_address_remote_by_rid(self) -> None:
        assert invoke_method_name(RESOLVE_ADDRESS_REMOTE_RID, RESOLVE_ADDRESS_REMOTE_METHOD) == "ResolveAddressRemote"
        # The RID alone identifies the resolver even with a foreign method id.
        assert invoke_method_name(RESOLVE_ADDRESS_REMOTE_RID, 9999) == "ResolveAddressRemote"

    def test_file_access_methods_resolve_only_for_a_known_manager_rid(self) -> None:
        # The RID is session-assigned, so the caller must say which object is
        # the file manager.
        known = {0x8A110001}
        assert invoke_method_name(0x8A110001, 3, known) == "RemoteFileAccessManager.ReadFile"
        assert invoke_method_name(0x8A110001, 6, known) == "RemoteFileAccessManager.OpenDir"

    def test_unrelated_rid_with_a_small_method_id_is_not_mislabelled(self) -> None:
        # Without manager knowledge, method id 2 on any object is just an
        # unknown method — not "OpenFile".
        assert invoke_method_name(1234, 2) == "method 0x2"
        assert invoke_method_name(0x8A0E0001, 1) == "method 0x1"
        # And even a known manager object does not claim unknown method ids.
        assert invoke_method_name(0x8A110001, 14, {0x8A110001}) == "method 0xE"

    def test_service_methods_still_resolve_without_manager_knowledge(self) -> None:
        # Fixed service ids are unambiguous on their own.
        assert invoke_method_name(0, 18829) == "RuntimeUpdateService.FinishRuntimeUpdate"

    def test_service_methods_resolve_by_fixed_id(self) -> None:
        assert invoke_method_name(0, 18829) == "RuntimeUpdateService.FinishRuntimeUpdate"
        assert invoke_method_name(0, 15000035) == "ScsProject.GetFullDownloadServiceRid"

    @pytest.mark.parametrize("method_id", [0, 14, 12345])
    def test_unknown_pairs_degrade_to_hex(self, method_id: int) -> None:
        name = invoke_method_name(0x1234, method_id)
        assert name == f"method 0x{method_id:X}"
