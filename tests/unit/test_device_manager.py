"""设备白名单隔离机制单元测试：安全铁律验证。"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.dynamic.backend import update_dynamic_status
from apkguard.dynamic.device_manager import (
    DeviceAccessDenied,
    DeviceManager,
)
from apkguard.engine.models import DynamicStatus, Report


def make_report() -> Report:
    return Report(
        file_name="t.apk", file_format="APK", file_size=1, sha256="x" * 64,
        dynamic=DynamicStatus(),
    )


class TestWhitelistGate:
    def test_empty_whitelist_denies_everything(self):
        dm = DeviceManager([])
        assert not dm.has_whitelist
        assert not dm.is_allowed("emulator-5554")
        with pytest.raises(DeviceAccessDenied):
            dm.assert_allowed("emulator-5554")

    def test_whitelisted_device_allowed(self):
        dm = DeviceManager(["emulator-5556"])
        assert dm.is_allowed("emulator-5556")
        dm.assert_allowed("emulator-5556")  # 不应抛异常

    def test_whitelist_never_touches_work_device(self):
        # 用户常连的工作设备绝不在白名单
        dm = DeviceManager(["emulator-5556"])
        assert not dm.is_allowed("emulator-5554")
        with pytest.raises(DeviceAccessDenied):
            dm.assert_allowed("emulator-5554")


class TestExplicitDeviceBypass:
    def test_explicit_device_allowed_with_empty_whitelist(self):
        dm = DeviceManager([], explicit_device="emulator-5554")
        assert dm.has_explicit_device
        assert dm.is_allowed("emulator-5554")
        dm.assert_allowed("emulator-5554")  # 显式指定 → 绕过白名单，不应抛异常

    def test_explicit_device_bypasses_whitelist(self):
        # 显式指定设备不在白名单中，仍被允许（用户明确授权）
        dm = DeviceManager(["emulator-5556"], explicit_device="emulator-5554")
        assert dm.is_allowed("emulator-5554")

    def test_explicit_device_property(self):
        dm = DeviceManager([], explicit_device="emulator-5554")
        assert dm.explicit_device == "emulator-5554"
        assert not DeviceManager([]).has_explicit_device

    def test_non_explicit_non_whitelist_still_denied(self):
        # 绕过只针对显式指定的那一台；其他设备依旧受白名单门槛约束
        dm = DeviceManager(["emulator-5556"], explicit_device="emulator-5554")
        assert not dm.is_allowed("0123456789ABCDEF")
        with pytest.raises(DeviceAccessDenied):
            dm.assert_allowed("0123456789ABCDEF")

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_get_online_test_device_prefers_explicit(self, mock_adb):
        # 白名单设备在线 + 显式设备在线 → 返回显式设备
        mock_adb.return_value = (
            "List of devices attached\n"
            "emulator-5556  device\n"
            "emulator-5554  device\n"
        )
        dm = DeviceManager(["emulator-5556"], explicit_device="emulator-5554")
        dev = dm.get_online_test_device()
        assert dev is not None and dev.serial == "emulator-5554"

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_explicit_offline_does_not_fall_back(self, mock_adb):
        # 显式设备离线、白名单设备在线 → 仍返回 None（不静默换设备）
        mock_adb.return_value = (
            "List of devices attached\n"
            "emulator-5554  offline\n"
            "emulator-5556  device\n"
        )
        dm = DeviceManager(["emulator-5556"], explicit_device="emulator-5554")
        assert dm.get_online_test_device() is None

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_describe_mentions_bypass(self, mock_adb):
        mock_adb.return_value = "List of devices attached\nemulator-5554  device\n"
        dm = DeviceManager([], explicit_device="emulator-5554")
        desc = dm.describe()
        assert "绕过白名单" in desc and "emulator-5554" in desc


class TestDeviceListing:
    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_list_devices_flags_allowed(self, mock_adb):
        mock_adb.return_value = (
            "List of devices attached\n"
            "emulator-5554  device product:sdk_gphone model:work_avd\n"
            "emulator-5556  device product:sdk_gphone model:test_avd\n"
        )
        dm = DeviceManager(["emulator-5556"])
        devices = dm.list_devices()
        by_serial = {d.serial: d for d in devices}
        assert by_serial["emulator-5554"].allowed is False
        assert by_serial["emulator-5556"].allowed is True

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_get_online_test_device(self, mock_adb):
        mock_adb.return_value = (
            "List of devices attached\n"
            "emulator-5554  device product:sdk_gphone model:work_avd\n"
            "emulator-5556  device product:sdk_gphone model:test_avd\n"
        )
        dm = DeviceManager(["emulator-5556"])
        dev = dm.get_online_test_device()
        assert dev is not None and dev.serial == "emulator-5556"

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_no_online_test_device(self, mock_adb):
        mock_adb.return_value = "List of devices attached\nemulator-5554  offline\n"
        dm = DeviceManager(["emulator-5554"])
        assert dm.get_online_test_device() is None


class TestDynamicStatusUpdate:
    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_no_whitelist_skips(self, mock_adb):
        report = make_report()
        dm = DeviceManager([])
        update_dynamic_status(report, dm, {"enabled": True})
        assert report.dynamic.status == "skipped"
        assert "白名单" in report.dynamic.note

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_disabled_skips(self, mock_adb):
        report = make_report()
        dm = DeviceManager(["emulator-5556"])
        update_dynamic_status(report, dm, {"enabled": False})
        assert report.dynamic.status == "skipped"

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_device_online_degraded_note(self, mock_adb):
        mock_adb.return_value = (
            "List of devices attached\nemulator-5556  device\n"
        )
        report = make_report()
        dm = DeviceManager(["emulator-5556"])
        update_dynamic_status(report, dm, {"enabled": True})
        assert report.dynamic.status == "degraded"
        assert report.dynamic.device_used == "emulator-5556"
        assert report.dynamic.backend == "adb"


class TestExplicitDeviceStatus:
    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_explicit_device_with_empty_whitelist_degraded(self, mock_adb):
        # 空白名单 + 显式指定在线设备 → 仍可执行（绕过），且标注绕过
        mock_adb.return_value = "List of devices attached\nemulator-5554  device\n"
        report = make_report()
        dm = DeviceManager([], explicit_device="emulator-5554")
        update_dynamic_status(report, dm, {"enabled": True})
        assert report.dynamic.status == "degraded"
        assert report.dynamic.device_used == "emulator-5554"
        assert report.dynamic.backend == "adb"
        assert "绕过白名单" in report.dynamic.note

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_explicit_offline_skips_with_clear_note(self, mock_adb):
        mock_adb.return_value = "List of devices attached\nemulator-5554  offline\n"
        report = make_report()
        dm = DeviceManager([], explicit_device="emulator-5554")
        update_dynamic_status(report, dm, {"enabled": True})
        assert report.dynamic.status == "skipped"
        assert "emulator-5554" in report.dynamic.note

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_no_whitelist_no_explicit_skips(self, mock_adb):
        # 空白名单且未显式指定 → 安全默认：跳过（默认状态）
        report = make_report()
        dm = DeviceManager([])
        update_dynamic_status(report, dm, {"enabled": True})
        assert report.dynamic.status == "skipped"
