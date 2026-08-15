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
