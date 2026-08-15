"""动态分析执行入口单元测试：run_dynamic_analysis 预检与结果落盘。"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.dynamic.backend import run_dynamic_analysis  # noqa: E402
from apkguard.dynamic.device_manager import DeviceManager  # noqa: E402
from apkguard.engine.models import AnalyzedApp, DynamicStatus, Report  # noqa: E402


def make_report() -> Report:
    return Report(
        file_name="t.apk", file_format="APK", file_size=1, sha256="x" * 64,
        dynamic=DynamicStatus(),
    )


def make_app(package: str = "com.malware.sample") -> AnalyzedApp:
    return AnalyzedApp(
        file_path="t.apk", file_format="APK", file_size=1, sha256="x" * 64,
        package=package,
        dangerous_permissions=["android.permission.SEND_SMS"],
    )


class FakeBackend:
    """假后端：直接返回"已执行"结果，device_used 取管理器准入的设备"""

    name = "adb"

    def __init__(self, device_manager: DeviceManager):
        self._dm = device_manager

    def is_available(self) -> bool:
        return True

    def analyze(self, apk_path, app, options):
        dev = self._dm.get_online_test_device()
        return {
            "status": "executed",
            "device_used": dev.serial if dev else "emulator-5556",
            "backend": "adb",
            "note": "动态分析完成 / done",
            "duration_seconds": 10,
            "traffic_endpoints": ["c2.example.com:443"],
            "traffic_count": 3,
            "frida_hooked": False,
            "decoy_installed": True,
            "cleanup_ok": True,
            "notes": ["installed", "decoy: 3 contacts"],
        }


class TestRunDynamicAnalysis:
    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_disabled_does_not_execute(self, mock_adb):
        report = make_report()
        dm = DeviceManager(["emulator-5556"])
        result = run_dynamic_analysis(report, dm, {"enabled": False}, Path("t.apk"), make_app())
        assert result["executed"] is False
        assert report.dynamic.status == "skipped"

    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_no_target_device_does_not_execute(self, mock_adb):
        mock_adb.return_value = "List of devices attached\n"
        report = make_report()
        dm = DeviceManager(["emulator-5556"])
        result = run_dynamic_analysis(report, dm, {"enabled": True}, Path("t.apk"), make_app())
        assert result["executed"] is False
        assert report.dynamic.status == "skipped"

    @patch("apkguard.dynamic.backend.resolve_backend")
    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_executed_result_populates_report(self, mock_adb, mock_resolve):
        mock_adb.return_value = "List of devices attached\nemulator-5556  device\n"
        report = make_report()
        dm = DeviceManager(["emulator-5556"])
        mock_resolve.return_value = FakeBackend(dm)
        result = run_dynamic_analysis(report, dm, {"enabled": True}, Path("t.apk"), make_app())

        assert result["executed"] is True or result["status"] == "executed"
        dyn = report.dynamic
        assert dyn.status == "executed"
        assert dyn.executed is True
        assert dyn.device_used == "emulator-5556"
        assert dyn.traffic_endpoints == ["c2.example.com:443"]
        assert dyn.traffic_count == 3
        assert dyn.decoy_installed is True
        assert dyn.cleanup_ok is True
        assert dyn.duration_seconds == 10
        assert any(f["message"] == "installed" for f in dyn.findings)

    @patch("apkguard.dynamic.backend.resolve_backend")
    @patch("apkguard.dynamic.device_manager.DeviceManager._adb")
    def test_explicit_device_with_empty_whitelist_executes(self, mock_adb, mock_resolve):
        mock_adb.return_value = "List of devices attached\nemulator-5554  device\n"
        report = make_report()
        dm = DeviceManager([], explicit_device="emulator-5554")
        mock_resolve.return_value = FakeBackend(dm)
        result = run_dynamic_analysis(report, dm, {"enabled": True}, Path("t.apk"), make_app())
        assert report.dynamic.status == "executed"
        assert report.dynamic.device_used == "emulator-5554"
