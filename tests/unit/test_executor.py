"""动态执行体单元测试：智能终止策略、流程编排、异常清理。"""
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.dynamic.executor import DynamicExecutor, should_stop  # noqa: E402


class FakeRunner:
    """记录调用的假 adb runner（不碰真实设备）"""

    def __init__(self, serial="emulator-5554"):
        self.serial = serial
        self.calls: list[tuple] = []
        self.install_ok = True
        self.launch_ok = True
        self.uninstall_ok = True
        self.monkey_raises: Exception | None = None
        self.foreground: str | None = None

    def install(self, apk_path, grant_permissions=True):
        self.calls.append(("install", str(apk_path), grant_permissions))
        return self.install_ok

    def ok(self, *args, timeout=60):
        # content insert 等 shell 命令：测试中一律失败 → 诱饵计数为 0
        self.calls.append(("ok", args))
        return False

    def grant_permissions(self, package, permissions):
        self.calls.append(("pm_grant", package, list(permissions)))
        return list(permissions)

    def launch(self, package):
        self.calls.append(("launch", package))
        return self.launch_ok

    def foreground_package(self):
        return self.foreground

    def monkey(self, package, events=200):
        self.calls.append(("monkey", package, events))
        if self.monkey_raises:
            raise self.monkey_raises
        return True

    def set_global_proxy(self, host, port):
        self.calls.append(("set_proxy", host, port))
        return True

    def clear_global_proxy(self):
        self.calls.append(("clear_proxy",))
        return True

    def uninstall(self, package):
        self.calls.append(("uninstall", package))
        return self.uninstall_ok

    def device_has_process(self, pattern):
        return False  # 无 frida-server → 采集降级


def free_port() -> int:
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_options(**overrides) -> dict:
    base = {
        "initial_timeout": 5,
        "max_timeout": 20,
        "idle_timeout": 2,
        "poll_interval": 1,
        "monkey_events": 10,
        "monkey_interval": 3,
        "proxy_port": free_port(),
        "install_decoy_data": True,
        "use_frida": True,
    }
    base.update(overrides)
    return base


class TestShouldStop:
    """智能终止判定纯函数"""

    def test_max_timeout_forces_stop(self):
        assert should_stop(elapsed=900, active=True, idle_seconds=0,
                           initial_timeout=300, max_timeout=900, idle_timeout=45)

    def test_idle_timeout_stops_early(self):
        assert should_stop(elapsed=10, active=False, idle_seconds=45,
                           initial_timeout=300, max_timeout=900, idle_timeout=45)

    def test_past_initial_and_not_active_stops(self):
        assert should_stop(elapsed=310, active=False, idle_seconds=10,
                           initial_timeout=300, max_timeout=900, idle_timeout=45)

    def test_active_within_budget_keeps_running(self):
        assert not should_stop(elapsed=120, active=True, idle_seconds=5,
                               initial_timeout=300, max_timeout=900, idle_timeout=45)

    def test_active_past_initial_extends(self):
        # 活跃 → 延长至 max_timeout
        assert not should_stop(elapsed=310, active=True, idle_seconds=5,
                               initial_timeout=300, max_timeout=900, idle_timeout=45)


class TestExecutorRun:
    def test_happy_path_installs_launches_cleans_up(self):
        runner = FakeRunner()
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(Path("sample.apk"), "com.malware.sample", ["android.permission.SEND_SMS"])

        assert result["status"] == "executed"
        assert runner.calls[0][0] == "install"  # 先安装
        assert any(c[0] == "launch" for c in runner.calls)
        assert any(c[0] == "uninstall" for c in runner.calls)  # 清理（铁律 3）
        assert any(c[0] == "clear_proxy" for c in runner.calls)
        assert result["cleanup_ok"] is True
        assert result["duration_seconds"] >= 0

    def test_install_failure_degrades(self):
        runner = FakeRunner()
        runner.install_ok = False
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(Path("sample.apk"), "com.malware.sample", [])
        assert result["status"] == "degraded"
        # 未安装 → 不应卸载（避免误删已有同名 App）
        assert not any(c[0] == "uninstall" for c in runner.calls)

    def test_no_package_skips(self):
        runner = FakeRunner()
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(Path("sample.apk"), None, [])
        assert result["status"] == "skipped"
        assert runner.calls == []  # 什么都不做

    def test_cleanup_runs_on_unexpected_error(self):
        runner = FakeRunner()
        runner.monkey_raises = RuntimeError("boom")
        ex = DynamicExecutor(runner, make_options(monkey_interval=1))  # 让 monkey 在收网前触发
        result = ex.run(Path("sample.apk"), "com.malware.sample", [])
        assert result["status"] == "degraded"
        # finally 清理仍然执行：卸载 + 清代理
        assert any(c[0] == "uninstall" for c in runner.calls)
        assert any(c[0] == "clear_proxy" for c in runner.calls)

    def test_idle_stop_terminates_quickly(self):
        runner = FakeRunner()
        runner.foreground = "com.other.app"  # 样本不在前台 → 无流量 → 很快静默
        ex = DynamicExecutor(runner, make_options())
        started = time.time()
        result = ex.run(Path("sample.apk"), "com.malware.sample", [])
        elapsed = time.time() - started
        assert result["status"] == "executed"
        # idle_timeout=2s + poll=1s → 应在数秒内收网，远小于 max_timeout
        assert elapsed < 10
        assert any("terminated" in n for n in result["notes"])
