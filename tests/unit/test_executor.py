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
        self.has_package: bool = False  # 设备上是否已有同包名应用
        self.installed_version: str | None = "100"  # 设备上已有包的 versionCode

    def install(self, apk_path, grant_permissions=True):
        self.calls.append(("install", str(apk_path), grant_permissions))
        return self.install_ok

    def package_installed(self, package):
        self.calls.append(("package_installed", package))
        return self.has_package

    def installed_package_version_code(self, package):
        self.calls.append(("installed_package_version_code", package))
        return self.installed_version

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

    def start_activity(self, package, activity):
        self.calls.append(("start_activity", package, activity))
        return True

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
        "baseline_seconds": 0,  # 测试默认不采集基线，避免拖慢每个用例 10s
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

    def test_termination_reason_labels(self):
        """收网标签与 should_stop 三条件一一对应"""
        from apkguard.dynamic.executor import termination_reason

        # max timeout：超上限强制收网
        assert termination_reason(900, 0, 300, 900, 45) == "max timeout"
        # idle：连续静默超阈值提前收网
        assert termination_reason(10, 45, 300, 900, 45) == "idle"
        # initial timeout：过初始窗口且 App 不在前台（非超时、非静默的兜底分支）
        # 回归锁定：28s 场景（initial=10, idle 未达 45）必须标 initial timeout，而非 idle
        assert termination_reason(28, 28, 10, 900, 45) == "initial timeout"
        assert termination_reason(310, 10, 300, 900, 45) == "initial timeout"

    def test_termination_reason_matches_should_stop(self):
        """should_stop=True 的每个分支，标签与该分支一致"""
        from apkguard.dynamic.executor import termination_reason

        cases = [
            # (elapsed, active, idle_seconds, initial, max, idle) → 期望标签
            (900, True, 0, 300, 900, 45, "max timeout"),
            (10, False, 45, 300, 900, 45, "idle"),
            (28, False, 28, 10, 900, 45, "initial timeout"),  # 用户报告的场景
            (310, False, 10, 300, 900, 45, "initial timeout"),
        ]
        for elapsed, active, idle_s, initial, max_t, idle_t, expected in cases:
            assert should_stop(elapsed, active, idle_s, initial, max_t, idle_t)
            assert termination_reason(elapsed, idle_s, initial, max_t, idle_t) == expected


class TestExecutorRun:
    def test_happy_path_installs_launches_cleans_up(self):
        runner = FakeRunner()
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(Path("sample.apk"), "com.malware.sample", ["android.permission.SEND_SMS"])

        assert result["status"] == "executed"
        calls = [c[0] for c in runner.calls]
        assert calls[0] == "package_installed"  # 安装前预检在先
        assert calls.index("install") < calls.index("launch")
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

    def test_existing_package_refused_by_default(self):
        """设备已有同包名应用（版本不同）+ replace_existing 默认 false → 拒绝安装，不卸载不覆盖"""
        runner = FakeRunner()
        runner.has_package = True
        runner.installed_version = "99"  # 与样本 version_code=100 不同
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(Path("sample.apk"), "com.malware.sample", [], version_code="100")
        assert result["status"] == "degraded"
        assert "已存在同包名" in result["note"]
        # 预检发生，但绝不 install / uninstall（不碰设备已有应用）
        assert any(c[0] == "package_installed" for c in runner.calls)
        assert not any(c[0] == "install" for c in runner.calls)
        assert not any(c[0] == "uninstall" for c in runner.calls)

    def test_existing_package_same_version_skips_install(self):
        """设备已有同包名且版本一致 → 跳过安装直接测试（跑后仍清理卸载）"""
        runner = FakeRunner()
        runner.has_package = True
        runner.installed_version = "100"  # 与样本 version_code=100 相同
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(Path("sample.apk"), "com.malware.sample", [], version_code="100")
        assert result["status"] == "executed"
        # 不安装（同版本已就绪）
        assert not any(c[0] == "install" for c in runner.calls)
        assert any("same version" in n for n in result["notes"])
        assert any(c[0] == "launch" for c in runner.calls)
        # 跑后清理仍卸载（铁律 3：样本不留设备）
        assert any(c[0] == "uninstall" for c in runner.calls)

    def test_existing_package_unknown_version_refused_by_default(self):
        """设备版本未知（解析失败）+ 默认配置 → 保守拒绝"""
        runner = FakeRunner()
        runner.has_package = True
        runner.installed_version = None
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(Path("sample.apk"), "com.malware.sample", [], version_code="100")
        assert result["status"] == "degraded"
        assert not any(c[0] == "install" for c in runner.calls)

    def test_existing_package_replaced_when_configured(self):
        """版本不同 + replace_existing=true → 先卸载旧包再安装（干净环境）"""
        runner = FakeRunner()
        runner.has_package = True
        runner.installed_version = "99"  # 与样本 version_code=100 不同
        ex = DynamicExecutor(runner, make_options(replace_existing=True))
        result = ex.run(Path("sample.apk"), "com.malware.sample", [], version_code="100")
        assert result["status"] == "executed"
        calls = [c[0] for c in runner.calls]
        assert calls.index("uninstall") < calls.index("install")  # 先卸再装
        assert calls.index("install") < calls.index("launch")
        assert any("different version" in n for n in result["notes"])

    def test_existing_package_replace_uninstall_failure_aborts(self):
        """replace_existing=true 但卸载失败 → 中止，不安装"""
        runner = FakeRunner()
        runner.has_package = True
        runner.installed_version = "99"
        runner.uninstall_ok = False
        ex = DynamicExecutor(runner, make_options(replace_existing=True))
        result = ex.run(Path("sample.apk"), "com.malware.sample", [], version_code="100")
        assert result["status"] == "degraded"
        assert not any(c[0] == "install" for c in runner.calls)

    def test_no_package_skips(self):
        runner = FakeRunner()
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(Path("sample.apk"), None, [])
        assert result["status"] == "skipped"
        assert runner.calls == []  # 什么都不做

    def test_cleanup_runs_on_unexpected_error(self):
        runner = FakeRunner()
        runner.monkey_raises = RuntimeError("boom")
        # first_interaction_delay=1：让首轮 monkey 在 idle 收网（2s）前触发
        ex = DynamicExecutor(runner, make_options(monkey_interval=1, first_interaction_delay=1))
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

    def test_activity_driving_uses_exported_only_by_default(self):
        """默认只唤起可导出 activity（exported-only），不碰非导出内部组件"""
        runner = FakeRunner()
        ex = DynamicExecutor(runner, make_options())
        activities = ["com.x.A", "com.x.Hidden"]
        result = ex.run(
            Path("sample.apk"),
            "com.x",
            [],
            activities=activities,
            exported_activities=["com.x.A"],
        )
        assert result["status"] == "executed"
        started_acts = [c[2] for c in runner.calls if c[0] == "start_activity"]
        assert started_acts == ["com.x.A"]  # 只有导出的被唤起
        assert any("exported-only" in n for n in result["notes"])

    def test_activity_driving_all_when_hidden_enabled(self):
        """interact_hidden_activities=true → 唤起全部 activity（含非导出）"""
        runner = FakeRunner()
        ex = DynamicExecutor(runner, make_options(interact_hidden_activities=True))
        activities = ["com.x.A", "com.x.Hidden"]
        result = ex.run(
            Path("sample.apk"),
            "com.x",
            [],
            activities=activities,
            exported_activities=["com.x.A"],
        )
        assert result["status"] == "executed"
        started_acts = {c[2] for c in runner.calls if c[0] == "start_activity"}
        assert started_acts == {"com.x.A", "com.x.Hidden"}
        assert any("(all)" in n for n in result["notes"])

    def test_activity_driving_disabled_skips(self):
        """interact_activities=false → 完全不唤起 activity"""
        runner = FakeRunner()
        ex = DynamicExecutor(runner, make_options(interact_activities=False))
        result = ex.run(
            Path("sample.apk"),
            "com.x",
            [],
            activities=["com.x.A"],
            exported_activities=["com.x.A"],
        )
        assert result["status"] == "executed"
        assert not any(c[0] == "start_activity" for c in runner.calls)

    def test_activity_driving_empty_exported_skips(self):
        """全非导出 + 默认配置 → 一组都不唤起（空导出集合是合法状态）"""
        runner = FakeRunner()
        ex = DynamicExecutor(runner, make_options())
        result = ex.run(
            Path("sample.apk"),
            "com.x",
            [],
            activities=["com.x.Hidden"],
            exported_activities=[],
        )
        assert result["status"] == "executed"
        assert not any(c[0] == "start_activity" for c in runner.calls)
