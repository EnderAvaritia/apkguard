"""动态分析后端抽象与执行入口。

可插拔后端：
  - AdbBackend（本地模拟器/真机，第一优先实现）
  - RemoteBackend（第三方沙箱 API，可选扩展，默认禁用——隐私硬约束）

执行路径：
  - run_dynamic_analysis()：预检（白名单/显式设备/开关）通过后真正运行样本，
    结果写入 Report.dynamic；预检不通过则回退为状态标注（update_dynamic_status）。
  - update_dynamic_status()：纯标注（analyze / scan 路径使用，不执行样本）。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from apkguard.dynamic.adb_runner import AdbRunner
from apkguard.dynamic.device_manager import DeviceInfo, DeviceManager
from apkguard.dynamic.executor import DynamicExecutor
from apkguard.engine.models import AnalyzedApp, DynamicStatus, Report


class DynamicBackend(ABC):
    """动态分析后端接口"""

    name: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """后端当前是否可用"""
        raise NotImplementedError

    @abstractmethod
    def analyze(self, apk_path: Path, app: AnalyzedApp, options: dict) -> dict:
        """对 APK 执行动态分析，返回行为结果 dict。

        流程：安装 → 诱饵数据 → 启动 → 采集（流量/Frida）→ 交互 → 智能终止 → 清理卸载。
        """
        raise NotImplementedError


class AdbBackend(DynamicBackend):
    """本地 adb 模拟器/真机后端（第一优先）"""

    name = "adb"

    def __init__(self, device_manager: DeviceManager):
        self.device_manager = device_manager

    def _target_device(self) -> Optional[DeviceInfo]:
        """准入后的目标设备：显式指定优先，否则第一个在线白名单设备"""
        return self.device_manager.get_online_test_device()

    def is_available(self) -> bool:
        """仅在存在在线目标设备时可用"""
        return self._target_device() is not None

    def analyze(self, apk_path: Path, app: AnalyzedApp, options: dict) -> dict:
        device = self._target_device()
        if device is None:
            return {"status": "skipped", "note": "无在线目标设备 / no online device"}
        runner = AdbRunner(device.serial)
        executor = DynamicExecutor(runner, options)
        result = executor.run(
            apk_path,
            app.package,
            app.dangerous_permissions,
            version_code=app.version_code,
            activities=app.activities,
            exported_activities=app.exported_activities,
        )
        result["device_used"] = device.serial
        result["backend"] = self.name
        return result


def resolve_backend(
    device_manager: DeviceManager, options: dict
) -> Optional[DynamicBackend]:
    """根据配置解析可用的动态后端。"""
    return AdbBackend(device_manager)


def update_dynamic_status(report: Report, device_manager: DeviceManager, options: dict) -> None:
    """第一版动态状态标注：根据配置与设备状态更新报告（降级逻辑）。

    不真正执行样本；仅如实标注动态分析状态，供报告展示。
    """
    dyn = report.dynamic
    dyn.enabled = bool(options.get("enabled", False))

    if not (device_manager.has_whitelist or device_manager.has_explicit_device):
        dyn.status = "skipped"
        dyn.note = (
            "未配置测试设备白名单且未显式指定设备，动态分析未执行（隐私安全默认状态）/ "
            "No test device whitelist or explicit device; dynamic analysis skipped (secure default)"
        )
        return

    if not dyn.enabled:
        dyn.status = "skipped"
        dyn.note = (
            "动态分析开关未开启（config.yaml: dynamic.enabled）/ "
            "Dynamic analysis disabled in config.yaml"
        )
        return

    online = device_manager.get_online_test_device()
    if online is None:
        dyn.status = "skipped"
        if device_manager.has_explicit_device:
            dyn.note = (
                f"显式指定设备 {device_manager.explicit_device} 不在线，动态分析未执行 / "
                f"Explicitly specified device {device_manager.explicit_device} offline; "
                f"dynamic analysis skipped"
            )
        else:
            dyn.note = (
                f"已配置测试设备白名单但无设备在线，动态分析未执行 / "
                f"Test devices configured but none online; dynamic analysis skipped"
            )
        return

    # 有可用设备（白名单或显式指定）在线 → 状态为"待第二阶段执行"
    dyn.status = "degraded"
    dyn.device_used = online.serial
    dyn.backend = "adb"
    if device_manager.has_explicit_device:
        dyn.note = (
            f"显式指定设备 {online.serial}（绕过白名单）在线；动态执行体将在第二阶段交付，"
            f"本次未执行 / Explicitly specified device {online.serial} (whitelist bypass) online; "
            f"dynamic executor lands in phase 2"
        )
    else:
        dyn.note = (
            f"检测到测试设备 {online.serial} 在线；动态执行体将在第二阶段交付，"
            f"本次未执行 / Test device {online.serial} online; dynamic executor lands in phase 2"
        )


def run_dynamic_analysis(
    report: Report,
    device_manager: DeviceManager,
    options: dict,
    apk_path: Path,
    app: AnalyzedApp,
) -> dict:
    """动态分析执行入口（dynamic 命令使用）。

    预检不通过（未启用 / 无目标设备）时回退为状态标注，返回 {"executed": False}；
    通过时真正运行样本并把结果写入 report.dynamic，返回执行结果 dict。
    """
    dyn = report.dynamic
    dyn.enabled = bool(options.get("enabled", False))

    if not (device_manager.has_whitelist or device_manager.has_explicit_device):
        update_dynamic_status(report, device_manager, options)
        return {"executed": False, "reason": "no_device_target"}

    if not dyn.enabled:
        update_dynamic_status(report, device_manager, options)
        return {"executed": False, "reason": "disabled"}

    backend = resolve_backend(device_manager, options)
    if backend is None or not backend.is_available():
        update_dynamic_status(report, device_manager, options)
        return {"executed": False, "reason": "no_online_device"}

    result = backend.analyze(apk_path, app, options)
    result["executed"] = True
    _apply_execution_result(report, result)
    return result


def _apply_execution_result(report: Report, result: dict) -> None:
    """把执行器返回的 result dict 写入 report.dynamic"""
    dyn: DynamicStatus = report.dynamic
    dyn.device_used = result.get("device_used") or dyn.device_used
    dyn.backend = result.get("backend") or dyn.backend

    if result.get("status") == "executed":
        dyn.status = "executed"
        dyn.executed = True
        dyn.note = result.get("note", "")
        dyn.duration_seconds = result.get("duration_seconds")
        dyn.traffic_endpoints = result.get("traffic_endpoints", [])
        dyn.traffic_count = result.get("traffic_count", 0)
        dyn.frida_hooked = result.get("frida_hooked", False)
        dyn.decoy_installed = result.get("decoy_installed", False)
        dyn.cleanup_ok = result.get("cleanup_ok", True)
        dyn.kept_installed = result.get("kept_installed", False)
        dyn.findings = [
            {"type": "note", "message": n} for n in result.get("notes", [])
        ]
    else:
        # degraded / skipped：保留执行器返回的状态与说明
        dyn.status = result.get("status", "degraded")
        dyn.note = result.get("note", "")
