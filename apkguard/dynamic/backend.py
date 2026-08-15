"""动态分析后端抽象（第二阶段执行体，第一版仅接口与降级逻辑）。

可插拔后端：
  - AdbBackend（本地模拟器/真机，第一优先实现）
  - RemoteBackend（第三方沙箱 API，可选扩展，默认禁用——隐私硬约束）

第一版行为：无论是否配置，动态分析均不会真正执行样本；
只会根据配置与设备状态更新报告的 DynamicStatus（降级标注）。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from apkguard.dynamic.device_manager import DeviceManager
from apkguard.engine.models import DynamicStatus, Report


class DynamicBackend(ABC):
    """动态分析后端接口"""

    name: str = ""

    @abstractmethod
    def is_available(self) -> bool:
        """后端当前是否可用"""
        raise NotImplementedError

    @abstractmethod
    def analyze(self, apk_path: Path, options: dict) -> dict:
        """对 APK 执行动态分析，返回行为结果 dict。

        第二阶段实现：安装 → 诱饵数据 → 启动 → 采集（流量/Frida）→
        交互 → 智能终止 → 清理卸载。
        """
        raise NotImplementedError


class AdbBackend(DynamicBackend):
    """本地 adb 模拟器/真机后端（第一优先）"""

    name = "adb"

    def __init__(self, device_manager: DeviceManager):
        self.device_manager = device_manager

    def is_available(self) -> bool:
        """仅在存在在线白名单测试设备时可用"""
        return self.device_manager.get_online_test_device() is not None

    def analyze(self, apk_path: Path, options: dict) -> dict:
        # 第二阶段实现：见类 docstring 注释
        raise NotImplementedError(
            "动态分析执行体将在第二阶段实现 / Dynamic execution lands in phase 2"
        )


def resolve_backend(
    device_manager: DeviceManager, options: dict
) -> Optional[DynamicBackend]:
    """根据配置解析可用的动态后端。

    第一版：始终返回 AdbBackend 实例（用于状态标注），即使不可执行。
    """
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
