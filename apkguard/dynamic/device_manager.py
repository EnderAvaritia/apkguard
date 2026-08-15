"""测试设备白名单隔离机制（安全核心）。

★ 三条铁律：
  1. 白名单门槛：只有 config.yaml 的 test_devices 中列出的设备才会被用于
     运行恶意样本；不在白名单的 adb 设备（包括用户日常连接的设备）一律拒绝操作。
  2. 样本不落地工作设备：恶意样本只安装到白名单测试设备。
  3. 跑后清理：动态分析结束自动卸载样本并清理采集文件。

★ 显式指定覆盖（CLI --device）：
  用户通过 --device <serial> 显式指定设备时，该设备绕过白名单门槛
  （用户明确授权）。绕过行为会如实标注在报告中，保证可审计。

本模块只做设备管理与准入校验，不执行任何样本安装/操作。
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DeviceInfo:
    """一台 adb 设备的信息"""

    serial: str  # 序列号（emulator-5554 / 设备序列号）
    state: str  # device | offline | unauthorized
    model: str = ""  # 型号（尽力获取）
    allowed: bool = False  # 是否在测试白名单中
    label: str = ""  # 白名单标签（如"恶意样本测试专用AVD"）


class DeviceAccessDenied(Exception):
    """对非白名单设备的操作被拒绝"""

    def __init__(self, serial: str):
        super().__init__(
            f"设备 {serial} 不在测试白名单中，已拒绝操作 / "
            f"Device {serial} is not in the test whitelist; operation denied. "
            f"如需使用，请在 config.yaml 的 test_devices 中显式声明。"
        )


class DeviceManager:
    """adb 设备管理 + 白名单准入校验"""

    def __init__(
        self,
        test_devices: list[str],
        labels: Optional[dict[str, str]] = None,
        explicit_device: Optional[str] = None,
    ):
        # test_devices: 白名单序列号列表；labels: 序列号 → 标签
        # explicit_device: CLI --device 显式指定的设备（绕过白名单，用户明确授权）
        self._whitelist = set(test_devices)
        self._labels = labels or {}
        self._explicit_device = explicit_device

    # ---- 白名单状态 ----

    @property
    def whitelist(self) -> set[str]:
        return set(self._whitelist)

    @property
    def has_whitelist(self) -> bool:
        """是否配置了任何测试设备（空白名单 = 动态分析永不自动触发）"""
        return len(self._whitelist) > 0

    @property
    def explicit_device(self) -> Optional[str]:
        """CLI --device 显式指定的设备序列号（无则为 None）"""
        return self._explicit_device

    @property
    def has_explicit_device(self) -> bool:
        """是否显式指定了设备（--device，绕过白名单门槛）"""
        return bool(self._explicit_device)

    def is_allowed(self, serial: str) -> bool:
        """准入判断：白名单门槛；显式指定（--device）的设备绕过白名单"""
        if self._explicit_device and serial == self._explicit_device:
            return True
        return serial in self._whitelist

    def assert_allowed(self, serial: str) -> None:
        """准入校验：不在白名单且非显式指定 → 抛 DeviceAccessDenied"""
        if not self.is_allowed(serial):
            raise DeviceAccessDenied(serial)

    # ---- adb 交互 ----

    @staticmethod
    def _adb(*args: str) -> str:
        try:
            result = subprocess.run(
                ["adb", *args],
                capture_output=True,
                text=True,
                encoding="utf-8",  # adb 输出为 UTF-8；Windows 系统代码页 GBK 会解码失败
                errors="replace",
                timeout=15,
            )
            return result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return ""

    def list_devices(self) -> list[DeviceInfo]:
        """列出当前所有 adb 在线设备（只读操作）"""
        output = self._adb("devices", "-l")
        devices: list[DeviceInfo] = []
        for line in output.splitlines()[1:]:
            parts = line.split()
            if not parts:
                continue
            serial = parts[0]
            state = parts[1] if len(parts) > 1 else "unknown"
            model = ""
            for part in parts[2:]:
                if part.startswith("model:"):
                    model = part[len("model:"):]
            devices.append(
                DeviceInfo(
                    serial=serial,
                    state=state,
                    model=model,
                    allowed=self.is_allowed(serial),
                    label=self._labels.get(serial, ""),
                )
            )
        return devices

    def get_online_test_device(self) -> Optional[DeviceInfo]:
        """返回可用测试设备：显式指定（--device）优先；否则取第一个在线白名单设备。

        显式指定设备不在线时返回 None（不静默回退到白名单设备，
        避免用到非预期设备）。
        """
        devices = self.list_devices()
        if self._explicit_device:
            for dev in devices:
                if dev.serial == self._explicit_device and dev.state == "device":
                    return dev
            return None
        for dev in devices:
            if dev.allowed and dev.state == "device":
                return dev
        return None

    def describe(self) -> str:
        """当前可用设备状态描述（用于报告标注）"""
        if self._explicit_device:
            online = [
                d
                for d in self.list_devices()
                if d.serial == self._explicit_device and d.state == "device"
            ]
            if not online:
                return (
                    f"显式指定设备 {self._explicit_device} 不在线，动态分析未执行 / "
                    f"Explicitly specified device {self._explicit_device} offline; "
                    f"dynamic analysis not executed"
                )
            return (
                f"已显式指定设备 {self._explicit_device}（绕过白名单）/ "
                f"Using explicitly specified device {self._explicit_device} (whitelist bypass)"
            )
        if not self.has_whitelist:
            return (
                "未配置测试设备白名单，动态分析未执行 / "
                "No test device whitelist configured; dynamic analysis not executed"
            )
        devices = self.list_devices()
        online = [d for d in devices if d.allowed and d.state == "device"]
        if not online:
            return (
                "已配置测试设备白名单但无设备在线，动态分析未执行 / "
                "Test devices configured but none online; dynamic analysis not executed"
            )
        return (
            f"已使用测试设备 {', '.join(d.serial for d in online)} / "
            f"Using test device(s): {', '.join(d.serial for d in online)}"
        )
