"""UI 交互（动态分析阶段）。

策略（按 README 设计）：
  1. 预授权：install -g + pm grant 直接授予危险权限（等效"弹窗授权优先点允许"）
  2. 兜底交互：monkey 随机点击，驱动 App 走到敏感行为路径
所有操作 best-effort，失败仅记录，不阻断主流程。
"""
from __future__ import annotations

from typing import Optional

from apkguard.dynamic.adb_runner import AdbRunner


def pre_grant_permissions(
    runner: AdbRunner, package: str, permissions: list[str]
) -> list[str]:
    """pm grant 危险权限；返回成功授权的权限列表"""
    return runner.grant_permissions(package, permissions)


def drive_interaction(
    runner: AdbRunner,
    package: str,
    events: int = 200,
    foreground: Optional[str] = None,
) -> bool:
    """monkey 随机事件驱动 App 交互；App 已退出前台时跳过"""
    if foreground is not None and foreground != package:
        return False
    return runner.monkey(package, events=events)
