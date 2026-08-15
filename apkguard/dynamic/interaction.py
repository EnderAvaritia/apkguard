"""UI 交互（动态分析阶段）。

策略（按 README 设计）：
  1. 预授权：install -g + pm grant 直接授予危险权限（等效"弹窗授权优先点允许"）
  2. 随机唤起 activity：am start 直达 activity 的 onCreate/onResume，强制执行
     更多代码路径（恶意行为常藏在非 launcher activity 中，随机点击永远点不到）。
     默认只唤起"可被外部唤起"的 activity（exported=true / 带 intent-filter）——
     由调用方（executor 按 config 决定）传入筛选后的列表；非导出内部组件只在
     显式开启 interact_hidden_activities 时才被唤起。
  3. 兜底交互：monkey 随机点击，驱动只在 UI 操作后出现的逻辑
所有操作 best-effort，失败仅记录，不阻断主流程。
"""
from __future__ import annotations

import random
import time
from typing import Optional

from apkguard.dynamic.adb_runner import AdbRunner

# 逐个唤起 activity 之间的间隔（秒），避免启动风暴
_ACTIVITY_LAUNCH_DELAY = 1.0


def pre_grant_permissions(
    runner: AdbRunner, package: str, permissions: list[str]
) -> list[str]:
    """pm grant 危险权限；返回成功授权的权限列表"""
    return runner.grant_permissions(package, permissions)


def drive_activities(
    runner: AdbRunner,
    package: str,
    activities: list[str],
    shuffle: bool = True,
) -> list[str]:
    """随机顺序逐个唤起给定 activity 列表；返回成功启动的组件列表。

    - 传入的列表由调用方决定（默认=可导出集合，见 executor）
    - shuffle=True：每次运行顺序不同，避免固定路径
    - best-effort：无法启动/崩溃一律忽略（崩溃本身也是行为证据，
      由 logcat/后续采集兜底）
    """
    acts = list(activities)
    if shuffle:
        random.shuffle(acts)
    launched: list[str] = []
    for act in acts:
        if runner.start_activity(package, act):
            launched.append(act)
        time.sleep(_ACTIVITY_LAUNCH_DELAY)
    return launched


def drive_interaction(
    runner: AdbRunner,
    package: str,
    events: int = 200,
    foreground: Optional[str] = None,
) -> bool:
    """把 App 拉回前台并注入 monkey 随机事件；返回是否执行了交互。

    对会自动退后台的 App（代理/常驻类）尤其关键：monkey 事件必须落在
    App 自己的窗口上才有意义。App 不在前台时先 `am start` 尽力拉回，再注入。
    """
    if foreground is None or foreground != package:
        runner.launch(package)  # best-effort 拉回前台（launch 内部会解析 launcher activity）
    return runner.monkey(package, events=events)
