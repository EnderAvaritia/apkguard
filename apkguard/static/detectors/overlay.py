"""检测器：悬浮窗 / 覆盖攻击。

恶意软件用 SYSTEM_ALERT_WINDOW 悬浮在其他应用之上，显示钓鱼界面
（伪造银行登录、伪造系统弹窗）诱导用户输入或点击。
检测：悬浮窗权限 + 覆盖层类型常量 + 相关 API。
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector

_OVERLAY_CONSTANTS = (
    "TYPE_APPLICATION_OVERLAY",
    "TYPE_PHONE",
    "TYPE_SYSTEM_ALERT",
    "TYPE_TOAST",
)
_OVERLAY_APIS = (
    "addView",
    "WindowManager",
)
# 覆盖攻击常配合：读取输入 / 监听屏幕解锁 / 获取前台应用
_OVERLAY_COMPANION_APIS = (
    "onInterceptTouchEvent",
    "onTouchEvent",
    "KEYGUARD",
    "getRunningTasks",
)


class OverlayDetector(BaseDetector):
    detector_id = "overlay"
    display_name = "悬浮窗/覆盖攻击"
    display_name_en = "Overlay attack"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        called = app.called_methods
        strings = app.strings
        declared = app.declared_permissions

        has_overlay_perm = "android.permission.SYSTEM_ALERT_WINDOW" in declared

        overlay_const_hits = [s for s in strings if s in _OVERLAY_CONSTANTS]
        overlay_api_hits = [
            m for m in called if any(api in m for api in _OVERLAY_APIS)
        ]
        companion_hits = [
            m for m in called if any(api in m for api in _OVERLAY_COMPANION_APIS)
        ]

        if not has_overlay_perm and not overlay_const_hits:
            return findings

        evidence: list[str] = []
        if overlay_const_hits:
            evidence.extend(overlay_const_hits[:5])
        evidence.extend(overlay_api_hits[:5])
        evidence.extend(companion_hits[:3])

        if has_overlay_perm and overlay_const_hits:
            severity = Severity.HIGH
            weight = 4
            title = "悬浮窗权限 + 覆盖层实现（疑似覆盖攻击）"
            title_en = "Overlay permission with overlay implementation (suspected overlay attack)"
            desc = (
                "同时声明了悬浮窗权限并在代码中创建覆盖层，可覆盖在其他应用之上显示伪造界面，"
                "是钓鱼欺诈（伪造银行/支付页面）的典型手法"
            )
        elif has_overlay_perm or overlay_const_hits:
            severity = Severity.MEDIUM
            weight = 2
            title = "具备悬浮窗能力"
            title_en = "Has overlay capability"
            desc = "应用具备在其他应用之上显示悬浮窗的能力，存在被用于覆盖攻击的可能"

        if not evidence:
            return findings

        findings.append(
            Finding(
                detector_id=self.detector_id,
                title=title,
                title_en=title_en,
                description=desc,
                severity=severity,
                weight=weight,
                evidence=evidence,
            )
        )
        return findings
