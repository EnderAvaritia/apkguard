"""检测器：无障碍服务滥用。

AccessibilityService 是安卓最危险的能力之一：可读取屏幕内容（键盘记录）、
模拟点击（自动授权/自动转账）、获取窗口内容（窃取密码）。
检测：Manifest 声明 BIND_ACCESSIBILITY_SERVICE + 存在 AccessibilityService
子类 + 代码调用关键无障碍 API。
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector

_ACCESSIBILITY_CLASSES = (
    "Landroid/accessibilityservice/AccessibilityService;",
)
# 敏感无障碍 API：获取屏幕内容 / 模拟手势
_SENSITIVE_APIS = (
    "getRootInActiveWindow",
    "findAccessibilityNodeInfosByText",
    "findAccessibilityNodeInfosByViewId",
    "dispatchGesture",
    "performAction",
    "getWindows",
)


class AccessibilityDetector(BaseDetector):
    detector_id = "accessibility"
    display_name = "无障碍服务滥用"
    display_name_en = "Accessibility service abuse"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        called = app.called_methods

        # 是否包含 AccessibilityService 子类（代码中存在继承/实例化）
        service_classes = [
            c for c in app.classes if _ACCESSIBILITY_CLASSES[0].strip("L;") in c
        ]
        has_service_bind = (
            "android.permission.BIND_ACCESSIBILITY_SERVICE" in app.declared_permissions
        )

        if not has_service_bind and not service_classes:
            return findings

        # 敏感调用
        sensitive_calls: list[str] = []
        for m in called:
            if any(api in m for api in _SENSITIVE_APIS):
                sensitive_calls.append(m)

        evidence = list(sensitive_calls[:8])
        if service_classes:
            evidence.extend(service_classes[:3])

        if sensitive_calls:
            severity = Severity.CRITICAL
            weight = 5
            title = "无障碍服务 + 读取屏幕/模拟操作（高危滥用）"
            title_en = "Accessibility service with screen reading / gesture injection (critical abuse)"
            desc = (
                "应用声明了无障碍服务并调用了读取屏幕内容或模拟操作的 API，"
                "可用于键盘记录、自动点击、自动授权、劫持转账，是金融诈骗类恶意软件的典型特征"
            )
        elif has_service_bind and service_classes:
            severity = Severity.HIGH
            weight = 4
            title = "声明并实现了无障碍服务"
            title_en = "Declares and implements accessibility service"
            desc = (
                "应用声明了无障碍服务权限并实现了服务类，具备读取屏幕与模拟操作能力，"
                "需结合具体行为评估用途"
            )
        else:
            severity = Severity.LOW
            weight = 1
            title = "声明了无障碍服务权限"
            title_en = "Declares accessibility service permission"
            desc = "应用声明了无障碍服务权限，但未发现服务实现或敏感调用"

        findings.append(
            Finding(
                detector_id=self.detector_id,
                title=title,
                title_en=title_en,
                description=desc,
                severity=severity,
                weight=weight,
                evidence=evidence or ["BIND_ACCESSIBILITY_SERVICE"],
            )
        )
        return findings
