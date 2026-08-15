"""检测器：危险权限 + 敏感 API 调用链。

原理：先看 Manifest 声明了哪些危险权限，再确认代码中是否实际调用了
对应敏感 API。声明 + 调用同时存在才报告（声明不调用可能只是 UI 需要）。
同时聚合 YAML 中的 permission 规则与 api 规则结果。
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import (
    RuleSet,
    match_api_rules,
    match_permission_rules,
)
from apkguard.static.detectors.base import BaseDetector

# 危险权限 → 应结合代码调用才显著的场景
_PERMISSION_API_PAIRS: list[dict] = [
    {
        "permission": "android.permission.SEND_SMS",
        "api": "Landroid/telephony/SmsManager;",
        "title": "声明发送短信权限且代码中存在短信发送 API 调用",
        "title_en": "SEND_SMS declared with SMS sending API in code",
        "desc": "同时声明了发送短信权限并在代码中调用短信发送 API，扣费短信/诈骗短信风险极高",
        "severity": Severity.CRITICAL,
        "weight": 5,
    },
    {
        "permission": "android.permission.RECEIVE_SMS",
        "api": "Landroid/content/BroadcastReceiver;",
        "title": "声明接收短信权限且注册了广播接收器",
        "title_en": "RECEIVE_SMS declared with broadcast receiver",
        "desc": "接收短信权限 + 广播接收器组合，可拦截验证码短信实施短信劫持",
        "severity": Severity.HIGH,
        "weight": 4,
    },
    {
        "permission": "android.permission.READ_CONTACTS",
        "api": "Landroid/content/ContentResolver;",
        "title": "声明读取通讯录权限且查询数据",
        "title_en": "READ_CONTACTS declared with data queries",
        "desc": "读取通讯录权限 + ContentResolver 查询组合，可能窃取联系人并外传",
        "severity": Severity.MEDIUM,
        "weight": 3,
    },
    {
        "permission": "android.permission.RECORD_AUDIO",
        "api": "Landroid/media/AudioRecord;",
        "title": "声明录音权限且代码中存在录音调用",
        "title_en": "RECORD_AUDIO declared with audio recording",
        "desc": "录音权限 + 录音 API 调用组合，可能窃听环境声音",
        "severity": Severity.HIGH,
        "weight": 3,
    },
]


class PermissionsDetector(BaseDetector):
    detector_id = "permissions"
    display_name = "危险权限与敏感 API 调用链"
    display_name_en = "Dangerous permissions and sensitive API chains"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        declared = app.declared_permissions

        # 1) YAML 权限规则
        findings.extend(match_permission_rules(rules, declared))

        # 2) YAML API 规则
        findings.extend(match_api_rules(rules, app.called_methods))

        # 3) Python 权限-API 配对检测
        for pair in _PERMISSION_API_PAIRS:
            if pair["permission"] not in declared:
                continue
            api_prefix = pair["api"]
            evidence = [m for m in app.called_methods if m.startswith(api_prefix)]
            if not evidence:
                continue
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title=pair["title"],
                    title_en=pair["title_en"],
                    description=pair["desc"],
                    severity=pair["severity"],
                    weight=pair["weight"],
                    evidence=[pair["permission"], *evidence[:8]],
                )
            )
        return findings
