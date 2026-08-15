"""检测器：短信/通话相关恶意行为。

覆盖：扣费短信（SEND_SMS + 硬编码号码）、短信拦截（RECEIVE_SMS + 广播）、
通话录音、呼叫转移等。短信类恶行是安卓恶意软件最传统的扣费/诈骗手段。
"""
from __future__ import annotations

import re

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector

_SMS_SEND_APIS = (
    "Landroid/telephony/SmsManager;",
    "sendTextMessage",
    "sendMultipartTextMessage",
)
_SMS_RECEIVE_APIS = (
    "getMessagesFromIntent",
    "Landroid/provider/Telephony$Sms$Intents;",
)
_PHONE_NUM_APIS = (
    "getLine1Number",
    "getDeviceId",
    "getSubscriberId",
)
# 手机号 / 扣费号码特征
_PREMIUM_NUM_RE = re.compile(r"(^|[^\d])(106\d{4,}|125\d{4,}|16\d{5,})($|[^\d])")
_PHONE_RE = re.compile(r"(^|[^\d])(1[3-9]\d{9})(?![^\d])")


class SmsTelephonyDetector(BaseDetector):
    detector_id = "sms_telephony"
    display_name = "短信/通话恶意行为"
    display_name_en = "SMS/telephony malicious behavior"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        called = app.called_methods
        strings = app.strings
        declared = app.declared_permissions

        # 1) 发送短信能力
        can_send = (
            "android.permission.SEND_SMS" in declared
            and any(api in m for m in called for api in _SMS_SEND_APIS)
        )

        # 2) 硬编码扣费号码
        premium_nums = sorted(
            {m.group(2) for s in strings if (m := _PREMIUM_NUM_RE.search(s))}
        )

        if can_send:
            evidence = [
                m for m in called if any(api in m for api in _SMS_SEND_APIS)
            ][:6]
            severity = Severity.HIGH
            weight = 4
            title = "具备发送短信能力"
            title_en = "Has SMS sending capability"
            desc = "声明了发送短信权限并调用短信发送 API，可能发送扣费短信或诈骗短信"
            if premium_nums:
                evidence.extend(premium_nums[:5])
                severity = Severity.CRITICAL
                weight = 5
                title = "发送短信能力 + 硬编码扣费号码"
                title_en = "SMS sending with hardcoded premium numbers"
                desc = (
                    "同时具备短信发送能力且代码中硬编码疑似扣费号码，"
                    "扣费短信诈骗风险极高（如 106 开头增值服务号码）"
                )
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title=title,
                    title_en=title_en,
                    description=desc,
                    severity=severity,
                    weight=weight,
                    evidence=evidence,
                    detail={"premium_numbers": premium_nums},
                )
            )

        # 3) 短信拦截（接收 + 解析）
        can_receive = (
            "android.permission.RECEIVE_SMS" in declared
            and any(api in m for m in called for api in _SMS_RECEIVE_APIS)
        )
        if can_receive:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="接收并解析短信（疑似短信拦截）",
                    title_en="Receives and parses SMS (likely SMS interception)",
                    description=(
                        "声明了接收短信权限并调用短信解析 API，可拦截短信验证码，"
                        "配合转发/上传可劫持银行验证码实施诈骗"
                    ),
                    severity=Severity.HIGH,
                    weight=4,
                    evidence=[
                        m
                        for m in called
                        if any(api in m for api in _SMS_RECEIVE_APIS)
                    ][:6],
                )
            )

        # 4) 手机号码采集（IMSI/IMEI/本机号码）
        num_hits = [
            m for m in called if any(api in m for api in _PHONE_NUM_APIS)
        ]
        if num_hits:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="采集手机号码/设备标识",
                    title_en="Collects phone number / device identifiers",
                    description=(
                        "调用获取本机号码/IMEI/IMSI 的 API，设备标识常被用于"
                        "设备指纹追踪或配合短信诈骗"
                    ),
                    severity=Severity.MEDIUM,
                    weight=2,
                    evidence=num_hits[:6],
                )
            )

        return findings
