"""检测器：隐私数据外传模式。

检测"读取敏感数据 API + 网络上传 API 同现"的组合。
单看读取或单看上传都不够定罪，但同现构成完整的数据窃取链路。
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector

# 敏感数据读取 API（按数据类别分组）
_SENSITIVE_READERS: dict[str, tuple[str, ...]] = {
    "通讯录": ("Landroid/provider/ContactsContract;", "query"),
    "短信": ("Landroid/provider/Telephony$Sms;", "Landroid/provider/Telephony$Inbox;"),
    "通话记录": ("Landroid/provider/CallLog;",),
    "地理位置": ("Landroid/location/LocationManager;", "getLastKnownLocation"),
    "设备信息": ("getDeviceId", "getSubscriberId", "getImei", "getSimSerialNumber"),
    "应用列表": ("getInstalledPackages", "getInstalledApplications"),
    "账户信息": ("Landroid/accounts/AccountManager;",),
}

# 网络上传 API
_UPLOAD_APIS = (
    "Ljava/net/HttpURLConnection;",
    "Ljava/net/URLConnection;",
    "Lorg/apache/http/client/methods/HttpPost;",
    "Lorg/apache/http/client/methods/HttpGet;",
    "Lokhttp3/Request$Builder;",
    "Lokhttp3/OkHttpClient;",
    "Ljava/net/Socket;",
    "Landroid/webkit/WebView;",
    "Lretrofit2/",
    "Ljava/io/DataOutputStream;",
)


class DataExfilDetector(BaseDetector):
    detector_id = "data_exfil"
    display_name = "隐私数据外传模式"
    display_name_en = "Privacy data exfiltration pattern"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        called = app.called_methods

        # 找出命中的敏感读取类别
        hit_categories: list[str] = []
        for category, apis in _SENSITIVE_READERS.items():
            hits = [m for m in called if any(api in m for api in apis)]
            if hits:
                hit_categories.append(category)

        if not hit_categories:
            return findings

        # 上传能力
        upload_calls = [
            m for m in called if any(api in m for api in _UPLOAD_APIS)
        ]
        has_upload = bool(upload_calls)

        # 组合判定
        if has_upload:
            severity = Severity.HIGH
            weight = 4
            title = f"读取敏感数据（{'、'.join(hit_categories)}）且具备网络上传能力"
            title_en = f"Reads sensitive data ({', '.join(hit_categories)}) with network upload capability"
            desc = (
                f"应用读取{'、'.join(hit_categories)}数据，同时代码中存在网络上传调用，"
                "构成完整的数据窃取外传链路，需重点核查数据流向"
            )
            evidence = [*hit_categories, *upload_calls[:6]]
        else:
            severity = Severity.MEDIUM
            weight = 2
            title = f"读取敏感数据（{'、'.join(hit_categories)}）"
            title_en = f"Reads sensitive data ({', '.join(hit_categories)})"
            desc = (
                f"应用读取{'、'.join(hit_categories)}数据，虽未发现直接的上传调用，"
                "仍需结合网络行为评估数据去向"
            )
            evidence = hit_categories

        findings.append(
            Finding(
                detector_id=self.detector_id,
                title=title,
                title_en=title_en,
                description=desc,
                severity=severity,
                weight=weight,
                evidence=evidence,
                detail={
                    "categories": hit_categories,
                    "has_upload": has_upload,
                    "upload_call_count": len(upload_calls),
                },
            )
        )
        return findings
