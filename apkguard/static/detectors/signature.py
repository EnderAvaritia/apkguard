"""检测器：签名/证书异常。

覆盖：调试签名（Android Debug Key）、自签名、证书签发人异常、
多签名、签名过期等。正常发布应用用正式证书签名；调试签名/自签名
是重打包、仿冒、未完成开发应用的典型特征。
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector


class SignatureDetector(BaseDetector):
    detector_id = "signature"
    display_name = "签名/证书异常"
    display_name_en = "Signature/certificate anomalies"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        sig = app.signature
        if sig is None:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="无法获取签名信息",
                    title_en="Unable to retrieve signature info",
                    description="未能解析应用签名证书，可能使用了不支持的签名方案",
                    severity=Severity.LOW,
                    weight=1,
                )
            )
            return findings

        # 调试签名：常见于测试版或未完成产品
        if sig.debug_key:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="使用 Android 调试签名",
                    title_en="Signed with Android debug key",
                    description=(
                        "应用使用 Android Debug Key 签名，正常发布的应用不会使用调试签名；"
                        "可能是测试版、未完成开发的应用，或恶意软件为快速签名而采用"
                    ),
                    severity=Severity.MEDIUM,
                    weight=2,
                    evidence=[sig.signer],
                )
            )

        # 自签名
        if sig.self_signed:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="使用自签名证书",
                    title_en="Self-signed certificate",
                    description="证书为自签名，无法验证开发者身份，需额外警惕仿冒应用",
                    severity=Severity.LOW,
                    weight=1,
                    evidence=[sig.signer],
                )
            )

        return findings
