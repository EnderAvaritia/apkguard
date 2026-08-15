"""检测器：C2 网络端点分析。

聚合 network_extract 的端点提取与特征打分结果，输出报告。
规则：无 C2 特征 → 仅记录端点；有特征 → 生成对应 finding。
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, NetworkEndpoint, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector
from apkguard.static.network_extract import extract_network_endpoints

# 端点特征 → 严重级别/分值映射（供汇总 finding 使用）
_FEATURE_WEIGHTS: dict[str, tuple[Severity, int]] = {
    "硬编码公网 IP (hardcoded public IP)": (Severity.HIGH, 3),
    "内网/保留地址 (private/reserved)": (Severity.MEDIUM, 2),
    "非标准端口 (non-standard port)": (Severity.MEDIUM, 2),
    "IDN punycode 伪装 (IDN punycode)": (Severity.HIGH, 3),
    "base64 编码的 URL (base64-encoded URL)": (Severity.HIGH, 3),
    "疑似编码混淆 URL (likely encoded URL)": (Severity.HIGH, 3),
    "含长数字串 (long digit sequence)": (Severity.MEDIUM, 2),
    "高熵随机串 (high entropy)": (Severity.MEDIUM, 2),
    "深层子域 (deep subdomain)": (Severity.LOW, 1),
    "IP 化域名 (IP-as-domain)": (Severity.MEDIUM, 2),
}


class C2NetworkDetector(BaseDetector):
    detector_id = "c2_network"
    display_name = "C2 网络端点分析"
    display_name_en = "C2 network endpoint analysis"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        endpoints = extract_network_endpoints(app.strings)
        if not endpoints:
            return findings

        # 汇总疑似 C2 端点（有特征的）
        suspicious = [e for e in endpoints if e.score > 0]
        total_susp_score = sum(e.score for e in suspicious)

        if suspicious:
            # 统计命中特征
            feature_counts: dict[str, int] = {}
            for e in suspicious:
                for f in e.features:
                    feature_counts[f] = feature_counts.get(f, 0) + 1

            detail = {
                "endpoint_count": len(endpoints),
                "suspicious_count": len(suspicious),
                "top_endpoints": [
                    {
                        "endpoint": e.endpoint,
                        "kind": e.kind,
                        "score": e.score,
                        "features": e.features,
                    }
                    for e in suspicious[:10]
                ],
            }
            evidence = [
                f"{e.endpoint} [{e.kind}] +{e.score}: {'; '.join(e.features[:3])}"
                for e in suspicious[:8]
            ]

            if total_susp_score >= 5 or len(suspicious) >= 3:
                severity = Severity.HIGH
                weight = 4
                title = f"发现 {len(suspicious)} 个疑似 C2 通信端点"
                title_en = f"Found {len(suspicious)} suspicious C2 communication endpoints"
                desc = (
                    "代码中硬编码多个带可疑特征的网络端点（硬编码 IP、非标准端口、"
                    "混淆编码 URL 等），高度疑似命令与控制（C2）服务器地址"
                )
            else:
                severity = Severity.MEDIUM
                weight = 2
                title = f"发现 {len(suspicious)} 个可疑网络端点"
                title_en = f"Found {len(suspicious)} suspicious network endpoints"
                desc = "代码中存在带可疑静态特征的网络端点，需结合其他行为判断是否为 C2 通信"

            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title=title,
                    title_en=title_en,
                    description=desc,
                    severity=severity,
                    weight=weight,
                    evidence=evidence,
                    detail=detail,
                )
            )

        return findings
