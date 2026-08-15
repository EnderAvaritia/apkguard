"""打分与分级：汇总 findings 计算总分，按档位阈值判定风险等级。

阈值语义（config.yaml 中可调）：
  clean_below:   总分 < 此值 → 干净
  malicious_at:  总分 >= 此值 → 恶意
  中间区间 → 可疑
"""
from __future__ import annotations

from apkguard.engine.models import Finding, Report, RiskLevel


def compute_total_score(findings: list[Finding]) -> int:
    """总分 = 所有 finding 分值之和"""
    return sum(f.weight for f in findings)


def classify(score: int, threshold: dict[str, int]) -> RiskLevel:
    """按阈值将总分分级"""
    clean_below = int(threshold.get("clean_below", 4))
    malicious_at = int(threshold.get("malicious_at", 8))
    if score >= malicious_at:
        return RiskLevel.MALICIOUS
    if score >= clean_below:
        return RiskLevel.SUSPICIOUS
    return RiskLevel.CLEAN


def apply_classification(report: Report, threshold: dict[str, int]) -> Report:
    """对报告应用分级：计算总分 + 判定等级 + 记录阈值"""
    report.total_score = compute_total_score(report.findings)
    report.risk_level = classify(report.total_score, threshold)
    report.threshold = threshold
    report.sort_findings()
    return report
