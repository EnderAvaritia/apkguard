"""规则引擎单元测试：YAML 规则加载、匹配、打分分级。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.config import Config
from apkguard.engine.models import AnalyzedApp, Report, RiskLevel
from apkguard.engine.rule_engine import (
    RuleSet,
    load_rules,
    match_api_rules,
    match_permission_rules,
    match_string_feature_rules,
)
from apkguard.engine.scoring import apply_classification, classify
from apkguard.engine.models import Finding, Severity


@pytest.fixture(scope="session")
def rules() -> RuleSet:
    config = Config()
    return load_rules(config.rules_dir)


class TestRuleLoading:
    def test_rules_loaded(self, rules: RuleSet):
        assert len(rules.all_rules) > 0

    def test_all_three_types_present(self, rules: RuleSet):
        types = {r.rule_type for r in rules.all_rules}
        assert {"permission", "api", "string_feature"} <= types


class TestPermissionRules:
    def test_match_existing_permission(self, rules: RuleSet):
        findings = match_permission_rules(rules, {"android.permission.SEND_SMS"})
        ids = {f.detector_id for f in findings}
        assert "rule:sms_send" in ids
        hit = next(f for f in findings if f.detector_id == "rule:sms_send")
        assert hit.weight == 4
        assert hit.severity == Severity.HIGH

    def test_no_match_for_unknown_permission(self, rules: RuleSet):
        findings = match_permission_rules(rules, {"android.permission.INTERNET"})
        assert findings == []


class TestApiRules:
    def test_match_dex_class_loader(self, rules: RuleSet):
        called = {"Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;)V"}
        findings = match_api_rules(rules, called)
        ids = {f.detector_id for f in findings}
        assert "rule:dex_class_loader" in ids

    def test_no_match(self, rules: RuleSet):
        findings = match_api_rules(rules, {"Ljava/lang/Object;->toString()Ljava/lang/String;"})
        assert findings == []


class TestStringFeatureRules:
    def test_match_feature(self, rules: RuleSet):
        findings = match_string_feature_rules(
            rules, {"some/prefix/xposed_core.jar"}
        )
        ids = {f.detector_id for f in findings}
        assert "rule:xposed_check" in ids


class TestScoring:
    def test_classify_clean(self):
        assert classify(0, {"clean_below": 4, "malicious_at": 8}) == RiskLevel.CLEAN

    def test_classify_suspicious(self):
        assert classify(6, {"clean_below": 4, "malicious_at": 8}) == RiskLevel.SUSPICIOUS

    def test_classify_malicious(self):
        assert classify(9, {"clean_below": 4, "malicious_at": 8}) == RiskLevel.MALICIOUS

    def test_apply_classification_sorts_findings(self):
        low = Finding("t", "低", "Low", "", Severity.LOW, 1)
        high = Finding("t", "高", "High", "", Severity.HIGH, 3)
        report = Report(
            file_name="t.apk", file_format="APK", file_size=1, sha256="x" * 64,
            findings=[low, high],
        )
        apply_classification(report, {"clean_below": 4, "malicious_at": 8})
        assert report.total_score == 4
        assert report.risk_level == RiskLevel.SUSPICIOUS
        assert report.findings[0].weight >= report.findings[1].weight
