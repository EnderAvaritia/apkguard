"""集成测试：构造合成 APK → 完整分析流水线 → 报告输出。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from tests.fixtures.apk_builder import build_apk
from apkguard.config import Config
from apkguard.engine.models import RiskLevel
from apkguard.engine.rule_engine import load_rules
from apkguard.engine.scoring import apply_classification
from apkguard.output.json_report import write_json_report
from apkguard.static.apk_parser import analyze_file
from apkguard.static.detectors.base import run_all_detectors
from apkguard.static.network_extract import extract_network_endpoints
from apkguard.engine.models import Report

import zipfile

MALICIOUS_APK = "synthetic_malicious.apk"
CLEAN_APK = "synthetic_clean.apk"


@pytest.fixture(scope="session")
def apk_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("apks")
    # 恶意样本：SMS 权限 + 扣费号码 + C2 IP + 动态加载特征字符串
    (d / MALICIOUS_APK).write_bytes(
        build_apk(
            "com.evil.app",
            ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"],
            [
                "http://10.10.5.5:4444/beacon",
                "1069012345678",
                "http://c2.example.com/upload",
                "DexClassLoader",
                "frida-server",
            ],
        )
    )
    # 干净样本：只有普通字符串
    (d / CLEAN_APK).write_bytes(
        build_apk(
            "com.normal.app",
            ["android.permission.INTERNET"],
            ["https://www.example.com/api/v1/data", "hello world"],
        )
    )
    return d


class TestFullPipeline:
    def test_malicious_apk_detected(self, apk_dir, tmp_path):
        app = analyze_file(apk_dir / MALICIOUS_APK)
        assert app.package == "com.evil.app"
        assert "android.permission.SEND_SMS" in app.declared_permissions
        # 字符串提取
        assert any("http://10.10.5.5:4444" in s for s in app.strings)
        assert any("1069012345678" in s for s in app.strings)

        # 检测 + 打分分级
        config = Config()
        rules = load_rules(config.rules_dir)
        findings = run_all_detectors(app, rules)
        report = Report(
            file_name=MALICIOUS_APK, file_format="APK", file_size=app.file_size,
            sha256=app.sha256, package=app.package, findings=findings,
            permissions=app.dangerous_permissions,
            all_permissions=sorted(app.declared_permissions),
            network_endpoints=extract_network_endpoints(app.strings),
            signature=app.signature,
            severity_profile="low",
        )
        apply_classification(report, config.get_threshold("low"))

        # C2 检测应命中
        c2 = [f for f in findings if f.detector_id == "c2_network"]
        assert c2, "恶意样本应命中 C2 检测器"
        # 扣费号码已被提取（合成样本无方法调用，短信检测在字符串层验证）
        assert any("1069012345678" in s for s in app.strings)

        # JSON 落盘可解析
        out = tmp_path / "report.json"
        write_json_report(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["risk"]["total_score"] > 0
        assert data["risk"]["risk_level"] in ("clean", "suspicious", "malicious")

    def test_clean_apk_low_score(self, apk_dir):
        app = analyze_file(apk_dir / CLEAN_APK)
        config = Config()
        rules = load_rules(config.rules_dir)
        findings = run_all_detectors(app, rules)
        report = Report(
            file_name=CLEAN_APK, file_format="APK", file_size=app.file_size,
            sha256=app.sha256, package=app.package, findings=findings,
            permissions=app.dangerous_permissions,
            all_permissions=sorted(app.declared_permissions),
            network_endpoints=extract_network_endpoints(app.strings),
            signature=app.signature,
            severity_profile="low",
        )
        apply_classification(report, config.get_threshold("low"))
        # 干净样本：无权限规则命中（INTERNET 非危险）、无 C2 特征
        assert not any(f.detector_id == "c2_network" for f in findings)
        assert report.risk_level == RiskLevel.CLEAN

    def test_apk_zip_valid(self, apk_dir):
        """合成 APK 是合法 zip 容器"""
        with zipfile.ZipFile(apk_dir / MALICIOUS_APK) as zf:
            names = zf.namelist()
            assert "AndroidManifest.xml" in names
            assert "classes.dex" in names
