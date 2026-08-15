"""CLI 报告命名逻辑单元测试：默认以输入文件名命名，含非法字符清理。"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.cli import _default_report_base, _sanitize_filename
from apkguard.engine.models import Report, RiskLevel


def make_report(file_name: str) -> Report:
    return Report(
        file_name=file_name, file_format="APK", file_size=1, sha256="x" * 64,
    )


class TestSanitizeFilename:
    def test_windows_illegal_chars_replaced(self):
        assert _sanitize_filename('a<b>c:d"e/f\\g|h?i*j') == "a_b_c_d_e_f_g_h_i_j"

    def test_empty_falls_back(self):
        assert _sanitize_filename("") == "report"
        assert _sanitize_filename("   ") == "report"

    def test_trailing_dot_removed(self):
        assert _sanitize_filename("app.") == "app"

    def test_truncated_to_max_len(self):
        assert len(_sanitize_filename("x" * 200)) == 60


class TestDefaultReportBase:
    def test_uses_input_file_name(self):
        """默认报告名 = 输入文件名（去掉扩展名），与包名/应用名无关"""
        report = make_report("app.apk")
        report.package = "com.whatever"
        report.app_name = "WangVPN"
        assert _default_report_base(report) == "app"

    def test_multi_dot_file_name(self):
        report = make_report("my.app.v2.apk")
        assert _default_report_base(report) == "my.app.v2"

    def test_no_extension(self):
        report = make_report("sample")
        assert _default_report_base(report) == "sample"


class TestWriteReports:
    """三命令共用写盘助手：默认命名、--json/--html 覆盖、scan 汇总"""

    def test_default_naming(self, tmp_path, monkeypatch):
        from apkguard.cli import _write_report_files

        monkeypatch.chdir(tmp_path)
        _write_report_files(
            "app", None, None,
            lambda p: Path(p).write_text("{}", encoding="utf-8"),
            lambda p: Path(p).write_text("<html></html>", encoding="utf-8"),
        )
        assert (tmp_path / "app.json").exists()
        assert (tmp_path / "app.html").exists()

    def test_custom_names(self, tmp_path, monkeypatch):
        from apkguard.cli import _write_report_files

        monkeypatch.chdir(tmp_path)
        _write_report_files(
            "app", "my.json", "my.html",
            lambda p: Path(p).write_text("{}", encoding="utf-8"),
            lambda p: Path(p).write_text("<html></html>", encoding="utf-8"),
        )
        assert (tmp_path / "my.json").exists()
        assert (tmp_path / "my.html").exists()
        assert not (tmp_path / "app.json").exists()

    def test_scan_summary_naming(self, tmp_path, monkeypatch):
        """scan 通过同一助手写 scan_summary.json/html"""
        from apkguard.cli import _write_report_files

        monkeypatch.chdir(tmp_path)
        _write_report_files(
            "scan_summary", None, None,
            lambda p: Path(p).write_text("{}", encoding="utf-8"),
            lambda p: Path(p).write_text("<html></html>", encoding="utf-8"),
        )
        assert (tmp_path / "scan_summary.json").exists()
        assert (tmp_path / "scan_summary.html").exists()

    def test_html_import_error_degrades_gracefully(self, tmp_path, monkeypatch, capsys):
        """HTML 模块不可用（抛 ImportError）时 JSON 照写、仅警告"""
        from apkguard.cli import _write_report_files

        monkeypatch.chdir(tmp_path)

        def boom(p):
            raise ImportError("html_report unavailable")

        _write_report_files("app", None, None, lambda p: Path(p).write_text("{}", encoding="utf-8"), boom)
        assert (tmp_path / "app.json").exists()
        assert not (tmp_path / "app.html").exists()
        assert "警告" in capsys.readouterr().err


class TestScanSummary:
    """scan 自动输出批量汇总报告"""

    def make_reports(self):
        clean = make_report("clean.apk")
        clean.risk_level = RiskLevel.CLEAN
        suspicious = make_report("susp.apk")
        suspicious.risk_level = RiskLevel.SUSPICIOUS
        malicious = make_report("mal.apk")
        malicious.risk_level = RiskLevel.MALICIOUS
        malicious.total_score = 12
        return [("a/clean.apk", clean), ("b/susp.apk", suspicious), ("c/mal.apk", malicious)]

    def test_json_summary(self, tmp_path):
        from apkguard.output.json_report import write_scan_summary_json

        out = tmp_path / "scan_summary.json"
        write_scan_summary_json(self.make_reports(), ["boom.apk failed"], out, "apk_folder")
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["counts"] == {"clean": 1, "suspicious": 1, "malicious": 1}
        assert data["total"] == 3
        assert data["errors"] == ["boom.apk failed"]
        assert data["files"][0]["path"] == "c/mal.apk"  # 按分数降序
        assert "report" in data["files"][0]

    def test_html_summary(self, tmp_path):
        from apkguard.output.html_report import write_scan_summary_html

        out = tmp_path / "scan_summary.html"
        entries = [(p, r.to_dict()) for p, r in self.make_reports()]
        write_scan_summary_html(entries, ["boom"], "apk_folder", out)
        text = out.read_text(encoding="utf-8")
        assert "apkguard" in text and "clean.apk" in text and "mal.apk" in text
        assert "失败 / Failed" in text  # 错误区块
        assert "<!DOCTYPE html>" in text
