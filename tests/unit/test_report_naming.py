"""CLI 报告命名逻辑单元测试：默认以输入文件名命名，含非法字符清理。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.cli import _default_report_base, _sanitize_filename
from apkguard.engine.models import Report


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
