"""命令行入口：apkguard analyze / scan / dynamic

用法示例:
  apkguard analyze app.apk                # 单文件分析
  apkguard analyze app.apk --json out.json  # 同时导出 JSON
  apkguard analyze app.apk --html out.html  # 同时导出 HTML
  apkguard scan ./apk_dir/                # 批量扫描
  apkguard scan ./apk_dir/ --workers 4    # 指定并发
  apkguard dynamic app.apk                # 动态分析（第二阶段，当前为状态标注）
"""
from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from apkguard import __version__
from apkguard.config import Config
from apkguard.dynamic.backend import update_dynamic_status
from apkguard.dynamic.device_manager import DeviceManager
from apkguard.engine.models import AnalyzedApp, Report
from apkguard.engine.rule_engine import RuleSet, load_rules
from apkguard.engine.scoring import apply_classification
from apkguard.output import console
from apkguard.output.json_report import write_json_report
from apkguard.static.apk_parser import analyze_file
from apkguard.static.detectors.base import run_all_detectors


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apkguard",
        description="Android 恶意行为静态检测工具 (APK/AAB) / Android malware behavior detector",
    )
    parser.add_argument("--version", action="version", version=f"apkguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # analyze 子命令
    p_analyze = sub.add_parser("analyze", help="单文件分析 / Analyze a single APK/AAB")
    p_analyze.add_argument("file", help="APK/AAB 文件路径")
    p_analyze.add_argument("--severity", choices=["low", "normal", "high"], default="low",
                           help="风险阈值档位 (默认 low: 少漏报)")
    p_analyze.add_argument("--rules-dir", default=None, help="自定义规则目录")
    p_analyze.add_argument("--json", default=None, metavar="OUT.json", help="导出 JSON 报告")
    p_analyze.add_argument("--html", default=None, metavar="OUT.html", help="导出 HTML 报告")
    p_analyze.add_argument("--config", default=None, metavar="config.yaml", help="自定义配置文件")

    # scan 子命令
    p_scan = sub.add_parser("scan", help="批量扫描目录 / Batch scan a directory")
    p_scan.add_argument("dir", help="包含 APK/AAB 的目录")
    p_scan.add_argument("--severity", choices=["low", "normal", "high"], default="low",
                        help="风险阈值档位 (默认 low: 少漏报)")
    p_scan.add_argument("--rules-dir", default=None, help="自定义规则目录")
    p_scan.add_argument("--workers", type=int, default=0,
                        help="并发数 (0=自动探测 CPU 核数)")
    p_scan.add_argument("--json-dir", default=None, metavar="OUT_DIR", help="逐样本 JSON 报告输出目录")
    p_scan.add_argument("--config", default=None, metavar="config.yaml", help="自定义配置文件")

    # dynamic 子命令
    p_dynamic = sub.add_parser("dynamic", help="动态分析 (第二阶段) / Dynamic analysis (phase 2)")
    p_dynamic.add_argument("file", help="APK/AAB 文件路径")
    p_dynamic.add_argument("--config", default=None, metavar="config.yaml", help="自定义配置文件")

    return parser


def _resolve_config(args) -> Config:
    config = Config(Path(args.config) if args.config else None)
    if getattr(args, "rules_dir", None):
        config.set_rules_dir(args.rules_dir)
    return config


def _make_report(app: AnalyzedApp, config: Config, severity: str, rules: RuleSet) -> Report:
    """解析结果 → 检测 → 打分分级 → Report"""
    findings = run_all_detectors(app, rules)
    report = Report(
        file_name=Path(app.file_path).name,
        file_format=app.file_format,
        file_size=app.file_size,
        sha256=app.sha256,
        package=app.package,
        app_name=app.app_name,
        version=app.version,
        min_sdk=app.min_sdk,
        target_sdk=app.target_sdk,
        findings=findings,
        permissions=app.dangerous_permissions,
        all_permissions=sorted(app.declared_permissions),
        network_endpoints=[],
        signature=app.signature,
        parse_warnings=app.parse_warnings,
        severity_profile=severity,
    )
    # 补充网络端点（由 C2 检测器提取，从 findings detail 中恢复或重新提取）
    from apkguard.static.network_extract import extract_network_endpoints

    report.network_endpoints = extract_network_endpoints(app.strings)
    apply_classification(report, config.get_threshold(severity))
    return report


def _attach_dynamic_status(report: Report, config: Config) -> None:
    """按配置与设备状态更新报告的动态分析标注（第一版不真正执行）"""
    dm = DeviceManager(config.test_devices)
    update_dynamic_status(report, dm, config.dynamic_options)


def cmd_analyze(args) -> int:
    config = _resolve_config(args)
    rules = load_rules(config.rules_dir)
    path = Path(args.file)
    if not path.exists():
        console._c(f"错误：文件不存在 / File not found: {path}", "red")
        return 1

    app = analyze_file(path)
    report = _make_report(app, config, args.severity, rules)
    _attach_dynamic_status(report, config)

    console.print_analysis_report(report)

    if args.json:
        write_json_report(report, Path(args.json))
        print(f"JSON 报告已写入 / JSON report written: {args.json}")
    if args.html:
        try:
            from apkguard.output.html_report import write_html_report

            write_html_report(report.to_dict(), Path(args.html))
            print(f"HTML 报告已写入 / HTML report written: {args.html}")
        except ImportError:
            print("警告：HTML 报告模块不可用 / Warning: HTML report module unavailable",
                  file=sys.stderr)
    return 0


def cmd_scan(args) -> int:
    config = _resolve_config(args)
    rules = load_rules(config.rules_dir)
    root = Path(args.dir)
    if not root.is_dir():
        console._c(f"错误：目录不存在 / Directory not found: {root}", "red")
        return 1

    files = sorted(
        p
        for p in root.rglob("*")
        if p.is_file()
        and p.suffix.lower() in (".apk", ".aab")
        and not p.name.startswith(".")
    )
    if not files:
        console._c(f"目录中没有 APK/AAB 文件 / No APK/AAB found in {root}", "yellow")
        return 1

    workers = args.workers or config.scan_workers or 0
    if workers <= 0:
        import os

        workers = max(1, os.cpu_count() or 1)

    console._c(
        f"开始批量扫描 {len(files)} 个文件，并发 {workers} / Scanning {len(files)} files with {workers} workers",
        "cyan",
    )
    results: list[tuple[str, Report]] = []
    errors: list[str] = []

    def scan_one(p: Path) -> tuple[str, Report]:
        try:
            app = analyze_file(p)
            report = _make_report(app, config, args.severity, rules)
            _attach_dynamic_status(report, config)
            if args.json_dir:
                out = Path(args.json_dir) / f"{p.stem}.json"
                out.parent.mkdir(parents=True, exist_ok=True)
                write_json_report(report, out)
            return str(p), report
        except Exception as e:
            raise RuntimeError(f"{p}: {e}") from e

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_one, p): p for p in files}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                errors.append(str(e))

    console.print_scan_summary(results, errors)
    return 0


def cmd_dynamic(args) -> int:
    config = _resolve_config(args)
    path = Path(args.file)
    if not path.exists():
        console._c(f"错误：文件不存在 / File not found: {path}", "red")
        return 1

    app = analyze_file(path)
    rules = load_rules(config.rules_dir)
    report = _make_report(app, config, "low", rules)
    dm = DeviceManager(config.test_devices)
    update_dynamic_status(report, dm, config.dynamic_options)

    console.print_analysis_report(report)
    console._c("提示：动态分析执行体将在第二阶段交付 / Dynamic executor lands in phase 2", "yellow")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "analyze": cmd_analyze,
        "scan": cmd_scan,
        "dynamic": cmd_dynamic,
    }
    return handlers[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
