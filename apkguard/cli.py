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
import logging
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from apkguard import __version__
from apkguard.config import Config
from apkguard.dynamic.backend import run_dynamic_analysis, update_dynamic_status
from apkguard.dynamic.device_manager import DeviceManager
from apkguard.engine.models import AnalyzedApp, Report
from apkguard.engine.rule_engine import RuleSet, load_rules
from apkguard.engine.scoring import apply_classification
from apkguard.output import console
from apkguard.output.json_report import write_json_report, write_scan_summary_json
from apkguard.static.apk_parser import analyze_file
from apkguard.static.detectors.base import run_all_detectors

# 单文件分析的估算内存需求：进程基座（androguard 导入等）+ 文件大小 × 膨胀系数。
# 实测 Picacg 13MB → 峰值 195MB（约 15MB/MB）；大文件边际膨胀略低，取 12 保守。
_SCAN_EST_BASE_MB = 150
_SCAN_EST_PER_MB = 12
# 内存预算 = 物理内存 × 50%（留一半给系统与其他程序）
_SCAN_MEM_BUDGET_RATIO = 0.5


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
    p_analyze.add_argument("--json", default=None, metavar="OUT.json",
                           help="JSON 报告路径（默认以 App 名称命名输出）")
    p_analyze.add_argument("--html", default=None, metavar="OUT.html",
                           help="HTML 报告路径（默认以 App 名称命名输出）")
    p_analyze.add_argument("--config", default=None, metavar="config.yaml", help="自定义配置文件")
    p_analyze.add_argument("--device", default=None, metavar="SERIAL",
                           help="显式指定 adb 设备（绕过 test_devices 白名单）")

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
    p_dynamic.add_argument("--device", default=None, metavar="SERIAL",
                           help="显式指定 adb 设备（绕过 test_devices 白名单）")
    p_dynamic.add_argument("--no-static", action="store_true",
                           help="跳过静态检测与打分，仅解析包名/权限后直接动态分析")
    p_dynamic.add_argument("--manual-login", action="store_true",
                           help="启动 App 后暂停自动化交互，等待手动登录（设备上登录后按回车继续），"
                                "应对需要登录的样本（等价 dynamic.manual_login: true）")
    p_dynamic.add_argument("--json", default=None, metavar="OUT.json",
                           help="JSON 报告路径（默认以输入文件名命名输出）")
    p_dynamic.add_argument("--html", default=None, metavar="OUT.html",
                           help="HTML 报告路径（默认以输入文件名命名输出）")

    return parser


def _resolve_config(args) -> Config:
    config = Config(Path(args.config) if args.config else None)
    if getattr(args, "rules_dir", None):
        config.set_rules_dir(args.rules_dir)
    return config


def _make_report(
    app: AnalyzedApp, config: Config, severity: str, rules: RuleSet | None
) -> Report:
    """解析结果 → 检测 → 打分分级 → Report。

    rules=None（--no-static）：跳过全部静态检测与打分，只保留解析产物
    （包名/权限/签名等，动态执行仍需），报告标注"静态分析已跳过"。
    """
    if rules is None:
        warnings = list(app.parse_warnings) + [
            "静态分析已跳过（--no-static）/ Static analysis skipped (--no-static)"
        ]
        return Report(
            file_name=Path(app.file_path).name,
            file_format=app.file_format,
            file_size=app.file_size,
            sha256=app.sha256,
            package=app.package,
            app_name=app.app_name,
            version=app.version,
            min_sdk=app.min_sdk,
            target_sdk=app.target_sdk,
            permissions=[],
            all_permissions=sorted(app.declared_permissions),
            network_endpoints=[],
            signature=app.signature,
            parse_warnings=warnings,
            severity_profile=severity,
        )

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

    report.network_endpoints = extract_network_endpoints(app.strings, app.classes)
    apply_classification(report, config.get_threshold(severity))
    return report


def _attach_dynamic_status(report: Report, config: Config, explicit_device: str | None = None) -> None:
    """按配置与设备状态更新报告的动态分析标注（第一版不真正执行）"""
    dm = DeviceManager(config.test_devices, explicit_device=explicit_device)
    update_dynamic_status(report, dm, config.dynamic_options)


def _sanitize_filename(name: str, max_len: int = 60) -> str:
    """清理为安全的文件名：移除 Windows 非法字符，兜底 'report'"""
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name)
    cleaned = cleaned.strip().strip(".")  # 结尾点号在 Windows 非法
    cleaned = cleaned[:max_len].strip()
    return cleaned or "report"


def _default_report_base(report: Report) -> str:
    """默认报告文件名主干：输入文件名（去掉扩展名），如 app.apk → app"""
    return _sanitize_filename(Path(report.file_name).stem)


def _write_html_report(html_data: dict, out_path: Path) -> None:
    """单样本 HTML 写盘（惰性导入：模块不可用时抛 ImportError，由助手兜底）"""
    from apkguard.output.html_report import write_html_report

    write_html_report(html_data, out_path)


def _write_scan_summary_html(
    entries: list[tuple[str, dict]], errors: list[str], scanned_dir: str, out_path: Path
) -> None:
    """批量汇总 HTML 写盘（惰性导入，同上）"""
    from apkguard.output.html_report import write_scan_summary_html

    write_scan_summary_html(entries, errors, scanned_dir, out_path)


def _write_report_files(
    default_base: str,
    json_arg: str | None,
    html_arg: str | None,
    write_json: Callable[[Path], None],
    write_html: Callable[[Path], None],
) -> None:
    """三命令共用的报告写盘助手。

    - analyze / dynamic：default_base=输入文件名（去扩展名），--json/--html 覆盖
    - scan：default_base="scan_summary"，无覆盖参数，写批量汇总
    - 默认输出到项目根目录的 reports/ 子目录（.gitignore 已忽略，报告不进版本控制）；
      显式 --json/--html 路径按用户指定（父目录自动创建）

    默认命名、路径覆盖、HTML 模块缺失的优雅降级统一在这里处理。
    """
    report_dir = Path("reports")
    json_out = Path(json_arg) if json_arg else report_dir / f"{default_base}.json"
    json_out.parent.mkdir(parents=True, exist_ok=True)
    write_json(json_out)
    print(f"JSON 报告已写入 / JSON report written: {json_out}")

    html_out = Path(html_arg) if html_arg else report_dir / f"{default_base}.html"
    html_out.parent.mkdir(parents=True, exist_ok=True)
    try:
        write_html(html_out)
        print(f"HTML 报告已写入 / HTML report written: {html_out}")
    except ImportError:
        print(
            f"警告：HTML 报告模块不可用，已跳过 / Warning: HTML report unavailable",
            file=sys.stderr,
        )


def cmd_analyze(args) -> int:
    _setup_logging()
    config = _resolve_config(args)
    rules = load_rules(config.rules_dir)
    path = Path(args.file)
    if not path.exists():
        console._c(f"错误：文件不存在 / File not found: {path}", "red")
        return 1

    app = analyze_file(path)
    report = _make_report(app, config, args.severity, rules)
    _attach_dynamic_status(report, config, getattr(args, "device", None))

    console.print_analysis_report(report)
    _write_report_files(
        _default_report_base(report),
        args.json,
        args.html,
        lambda p: write_json_report(report, p),
        lambda p: _write_html_report(report.to_dict(), p),
    )
    return 0


def _system_memory_mb() -> int:
    """系统物理内存（MB）。尽力获取；失败返回保守默认 8192（8GB）。

    Windows: GlobalMemoryStatusEx；Linux: /proc/meminfo。纯标准库实现。
    """
    try:
        if sys.platform == "win32":
            import ctypes

            class _MEMORYSTATUSEX(ctypes.Structure):  # noqa: N801 - ctypes 结构体命名约定
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = _MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                return int(stat.ullTotalPhys / 1024 / 1024)
        else:
            with open("/proc/meminfo", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal"):
                        return int(line.split()[1]) // 1024  # kB → MB
    except Exception:
        pass
    return 8192


def _scan_est_mb(size_bytes: int) -> int:
    """估算单文件分析峰值内存（MB）：进程基座 + 文件大小 × 膨胀系数"""
    return _SCAN_EST_BASE_MB + int(size_bytes / 1024 / 1024 * _SCAN_EST_PER_MB)


def _adaptive_workers(files: list[Path], requested: int, mem_budget_mb: int) -> int:
    """按文件大小自适应并发：防止大文件并行叠加导致内存溢出。

    约束：并发数 × 最大单文件估算 ≤ 内存预算。
    请求并发为 1 时不缩减；结果为 [1, requested]。
    """
    if requested <= 1 or not files:
        return max(1, requested)
    largest_est = max(_scan_est_mb(p.stat().st_size) for p in files)
    by_memory = max(1, mem_budget_mb // max(1, largest_est))
    return max(1, min(requested, by_memory))


def _scan_worker(
    path_str: str,
    severity: str,
    rules_dir: str,
    config_path: str,
    explicit_device: str | None,
    json_dir: str,
) -> tuple[str, dict]:
    """单文件扫描 worker（模块级：可被 ProcessPoolExecutor 在 Windows spawn 模式 pickle）。

    参数全为基本类型/字符串；返回 (路径, Report.to_dict())。
    失败抛异常，由调用方收集到 errors 列表。
    """
    _suppress_androguard_logs()  # 子进程各自压制，防 20 万行/文件刷屏
    from apkguard.output.json_report import write_json_report

    config = Config(Path(config_path) if config_path else None)
    if rules_dir:
        config.set_rules_dir(rules_dir)
    rules = load_rules(config.rules_dir)

    p = Path(path_str)
    app = analyze_file(p)
    report = _make_report(app, config, severity, rules)
    _attach_dynamic_status(report, config, explicit_device)
    if json_dir:
        out = Path(json_dir) / f"{p.stem}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        write_json_report(report, out)
    return path_str, report.to_dict()


def cmd_scan(args) -> int:
    _setup_logging()
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

    # 大小感知并发：多进程隔离内存（每个 worker 独立进程，大文件不再共享叠加），
    # 且按文件大小与物理内存预算自动限流，防止单文件估算 × 并发数 OOM。
    mem_budget = int(_system_memory_mb() * _SCAN_MEM_BUDGET_RATIO)
    effective_workers = _adaptive_workers(files, workers, mem_budget)
    if effective_workers < workers:
        console._c(
            f"检测到大型样本，并发从 {workers} 自动降至 {effective_workers}（内存预算 {mem_budget}MB）/ "
            f"Large samples detected; workers reduced {workers} → {effective_workers} "
            f"(memory budget {mem_budget}MB)",
            "yellow",
        )
    workers = effective_workers

    console._c(
        f"开始批量扫描 {len(files)} 个文件，并发 {workers}（多进程隔离）/ "
        f"Scanning {len(files)} files with {workers} workers (isolated processes)",
        "cyan",
    )
    results: list[tuple[str, dict]] = []
    errors: list[str] = []

    config_path = str(args.config) if getattr(args, "config", None) else ""
    rules_dir = config.rules_dir
    json_dir = str(args.json_dir) if args.json_dir else ""
    explicit_device = getattr(args, "device", None)

    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _scan_worker,
                str(p),
                args.severity,
                rules_dir,
                config_path,
                explicit_device,
                json_dir,
            ): p
            for p in files
        }
        done = 0
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                errors.append(str(e))
            done += 1
            logging.getLogger("apkguard").info(
                f"scan progress: {done}/{len(files)} files done"
            )

    console.print_scan_summary(results, errors)
    # 自动输出批量汇总报告（JSON + HTML，落盘当前目录）——与 analyze/dynamic 共用写盘助手
    _write_report_files(
        "scan_summary",
        None,
        None,
        lambda p: write_scan_summary_json(results, errors, p, str(root)),
        lambda p: _write_scan_summary_html(results, errors, str(root), p),
    )
    return 0


def _suppress_androguard_logs() -> None:
    """压制 androguard（loguru）DEBUG/INFO 刷屏——只保留 WARNING 及以上。

    androguard 在 APK()/DEX() 解析时会经 loguru 输出大量调试日志
    （实测 80MB 样本可刷 20 万行），且只在当前进程生效：
    scan 的每个 worker 子进程都必须各自调用（spawn 不继承全局状态）。
    """
    try:
        from loguru import logger as _loguru

        _loguru.disable("androguard")
    except ImportError:
        pass  # 无 loguru（非 Windows/精简环境）无需压制


def _setup_logging() -> None:
    """统一运行日志配置（幂等）：

    - 全部命令 → INFO 实时输出执行步骤到 stderr（与报告 stdout 分离）
    - 压制 androguard（loguru）刷屏
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
        stream=sys.stderr,
        force=True,
    )
    _suppress_androguard_logs()


def cmd_dynamic(args) -> int:
    _setup_logging()
    config = _resolve_config(args)
    path = Path(args.file)
    if not path.exists():
        console._c(f"错误：文件不存在 / File not found: {path}", "red")
        return 1

    app = analyze_file(path)
    no_static = getattr(args, "no_static", False)
    rules = None if no_static else load_rules(config.rules_dir)
    report = _make_report(app, config, "low", rules)
    if no_static:
        console._c(
            "提示：静态分析已跳过（--no-static），报告仅含动态结果 / "
            "Static analysis skipped; dynamic results only",
            "yellow",
        )
    dm = DeviceManager(config.test_devices, explicit_device=args.device)

    # --manual-login CLI 参数覆盖 config.yaml 的 dynamic.manual_login（便于临时开启）
    dynamic_options = dict(config.dynamic_options)
    if getattr(args, "manual_login", False):
        dynamic_options["manual_login"] = True

    if config.dynamic_enabled:
        result = run_dynamic_analysis(report, dm, dynamic_options, path, app)
        if not result.get("executed"):
            console._c(
                "提示：动态分析预检未通过，仅做状态标注（见报告 Dynamic 部分）/ "
                "Dynamic analysis pre-check failed; status annotated only",
                "yellow",
            )
    else:
        update_dynamic_status(report, dm, dynamic_options)
        console._c(
            "提示：动态分析开关未开启（config.yaml: dynamic.enabled）。开启后本命令将真正"
            "在测试设备上安装运行样本 / Dynamic analysis disabled in config.yaml",
            "yellow",
        )

    console.print_analysis_report(report)
    _write_report_files(
        _default_report_base(report),
        args.json,
        args.html,
        lambda p: write_json_report(report, p),
        lambda p: _write_html_report(report.to_dict(), p),
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    # Windows 控制台默认 GBK，强制 UTF-8 输出保证中文正常（建议使用 Windows Terminal）
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass  # 流不支持 reconfigure（如已关闭/重定向的流），保持默认编码即可
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
