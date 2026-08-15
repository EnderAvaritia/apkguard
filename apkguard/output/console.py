"""终端输出：单文件详情（analyze）与批量汇总表（scan）。"""
from __future__ import annotations

import sys
from typing import Optional

from apkguard.engine.models import Finding, Report, RiskLevel

# ANSI 颜色（Windows 10+ 支持；无颜色环境自动降级）
_COLORS = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "green": "\033[92m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}
_USE_COLOR = sys.stdout.isatty()

_LEVEL_COLOR = {
    RiskLevel.CLEAN: "green",
    RiskLevel.SUSPICIOUS: "yellow",
    RiskLevel.MALICIOUS: "red",
}


def _c(text: str, color: str) -> str:
    if not _USE_COLOR:
        return text
    return f"{_COLORS[color]}{text}{_COLORS['reset']}"


def _severity_color(sev: str) -> str:
    return {
        "info": "dim",
        "low": "dim",
        "medium": "yellow",
        "high": "yellow",
        "critical": "red",
    }.get(sev, "reset")


def print_analysis_report(report: Report) -> None:
    """analyze 模式：单文件详细报告"""
    risk_color = _LEVEL_COLOR.get(report.risk_level, "reset")
    line = "=" * 68

    print()
    print(_c(line, "cyan"))
    print(_c(f"  apkguard 分析报告 / Analysis Report", "bold"))
    print(_c(f"  文件 / File    : {report.file_name}  ({report.file_format})", "dim"))
    print(_c(f"  大小 / Size    : {report.file_size:,} bytes", "dim"))
    print(_c(f"  SHA-256        : {report.sha256[:32]}...", "dim"))
    if report.package:
        print(_c(f"  包名 / Package : {report.package}", "dim"))
    if report.app_name:
        print(_c(f"  应用名 / Name  : {report.app_name}", "dim"))
    if report.version:
        print(_c(f"  版本 / Version : {report.version}", "dim"))
    print(_c(line, "cyan"))
    print(
        _c(
            f"  风险等级 / Risk : {report.risk_level.label}    "
            f"总分 / Score: {report.total_score}",
            risk_color,
        )
    )
    print(_c(f"  阈值档位 / Profile: {report.severity_profile}", "dim"))
    if report.threshold:
        print(
            _c(
                f"  阈值 / Threshold: <{report.threshold.get('clean_below')} 干净, "
                f">={report.threshold.get('malicious_at')} 恶意",
                "dim",
            )
        )
    print(_c(line, "cyan"))

    # 动态分析状态
    dyn = report.dynamic
    if dyn.status != "not_executed" or dyn.note:
        print()
        print(_c("  动态分析 / Dynamic Analysis", "bold"))
        if dyn.note:
            print(_c(f"    状态 / Status: {dyn.note}", "yellow"))
        if dyn.executed:
            print(
                _c(
                    f"    设备 / Device: {dyn.device_used}    时长 / Duration: "
                    f"{dyn.duration_seconds}s    Frida: "
                    f"{'是' if dyn.frida_hooked else '否'}    诱饵数据: "
                    f"{'已注入' if dyn.decoy_installed else '未注入'}",
                    "dim",
                )
            )
            if dyn.traffic_endpoints:
                print(
                    _c(
                        f"    网络端点 / Endpoints ({len(dyn.traffic_endpoints)}, "
                        f"请求数 / Requests: {dyn.traffic_count}):",
                        "cyan",
                    )
                )
                for ep in dyn.traffic_endpoints[:15]:
                    print(_c(f"      - {ep}", "cyan"))
            if not dyn.cleanup_ok:
                print(_c("    ⚠️ 跑后清理未完成！请手动卸载样本 / cleanup failed!", "red"))

    # Findings
    if report.findings:
        print()
        print(_c(f"  检测发现 / Findings ({len(report.findings)})", "bold"))
        for f in report.findings:
            _print_finding(f)
    else:
        print()
        print(_c("  未发现可疑行为 / No suspicious behavior found", "green"))

    # 危险权限
    if report.permissions:
        print()
        print(_c(f"  声明的危险权限 / Dangerous Permissions ({len(report.permissions)})", "bold"))
        for p in report.permissions:
            print(_c(f"    - {p}", "yellow"))

    # 网络端点
    suspicious_endpoints = [e for e in report.network_endpoints if e.score > 0]
    if suspicious_endpoints:
        print()
        print(
            _c(
                f"  疑似 C2 网络端点 / Suspicious Network Endpoints "
                f"({len(suspicious_endpoints)})",
                "bold",
            )
        )
        for e in suspicious_endpoints[:15]:
            print(
                _c(f"    - {e.endpoint}  [{e.kind}] +{e.score}", "red")
                + _c(f"  {'; '.join(e.features[:3])}", "dim")
            )

    # 签名
    if report.signature:
        sig = report.signature
        print()
        print(_c("  签名信息 / Signature", "bold"))
        print(_c(f"    - 签名者 / Signer : {sig.signer}", "dim"))
        print(_c(f"    - 方案 / Scheme   : {sig.signature_scheme}", "dim"))
        if sig.debug_key:
            print(_c(f"    - 调试签名 (debug key)", "yellow"))

    # 解析警告
    if report.parse_warnings:
        print()
        print(_c("  解析警告 / Parse Warnings", "yellow"))
        for w in report.parse_warnings:
            print(_c(f"    - {w}", "yellow"))

    print(_c(line, "cyan"))
    print()


def _print_finding(f: Finding) -> None:
    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
    color = _severity_color(sev)
    print(
        _c(f"  [{sev.upper():<8}] +{f.weight}  {f.title}", color)
    )
    if f.evidence:
        for ev in f.evidence[:5]:
            print(_c(f"           {ev}", "dim"))
    print(_c(f"           {f.description}", "dim"))


def _scan_item_score(item: tuple[str, Report | dict]) -> int:
    """汇总表取分数：兼容 Report 对象与 Report.to_dict()（多进程 worker 返回 dict）"""
    r = item[1]
    if isinstance(r, dict):
        return r.get("risk", {}).get("total_score", 0)
    return r.total_score


def _scan_item_level(item: tuple[str, Report | dict]) -> RiskLevel:
    r = item[1]
    if isinstance(r, dict):
        return RiskLevel(r.get("risk", {}).get("risk_level", RiskLevel.CLEAN.value))
    return r.risk_level


def print_scan_summary(
    results: list[tuple[str, Report | dict]], errors: list[str]
) -> None:
    """scan 模式：批量汇总表"""
    line = "-" * 68
    print()
    print(_c("  apkguard 批量扫描结果 / Batch Scan Summary", "bold"))
    print(_c(line, "cyan"))
    print(f"  {'文件 / File':<42} {'风险 / Risk':<20} 分")
    print(_c(line, "cyan"))

    for path, report in sorted(results, key=lambda r: -_scan_item_score(r)):
        level = _scan_item_level((path, report))
        risk_color = _LEVEL_COLOR.get(level, "reset")
        name = path if len(path) <= 40 else "..." + path[-39:]
        print(
            f"  {name:<42} "
            + _c(f"{level.label:<20}", risk_color)
            + f"{_scan_item_score((path, report))}"
        )

    if errors:
        print(_c(line, "yellow"))
        print(_c(f"  失败 / Failed ({len(errors)}):", "yellow"))
        for e in errors:
            print(_c(f"    - {e}", "yellow"))

    # 统计
    levels = {_scan_item_level(r) for r in results}
    summary = ", ".join(
        f"{lv.label}: {sum(1 for r in results if _scan_item_level(r) == lv)}"
        for lv in RiskLevel
        if lv in levels
    )
    print(_c(line, "cyan"))
    print(_c(f"  合计 / Total: {len(results)}  |  {summary}", "bold"))
    print()
