"""JSON 报告输出：中英双语标签的结构化报告，可落盘供程序化消费。"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from apkguard.engine.models import Report


def report_to_dict(report: Report) -> dict[str, Any]:
    """报告 → dict（双语标签结构）"""
    return report.to_dict()


def write_json_report(report: Report, out_path: Path) -> None:
    """报告落盘为 JSON 文件"""
    data = report_to_dict(report)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def write_scan_summary_json(
    results: list[tuple[str, Report]],
    errors: list[str],
    out_path: Path,
    scanned_dir: str = "",
) -> None:
    """批量扫描汇总落盘为 JSON：统计 + 文件清单（含完整报告）+ 失败列表"""
    counts = {"clean": 0, "suspicious": 0, "malicious": 0}
    for _, report in results:
        level = report.risk_level.value
        if level in counts:
            counts[level] += 1
    data: dict[str, Any] = {
        "tool": "apkguard scan",
        "scanned_dir": scanned_dir,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "counts": counts,
        "total": len(results),
        "files": [
            {"path": p, "report": report.to_dict()}
            for p, report in sorted(results, key=lambda x: -x[1].total_score)
        ],
        "errors": errors,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
