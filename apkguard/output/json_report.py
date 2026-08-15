"""JSON 报告输出：中英双语标签的结构化报告，可落盘供程序化消费。"""
from __future__ import annotations

import json
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
