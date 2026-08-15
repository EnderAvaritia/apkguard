"""检测器基类与注册机制。

检测器契约：
  输入: AnalyzedApp（解析层产物）+ RuleSet（YAML 规则）
  输出: list[Finding]

内置检测器预写齐全；新增检测器只需继承 BaseDetector 并实现 detect()，
然后加入 DETECTOR_REGISTRY。
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from apkguard.engine.models import AnalyzedApp, Finding
from apkguard.engine.rule_engine import RuleSet


class BaseDetector(ABC):
    """所有检测器的基类"""

    detector_id: str = ""
    display_name: str = ""  # 中文名
    display_name_en: str = ""  # 英文名

    def __init__(self) -> None:
        if not self.detector_id:
            raise ValueError("detector_id 不能为空")

    @abstractmethod
    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        """对样本执行检测，返回 findings"""
        raise NotImplementedError


def _collect_detector_classes() -> list[type[BaseDetector]]:
    """自动收集所有 BaseDetector 子类（遍历已导入模块）"""
    import sys

    classes: list[type[BaseDetector]] = []
    for module in list(sys.modules.values()):
        for obj in vars(module).values():
            if (
                isinstance(obj, type)
                and issubclass(obj, BaseDetector)
                and obj is not BaseDetector
            ):
                classes.append(obj)
    return classes


DETECTOR_REGISTRY: list[BaseDetector] = []


def register_detectors() -> None:
    """注册所有内置检测器（显式导入各检测器模块后自动收集）"""
    from apkguard.static.detectors import (  # noqa: F401  确保子模块被导入
        accessibility,
        antiav_evasion,
        c2_network,
        data_exfil,
        dynamic_loading,
        overlay,
        permissions,
        signature,
        sms_telephony,
    )

    seen: dict[str, BaseDetector] = {}
    for cls in _collect_detector_classes():
        inst = cls()
        seen[inst.detector_id] = inst
    DETECTOR_REGISTRY.clear()
    DETECTOR_REGISTRY.extend(seen.values())


def get_detectors() -> list[BaseDetector]:
    """返回已注册的检测器列表（懒注册）"""
    if not DETECTOR_REGISTRY:
        register_detectors()
    return DETECTOR_REGISTRY


def run_all_detectors(app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
    """运行全部检测器，聚合所有 findings"""
    findings: list[Finding] = []
    for detector in get_detectors():
        try:
            findings.extend(detector.detect(app, rules))
        except Exception as e:
            # 单个检测器失败不应阻断整体分析
            findings.append(
                Finding(
                    detector_id=detector.detector_id,
                    title=f"检测器执行异常: {detector.display_name}",
                    title_en=f"Detector error: {detector.display_name_en}",
                    description=f"检测器执行时发生异常，结果可能不完整: {e}",
                    severity="info",
                    weight=0,
                )
            )
    return findings
