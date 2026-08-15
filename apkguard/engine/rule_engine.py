"""规则引擎：加载 YAML 规则文件，对解析结果执行简单规则匹配。

规则形态（简单规则走 YAML，复杂逻辑走 Python 检测器插件）：
  - type: permission    → 检查声明的权限
  - type: api           → 检查 dex 代码中是否调用指定 API
  - type: string_feature→ 检查代码字符串/常量中的特征（URL、关键词等）

用户日常只编辑 rules/*.yaml，不需要修改任何 Python 代码。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from apkguard.engine.models import Finding, Severity


@dataclass
class YamlRule:
    """一条 YAML 规则"""

    rule_id: str
    rule_type: str  # permission | api | string_feature
    title: str
    title_en: str
    description: str
    severity: Severity
    weight: int
    # 按类型取用的字段
    permission: Optional[str] = None
    api_class: Optional[str] = None  # smali 类名，如 Ldalvik/system/DexClassLoader;
    api_method: Optional[str] = None
    feature: Optional[str] = None  # string_feature 的匹配串
    enabled: bool = True

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "YamlRule":
        sev = Severity(data.get("severity", "medium"))
        return cls(
            rule_id=str(data["id"]),
            rule_type=str(data["type"]),
            title=str(data.get("title", "")),
            title_en=str(data.get("title_en", "")),
            description=str(data.get("description", "")),
            severity=sev,
            weight=int(data.get("weight", sev.weight)),
            permission=data.get("permission"),
            api_class=data.get("api_class"),
            api_method=data.get("api_method"),
            feature=data.get("feature"),
            enabled=bool(data.get("enabled", True)),
        )


class RuleSet:
    """加载后的规则集合"""

    def __init__(self, rules: list[YamlRule]):
        self.rules = rules
        self._by_type: dict[str, list[YamlRule]] = {}
        for rule in rules:
            if not rule.enabled:
                continue
            self._by_type.setdefault(rule.rule_type, []).append(rule)

    def of_type(self, rule_type: str) -> list[YamlRule]:
        return self._by_type.get(rule_type, [])

    @property
    def all_rules(self) -> list[YamlRule]:
        return self.rules


def load_rules(rules_dir: Path) -> RuleSet:
    """从目录加载所有 *.yaml 规则文件"""
    rules: list[YamlRule] = []
    if not rules_dir.exists():
        return RuleSet(rules)
    for yaml_file in sorted(rules_dir.glob("*.yaml")):
        with open(yaml_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        items = data.get("rules", [])
        for item in items:
            rules.append(YamlRule.from_dict(item))
    return RuleSet(rules)


def match_permission_rules(rules: RuleSet, declared_permissions: set[str]) -> list[Finding]:
    """匹配 permission 类型规则"""
    findings: list[Finding] = []
    for rule in rules.of_type("permission"):
        if rule.permission and rule.permission in declared_permissions:
            findings.append(
                Finding(
                    detector_id=f"rule:{rule.rule_id}",
                    title=rule.title,
                    title_en=rule.title_en,
                    description=rule.description,
                    severity=rule.severity,
                    weight=rule.weight,
                    evidence=[rule.permission],
                    detail={"rule_id": rule.rule_id},
                )
            )
    return findings


def match_api_rules(
    rules: RuleSet, called_methods: set[str]
) -> list[Finding]:
    """匹配 api 类型规则。

    called_methods: 形如 "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;)V"
    的调用集合（由解析层收集）。匹配时做前缀匹配：api_class 相同且
    api_method（若指定）包含在签名中即可。
    """
    findings: list[Finding] = []
    for rule in rules.of_type("api"):
        if not rule.api_class:
            continue
        # 形如 "Ldalvik/system/DexClassLoader;->" 的前缀
        prefix = f"{rule.api_class}->"
        matches = [m for m in called_methods if m.startswith(prefix)]
        if rule.api_method:
            matches = [m for m in matches if rule.api_method in m]
        if matches:
            findings.append(
                Finding(
                    detector_id=f"rule:{rule.rule_id}",
                    title=rule.title,
                    title_en=rule.title_en,
                    description=rule.description,
                    severity=rule.severity,
                    weight=rule.weight,
                    evidence=matches[:10],
                    detail={"rule_id": rule.rule_id, "match_count": len(matches)},
                )
            )
    return findings


def match_string_feature_rules(
    rules: RuleSet, strings: set[str]
) -> list[Finding]:
    """匹配 string_feature 类型规则：在提取的字符串集中查找特征"""
    findings: list[Finding] = []
    for rule in rules.of_type("string_feature"):
        if not rule.feature:
            continue
        matches = [s for s in strings if rule.feature.lower() in s.lower()]
        if matches:
            findings.append(
                Finding(
                    detector_id=f"rule:{rule.rule_id}",
                    title=rule.title,
                    title_en=rule.title_en,
                    description=rule.description,
                    severity=rule.severity,
                    weight=rule.weight,
                    evidence=matches[:10],
                    detail={"rule_id": rule.rule_id, "match_count": len(matches)},
                )
            )
    return findings
