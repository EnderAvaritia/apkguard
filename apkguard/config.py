"""配置加载：读取 config.yaml，提供类型化访问。

CLI 参数优先级 > config.yaml > 内置默认值。
"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Optional

import yaml

# 项目根目录（apkguard/ 的上一级）
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.yaml"
# 规则随包分发：apkguard/rules/
DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"

DEFAULT_SEVERITY_PROFILES: dict[str, dict[str, int]] = {
    "low": {"clean_below": 4, "malicious_at": 8},
    "normal": {"clean_below": 8, "malicious_at": 15},
    "high": {"clean_below": 15, "malicious_at": 25},
}


def _deep_merge(base: dict, override: dict) -> dict:
    """递归合并字典：override 覆盖 base"""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


class Config:
    """apkguard 配置对象"""

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or DEFAULT_CONFIG_PATH
        self.raw: dict[str, Any] = self._load()
        # 深度合并默认档位，保证配置缺失时也有兜底
        profiles = self.raw.setdefault("severity_profiles", {})
        for name, values in DEFAULT_SEVERITY_PROFILES.items():
            profiles.setdefault(name, values)

    def _load(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {}
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}

    # ---- 阈值档位 ----

    @property
    def severity_profiles(self) -> dict[str, dict[str, int]]:
        return self.raw["severity_profiles"]

    def get_threshold(self, profile: str) -> dict[str, int]:
        """返回指定档位的阈值；未知档位回退到 low"""
        profiles = self.severity_profiles
        if profile not in profiles:
            return profiles["low"]
        return profiles[profile]

    # ---- 规则目录 ----

    @property
    def rules_dir(self) -> Path:
        path = self.raw.get("rules_dir", "rules")
        p = Path(path)
        if not p.is_absolute():
            p = DEFAULT_RULES_DIR
        return p

    def set_rules_dir(self, path: str | Path) -> None:
        p = Path(path)
        self.raw["rules_dir"] = str(p.resolve() if not p.is_absolute() else p)

    # ---- 批量扫描 ----

    @property
    def scan_workers(self) -> int:
        return int(self.raw.get("scan_workers", 0))

    # ---- 动态分析（第二阶段） ----

    @property
    def test_devices(self) -> list[str]:
        """★ 测试设备白名单：只有白名单设备才会被用于运行样本"""
        return list(self.raw.get("test_devices", []))

    @property
    def dynamic_enabled(self) -> bool:
        return bool(self.raw.get("dynamic", {}).get("enabled", False))

    @property
    def dynamic_options(self) -> dict[str, Any]:
        return self.raw.get("dynamic", {})

    # ---- 可选增强（默认关闭） ----

    @property
    def hash_check_enabled(self) -> bool:
        return bool(self.raw.get("enhancements", {}).get("hash_check", {}).get("enabled", False))

    @property
    def threat_intel_enabled(self) -> bool:
        return bool(self.raw.get("enhancements", {}).get("threat_intel", {}).get("enabled", False))

    def get(self, key: str, default: Any = None) -> Any:
        return self.raw.get(key, default)
