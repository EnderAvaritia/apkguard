"""核心数据模型：所有检测器、规则引擎、报告模块共同遵守的契约。

中文标注：报告字段使用中英双语标签，便于直接转给他人阅读。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    """严重级别 / Severity level"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        """严重级别对应的分值权重"""
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class RiskLevel(str, Enum):
    """样本风险分级 / Risk classification"""

    CLEAN = "clean"  # 干净
    SUSPICIOUS = "suspicious"  # 可疑
    MALICIOUS = "malicious"  # 恶意

    @property
    def label(self) -> str:
        return {
            RiskLevel.CLEAN: "干净 (Clean)",
            RiskLevel.SUSPICIOUS: "可疑 (Suspicious)",
            RiskLevel.MALICIOUS: "恶意 (Malicious)",
        }[self]


@dataclass
class Finding:
    """单条检测发现 / A single detection finding"""

    detector_id: str  # 检测器 ID
    title: str  # 中文标题
    title_en: str  # 英文标题
    description: str  # 中文描述
    severity: Severity  # 严重级别
    weight: int  # 分值
    evidence: list[str] = field(default_factory=list)  # 证据（代码位置/权限/端点）
    detail: dict[str, Any] = field(default_factory=dict)  # 结构化细节

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class NetworkEndpoint:
    """提取到的网络端点 / Extracted network endpoint"""

    endpoint: str  # 域名 / IP / URL
    kind: str  # "domain" | "ip" | "url"
    features: list[str] = field(default_factory=list)  # C2 可疑特征
    score: int = 0  # 特征打分
    contexts: list[str] = field(default_factory=list)  # 出现位置上下文

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SignatureInfo:
    """签名/证书信息 / Signing certificate info"""

    valid: bool
    signature_scheme: str
    signer: str
    issuer: str
    serial: str
    sha256: str
    not_before: Optional[str]
    not_after: Optional[str]
    self_signed: bool
    debug_key: bool  # 是否使用 Android 调试签名
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicStatus:
    """动态分析状态（第二阶段）/ Dynamic analysis status"""

    enabled: bool = False  # 是否配置了动态后端
    executed: bool = False  # 本次是否实际执行
    device_used: Optional[str] = None  # 使用的测试设备
    backend: Optional[str] = None  # 后端类型
    status: str = "not_executed"  # not_executed | executed | degraded | skipped
    note: str = ""  # 说明（如"未配置测试设备白名单，动态分析未执行"）
    findings: list[dict[str, Any]] = field(default_factory=list)
    # ---- 执行结果（status == "executed" 时填充） ----
    duration_seconds: Optional[int] = None  # 实际运行时长
    traffic_endpoints: list[str] = field(default_factory=list)  # 采集到的网络端点（去重）
    traffic_count: int = 0  # 捕获到的请求数
    baseline_excluded: int = 0  # 基线剔除的环境端点数（邻居流量）
    baseline_endpoints: list[str] = field(default_factory=list)  # 基线期环境端点
    frida_hooked: bool = False  # Frida hook 是否成功采集
    decoy_installed: bool = False  # 诱饵数据是否注入成功
    cleanup_ok: bool = True  # 跑后清理是否完成（安全铁律 3）
    kept_installed: bool = False  # cleanup_uninstall=false 时保留设备应用不卸载（审计标注）
    # 手动登录门（manual_login）：None=未启用；True=操作者已按回车确认登录；
    # False=等待超时自动继续。用于需要登录才能展现真实行为的样本。
    manual_login_confirmed: Optional[bool] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalyzedApp:
    """解析层产物：APK/AAB 解析后的结构化数据，是检测器的输入契约"""

    file_path: str
    file_format: str  # "APK" | "AAB"
    file_size: int
    sha256: str

    # 应用信息
    package: Optional[str] = None
    app_name: Optional[str] = None
    version: Optional[str] = None
    version_code: Optional[str] = None  # 动态分析同包名版本比对用
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None

    # 权限
    declared_permissions: set[str] = field(default_factory=set)  # 所有声明的权限
    dangerous_permissions: list[str] = field(default_factory=list)  # 危险权限（按危险权限列表过滤）

    # 代码层信息
    called_methods: set[str] = field(default_factory=set)  # 被调用的方法全名集合（api 规则匹配用）
    strings: set[str] = field(default_factory=set)  # 字符串池（特征匹配、网络端点提取用）
    classes: list[str] = field(default_factory=list)  # 所有类名

    # 组件
    services: list[str] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    activities: list[str] = field(default_factory=list)
    receivers: list[str] = field(default_factory=list)
    exported_activities: list[str] = field(default_factory=list)  # 可被外部唤起的 activity（动态分析交互用）

    # 其他
    signature: Optional[SignatureInfo] = None
    parse_warnings: list[str] = field(default_factory=list)


@dataclass
class Report:
    """完整分析报告 / Full analysis report"""

    # 文件元信息
    file_name: str
    file_format: str  # "APK" | "AAB"
    file_size: int
    sha256: str

    # 应用信息
    package: Optional[str] = None
    app_name: Optional[str] = None
    version: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None

    # 检测结果
    total_score: int = 0
    risk_level: RiskLevel = RiskLevel.CLEAN
    findings: list[Finding] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)  # 危险权限（已声明）
    all_permissions: list[str] = field(default_factory=list)
    network_endpoints: list[NetworkEndpoint] = field(default_factory=list)

    # 其他信息
    signature: Optional[SignatureInfo] = None
    dynamic: DynamicStatus = field(default_factory=DynamicStatus)
    parse_warnings: list[str] = field(default_factory=list)
    rule_version: Optional[str] = None
    severity_profile: str = "low"  # low | normal | high
    threshold: dict[str, int] = field(default_factory=dict)

    def sort_findings(self) -> None:
        """按分值降序排列 findings"""
        self.findings.sort(key=lambda f: f.weight, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        """转 dict：报告字段中英双语标签，可直接序列化为 JSON"""
        return {
            "file_name": self.file_name,
            "file_format": self.file_format,
            "file_size": self.file_size,
            "sha256": self.sha256,
            "app_info": {
                "package": self.package,
                "app_name": self.app_name,
                "version": self.version,
                "min_sdk": self.min_sdk,
                "target_sdk": self.target_sdk,
            },
            "risk": {
                "total_score": self.total_score,
                "risk_level": self.risk_level.value,
                "risk_label": self.risk_level.label,
                "severity_profile": self.severity_profile,
                "threshold": self.threshold,
            },
            "findings": [f.to_dict() for f in self.findings],
            "permissions": {
                "dangerous_declared": self.permissions,
                "all_declared_count": len(self.all_permissions),
            },
            "network_endpoints": [e.to_dict() for e in self.network_endpoints],
            "signature": self.signature.to_dict() if self.signature else None,
            "dynamic": self.dynamic.to_dict(),
            "parse_warnings": self.parse_warnings,
            "rule_version": self.rule_version,
        }
