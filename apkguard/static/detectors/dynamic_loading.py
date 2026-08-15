"""检测器：动态代码加载。

恶意软件常用手法：运行时下载 dex/apk 再加载，绕过静态检测。
关键信号：DexClassLoader / PathClassLoader / loadDex / 反射加载 +
下载器 API + 写入文件 API 的组合。
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector

_LOADER_CLASSES = (
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
    "Ldalvik/system/DexFile;",
)
_DOWNLOADER_CLASSES = (
    "Ljava/net/URL;",
    "Lorg/apache/http/",
    "Lokhttp3/",
    "Ljava/net/HttpURLConnection;",
)
_WRITE_CLASSES = (
    "Ljava/io/FileOutputStream;",
    "Ljava/io/File;",
)


class DynamicLoadingDetector(BaseDetector):
    detector_id = "dynamic_loading"
    display_name = "动态代码加载"
    display_name_en = "Dynamic code loading"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        called = app.called_methods

        # 基础信号：加载器调用
        loader_calls = [m for m in called if m.startswith(_LOADER_CLASSES)]
        if not loader_calls:
            return findings

        # 证据：加载器调用 + 关联的下载/写入调用
        evidence = list(loader_calls[:8])
        download_calls = [
            m for m in called if m.startswith(_DOWNLOADER_CLASSES) and "open" in m
        ]
        write_calls = [
            m for m in called
            if m.startswith(_WRITE_CLASSES)
            and ("write" in m or "<init>" in m)
        ]

        detail: dict = {"loader_count": len(loader_calls)}
        if download_calls:
            evidence.extend(download_calls[:4])
            detail["has_downloader"] = True
        if write_calls:
            evidence.extend(write_calls[:4])
            detail["has_file_write"] = True

        # 等级加权：加载 + 下载 + 写文件同时出现 → 高危（典型的云端下发载荷）
        weight = 3
        severity = Severity.HIGH
        if download_calls and write_calls:
            weight = 5
            severity = Severity.CRITICAL
            title = "动态代码加载 + 网络下载 + 文件写入（典型恶意载荷链）"
            title_en = "Dynamic loading with download and file write (malicious payload chain)"
            desc = "同时具备动态加载、网络下载与文件写入能力，高度疑似从云端下载并执行恶意代码"
        elif download_calls or write_calls:
            weight = 4
            severity = Severity.HIGH
            title = "动态代码加载伴随下载或文件写入"
            title_en = "Dynamic loading with download or file write"
            desc = "动态加载代码的同时具备网络下载或文件写入能力，可能从远端获取并执行载荷"
        else:
            title = "使用动态代码加载"
            title_en = "Uses dynamic code loading"
            desc = "通过 DexClassLoader/PathClassLoader 等动态加载代码，加载的代码无法通过静态分析验证"

        findings.append(
            Finding(
                detector_id=self.detector_id,
                title=title,
                title_en=title_en,
                description=desc,
                severity=severity,
                weight=weight,
                evidence=evidence,
                detail=detail,
            )
        )
        return findings
