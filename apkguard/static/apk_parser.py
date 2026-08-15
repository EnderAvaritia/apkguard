"""输入解析层：APK/AAB 双通道解析，产出 AnalyzedApp（检测器的输入契约）。

- APK 通道：androguard 完整解析（Manifest + dex 反编译 + 签名）
- AAB 通道：zip 容器解析 + dex 抽取（代码分析完全可用）+ protobuf
  Manifest 启发式基础解析（实验性，标注 warning，待真实样本验证）

本模块只做"读取与提取"，不做任何恶意判定。
"""
from __future__ import annotations

import hashlib
import logging
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from androguard.core.apk import APK
from androguard.core.dex import DEX

from apkguard.engine.models import AnalyzedApp, SignatureInfo

logger = logging.getLogger("apkguard.static")

# Android 危险权限（dangerous 级别）——用于 filtering 展示
DANGEROUS_PERMISSIONS: set[str] = {
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.BODY_SENSORS",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.PACKAGE_USAGE_STATS",
}


def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def is_aab(path: Path) -> bool:
    """判断是否为 AAB：zip 容器且包含 AAB 特征条目"""
    try:
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
            return any(
                n.startswith("base/manifest/AndroidManifest.xml") for n in names
            ) and any(n.startswith("base/dex/") and n.endswith(".dex") for n in names)
    except (zipfile.BadZipFile, OSError):
        return False


def analyze_file(path: Path) -> AnalyzedApp:
    """入口：识别格式并分发到对应通道"""
    if is_aab(path):
        return _analyze_aab(path)
    return _analyze_apk(path)


# ---------------------------------------------------------------------------
# APK 通道（完整支持）
# ---------------------------------------------------------------------------

def _extract_exported_activities(apk: APK, package: Optional[str], target_sdk: int) -> Optional[list[str]]:
    """提取可被外部唤起的 activity（exported=true 或 带 intent-filter 且 targetSdk<=30）。

    规则（Android 导出模型）：
      - android:exported 显式声明 → 以其为准
      - 未声明 → 有 intent-filter 且 targetSdk<=30（Android 11 前隐式导出）才视为可导出
      - 非导出（含 targetSdk>=31 未声明）→ 内部组件，默认不唤起（防误触发副作用路径）

    返回 None 表示解析失败（调用方回退到全量 activities）；空列表合法（全部为内部组件）。
    """
    try:
        xml_bytes = apk.get_android_manifest_axml().get_xml()
    except Exception:
        return None
    try:
        import xml.etree.ElementTree as ET

        root = ET.fromstring(xml_bytes)
    except Exception:
        return None

    all_activities = set()
    try:
        all_activities = set(apk.get_activities() or [])
    except Exception:
        pass

    def _local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]

    def _resolve(name: str) -> str:
        """manifest 相对类名 → 全限定类名（与 get_activities() 对齐）"""
        if name.startswith("."):
            return (package or "") + name
        if "." not in name and package:
            return package + "." + name
        return name

    exported: list[str] = []
    for node in root.iter():
        if _local(node.tag) != "activity":
            continue
        attrs = {_local(k): v for k, v in node.attrib.items()}
        name = attrs.get("name")
        if not name:
            continue
        full = _resolve(name)
        # 只保留 get_activities() 也认可的全限定名（保证 am start -n 解析一致）
        if all_activities and full not in all_activities:
            continue
        declared = attrs.get("exported")
        if declared is not None:
            if declared == "true":
                exported.append(full)
            continue
        has_filter = any(_local(c.tag) == "intent-filter" for c in node)
        if has_filter and (target_sdk or 0) <= 30:
            exported.append(full)
    return sorted(set(exported))


def _analyze_apk(path: Path) -> AnalyzedApp:
    warnings: list[str] = []
    size_mb = path.stat().st_size / 1048576
    logger.info(f"Parsing APK: {path.name} ({size_mb:.1f} MB)")
    apk = APK(str(path))
    logger.info("Manifest parsed")
    app = AnalyzedApp(
        file_path=str(path),
        file_format="APK",
        file_size=path.stat().st_size,
        sha256=sha256_of_file(path),
    )
    try:
        app.package = apk.get_package()
    except Exception:
        warnings.append("无法解析包名 / Failed to parse package name")
    try:
        app.app_name = apk.get_app_name()
    except Exception:
        pass  # 应用名缺失（部分精简 APK）不影响分析
    try:
        app.version = apk.get_androidversion_name()
    except Exception:
        pass  # 版本号缺失不影响分析
    try:
        app.version_code = str(apk.get_androidversion_code())
    except Exception:
        pass  # versionCode 缺失不影响分析（动态分析版本比对时视为未知）
    try:
        app.min_sdk = apk.get_min_sdk_version()
    except Exception:
        pass  # SDK 信息缺失不影响分析
    try:
        app.target_sdk = apk.get_target_sdk_version()
    except Exception:
        pass  # SDK 信息缺失不影响分析

    # 权限
    try:
        perms = apk.get_permissions()
        app.declared_permissions = set(perms)
        app.dangerous_permissions = sorted(
            p for p in perms if p in DANGEROUS_PERMISSIONS
        )
    except Exception:
        warnings.append("无法解析权限声明 / Failed to parse permissions")

    # 组件
    try:
        app.services = apk.get_services()
        app.providers = apk.get_providers()
        app.activities = apk.get_activities()
        app.receivers = apk.get_receivers()
    except Exception:
        warnings.append("无法解析组件 / Failed to parse components")

    # 可导出 activity（动态分析随机唤起用；解析失败时回退全量，宁可多唤不可漏行为）
    try:
        target_sdk = int(app.target_sdk or 0)
    except Exception:
        target_sdk = 0
    try:
        exported = _extract_exported_activities(apk, app.package, target_sdk)
        if exported is None:
            app.exported_activities = list(app.activities)
            warnings.append("无法解析 activity 导出标记，回退全量 / exported flag parse failed, fallback to all")
        else:
            app.exported_activities = exported
    except Exception:
        app.exported_activities = list(app.activities)

    # 签名
    try:
        app.signature = _extract_signature(apk)
    except Exception:
        warnings.append("无法解析签名 / Failed to parse signature")

    # dex 代码分析
    try:
        _collect_code_info(apk, app)
    except Exception as e:
        warnings.append(f"dex 分析失败: {e} / dex analysis failed")

    app.parse_warnings = warnings
    return app


def _extract_signature(apk: APK) -> Optional[SignatureInfo]:
    certs = apk.get_certificates()
    if not certs:
        return None
    cert = certs[0]
    common_name = _cn_from_subject(cert.subject)
    issuer_name = _cn_from_subject(cert.issuer)
    try:
        serial = str(cert.serial_number)
    except Exception:
        serial = ""
    return SignatureInfo(
        valid=True,
        signature_scheme=", ".join(_signature_schemes(apk)),
        signer=common_name or str(cert.subject.human_friendly),
        issuer=issuer_name or str(cert.issuer.human_friendly),
        serial=serial,
        sha256=cert.sha256.hex() if hasattr(cert, "sha256") else "",
        not_before=str(cert.not_valid_before) if cert.not_valid_before else None,
        not_after=str(cert.not_valid_after) if cert.not_valid_after else None,
        self_signed=_is_self_signed(cert),
        debug_key=common_name is not None and "androiddebugkey" in common_name.lower(),
        warnings=[],
    )


def _cn_from_subject(subject) -> str:
    """从 asn1crypto x509 subject 提取 CN"""
    try:
        cn = subject.native.get("common_name")
        return cn if cn else ""
    except Exception:
        return ""


def _is_self_signed(cert) -> bool:
    try:
        return cert.self_signed == "yes"
    except Exception:
        return False


def _signature_schemes(apk: APK) -> list[str]:
    """尽力识别签名方案"""
    schemes = []
    try:
        apk.get_signature_version()
    except Exception:
        pass  # 4.1.4 中该 API 返回方式不稳定，仅尽力探测
    return schemes or ["v1"]


def _collect_method_ids(dexs: list[DEX], app: AnalyzedApp) -> None:
    """从 dex 方法引用表（method_ids）收集被调用方法全名（Smali 风格）。

    为什么不用 Analysis.create_xref()：
      1. 内存：xref 构建完整调用图，内存占用是 dex 的 10 倍以上，
         186MB 大 APK 单文件分析即可吃掉数 GB；method_ids 直接读引用表，
         内存占用低一个数量级。
      2. 格式：xref 的 full_name 是空格风格（'Lclass; name (desc)'），
         与 YAML api 规则/检测器的 Smali 风格（'Lclass;->name(desc)'）不匹配，
         导致 api 规则在真实样本上失配（0 命中）。method_ids 拼接 Smali 风格
         正好匹配，顺带修复该隐藏 bug。

    method_ids 表包含 dex 中所有被引用的方法（含 android.jar 外部 API），
    覆盖面与 xref 的"被调用方法"集合一致。
    """
    for dex in dexs:
        try:
            for m in dex.get_methods_id_item().gets():
                cls = m.get_class_name()
                name = m.get_name()
                desc = m.get_real_descriptor()
                if cls and name:
                    app.called_methods.add(f"{cls}->{name}{desc}")
        except Exception:
            continue


def _collect_code_info(apk: APK, app: AnalyzedApp) -> None:
    """收集 called_methods / strings / classes"""
    dexs: list[DEX] = []
    all_raw = list(apk.get_all_dex())  # generator → list（需要 len 做进度分母）
    total = len(all_raw)
    for i, raw in enumerate(all_raw, 1):
        try:
            logger.info(f"Parsing dex {i}/{total} ({len(raw) / 1048576:.1f} MB)")
            dexs.append(DEX(raw))
        except Exception:
            continue
    if not dexs:
        app.parse_warnings.append("未找到可解析的 dex / No parseable dex found")
        return
    logger.info(f"Extracting method refs / strings / classes from {len(dexs)} dex")

    # 方法引用表（轻量，不建 xref 调用图）
    _collect_method_ids(dexs, app)

    # 字符串池
    for dex in dexs:
        try:
            for s in dex.get_strings():
                app.strings.add(s)
        except Exception:
            continue

    # 类名
    for dex in dexs:
        for cls in dex.get_classes():
            try:
                app.classes.append(cls.get_name())
            except Exception:
                continue


# ---------------------------------------------------------------------------
# AAB 通道（基础支持，实验性）
# ---------------------------------------------------------------------------

# 可打印 ASCII 字符串提取：用于 protobuf Manifest 的启发式解析
_ASCII_STR = re.compile(rb"[\x20-\x7e]{4,}")


def _extract_readable_strings(data: bytes) -> list[str]:
    """从 protobuf bytes 中提取连续可读 ASCII 字符串（启发式）"""
    return [m.decode("ascii") for m in _ASCII_STR.findall(data)]


def _analyze_aab(path: Path) -> AnalyzedApp:
    warnings: list[str] = [
        "AAB 支持为实验性：Manifest 采用启发式解析，待真实样本验证 / "
        "AAB support is experimental: heuristic manifest parsing pending real-sample validation"
    ]
    logger.info(f"Parsing AAB: {path.name} ({path.stat().st_size / 1048576:.1f} MB)")
    app = AnalyzedApp(
        file_path=str(path),
        file_format="AAB",
        file_size=path.stat().st_size,
        sha256=sha256_of_file(path),
    )
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()

        # 1) Manifest 启发式解析
        manifest_names = [n for n in names if n.endswith("AndroidManifest.xml")]
        if manifest_names:
            manifest_bytes = zf.read(manifest_names[0])
            strings = _extract_readable_strings(manifest_bytes)
            app.package = _find_package_from_strings(strings)
            app.declared_permissions = _find_permissions_from_strings(strings)
            app.dangerous_permissions = sorted(
                p for p in app.declared_permissions if p in DANGEROUS_PERMISSIONS
            )
            logger.info(f"Manifest heuristic parse done: package={app.package or '?'}")

        # 2) dex 抽取（代码分析完整可用）
        dex_names = sorted(
            n for n in names if n.startswith("base/dex/") and n.endswith(".dex")
        )
        total = len(dex_names)
        dexs: list[DEX] = []
        for i, dex_name in enumerate(dex_names, 1):
            try:
                logger.info(f"Parsing dex {i}/{total}: {dex_name}")
                dexs.append(DEX(zf.read(dex_name)))
            except Exception:
                continue
        if not dexs:
            warnings.append("AAB 中未找到可解析的 dex / No parseable dex in AAB")
        else:
            logger.info(f"Extracting method refs / strings / classes from {len(dexs)} dex")
            _collect_method_ids(dexs, app)
            for dex in dexs:
                for s, _offset in dex.get_strings():
                    app.strings.add(s)
                for cls in dex.get_classes():
                    try:
                        app.classes.append(cls.get_name())
                    except Exception:
                        continue

    app.parse_warnings = warnings
    return app


def _find_package_from_strings(strings: list[str]) -> Optional[str]:
    """启发式：包名通常形如 com.example.app，在 manifest 字符串中出现"""
    for s in strings:
        if re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z0-9_]+){1,5}", s):
            return s
    return None


def _find_permissions_from_strings(strings: list[str]) -> set[str]:
    return {s for s in strings if s.startswith("android.permission.")}
