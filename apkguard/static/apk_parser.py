"""输入解析层：APK/AAB 双通道解析，产出 AnalyzedApp（检测器的输入契约）。

- APK 通道：androguard 完整解析（Manifest + dex 反编译 + 签名）
- AAB 通道：zip 容器解析 + dex 抽取（代码分析完全可用）+ protobuf
  Manifest 启发式基础解析（实验性，标注 warning，待真实样本验证）

本模块只做"读取与提取"，不做任何恶意判定。
"""
from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from androguard.core.apk import APK
from androguard.core.analysis.analysis import Analysis
from androguard.core.dex import DEX

from apkguard.engine.models import AnalyzedApp, SignatureInfo

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

def _analyze_apk(path: Path) -> AnalyzedApp:
    warnings: list[str] = []
    apk = APK(str(path))
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
        pass
    try:
        app.version = apk.get_androidversion_name()
    except Exception:
        pass
    try:
        app.min_sdk = apk.get_min_sdk_version()
    except Exception:
        pass
    try:
        app.target_sdk = apk.get_target_sdk_version()
    except Exception:
        pass

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
        pass
    return schemes or ["v1"]


def _collect_code_info(apk: APK, app: AnalyzedApp) -> None:
    """收集 called_methods / strings / classes"""
    dexs: list[DEX] = []
    for raw in apk.get_all_dex():
        try:
            dexs.append(DEX(raw))
        except Exception:
            continue
    if not dexs:
        app.parse_warnings.append("未找到可解析的 dex / No parseable dex found")
        return

    analysis = Analysis(dexs)

    # 被调用的方法全名（供 api 规则匹配）
    for method in analysis.get_methods():
        try:
            for _cls, callee, _offset in method.get_xref_to():
                app.called_methods.add(callee.full_name)
        except Exception:
            continue
    # 也加入方法自身的声明名，防止只被外部调用的情况
    for method in analysis.get_methods():
        try:
            app.called_methods.add(method.full_name)
        except Exception:
            continue

    # 字符串池
    for dex in dexs:
        try:
            for s, _offset in dex.get_strings():
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

        # 2) dex 抽取（代码分析完整可用）
        dex_names = sorted(
            n for n in names if n.startswith("base/dex/") and n.endswith(".dex")
        )
        dexs: list[DEX] = []
        for dex_name in dex_names:
            try:
                dexs.append(DEX(zf.read(dex_name)))
            except Exception:
                continue
        if not dexs:
            warnings.append("AAB 中未找到可解析的 dex / No parseable dex in AAB")
        else:
            analysis = Analysis(dexs)
            for method in analysis.get_methods():
                try:
                    for _cls, callee, _offset in method.get_xref_to():
                        app.called_methods.add(callee.full_name)
                    app.called_methods.add(method.full_name)
                except Exception:
                    continue
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
