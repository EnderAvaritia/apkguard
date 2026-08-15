"""检测器：模拟器探测 / 反沙箱 / 反调试识别。

正常应用不需要检测自己是否运行在模拟器中、是否被调试、是否被 Hook。
存在这些逻辑本身就是可疑信号：恶意软件用它们逃避分析。
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector

# 模拟器特征字符串（Build 属性检测、文件路径检测）
_EMULATOR_STRINGS = (
    "generic",
    "goldfish",
    "ranchu",
    "sdk_gphone",
    "emulator",
    "qemu",
    "no.emulator",
    "is_emulator",
    "phone_emulator",
)
# 反调试字符串/API
_ANTIDEBUG_STRINGS = (
    "isDebuggerConnected",
    "Debug.isDebuggerConnected",
    "TracerPid",
    "/proc/self/status",
)
# Hook 检测字符串
_HOOK_STRINGS = (
    "xposed",
    "frida",
    "substrate",
    "edxposed",
)
# Root 检测字符串
_ROOT_STRINGS = (
    "su",
    "Superuser.apk",
    "magisk",
    "/system/xbin/which",
    "ro.secure",
    "test-keys",
)


class AntiavEvasionDetector(BaseDetector):
    detector_id = "antiav_evasion"
    display_name = "模拟器探测/反沙箱/反调试"
    display_name_en = "Emulator detection / anti-sandbox / anti-debug"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        strings = app.strings
        called = app.called_methods

        def count_hits(keywords: tuple[str, ...]) -> list[str]:
            hits: list[str] = []
            lower_strings = {s.lower() for s in strings}
            for kw in keywords:
                for s in lower_strings:
                    if kw in s:
                        hits.append(s[:80])
                        break
            return hits[:10]

        # 1) 模拟器检测
        emu_hits = count_hits(_EMULATOR_STRINGS)
        if emu_hits:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="存在模拟器环境探测逻辑",
                    title_en="Contains emulator environment detection",
                    description=(
                        "代码中出现模拟器特征检测（Build 属性/文件/字符串），"
                        "正常应用无需检测运行环境；恶意软件用它识别沙箱并隐藏恶意行为"
                    ),
                    severity=Severity.MEDIUM,
                    weight=2,
                    evidence=emu_hits[:6],
                )
            )

        # 2) 反调试
        debug_hits = count_hits(_ANTIDEBUG_STRINGS)
        debug_calls = [m for m in called if "isDebuggerConnected" in m]
        if debug_hits or debug_calls:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="存在反调试逻辑",
                    title_en="Contains anti-debugging logic",
                    description="代码包含调试器检测逻辑，恶意软件常用它阻止分析人员动态调试",
                    severity=Severity.MEDIUM,
                    weight=2,
                    evidence=(debug_calls + debug_hits)[:6],
                )
            )

        # 3) Hook 框架检测
        hook_hits = count_hits(_HOOK_STRINGS)
        if hook_hits:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="检测 Hook 框架（Xposed/Frida）",
                    title_en="Detects hooking frameworks (Xposed/Frida)",
                    description="代码包含 Xposed/Frida 等 Hook 框架检测，用于对抗动态分析插桩",
                    severity=Severity.MEDIUM,
                    weight=2,
                    evidence=hook_hits[:6],
                )
            )

        # 4) Root 检测
        root_hits = count_hits(_ROOT_STRINGS)
        if root_hits:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="包含 Root 检测逻辑",
                    title_en="Contains root detection logic",
                    description="代码包含 Root 环境检测，部分恶意软件以此确认提权环境或规避分析",
                    severity=Severity.LOW,
                    weight=1,
                    evidence=root_hits[:6],
                )
            )

        return findings
