"""动态分析执行体：编排整个流程。

流程（README 第二阶段设计）：
  1. 安装样本（install -g 预授权全部危险权限）
  2. 诱饵数据（可配，best-effort：通讯录/短信/通话）
  3. 启动 App（解析 launcher activity，失败退回 monkey 1）
  4. 采集：代理抓包（必做，C2 端点核心证据）+ Frida hook（可选，有则全量无则降级）
  5. 交互：monkey 随机点击兜底（弹窗授权已由 install -g / pm grant 规避）
  6. 智能终止：初始 initial_timeout / 活跃延长至 max_timeout / 静默 idle_timeout 提前收网
  7. 清理（finally）：卸载样本 + 清除代理 + 结束采集（安全铁律 3）

执行体不做准入校验（由 DeviceManager / backend 把关），只操作传入的 runner
所限定的那台设备。
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Optional

from apkguard.dynamic.adb_runner import AdbRunner
from apkguard.dynamic.decoy import install_decoy_data
from apkguard.dynamic.frida_collector import FridaCollector, FridaResult
from apkguard.dynamic.interaction import (
    drive_activities,
    drive_interaction,
    pre_grant_permissions,
)
from apkguard.dynamic.traffic import ProxyCapture, resolve_proxy_target

# 动态分析过程日志（CLI 配置级别；INFO 输出执行步骤，DEBUG 输出 adb 细节）
logger = logging.getLogger("apkguard.dynamic")


def should_stop(
    elapsed: float,
    active: bool,
    idle_seconds: float,
    initial_timeout: int,
    max_timeout: int,
    idle_timeout: int,
) -> bool:
    """智能终止判定（纯函数，便于单测）。

    - 超时上限 max_timeout → 强制收网
    - 连续静默 idle_timeout 秒 → 提前收网
    - 已过初始窗口且 App 不在前台 → 收网
    """
    if elapsed >= max_timeout:
        return True
    if idle_seconds >= idle_timeout:
        return True
    if elapsed >= initial_timeout and not active:
        return True
    return False


def termination_reason(
    elapsed: float,
    idle_seconds: float,
    initial_timeout: int,
    max_timeout: int,
    idle_timeout: int,
) -> str:
    """收网原因标签（与 should_stop 同规则，纯函数便于测试）"""
    if elapsed >= max_timeout:
        return "max timeout"
    if idle_seconds >= idle_timeout:
        return "idle"
    return "initial timeout"


def _exclude_baseline(endpoints: list[str], baseline: list[str]) -> list[str]:
    """剔除基线期已出现的环境端点，保留样本相关端点。

    全局代理会捕获设备上所有 App 的流量（含系统/其它应用的"邻居流量"），
    运行前先采集一段基线，跑完后差集即为最可能属于样本的端点。
    """
    baseline_set = set(baseline)
    return [e for e in endpoints if e not in baseline_set]


class DynamicExecutor:
    """针对单台准入设备的一次动态分析"""

    def __init__(self, runner: AdbRunner, options: dict):
        self._runner = runner
        self._options = options or {}

    # ---- 参数 ----

    def _opt(self, key: str, default):
        return self._options.get(key, default)

    def _note(self, notes: list[str], message: str) -> None:
        """记录过程信息：写入报告 notes + 实时输出到动态分析日志"""
        logger.info(message)
        notes.append(message)

    # ---- 主流程 ----

    def run(
        self,
        apk_path: Path,
        package: Optional[str],
        dangerous_permissions: list[str],
        version_code: Optional[str] = None,
        activities: Optional[list[str]] = None,
        exported_activities: Optional[list[str]] = None,
    ) -> dict:
        """执行动态分析，返回结果 dict（永不抛异常——失败也降级为状态结果）"""
        notes: list[str] = []
        if not package:
            return {
                "status": "skipped",
                "note": "无法解析样本包名，无法安装运行 / package name unknown",
                "notes": notes,
            }

        started = time.time()
        capture = ProxyCapture(port=int(self._opt("proxy_port", 8080)))
        frida_holder: dict = {}
        frida_result = FridaResult(note="frida capture not started")
        decoy_detail: dict = {}
        decoy_installed = False
        granted: list[str] = []
        proxy_set = False
        cleanup_ok = True
        installed = False
        skip_install = False  # 同版本已装 → 跳过安装但跑后仍清理

        try:
            # 0) 安装前预检：设备上是否已存在同包名应用
            #    - 已有且版本一致（version_code 相同）→ 视为同一应用的残留，
            #      跳过安装直接测试（跑后仍卸载清理）
            #    - 已有但版本不同 / 版本未知 → 默认保守（replace_existing=false）
            #      拒绝安装并提示，绝不误覆盖设备上已有的应用；
            #      显式配置 replace_existing=true 才允许先卸载再装。
            if self._runner.package_installed(package):
                installed_code = self._runner.installed_package_version_code(package)
                if version_code and installed_code and version_code == installed_code:
                    self._note(notes, 
                        f"existing package {package} same version ({version_code}); "
                        "skip install, test as-is"
                    )
                    skip_install = True
                elif not self._opt("replace_existing", False):
                    return {
                        "status": "degraded",
                        "note": (
                            f"设备上已存在同包名应用 {package}（版本 {installed_code or '未知'}，"
                            f"样本版本 {version_code or '未知'}）；为避免误覆盖，本次不安装"
                            f"（可在 config.yaml 设置 dynamic.replace_existing: true 允许"
                            f"先卸载再装）/ package {package} already installed on device "
                            f"(installed={installed_code or 'unknown'}, sample={version_code or 'unknown'}); "
                            f"skipped to avoid overwriting (set dynamic.replace_existing: true to replace)"
                        ),
                        "notes": notes + ["existing package refused"],
                    }
                else:
                    self._note(notes, "existing package found with different version; uninstalling before install")
                    if not self._runner.uninstall(package):
                        return {
                            "status": "degraded",
                            "note": "卸载设备上已有同包名应用失败，中止本次安装 / "
                                    "failed to uninstall existing package; abort",
                            "notes": notes + ["uninstall existing failed"],
                        }

            # 1) 安装（-g 预授权全部危险权限；同版本已装时跳过）
            if not skip_install:
                installed = self._runner.install(str(apk_path), grant_permissions=True)
                if not installed:
                    return {
                        "status": "degraded",
                        "note": "样本安装失败，动态分析未执行 / install failed",
                        "notes": notes + ["install failed"],
                    }
            else:
                installed = True  # 已在设备上（同版本），跑后清理仍会卸载
            self._note(notes, "installed")

            # 2) 危险权限兜底 pm grant
            granted = pre_grant_permissions(
                self._runner, package, dangerous_permissions or []
            )
            if granted:
                self._note(notes, f"pm granted {len(granted)} permissions")

            # 3) 诱饵数据
            if self._opt("install_decoy_data", True):
                decoy_detail = install_decoy_data(self._runner)
                decoy_installed = any(decoy_detail.values())
                self._note(notes, 
                    f"decoy: {decoy_detail.get('contacts', 0)} contacts, "
                    f"{decoy_detail.get('sms', 0)} sms, "
                    f"{decoy_detail.get('call_log', 0)} call_log"
                )
            else:
                decoy_detail, decoy_installed = {}, False

            # 4) 启动代理抓包 + 基线采集（剔除设备环境流量）
            baseline_endpoints: list[str] = []
            baseline_count = 0
            proxy_addr = resolve_proxy_target(
                self._runner.serial,
                self._opt("host_ip", ""),
                int(self._opt("proxy_port", 8080)),
            )
            if proxy_addr:
                proxy_host, proxy_port = proxy_addr.rsplit(":", 1)
                if capture.start() and self._runner.set_global_proxy(proxy_host, int(proxy_port)):
                    proxy_set = True
                    self._note(notes, f"proxy {proxy_addr}")
                    baseline_seconds = max(0, int(self._opt("baseline_seconds", 10)))
                    if baseline_seconds > 0:
                        # 样本启动前先采集环境流量，跑完后差集即样本相关端点
                        time.sleep(baseline_seconds)
                        baseline_endpoints = list(capture.endpoints)
                        baseline_count = capture.count
                        self._note(notes, 
                            f"baseline captured {len(baseline_endpoints)} ambient endpoints"
                        )
                else:
                    capture.stop()
                    self._note(notes, "proxy unavailable (capture skipped)")
            else:
                self._note(notes, "no proxy target (real device without host_ip; capture skipped)")

            # 5) 启动 App
            launched = self._runner.launch(package)
            if not launched:
                self._note(notes, "launch failed (best-effort continue)")

            # 5.5) 随机唤起 activity（强制执行更多代码路径）
            #      默认只唤起"可被外部唤起"的（exported=true / 带 intent-filter），
            #      避免误触发非导出内部组件的副作用路径或缺 extras 的噪音崩溃；
            #      显式配置 interact_hidden_activities: true 才随机唤起全部。
            #      同时排除 launcher activity（MainActivity）——它已由 launch()
            #      打开，再 am start 一次等于"重启整个程序"而非"跳转界面"；
            #      其余 activity 在同一 task 栈内压栈导航（返回键可回退）。
            activity_pool = activities or []
            hidden = self._opt("interact_hidden_activities", False)
            drive_list = activity_pool if hidden else (exported_activities or [])
            if drive_list:
                launcher = self._runner.resolve_launcher_activity(package)
                if launcher and "/" in launcher:
                    launcher_name = launcher.split("/", 1)[1]
                    drive_list = [a for a in drive_list if a != launcher_name]
            if self._opt("interact_activities", True) and drive_list:
                activity_launched = drive_activities(self._runner, package, drive_list)
                self._note(notes, 
                    f"activity driving: launched {len(activity_launched)}/{len(drive_list)}"
                    f" ({'all' if hidden else 'exported-only'})"
                )
            else:
                activity_launched = []

            # 6) Frida 采集（后台线程，有则全量无则降级）
            use_frida = self._opt("use_frida", True)
            frida_collector = FridaCollector(self._runner)
            if use_frida and frida_collector.is_available():
                window = int(min(int(self._opt("initial_timeout", 300)), 120))

                def _run_frida() -> None:
                    frida_holder["result"] = frida_collector.capture(package, seconds=window)

                threading.Thread(target=_run_frida, daemon=True).start()
            elif use_frida:
                self._note(notes, "frida unavailable (system-level collection only)")

            # 7) 交互 + 智能终止轮询
            self._interact_and_wait(package, capture, started, notes)

            # 8) 收尾采集
            if frida_holder.get("result") is not None:
                frida_result = frida_holder["result"]
            if frida_result.hooked:
                self._note(notes, f"frida hooked {len(frida_result.messages)} events")
            elif frida_result.note:
                self._note(notes, f"frida degraded: {frida_result.note}")

        except Exception as e:  # noqa: BLE001 - 执行体承诺永不抛异常，全部降级
            self._note(notes, f"unexpected error: {e}")
            return {
                "status": "degraded",
                "note": f"动态分析异常中断 / dynamic analysis failed: {e}",
                "notes": notes,
            }
        finally:
            # 9) 清理（安全铁律 3）
            if installed:
                cleanup_ok = self._runner.uninstall(package)
                if not cleanup_ok:
                    self._note(notes, "uninstall failed!")
                else:
                    logger.info(f"cleanup: uninstalled {package}")
            if proxy_set:
                if not self._runner.clear_global_proxy():
                    cleanup_ok = False
                    self._note(notes, "proxy reset failed!")
                else:
                    logger.info("cleanup: device proxy reset")
            capture.stop()

        all_endpoints = capture.endpoints
        sample_endpoints = _exclude_baseline(all_endpoints, baseline_endpoints)
        excluded = len(all_endpoints) - len(sample_endpoints)
        return {
            "status": "executed",
            "note": (
                f"动态分析完成，采集到 {len(sample_endpoints)} 个样本相关网络端点"
                f"（基线剔除 {excluded} 个环境端点）/ Dynamic analysis done; "
                f"{len(sample_endpoints)} sample endpoints captured "
                f"({excluded} ambient endpoints excluded by baseline)"
            ),
            "notes": notes,
            "duration_seconds": int(time.time() - started),
            "traffic_endpoints": sample_endpoints,
            "traffic_count": capture.count,
            "baseline_excluded": excluded,
            "baseline_endpoints": baseline_endpoints,
            "frida_hooked": bool(frida_result.hooked) if frida_holder else False,
            "frida_messages": frida_result.messages if frida_holder else [],
            "frida_note": frida_result.note if frida_holder else "",
            "decoy_installed": decoy_installed,
            "decoy_detail": decoy_detail,
            "cleanup_ok": cleanup_ok,
            "granted_permissions": granted,
        }

    # ---- 交互与智能终止 ----

    def _interact_and_wait(
        self, package: str, capture: ProxyCapture, started: float, notes: list[str]
    ) -> None:
        """轮询前台状态与流量活跃度，周期性 monkey 交互，按智能终止策略收网"""
        poll = max(1, int(self._opt("poll_interval", 5)))
        initial = int(self._opt("initial_timeout", 300))
        max_t = int(self._opt("max_timeout", 900))
        idle_t = int(self._opt("idle_timeout", 45))
        monkey_events = int(self._opt("monkey_events", 200))
        monkey_interval = max(poll, int(self._opt("monkey_interval", 30)))
        first_delay = max(poll, int(self._opt("first_interaction_delay", 5)))

        last_active = time.time()
        last_count = capture.count
        next_monkey = started + first_delay  # 首次交互尽早触发（早于 initial_timeout 才可能发生）

        while True:
            time.sleep(poll)
            now = time.time()
            elapsed = now - started

            fg = self._runner.foreground_package()
            active = fg == package or capture.count > last_count
            last_count = capture.count

            if active:
                last_active = now

            if should_stop(
                elapsed=elapsed,
                active=active,
                idle_seconds=now - last_active,
                initial_timeout=initial,
                max_timeout=max_t,
                idle_timeout=idle_t,
            ):
                self._note(notes, 
                    f"terminated at {int(elapsed)}s ("
                    f"{termination_reason(elapsed, now - last_active, initial, max_t, idle_t)})"
                )
                break

            if now >= next_monkey:
                drive_interaction(self._runner, package, events=monkey_events, foreground=fg)
                logger.info(
                    f"interaction: monkey {monkey_events} events @ {int(now - started)}s "
                    f"(foreground={fg or 'unknown'})"
                )
                next_monkey = now + monkey_interval
