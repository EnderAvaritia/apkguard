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

import threading
import time
from pathlib import Path
from typing import Optional

from apkguard.dynamic.adb_runner import AdbRunner
from apkguard.dynamic.decoy import install_decoy_data
from apkguard.dynamic.frida_collector import FridaCollector, FridaResult
from apkguard.dynamic.interaction import drive_interaction, pre_grant_permissions
from apkguard.dynamic.traffic import ProxyCapture, resolve_proxy_target


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


class DynamicExecutor:
    """针对单台准入设备的一次动态分析"""

    def __init__(self, runner: AdbRunner, options: dict):
        self._runner = runner
        self._options = options or {}

    # ---- 参数 ----

    def _opt(self, key: str, default):
        return self._options.get(key, default)

    # ---- 主流程 ----

    def run(
        self,
        apk_path: Path,
        package: Optional[str],
        dangerous_permissions: list[str],
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

        try:
            # 0) 安装前预检：设备上是否已存在同包名应用
            #    默认保守（replace_existing=false）：拒绝安装并提示，绝不误覆盖
            #    设备上已有的应用；显式配置 replace_existing=true 才允许先卸载再装。
            if self._runner.package_installed(package):
                if not self._opt("replace_existing", False):
                    return {
                        "status": "degraded",
                        "note": (
                            f"设备上已存在同包名应用 {package}；为避免误覆盖，"
                            f"本次不安装（可在 config.yaml 设置 dynamic.replace_existing: true "
                            f"允许先卸载再装）/ package {package} already installed on device; "
                            f"skipped to avoid overwriting (set dynamic.replace_existing: true to replace)"
                        ),
                        "notes": notes + ["existing package refused"],
                    }
                notes.append("existing package found; uninstalling before install")
                if not self._runner.uninstall(package):
                    return {
                        "status": "degraded",
                        "note": "卸载设备上已有同包名应用失败，中止本次安装 / "
                                "failed to uninstall existing package; abort",
                        "notes": notes + ["uninstall existing failed"],
                    }

            # 1) 安装（-g 预授权全部危险权限）
            installed = self._runner.install(str(apk_path), grant_permissions=True)
            if not installed:
                return {
                    "status": "degraded",
                    "note": "样本安装失败，动态分析未执行 / install failed",
                    "notes": notes + ["install failed"],
                }
            notes.append("installed")

            # 2) 危险权限兜底 pm grant
            granted = pre_grant_permissions(
                self._runner, package, dangerous_permissions or []
            )
            if granted:
                notes.append(f"pm granted {len(granted)} permissions")

            # 3) 诱饵数据
            if self._opt("install_decoy_data", True):
                decoy_detail = install_decoy_data(self._runner)
                decoy_installed = any(decoy_detail.values())
                notes.append(
                    f"decoy: {decoy_detail.get('contacts', 0)} contacts, "
                    f"{decoy_detail.get('sms', 0)} sms, "
                    f"{decoy_detail.get('call_log', 0)} call_log"
                )
            else:
                decoy_detail, decoy_installed = {}, False

            # 4) 启动代理抓包
            proxy_addr = resolve_proxy_target(
                self._runner.serial,
                self._opt("host_ip", ""),
                int(self._opt("proxy_port", 8080)),
            )
            if proxy_addr:
                proxy_host, proxy_port = proxy_addr.rsplit(":", 1)
                if capture.start() and self._runner.set_global_proxy(proxy_host, int(proxy_port)):
                    proxy_set = True
                    notes.append(f"proxy {proxy_addr}")
                else:
                    capture.stop()
                    notes.append("proxy unavailable (capture skipped)")
            else:
                notes.append("no proxy target (real device without host_ip; capture skipped)")

            # 5) 启动 App
            launched = self._runner.launch(package)
            if not launched:
                notes.append("launch failed (best-effort continue)")

            # 6) Frida 采集（后台线程，有则全量无则降级）
            use_frida = self._opt("use_frida", True)
            frida_collector = FridaCollector(self._runner)
            if use_frida and frida_collector.is_available():
                window = int(min(int(self._opt("initial_timeout", 300)), 120))

                def _run_frida() -> None:
                    frida_holder["result"] = frida_collector.capture(package, seconds=window)

                threading.Thread(target=_run_frida, daemon=True).start()
            elif use_frida:
                notes.append("frida unavailable (system-level collection only)")

            # 7) 交互 + 智能终止轮询
            self._interact_and_wait(package, capture, started, notes)

            # 8) 收尾采集
            if frida_holder.get("result") is not None:
                frida_result = frida_holder["result"]
            if frida_result.hooked:
                notes.append(f"frida hooked {len(frida_result.messages)} events")
            elif frida_result.note:
                notes.append(f"frida degraded: {frida_result.note}")

        except Exception as e:  # noqa: BLE001 - 执行体承诺永不抛异常，全部降级
            notes.append(f"unexpected error: {e}")
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
                    notes.append("uninstall failed!")
            if proxy_set:
                if not self._runner.clear_global_proxy():
                    cleanup_ok = False
                    notes.append("proxy reset failed!")
            capture.stop()

        endpoints = capture.endpoints
        return {
            "status": "executed",
            "note": (
                f"动态分析完成，采集到 {len(endpoints)} 个网络端点 / "
                f"Dynamic analysis done; {len(endpoints)} endpoints captured"
            ),
            "notes": notes,
            "duration_seconds": int(time.time() - started),
            "traffic_endpoints": endpoints,
            "traffic_count": capture.count,
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

        last_active = time.time()
        last_count = capture.count
        next_monkey = time.time() + monkey_interval

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
                notes.append(
                    f"terminated at {int(elapsed)}s "
                    f"({'max timeout' if elapsed >= max_t else 'idle'})"
                )
                break

            if now >= next_monkey:
                drive_interaction(self._runner, package, events=monkey_events, foreground=fg)
                next_monkey = now + monkey_interval
