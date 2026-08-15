"""按设备限定的 adb 命令封装。

安全要点：所有命令都通过 `adb -s <serial>` 限定目标设备——
同一台机器可能连着多个 adb 设备，裸 `adb` 命令会落到"默认设备"上，
这可能就是用户的工作设备。动态执行体只允许操作准入过的设备，
故本模块强制要求传入 serial，禁止裸调。

只做命令执行与解析，不做准入校验（准入由 device_manager 负责）。
"""
from __future__ import annotations

import subprocess
from typing import Optional


class AdbRunner:
    """针对单台 adb 设备的命令执行器（始终带 -s <serial>）"""

    def __init__(self, serial: str, adb_bin: str = "adb"):
        self.serial = serial
        self._adb_bin = adb_bin

    def run(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        """执行 `adb -s <serial> <args>`；异常（找不到 adb/超时/OS 错误）转为 rc=1 结果"""
        try:
            return subprocess.run(
                [self._adb_bin, "-s", self.serial, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            return subprocess.CompletedProcess(
                args=args, returncode=1, stdout="", stderr=str(e)
            )

    def ok(self, *args: str, timeout: int = 60) -> bool:
        """执行命令并返回是否成功（rc == 0）"""
        return self.run(*args, timeout=timeout).returncode == 0

    def shell(self, command: str, timeout: int = 60) -> str:
        """`adb -s <serial> shell <command>`，返回 stdout"""
        return self.run("shell", command, timeout=timeout).stdout.strip()

    # ---- 常用操作 ----

    def install(self, apk_path: str, grant_permissions: bool = True) -> bool:
        """安装 APK。grant_permissions=True 时用 -g 预授权全部危险权限
        （等效"弹窗授权优先点允许"，规避运行时授权弹窗）"""
        args = ["install"]
        if grant_permissions:
            args.append("-g")
        args.append(apk_path)
        return self.ok(*args, timeout=180)

    def package_installed(self, package: str) -> bool:
        """设备上是否已存在同包名应用（`pm path <pkg>` 非空即已安装）。

        用于动态分析安装前预检：避免重复安装失败，或误覆盖已有应用。
        """
        return bool(self.shell(f"pm path {package}", timeout=30))

    def installed_package_version_code(self, package: str) -> Optional[str]:
        """设备上已安装包的 versionCode（`dumpsys package` 解析）。

        与样本 version_code 比对：同版本视为同一应用（可直接测试），
        解析失败返回 None（版本未知 → 走保守的 replace_existing 逻辑）。
        """
        out = self.shell(
            f"dumpsys package {package} | grep 'versionCode='",
            timeout=30,
        )
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("versionCode="):
                # 形如: versionCode=172312 minSdk=21 targetSdk=34
                return line.split(" ", 1)[0].split("=", 1)[1]
        return None

    def uninstall(self, package: str) -> bool:
        """卸载已安装的样本包（跑后清理）。
        不带 -k：连 /data/data/<pkg> 用户数据一并清除，保证下次安装环境干净。"""
        return self.ok("uninstall", package, timeout=60)

    def launch(self, package: str) -> bool:
        """启动 App：解析 launcher activity 后 am start；解析失败退回 monkey"""
        activity = self.resolve_launcher_activity(package)
        if activity:
            return self.ok("shell", "am", "start", "-n", activity, timeout=30)
        # 兜底：monkey -p pkg 1 会拉起 launcher activity
        return self.monkey(package, events=1)

    def resolve_launcher_activity(self, package: str) -> Optional[str]:
        """返回 `pkg/activity` 形式的 launcher activity；失败返回 None"""
        out = self.shell("cmd package resolve-activity --brief " + package, timeout=30)
        for line in out.splitlines():
            line = line.strip()
            if line and "/" in line and "android.intent" not in line:
                return line
        return None

    def foreground_package(self) -> Optional[str]:
        """当前前台 App 包名（dumpsys activity 解析）；失败返回 None"""
        out = self.shell(
            "dumpsys activity activities | grep -E 'ResumedActivity|topResumedActivity'",
            timeout=30,
        )
        for line in out.splitlines():
            if "ResumedActivity" in line and "{" in line:
                # 形如: ResumedActivity: {com.android.launcher/...}
                part = line.split("{", 1)[1]
                pkg = part.split("/", 1)[0]
                return pkg.strip()
        return None

    def grant_permissions(self, package: str, permissions: list[str]) -> list[str]:
        """逐个 pm grant 授权；返回成功授权的权限列表（失败静默跳过）"""
        granted: list[str] = []
        for perm in permissions:
            if self.ok("shell", "pm", "grant", package, perm, timeout=30):
                granted.append(perm)
        return granted

    def monkey(self, package: str, events: int = 200, throttle_ms: int = 50) -> bool:
        """monkey 随机事件驱动 UI；失败返回 False（不影响主流程）"""
        return self.ok(
            "shell",
            "monkey",
            "-p", package,
            "--throttle", str(throttle_ms),
            "-v", str(events),
            timeout=120,
        )

    def set_global_proxy(self, host: str, port: int) -> bool:
        """设置设备全局 HTTP 代理（流量抓包用）；失败返回 False"""
        return self.ok(
            "shell", "settings", "put", "global", "http_proxy", f"{host}:{port}",
            timeout=30,
        )

    def clear_global_proxy(self) -> bool:
        """清除设备全局代理（跑后清理）；失败返回 False"""
        return self.ok("shell", "settings", "put", "global", "http_proxy", ":0", timeout=30)

    def device_has_process(self, pattern: str) -> bool:
        """设备上是否存在匹配 pattern 的进程（如 frida-server）"""
        out = self.shell("ps -A | grep " + pattern, timeout=30)
        return bool(out)

    def logcat(self, filter_spec: str = "*:S ActivityManager:I") -> str:
        """读取当前 logcat 缓冲（activity 启动证据等）；失败返回空串"""
        return self.shell(f"logcat -d -t 200 {filter_spec}", timeout=30)
