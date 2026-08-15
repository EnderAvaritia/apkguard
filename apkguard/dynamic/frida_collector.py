"""Frida 敏感 API hook（可选，不可用则降级为系统层采集）。

设计（README）："有则全量，无则降级"。本模块的依赖 frida 为软依赖：
  - frida Python 包未安装 / 设备上无 frida-server → 返回 unavailable，不报错
  - 附加失败 / 脚本执行失败 → 返回 degraded，不报错
只有全部就绪并成功采集，才返回 hooked=True。

hook 目标（恶意行为高信号）：
  - Runtime.exec：命令执行（shell 反弹 / 提权）
  - SmsManager.sendTextMessage：扣费短信 / 短信外传
  - DexClassLoader.<init>：动态加载代码
  - URL.<init>：网络端点（与抓包互相印证）
  - File.delete / FileOutputStream：文件删除 / 写入（破坏性操作，运行时真实发生才记录）
  - SQLiteDatabase.execSQL / delete、ContextWrapper.deleteDatabase：删库 / 删数据
  - DevicePolicyManager.wipeData / lockNow：设备管理器远程擦除 / 锁定

注意：所有带返回值的 hook 必须 return 原始结果，绝不改变样本行为（纯观测）。
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from apkguard.dynamic.adb_runner import AdbRunner

_SCRIPT = r"""
Java.perform(function () {
    function logMsg(tag, payload) {
        send({ tag: tag, payload: payload });
    }
    try {
        var Rt = Java.use('java.lang.Runtime');
        Rt.exec.overload('java.lang.String').implementation = function (cmd) {
            logMsg('exec', cmd);
            return this.exec(cmd);
        };
        Rt.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
            logMsg('exec_array', JSON.stringify(cmds));
            return this.exec(cmds);
        };
    } catch (e) {}
    try {
        var Sms = Java.use('android.telephony.SmsManager');
        Sms.sendTextMessage.overload(
            'java.lang.String', 'java.lang.String', 'java.lang.String',
            'android.app.PendingIntent', 'android.app.PendingIntent'
        ).implementation = function (dest, sc, text, si, di) {
            logMsg('sms_send', dest + ' => ' + text);
            return this.sendTextMessage(dest, sc, text, si, di);
        };
    } catch (e) {}
    try {
        var Dcl = Java.use('dalvik.system.DexClassLoader');
        Dcl.$init.overload('java.lang.String', 'java.lang.String',
                           'java.lang.String', 'java.lang.ClassLoader')
           .implementation = function (dexPath, opt, lib, parent) {
            logMsg('dex_load', dexPath);
            return this.$init(dexPath, opt, lib, parent);
        };
    } catch (e) {}
    try {
        var Url = Java.use('java.net.URL');
        Url.$init.overload('java.lang.String').implementation = function (spec) {
            logMsg('url', spec);
            return this.$init(spec);
        };
    } catch (e) {}
    // ---- 破坏性操作 hook（被动观测，绝不改变样本行为）----
    try {
        var File = Java.use('java.io.File');
        File['delete'].implementation = function () {
            logMsg('file_delete', this.getAbsolutePath());
            return this['delete']();
        };
    } catch (e) {}
    try {
        var Fos = Java.use('java.io.FileOutputStream');
        Fos.$init.overload('java.lang.String').implementation = function (path) {
            logMsg('file_write', path);
            return this.$init(path);
        };
        Fos.$init.overload('java.io.File').implementation = function (file) {
            logMsg('file_write', file.getAbsolutePath());
            return this.$init(file);
        };
    } catch (e) {}
    try {
        var Sdb = Java.use('android.database.sqlite.SQLiteDatabase');
        Sdb.execSQL.overload('java.lang.String').implementation = function (sql) {
            logMsg('db_execsql', sql);
            return this.execSQL(sql);
        };
        Sdb.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function (sql, bind) {
            logMsg('db_execsql', sql);
            return this.execSQL(sql, bind);
        };
        Sdb['delete'].overload('java.lang.String', 'java.lang.String', '[Ljava.lang.String;').implementation = function (table, where, args) {
            logMsg('db_delete', table + (where ? ' WHERE ' + where : ''));
            return this['delete'](table, where, args);
        };
    } catch (e) {}
    try {
        var Ctx = Java.use('android.content.ContextWrapper');
        Ctx.deleteDatabase.overload('java.lang.String').implementation = function (name) {
            logMsg('db_drop', name);
            return this.deleteDatabase(name);
        };
    } catch (e) {}
    try {
        var Dpm = Java.use('android.app.admin.DevicePolicyManager');
        Dpm.wipeData.overload('int').implementation = function (flags) {
            logMsg('admin_wipe', 'flags=' + flags);
            return this.wipeData(flags);
        };
        Dpm.wipeData.overload('int', 'java.lang.CharSequence').implementation = function (flags, reason) {
            logMsg('admin_wipe', 'flags=' + flags + ' reason=' + reason);
            return this.wipeData(flags, reason);
        };
        Dpm.lockNow.overload().implementation = function () {
            logMsg('admin_lock', '');
            return this.lockNow();
        };
        Dpm.lockNow.overload('int').implementation = function (flags) {
            logMsg('admin_lock', 'flags=' + flags);
            return this.lockNow(flags);
        };
    } catch (e) {}
});
"""


@dataclass
class FridaResult:
    hooked: bool = False
    messages: list[dict] = field(default_factory=list)
    note: str = ""


class FridaCollector:
    """针对单台设备的一次性 Frida 采集"""

    def __init__(self, runner: AdbRunner):
        self._runner = runner

    def is_available(self) -> bool:
        """frida 包可导入 + 设备上有 frida-server 进程，才认为可用"""
        try:
            import frida  # noqa: F401
        except ImportError:
            return False
        return self._runner.device_has_process("frida-server")

    def capture(self, package: str, seconds: int = 30) -> FridaResult:
        """附加到 App 进程并采集 seconds 秒；任何失败都降级不抛异常"""
        try:
            import frida
        except ImportError as e:
            return FridaResult(note=f"frida 未安装 / frida not installed ({e})")

        if not self._runner.device_has_process("frida-server"):
            return FridaResult(note="设备上无 frida-server，已降级系统层采集 / no frida-server")

        messages: list[dict] = []
        session: Optional[object] = None
        try:
            device = frida.get_device(self._runner.serial, timeout=5)
            # 附加可能发生在进程刚启动时：先等待进程出现
            pid = self._wait_for_process(package, timeout=15)
            if pid is None:
                return FridaResult(note=f"未发现进程 {package} / process not found")
            session = device.attach(pid)

            def on_message(message: dict, data: bytes | None) -> None:
                if message.get("type") == "send":
                    messages.append(message.get("payload") or {})

            script = session.create_script(_SCRIPT)
            script.on("message", on_message)
            script.load()
            time.sleep(max(1, min(seconds, 60)))
            return FridaResult(hooked=True, messages=messages)
        except Exception as e:  # noqa: BLE001 - 任何 Frida 失败都降级
            return FridaResult(note=f"Frida 采集降级 / degraded: {e}")
        finally:
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass

    def _wait_for_process(self, package: str, timeout: int = 15) -> Optional[int]:
        """等待目标包进程出现，返回 pid；超时返回 None"""
        import frida

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                device = frida.get_device(self._runner.serial, timeout=5)
                for proc in device.enumerate_processes():
                    if proc.name == package:
                        return proc.pid
            except Exception:
                pass
            time.sleep(1)
        return None
