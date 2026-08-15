"""检测器：数据破坏性操作（跨目录读写 / 删库 / 远程擦除）。

检测三类信号：
  1. 跨目录/系统路径访问：硬编码指向其他应用私有目录（/data/data/<pkg>）
     或系统目录（/data/system/、/proc/ 等）的路径字符串，配合文件 API 调用。
  2. 删库操作：SQLiteDatabase.delete/execSQL（DELETE/DROP）、Context.deleteDatabase。
  3. 设备管理器擦除：DevicePolicyManager.wipeData/lockNow/resetPassword（远程擦除/锁定）。

防误报设计（沿袭 C2 端点误报修复思路）：
  - 单独出现 File.delete() / 单条危险路径字符串不显著加分（清缓存、卸载清理等合法应用常见）
  - "危险路径 + 文件 API 同现"、"execSQL + SQL 删除语句" 组合才显著加分
"""
from __future__ import annotations

from apkguard.engine.models import AnalyzedApp, Finding, Severity
from apkguard.engine.rule_engine import RuleSet
from apkguard.static.detectors.base import BaseDetector

# 危险路径特征：指向其他应用私有数据目录或系统敏感目录
# 注意不用裸 "/data/" 之类过宽前缀——备份/存储类正常应用也会访问外部存储
_DANGEROUS_PATHS = (
    "/data/data/",  # 其他应用私有数据目录
    "/data/user/",  # 多用户数据目录（/data/user/0/<pkg>）
    "/data/system/",  # 系统配置/密码/KeyStore
    "/data/app/",  # 已安装应用目录（odex/base.apk）
    "/data/local/",  # 本地提权相关
    "/data/anr/",  # ANR 日志
    "/data/tombstones/",  # native crash 墓碑
    "/proc/self/",  # 进程信息（配合反调试已另覆盖）
    "/proc/",  # 全局 /proc 遍历
    "/system/bin/",  # 系统可执行文件
    "/system/xbin/",  # 系统可执行文件（su 常驻）
    "/system/app/",  # 系统应用
)

# 文件访问 API（跨目录读写的载体；以类前缀匹配）
_FILE_APIS = (
    "Ljava/io/File;",
    "Ljava/io/FileInputStream;",
    "Ljava/io/FileOutputStream;",
    "Ljava/io/RandomAccessFile;",
    "Ljava/io/FileReader;",
    "Ljava/io/FileWriter;",
    "Ljava/nio/file/Files;",
    "Lorg/apache/commons/io/",
)

# 删库 / 数据清除 API（精确类限定，避免误伤同名方法）
_DELETE_APIS = (
    "Landroid/database/sqlite/SQLiteDatabase;->delete(",  # 删除表行
    "Landroid/database/sqlite/SQLiteDatabase;->execSQL(",  # 任意 SQL（配合 DROP/DELETE）
    "Landroid/content/ContextWrapper;->deleteDatabase(",  # 删除整个数据库文件
    "Landroid/app/Activity;->deleteDatabase(",
    "Landroid/app/Application;->deleteDatabase(",
)

# SQL 删除语句特征（execSQL 的字符串参数）
_SQL_DELETE_STRINGS = (
    "DELETE FROM",
    "DROP TABLE",
    "DROP DATABASE",
    "TRUNCATE",
)

# 设备管理器擦除/锁定（远程擦除设备数据）
_DEVICE_ADMIN_APIS = (
    "Landroid/app/admin/DevicePolicyManager;->wipeData(",
    "Landroid/app/admin/DevicePolicyManager;->lockNow(",
    "Landroid/app/admin/DevicePolicyManager;->resetPassword(",
)
_DEVICE_ADMIN_RECEIVER = "Landroid/app/admin/DeviceAdminReceiver;"
_DEVICE_ADMIN_PERMISSION = "android.permission.BIND_DEVICE_ADMIN"


class DestructiveOpsDetector(BaseDetector):
    detector_id = "destructive_ops"
    display_name = "数据破坏性操作"
    display_name_en = "Destructive operations (cross-directory access / data wipe)"

    def detect(self, app: AnalyzedApp, rules: RuleSet) -> list[Finding]:
        findings: list[Finding] = []
        strings = app.strings
        called = app.called_methods
        lower_strings = {s.lower() for s in strings}

        # 1) 跨目录 / 系统路径访问
        path_hits: list[str] = []
        for kw in _DANGEROUS_PATHS:
            for s in lower_strings:
                if kw in s:
                    path_hits.append(s[:120])
                    break
        path_hits = path_hits[:8]

        file_calls = [m for m in called if any(api in m for api in _FILE_APIS)]

        if path_hits and file_calls:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="跨目录读写系统/其他应用数据",
                    title_en="Cross-directory access to system or other apps' data",
                    description=(
                        "代码中硬编码了指向系统目录或其他应用私有数据目录的路径，"
                        "且同时存在文件读写 API 调用，构成跨目录数据访问意图"
                        "（正常沙箱下仅能访问自身 /data/data/<pkg> 目录）"
                    ),
                    severity=Severity.HIGH,
                    weight=4,
                    evidence=[*path_hits[:4], *file_calls[:4]],
                    detail={
                        "paths": path_hits,
                        "file_api_count": len(file_calls),
                    },
                )
            )
        elif path_hits:
            # 仅出现危险路径字符串（无文件 API）→ 低权提示，可能是常量/反射
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="硬编码系统/其他应用路径",
                    title_en="Hardcoded system or other apps' paths",
                    description=(
                        "代码中硬编码了系统目录或其他应用私有目录路径，"
                        "暂未发现配套的文件 API 调用；若后续发现文件读写调用需重点核查"
                    ),
                    severity=Severity.LOW,
                    weight=1,
                    evidence=path_hits[:6],
                    detail={"paths": path_hits},
                )
            )

        # 2) 删库操作
        delete_calls = [m for m in called if any(api in m for api in _DELETE_APIS)]
        sql_delete_hits = [s for s in strings if any(k in s for k in _SQL_DELETE_STRINGS)]

        if sql_delete_hits and any("execSQL" in m for m in delete_calls):
            # execSQL + DELETE/DROP 语句：明确的删库/删表意图
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="执行删库/删表 SQL（DROP/DELETE）",
                    title_en="Executes destructive SQL (DROP/DELETE)",
                    description=(
                        "代码调用 SQLiteDatabase.execSQL 执行删除表/删除数据语句，"
                        "且字符串池中存在对应 SQL；正常应用极少直接写 DROP TABLE/DELETE FROM"
                    ),
                    severity=Severity.HIGH,
                    weight=3,
                    evidence=[*sql_delete_hits[:4], *delete_calls[:4]],
                    detail={"sql": sql_delete_hits, "api_calls": delete_calls},
                )
            )
        elif delete_calls:
            # 单独出现 deleteDatabase / SQLiteDatabase.delete → 中权（可能用于重置数据）
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="调用数据库/文件删除 API",
                    title_en="Calls database/file deletion APIs",
                    description=(
                        "代码调用了 SQLiteDatabase.delete / deleteDatabase 等删除类 API，"
                        "可能用于清除自身数据（合法）或销毁证据（恶意）；"
                        "结合其他行为评估其意图"
                    ),
                    severity=Severity.MEDIUM,
                    weight=2,
                    evidence=delete_calls[:6],
                    detail={"api_calls": delete_calls},
                )
            )

        # 3) 设备管理器擦除 / 锁定
        admin_calls = [m for m in called if any(api in m for api in _DEVICE_ADMIN_APIS)]
        has_admin_receiver = any(_DEVICE_ADMIN_RECEIVER in c for c in app.classes)
        has_admin_permission = _DEVICE_ADMIN_PERMISSION in app.declared_permissions

        if admin_calls:
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="设备管理器远程擦除/锁定",
                    title_en="Device admin wipe/lock capability",
                    description=(
                        "代码调用 DevicePolicyManager.wipeData/lockNow/resetPassword，"
                        "可远程擦除设备数据或锁定屏幕；恶意软件（勒索类）常用此能力"
                        "做数据破坏，正常 MDM/防盗应用需具备该权限但调用场景受限"
                    ),
                    severity=Severity.HIGH,
                    weight=4,
                    evidence=[*admin_calls, *([c for c in app.classes if _DEVICE_ADMIN_RECEIVER in c][:2])],
                    detail={
                        "api_calls": admin_calls,
                        "has_admin_receiver": has_admin_receiver,
                        "has_admin_permission": has_admin_permission,
                    },
                )
            )
        elif has_admin_receiver and has_admin_permission:
            # 仅声明设备管理员（无擦除调用）→ 低权提示
            findings.append(
                Finding(
                    detector_id=self.detector_id,
                    title="声明设备管理器权限",
                    title_en="Declares device admin permission",
                    description=(
                        "应用声明了设备管理器权限并注册 DeviceAdminReceiver；"
                        "设备管理器具有锁定/擦除/修改密码等高危能力，需核查用途"
                    ),
                    severity=Severity.LOW,
                    weight=1,
                    evidence=[c for c in app.classes if _DEVICE_ADMIN_RECEIVER in c][:2],
                    detail={"has_admin_receiver": True},
                )
            )

        return findings
