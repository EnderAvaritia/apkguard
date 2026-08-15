"""诱饵数据注入（通讯录 / 短信 / 通话记录）。

通过 adb shell content 命令写入系统 ContentProvider，为样本提供"真实环境"
以触发采集敏感数据的行为。全部 best-effort：权限不足 / provider 拒绝时
静默跳过对应类别，只统计成功注入的数量。
"""
from __future__ import annotations

from apkguard.dynamic.adb_runner import AdbRunner

# 每个类别的诱饵条目
_CONTACTS = [
    ("张伟", "13800138000"),
    ("李娜", "13900139000"),
    ("王强", "13700137000"),
    ("刘敏", "13600136000"),
]

_SMS = [
    ("10086", "您的余额为 58.30 元，有效期至月底。"),
    ("95588", "您尾号 6688 的账户收入人民币 12,000.00 元。"),
    ("13800138000", "晚上一起吃饭？老地方见。"),
]

_CALL_LOG = [
    ("13800138000", 2),  # (号码, 类型: 1=来电 2=去电 3=未接)
    ("13900139000", 1),
    ("13700137000", 3),
]


def _insert(runner: AdbRunner, uri: str, binds: list[str]) -> bool:
    cmd = f"content insert --uri {uri} " + " ".join(binds)
    return runner.ok("shell", cmd, timeout=30)


def install_decoy_data(runner: AdbRunner) -> dict[str, int]:
    """注入诱饵数据；返回 {category: inserted_count}"""
    result = {"contacts": 0, "sms": 0, "call_log": 0}

    for name, phone in _CONTACTS:
        if _insert(
            runner,
            "content://contacts/raw_contacts",
            [
                "--bind account_type:s:local",
                "--bind account_name:s:local",
                "--bind display_name:s:" + name,
            ],
        ) and _insert(
            runner,
            "content://contacts/data",
            [
                "--bind raw_contact_id:i:1",
                "--bind mimetype:s:vnd.android.cursor.item/phone_v2",
                "--bind data1:s:" + phone,
                "--bind data2:s:2",
            ],
        ):
            result["contacts"] += 1

    for number, body in _SMS:
        if _insert(
            runner,
            "content://sms",
            [
                "--bind address:s:" + number,
                "--bind body:s:" + body,
                "--bind date:l:1700000000000",
                "--bind read:i:1",
                "--bind type:i:1",
            ],
        ):
            result["sms"] += 1

    for number, call_type in _CALL_LOG:
        if _insert(
            runner,
            "content://call_log/calls",
            [
                "--bind number:s:" + number,
                "--bind type:i:" + str(call_type),
                "--bind date:l:1700000000000",
                "--bind duration:i:35",
            ],
        ):
            result["call_log"] += 1

    return result
