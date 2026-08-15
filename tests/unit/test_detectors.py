"""检测器单元测试：构造 AnalyzedApp 数据类喂给各检测器，验证判定逻辑。"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.config import Config
from apkguard.engine.models import AnalyzedApp, SignatureInfo
from apkguard.engine.rule_engine import load_rules
from apkguard.static.detectors.base import get_detectors
from apkguard.static.detectors.accessibility import AccessibilityDetector
from apkguard.static.detectors.antiav_evasion import AntiavEvasionDetector
from apkguard.static.detectors.c2_network import C2NetworkDetector
from apkguard.static.detectors.data_exfil import DataExfilDetector
from apkguard.static.detectors.destructive_ops import DestructiveOpsDetector
from apkguard.static.detectors.dynamic_loading import DynamicLoadingDetector
from apkguard.static.detectors.overlay import OverlayDetector
from apkguard.static.detectors.permissions import PermissionsDetector
from apkguard.static.detectors.signature import SignatureDetector
from apkguard.static.detectors.sms_telephony import SmsTelephonyDetector


@pytest.fixture(scope="session")
def rules():
    return load_rules(Config().rules_dir)


def make_app(**kwargs) -> AnalyzedApp:
    base = dict(
        file_path="test.apk",
        file_format="APK",
        file_size=100,
        sha256="0" * 64,
        declared_permissions=set(),
        called_methods=set(),
        strings=set(),
        classes=[],
    )
    base.update(kwargs)
    return AnalyzedApp(**base)


class TestPermissionsDetector:
    def test_sms_chain_detected(self, rules):
        app = make_app(
            declared_permissions={"android.permission.SEND_SMS"},
            called_methods={
                "Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;)V"
            },
        )
        findings = PermissionsDetector().detect(app, rules)
        ids = {f.detector_id for f in findings}
        assert "permissions" in ids
        chain = [f for f in findings if "短信" in f.title]
        assert chain, "应命中短信权限+API 调用链"

    def test_permission_only_no_chain(self, rules):
        app = make_app(declared_permissions={"android.permission.SEND_SMS"})
        findings = PermissionsDetector().detect(app, rules)
        # YAML 权限规则命中，但无配对调用链
        assert any(f.detector_id == "rule:sms_send" for f in findings)


class TestDynamicLoadingDetector:
    def test_basic_loader(self, rules):
        app = make_app(
            called_methods={"Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;)V"}
        )
        findings = DynamicLoadingDetector().detect(app, rules)
        assert len(findings) == 1
        assert findings[0].detector_id == "dynamic_loading"

    def test_loader_with_download_and_write_critical(self, rules):
        app = make_app(
            called_methods={
                "Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;)V",
                "Ljava/net/URL;->openConnection()Ljava/net/URLConnection;",
                "Ljava/io/FileOutputStream;->write([B)V",
            }
        )
        findings = DynamicLoadingDetector().detect(app, rules)
        assert findings[0].severity.value == "critical"
        assert findings[0].weight == 5

    def test_clean_app_no_finding(self, rules):
        app = make_app(called_methods={"Ljava/lang/String;->length()I"})
        assert DynamicLoadingDetector().detect(app, rules) == []


class TestAccessibilityDetector:
    def test_abuse_detected(self, rules):
        app = make_app(
            declared_permissions={"android.permission.BIND_ACCESSIBILITY_SERVICE"},
            classes=["com.malware.HookService"],
            called_methods={"Landroid/accessibilityservice/AccessibilityService;->getRootInActiveWindow()"},
        )
        findings = AccessibilityDetector().detect(app, rules)
        assert findings and findings[0].severity.value == "critical"

    def test_no_sensitive_call_low(self, rules):
        app = make_app(
            declared_permissions={"android.permission.BIND_ACCESSIBILITY_SERVICE"},
            classes=["com.malware.HookService"],
            called_methods=set(),
        )
        findings = AccessibilityDetector().detect(app, rules)
        assert findings and findings[0].weight == 1


class TestOverlayDetector:
    def test_overlay_attack(self, rules):
        app = make_app(
            declared_permissions={"android.permission.SYSTEM_ALERT_WINDOW"},
            strings={"TYPE_APPLICATION_OVERLAY"},
        )
        findings = OverlayDetector().detect(app, rules)
        assert findings and findings[0].severity.value == "high"


class TestSmsTelephonyDetector:
    def test_premium_number_detected(self, rules):
        app = make_app(
            declared_permissions={"android.permission.SEND_SMS"},
            called_methods={"Landroid/telephony/SmsManager;->sendTextMessage(Ljava/lang/String;)V"},
            strings={"1069012345678"},
        )
        findings = SmsTelephonyDetector().detect(app, rules)
        assert any("扣费" in f.title for f in findings)
        assert findings[0].severity.value == "critical"

    def test_sms_interception(self, rules):
        app = make_app(
            declared_permissions={"android.permission.RECEIVE_SMS"},
            called_methods={"Landroid/provider/Telephony$Sms$Intents;->getMessagesFromIntent()"},
        )
        findings = SmsTelephonyDetector().detect(app, rules)
        assert any("拦截" in f.title for f in findings)

    def test_keyevent_getdeviceid_not_flagged(self, rules):
        """KeyEvent.getDeviceId() 与手机设备标识无关，不应触发采集告警"""
        app = make_app(
            called_methods={
                "Landroid/view/KeyEvent;->getDeviceId()I",
            }
        )
        findings = SmsTelephonyDetector().detect(app, rules)
        assert not any("采集" in f.title for f in findings), (
            f"KeyEvent.getDeviceId 不应触发: {[f.title for f in findings]}"
        )

    def test_telephony_getdeviceid_flagged(self, rules):
        """TelephonyManager.getDeviceId()（IMEI）应触发采集告警"""
        app = make_app(
            called_methods={
                "Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;",
            }
        )
        findings = SmsTelephonyDetector().detect(app, rules)
        assert any("采集" in f.title for f in findings)


class TestDataExfilDetector:
    def test_exfil_chain(self, rules):
        app = make_app(
            called_methods={
                "Landroid/provider/ContactsContract;->query()",
                "Ljava/net/HttpURLConnection;->getOutputStream()Ljava/io/OutputStream;",
            }
        )
        findings = DataExfilDetector().detect(app, rules)
        assert findings and findings[0].detail.get("has_upload") is True


class TestC2NetworkDetector:
    def test_hardcoded_ip_detected(self, rules):
        app = make_app(strings={"http://192.168.1.100:8080/api"})
        findings = C2NetworkDetector().detect(app, rules)
        assert findings and findings[0].detector_id == "c2_network"
        assert findings[0].detail.get("suspicious_count", 0) >= 1

    def test_clean_domain_no_finding(self, rules):
        app = make_app(strings={"https://www.example.com/index.html"})
        assert C2NetworkDetector().detect(app, rules) == []


class TestSignatureDetector:
    def test_debug_key_detected(self, rules):
        app = make_app(
            signature=SignatureInfo(
                valid=True, signature_scheme="v1", signer="CN=Android Debug",
                issuer="CN=Android Debug", serial="1", sha256="x" * 64,
                not_before=None, not_after=None, self_signed=True, debug_key=True,
            )
        )
        findings = SignatureDetector().detect(app, rules)
        assert any("调试签名" in f.title for f in findings)

    def test_no_signature(self, rules):
        app = make_app(signature=None)
        findings = SignatureDetector().detect(app, rules)
        assert findings and "无法获取签名信息" in findings[0].title


class TestAntiavEvasionDetector:
    def test_emulator_detection(self, rules):
        app = make_app(
            strings={"Build.FINGERPRINT", "generic_x86", "xposed_module"},
            called_methods={"Landroid/os/Debug;->isDebuggerConnected()Z"},
        )
        findings = AntiavEvasionDetector().detect(app, rules)
        titles = " | ".join(f.title for f in findings)
        assert "模拟器" in titles
        assert "Hook" in titles
        assert "反调试" in titles

    def test_clean_no_finding(self, rules):
        app = make_app(strings={"hello world"})
        assert AntiavEvasionDetector().detect(app, rules) == []

    def test_bouncycastle_class_name_not_emulator(self, rules):
        """BouncyCastle 类名含 'generic' 子串，不应误判为模拟器检测"""
        app = make_app(
            strings={
                "lorg/bouncycastle/jcajce/provider/symmetric/util/baseblockcipher$aeadgenericblockcipher"
            }
        )
        findings = AntiavEvasionDetector().detect(app, rules)
        assert not any("模拟器" in f.title for f in findings), (
            f"BouncyCastle 类名不应触发模拟器检测: {[f.title for f in findings]}"
        )

    def test_successcontinuation_not_root(self, rules):
        """类名含 'su' 子串（如 successcontinuation）不应误判为 Root 检测"""
        app = make_app(
            strings={"lcom/google/android/gms/tasks/successcontinuation;"}
        )
        findings = AntiavEvasionDetector().detect(app, rules)
        assert not any("Root" in f.title for f in findings), (
            f"successcontinuation 不应触发 Root 检测: {[f.title for f in findings]}"
        )


class TestDestructiveOpsDetector:
    def test_cross_directory_read_write(self, rules):
        """危险路径 + 文件 API 同现 → 跨目录读写 HIGH"""
        app = make_app(
            called_methods={"Ljava/io/File;->openFileInput()"},
            strings={"/data/data/com.target.app/databases/secret.db"},
        )
        findings = DestructiveOpsDetector().detect(app, rules)
        assert any("跨目录" in f.title for f in findings)
        hit = [f for f in findings if "跨目录" in f.title][0]
        assert hit.severity.value == "high"
        assert hit.weight == 4

    def test_dangerous_path_string_only_low(self, rules):
        """仅有危险路径字符串（无文件 API）→ 低权提示"""
        app = make_app(
            strings={"/data/system/packages.xml"},
        )
        findings = DestructiveOpsDetector().detect(app, rules)
        assert any("硬编码" in f.title for f in findings)
        hit = [f for f in findings if "硬编码" in f.title][0]
        assert hit.severity.value == "low"
        assert hit.weight == 1

    def test_execsql_drop_table_high(self, rules):
        """execSQL + DROP TABLE → 删库 HIGH"""
        app = make_app(
            called_methods={
                "Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V"
            },
            strings={"DROP TABLE IF EXISTS user_info"},
        )
        findings = DestructiveOpsDetector().detect(app, rules)
        assert any("删库" in f.title for f in findings)
        hit = [f for f in findings if "删库" in f.title][0]
        assert hit.severity.value == "high"

    def test_delete_database_medium(self, rules):
        """单独 deleteDatabase → 中权（无 SQL 字符串）"""
        app = make_app(
            called_methods={
                "Landroid/content/ContextWrapper;->deleteDatabase(Ljava/lang/String;)Z"
            },
        )
        findings = DestructiveOpsDetector().detect(app, rules)
        assert any("删除" in f.title for f in findings)
        hit = [f for f in findings if "删除" in f.title][0]
        assert hit.severity.value == "medium"
        assert hit.weight == 2

    def test_device_admin_wipe_high(self, rules):
        """DevicePolicyManager.wipeData → 远程擦除 HIGH"""
        app = make_app(
            called_methods={
                "Landroid/app/admin/DevicePolicyManager;->wipeData(I)V"
            },
            declared_permissions={"android.permission.BIND_DEVICE_ADMIN"},
            classes=["com.malware.AdminReceiver"],
        )
        findings = DestructiveOpsDetector().detect(app, rules)
        assert any("擦除" in f.title for f in findings)
        hit = [f for f in findings if "擦除" in f.title][0]
        assert hit.weight == 4

    def test_file_delete_alone_no_finding(self, rules):
        """单独 File.delete()（无危险路径）→ 不误报（清缓存等合法常见）"""
        app = make_app(
            called_methods={"Ljava/io/File;->delete()Z"},
            strings={"cache"},
        )
        assert DestructiveOpsDetector().detect(app, rules) == []

    def test_clean_app_no_finding(self, rules):
        app = make_app(
            called_methods={"Ljava/lang/String;->length()I"},
            strings={"hello world"},
        )
        assert DestructiveOpsDetector().detect(app, rules) == []


class TestDetectorRegistry:
    def test_all_10_detectors_registered(self):
        ids = {d.detector_id for d in get_detectors()}
        assert ids == {
            "permissions", "dynamic_loading", "accessibility", "overlay",
            "sms_telephony", "data_exfil", "c2_network", "signature",
            "antiav_evasion", "destructive_ops",
        }
