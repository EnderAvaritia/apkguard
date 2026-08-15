"""网络端点提取单元测试：C2 特征打分与误报控制。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.static.network_extract import (
    _is_private_ip,
    extract_network_endpoints,
)


class TestPrivateIp:
    def test_private_ranges(self):
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.1.1"):
            assert _is_private_ip(ip), ip

    def test_public_ip(self):
        assert not _is_private_ip("8.8.8.8")
        assert not _is_private_ip("114.114.114.114")


class TestEndpointExtraction:
    def test_hardcoded_ip_flagged(self):
        endpoints = extract_network_endpoints({"connect to http://45.33.21.9:8080/x"})
        ips = [e for e in endpoints if e.kind == "ip" and e.score > 0]
        assert ips, "应提取出硬编码公网 IP 并打分"

    def test_private_ip_lower_score(self):
        endpoints = extract_network_endpoints({"http://10.0.0.5/api"})
        ips = [e for e in endpoints if e.kind == "ip"]
        assert ips and ips[0].score == 2  # 内网地址

    def test_normal_domain_no_score(self):
        endpoints = extract_network_endpoints({"https://www.baidu.com/s?wd=1"})
        domains = [e for e in endpoints if e.kind == "domain"]
        assert domains
        assert all(e.score == 0 for e in domains)

    def test_dga_feature(self):
        endpoints = extract_network_endpoints({"http://x8f3k2j9q4w7v1.example.net/"})
        domains = [e for e in endpoints if e.kind == "domain"]
        assert domains and domains[0].score > 0

    def test_noise_domains_filtered(self):
        endpoints = extract_network_endpoints(
            {"http://schemas.android.com/apk/res/android", "http://www.w3.org/2001/XMLSchema"}
        )
        assert not any("schemas.android.com" == e.endpoint for e in endpoints)

    def test_oid_not_flagged_as_ip(self):
        """证书 OID（如 2.5.29.18）不是 IP，不应被当作 C2 端点"""
        endpoints = extract_network_endpoints(
            {"2.5.29.18", "1.3.6.1.4.1.11129.2.4.2", "1.2.840.113549.1.1.11"}
        )
        assert not any(e.kind == "ip" for e in endpoints), (
            f"OID 不应被识别为 IP: {[e.endpoint for e in endpoints]}"
        )

    def test_oid_like_url_host_ignored(self):
        """URL 中的 OID 伪 IP host 不应加分"""
        endpoints = extract_network_endpoints({"http://2.5.29.18/something"})
        urls = [e for e in endpoints if e.kind == "url"]
        assert all(e.score == 0 for e in urls), "OID host 不应产生 C2 评分"

    def test_real_public_ip_still_flagged(self):
        """真实公网 IP 仍然被识别（不误伤）"""
        endpoints = extract_network_endpoints({"http://45.33.21.9:6666/beacon"})
        ips = [e for e in endpoints if e.kind == "ip" and e.score > 0]
        assert ips, "真实公网 IP 应被识别"

    def test_java_class_name_not_domain(self):
        """Java 类名/包名（com.foo.bar）与域名同形，应被类名交叉验证过滤"""
        strings = {
            "com.google.android.gms.ads.identifier.service.AdsIdentifierService",
            "org.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi",
        }
        classes = [
            "Lcom/google/android/gms/ads/identifier/service/AdsIdentifierService;",
            "Lorg/bouncycastle/jcajce/provider/asymmetric/ec/KeyAgreementSpi;",
        ]
        endpoints = extract_network_endpoints(strings, classes)
        assert not any(e.kind == "domain" for e in endpoints), (
            f"类名不应被识别为域名: {[e.endpoint for e in endpoints]}"
        )

    def test_real_domain_not_filtered_by_class_check(self):
        """真实域名不应被类名交叉验证误伤"""
        strings = {"https://api.example.com/v1/data"}
        classes = ["Lcom/google/android/gms/ads/identifier/service/AdsIdentifierService;"]
        endpoints = extract_network_endpoints(strings, classes)
        assert any(e.kind == "domain" for e in endpoints)
        assert any("example.com" in e.endpoint for e in endpoints)

    def test_low_first_octet_bare_ip_filtered(self):
        """裸 IP 首段 0-5（OID/版本号重灾区）应被过滤"""
        endpoints = extract_network_endpoints({"1.9.16.3", "5.5.7.4", "3.1.3.4"})
        assert not any(e.kind == "ip" for e in endpoints), (
            f"OID 变体不应被识别为 IP: {[e.endpoint for e in endpoints]}"
        )

    def test_url_with_standard_port_no_flag(self):
        endpoints = extract_network_endpoints({"https://api.example.com:443/v1"})
        urls = [e for e in endpoints if e.kind == "url"]
        # 标准端口不应加分
        assert all("非标准端口" not in " ".join(e.features) for e in urls)

    def test_url_nonstandard_port_flagged(self):
        endpoints = extract_network_endpoints({"http://c2.example.com:4444/beacon"})
        urls = [e for e in endpoints if e.kind == "url"]
        assert any("非标准端口" in " ".join(e.features) for e in urls)
