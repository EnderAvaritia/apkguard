"""C2 网络端点提取与分析：从字符串池挖掘域名/IP/URL，按静态特征打分。

特征打分规则（分数可调）：
  +3 纯 IP 硬编码（正常 App 极少硬编码 IP，C2 常见）
  +2 非标准端口（非 80/443/8080）
  +2 内网/保留地址（10.x / 192.168.x / 127.x / 0.0.0.0 等）
  +2 DGA 特征（域名含长数字串或高熵）
  +3 IDN 伪装（punycode xn-- 前缀）
  +3 混淆串（解码后为 URL 的 base64/hex 字符串）
  +1 深层子域/随机子域
"""
from __future__ import annotations

import base64
import ipaddress
import math
import re
import string
from urllib.parse import urlsplit

from apkguard.engine.models import NetworkEndpoint

# IPv4 / IPv6 / 域名 / URL 提取
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_IPV6_RE = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b"
)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,63})\b"
)
_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)

# 常见噪音域名（误报过滤）
_NOISE_DOMAINS = {
    "schemas.android.com",
    "www.w3.org",
    "android.com",
    "google.com",
    "android.googleapis.com",
    "play.google.com",
    "example.com",
    "example.org",
    "apache.org",
    "xmlpull.org",
}

# 非标准端口判定（这些是常见正常端口）
_STANDARD_PORTS = {80, 443, 8080, 8443}

# 混淆串前缀特征（base64/hex 常以这些开头）
_CONFUSED_PREFIXES = ("aHR0c", "68747470", "2f2f", "68 74 74 70")


def _entropy(s: str) -> float:
    """字符串香农熵"""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(s)]
    return -sum(p * math.log2(p) for p in prob)


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def _dga_features(domain: str) -> list[str]:
    """检测 DGA（域名生成算法）特征"""
    features: list[str] = []
    # 域名主体（去掉 TLD）
    parts = domain.split(".")
    body = ".".join(parts[:-1]) if len(parts) > 1 else domain
    # 长数字串（如 dns 隧道 / DGA）
    if re.search(r"\d{4,}", body):
        features.append("含长数字串 (long digit sequence)")
    # 高熵（随机字符串域名）
    if len(body) >= 8 and _entropy(body) > 3.8:
        features.append("高熵随机串 (high entropy)")
    # 深层子域
    if len(parts) >= 4:
        features.append("深层子域 (deep subdomain)")
    return features


def _confused_features(s: str) -> list[str]:
    """检测混淆编码的 URL 串"""
    features: list[str] = []
    stripped = s.strip()
    for prefix in _CONFUSED_PREFIXES:
        if stripped.startswith(prefix):
            features.append("疑似编码混淆 URL (likely encoded URL)")
            break
    else:
        # 通用 base64 检测：可解码且解码后含 http
        try:
            decoded = base64.b64decode(stripped + "=" * (-len(stripped) % 4))
            if decoded and b"http" in decoded.lower():
                features.append("base64 编码的 URL (base64-encoded URL)")
        except Exception:
            pass
    return features


def _score_and_features(endpoint: str, kind: str) -> tuple[int, list[str]]:
    """对端点打分并返回特征列表"""
    score = 0
    features: list[str] = []

    if kind == "ip":
        if _is_private_ip(endpoint):
            features.append("内网/保留地址 (private/reserved)")
            score += 2
        else:
            score += 3  # 公网 IP 硬编码
            features.append("硬编码公网 IP (hardcoded public IP)")

    elif kind == "domain":
        dga_features = _dga_features(endpoint)
        if dga_features:
            features.extend(dga_features)
            score += 2  # DGA 特征（长数字串/高熵/深层子域）
        if endpoint.startswith("xn--"):
            features.append("IDN punycode 伪装 (IDN punycode)")
            score += 3
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", endpoint.split(".")[0]):
            # IP 化域名
            features.append("IP 化域名 (IP-as-domain)")
            score += 2

    # URL：解析出 host 和端口再评估
    if kind == "url":
        try:
            parts = urlsplit(endpoint)
            host = parts.hostname or ""
            port = parts.port
            if port and port not in _STANDARD_PORTS:
                features.append(f"非标准端口 {port} (non-standard port)")
                score += 2
            # 递归评估 host
            if host and re.fullmatch(r"[\d.]+", host):
                if _is_private_ip(host):
                    features.append("内网地址 (private IP)")
                    score += 2
                else:
                    features.append("硬编码公网 IP (hardcoded public IP)")
                    score += 3
            elif host:
                sub_score, sub_features = _score_and_features(host, "domain")
                score += sub_score
                features.extend(sub_features)
            if "http" in endpoint.split("://")[0].lower():
                pass
        except ValueError:
            pass

    # 通用：混淆特征（对 domain 和 url 都检查）
    confused = _confused_features(endpoint)
    if confused:
        features.extend(confused)
        score += 3

    return score, features


def extract_network_endpoints(strings: set[str]) -> list[NetworkEndpoint]:
    """从字符串池提取所有网络端点并打分"""
    endpoints: dict[str, NetworkEndpoint] = {}

    def add(endpoint: str, kind: str, context: str = "") -> None:
        endpoint = endpoint.rstrip(".,;:)")
        if not endpoint or len(endpoint) > 512:
            return
        score, features = _score_and_features(endpoint, kind)
        if endpoint in endpoints:
            existing = endpoints[endpoint]
            if context and context not in existing.contexts:
                existing.contexts.append(context)
            return
        endpoints[endpoint] = NetworkEndpoint(
            endpoint=endpoint, kind=kind, features=features, score=score
        )

    for s in strings:
        # URL（完整提取）
        for m in _URL_RE.findall(s):
            add(m.rstrip(".,;:)"), "url")
        # IP
        for m in _IPV4_RE.findall(s):
            add(m, "ip")
        for m in _IPV6_RE.findall(s):
            if not _looks_like_hash(m):
                add(m, "ip")
        # 域名
        for m in _DOMAIN_RE.findall(s):
            low = m.lower()
            if low not in _NOISE_DOMAINS and not low.endswith(".local"):
                add(low, "domain")

    result = list(endpoints.values())
    result.sort(key=lambda e: e.score, reverse=True)
    return result


def _looks_like_hash(s: str) -> bool:
    """IPv6 候选看起来像 hash（全 hex 且过长）时排除"""
    return len(s) > 39 and all(c in string.hexdigits + ":" for c in s)
