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

# 常见 TLD 白名单：域名候选的最后一段必须是常见 TLD 或国家码。
# Java 类名（com.foo.bar.baz 等）以任意词结尾，用 TLD 校验可通用区分，
# 避免对每个框架包维护前缀黑名单（军备竞赛）。
_VALID_TLDS: frozenset[str] = frozenset(
    {
        # 通用 TLD
        "com", "net", "org", "io", "co", "info", "biz", "me", "tv", "cc",
        "top", "xyz", "online", "site", "tech", "store", "app", "dev", "ai",
        "vip", "club", "shop", "link", "live", "fun", "xin", "wang", "mobi",
        "asia", "cloud", "digital", "space", "website", "world", "email",
        "blog", "news", "media", "pro", "name", "social", "work", "tech",
        # 常见国家码
        "us", "uk", "de", "fr", "jp", "kr", "ru", "in", "br", "au", "ca",
        "nl", "se", "ch", "it", "es", "mx", "za", "sg", "hk", "tw", "mo",
        "th", "my", "id", "vn", "ph", "nz", "ie", "at", "be", "dk", "fi",
        "no", "pl", "pt", "gr", "tr", "il", "ae", "sa", "eg", "ar", "cl",
        "pe", "uy", "py", "bo", "cn", "hk", "tw", "io", "co", "eu",
    }
)


def _is_valid_domain(domain: str) -> bool:
    """域名候选的 TLD 必须在常见列表中，否则视为类名/伪域名"""
    tld = domain.rsplit(".", 1)[-1]
    return tld in _VALID_TLDS


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

# Java 框架包前缀：混淆 APK 的字符串池会保留大量框架类全名，
# 这些包名（com.google.android.gms.* 等）永远不可能是真实域名，直接过滤。
# 注意：com.google.android 会被过滤，但 google.com / googleapis.com 保留。
_CLASS_PREFIX_FILTERS = (
    "android.",
    "androidx.",
    "android.support.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "dalvik.",
    "junit.",
    "org.apache.",
    "org.bouncycastle.",
    "org.chromium.",
    "org.json.",
    "org.xml.",
    "org.greenrobot.",
    "com.android.",
    "com.google.android.",
    "com.google.firebase.",
    "com.google.protobuf.",
    "com.google.gson.",
    "com.squareup.",
    "com.facebook.",
    "com.tencent.",
    "com.alibaba.",
    "com.bytedance.",
    "okhttp3.",
    "retrofit2.",
    "rx.",
    "io.reactivex.",
)

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


# OID（对象标识符）子树黑名单：证书/加密库中的数字标识符会被 IPv4 正则误提取
# 如 2.5.29.x (X.509 扩展)、1.3.6.1 (互联网 OID)、1.2.840 (ANSI)、5.5.7.x 等。
# 实测真实 APK：裸 IP（非 URL 上下文）首段 0-5 的几乎全是 OID/版本号残留；
# 真实硬编码 IP（61.x、223.x 等）首段都在 6 以上。


def _is_oid_like(ip_str: str) -> bool:
    """判断一个裸 IPv4 字符串是否更可能是 OID/版本号而非 IP。

    仅用于裸 IP 判定；URL 中的 IP host（http://x.x.x.x）上下文更强，
    由调用方单独处理，不走此过滤。
    """
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
    except ValueError:
        return False
    # 0-5 段：OID/版本号重灾区；真实公网 C2 硬编码几乎不在此范围
    return first <= 5


_MAC_RE = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")
_TIME_RE = re.compile(r"\d{1,2}:\d{2}:\d{2}")


def _is_mac_or_time(ip_str: str) -> bool:
    """MAC 地址（6 组两位十六进制，如 02:00:00:00:00:00）或时间串
    （HH:MM:SS，如 02:18:46）与 IPv6 同形，但绝不可能是合法 IPv6
    （IPv6 需要 8 组或 :: 压缩），直接排除，避免被误报为"硬编码公网 IP"。
    """
    return bool(_MAC_RE.fullmatch(ip_str)) or bool(_TIME_RE.fullmatch(ip_str))


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
            pass  # 解码失败说明不是 base64 混淆串，忽略
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
                if _is_oid_like(host):
                    pass  # OID 伪 IP（如 http://2.5.29.x 的字符串），不评分
                elif _is_private_ip(host):
                    features.append("内网地址 (private IP)")
                    score += 2
                else:
                    features.append("硬编码公网 IP (hardcoded public IP)")
                    score += 3
            elif host:
                sub_score, sub_features = _score_and_features(host, "domain")
                score += sub_score
                features.extend(sub_features)
        except ValueError:
            pass  # 畸形 URL（如非法端口）不评分，忽略

    # 通用：混淆特征（对 domain 和 url 都检查）
    confused = _confused_features(endpoint)
    if confused:
        features.extend(confused)
        score += 3

    return score, features


def _build_class_path_index(classes: list[str]) -> set[str]:
    """构建类名包路径索引：用于区分"域名"与 Java 类名。

    Java 包名（com.foo.bar）与域名格式完全同形，是域名提取的最大误报源。
    把每个类名按 '/' 切分，收集所有层级路径（小写），
    域名候选转斜杠后若命中该索引即判定为类名。
    """
    paths: set[str] = set()
    for cls in classes:
        c = cls.lstrip("L").rstrip(";").lower()
        parts = c.split("/")
        for i in range(1, len(parts) + 1):
            paths.add("/".join(parts[:i]))
    return paths


def extract_network_endpoints(
    strings: set[str], classes: list[str] | None = None
) -> list[NetworkEndpoint]:
    """从字符串池提取所有网络端点并打分。

    classes: dex 类名列表（可选），用于过滤被误判为域名的 Java 包名。
    """
    endpoints: dict[str, NetworkEndpoint] = {}
    class_paths = _build_class_path_index(classes or []) if classes else None

    def add(endpoint: str, kind: str, context: str = "") -> None:
        endpoint = endpoint.rstrip(".,;:)")
        if not endpoint or len(endpoint) > 512:
            return
        # OID 伪 IP 过滤：证书/加密库的数字标识符不是网络端点
        if kind == "ip" and _is_oid_like(endpoint):
            return
        # MAC 地址 / 时间串过滤：与 IPv6 同形但不是 IP（蓝牙/WiFi MAC、HH:MM:SS）
        if kind == "ip" and _is_mac_or_time(endpoint):
            return
        # Java 类名过滤：包路径与域名同形
        if kind == "domain":
            low = endpoint.lower()
            if low in _NOISE_DOMAINS or low.endswith(".local"):
                return
            # TLD 白名单：非标准 TLD 的多段点分串是类名/伪域名
            if not _is_valid_domain(low):
                return
            if any(low.startswith(p) for p in _CLASS_PREFIX_FILTERS):
                return
            if class_paths is not None:
                norm = low.replace(".", "/")
                if norm in class_paths:
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
