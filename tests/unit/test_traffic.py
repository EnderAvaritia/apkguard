"""抓包代理单元测试：HTTP/CONNECT 端点记录、去重、代理地址解析。"""
from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from apkguard.dynamic.traffic import ProxyCapture, resolve_proxy_target  # noqa: E402


def free_port() -> int:
    s = socket.socket()
    s.bind(("0.0.0.0", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _raw_request(port: int, payload: bytes) -> bytes:
    """向代理发送原始字节，返回响应头前若干字节（不等待完整响应）"""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(payload)
        sock.settimeout(5)
        try:
            return sock.recv(1024)
        except socket.timeout:
            return b""


def _wait_endpoints(cap: ProxyCapture, expected: int, timeout: float = 5.0) -> list[str]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        eps = cap.endpoints
        if len(eps) >= expected:
            return eps
        time.sleep(0.05)
    return cap.endpoints


class TestProxyCapture:
    def test_records_http_absolute_url(self):
        cap = ProxyCapture(port=free_port())
        assert cap.start()
        try:
            # 模拟设备侧代理请求：绝对形式请求行
            _raw_request(
                cap.port,
                b"GET http://c2.example.com/beacon?id=1 HTTP/1.1\r\n"
                b"Host: c2.example.com\r\n\r\n",
            )
            eps = _wait_endpoints(cap, 1)
            assert "http://c2.example.com/beacon?id=1" in eps
        finally:
            cap.stop()

    def test_records_connect_endpoint_even_if_unreachable(self):
        cap = ProxyCapture(port=free_port())
        assert cap.start()
        try:
            # 目标不可达（127.0.0.1:1）→ 502，但端点必须先被记录
            _raw_request(cap.port, b"CONNECT 127.0.0.1:1 HTTP/1.1\r\n\r\n")
            eps = _wait_endpoints(cap, 1)
            assert "127.0.0.1:1" in eps
        finally:
            cap.stop()

    def test_dedupes_endpoints(self):
        cap = ProxyCapture(port=free_port())
        assert cap.start()
        try:
            req = b"CONNECT c2.example.com:443 HTTP/1.1\r\n\r\n"
            _raw_request(cap.port, req)
            _raw_request(cap.port, req)
            eps = _wait_endpoints(cap, 1)
            assert len(eps) == 1
            assert cap.count == 2  # 计数不重复去重
        finally:
            cap.stop()

    def test_bind_failure_returns_false(self):
        # 先占用一个端口，再让 ProxyCapture 绑定 → 应失败不抛异常
        blocker = socket.socket()
        blocker.bind(("0.0.0.0", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        try:
            cap = ProxyCapture(port=port)
            assert cap.start() is False
            cap.stop()  # 幂等，不应抛异常
        finally:
            blocker.close()


class TestResolveProxyTarget:
    def test_emulator_uses_host_loopback_alias(self):
        assert resolve_proxy_target("emulator-5554", "", 8080) == "10.0.2.2:8080"

    def test_real_device_uses_configured_host_ip(self):
        assert resolve_proxy_target("0123456789ABCDEF", "192.168.1.5", 8080) == "192.168.1.5:8080"
